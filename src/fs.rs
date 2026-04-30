use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, FUSE_ROOT_ID,
};

use crate::overlay::Overlay;
use crate::rules::{PathClass, RuleSet};

const TTL: Duration = Duration::from_secs(1);

pub struct ShadowFs {
    source: PathBuf,
    source_fd: File,
    mountpoint: PathBuf,
    rules: RuleSet,
    overlay: Overlay,
    next_inode: u64,
    inode_to_path: HashMap<u64, PathBuf>,
    path_to_inode: HashMap<PathBuf, u64>,
    next_fh: u64,
    open_files: HashMap<u64, File>,
}

impl ShadowFs {
    pub fn new(source: PathBuf, mountpoint: PathBuf, rules: RuleSet, overlay: Overlay) -> Self {
        let mut inode_to_path = HashMap::new();
        let mut path_to_inode = HashMap::new();

        let root = PathBuf::new();
        inode_to_path.insert(FUSE_ROOT_ID, root.clone());
        path_to_inode.insert(root, FUSE_ROOT_ID);

        // Open source dir as an fd so we can access it via /proc/self/fd/<n>/
        // even after a bind-mount obscures the original path.
        let source_fd = File::open(&source).expect("failed to open source directory fd");

        Self {
            source,
            source_fd,
            mountpoint,
            rules,
            overlay,
            next_inode: FUSE_ROOT_ID + 1,
            inode_to_path,
            path_to_inode,
            next_fh: 1,
            open_files: HashMap::new(),
        }
    }

    fn real_path(&self, rel: &Path) -> PathBuf {
        // Route through /proc/self/fd/<n> so the fd-based reference bypasses
        // any bind-mount that may later be stacked on top of self.source.
        let fd_root = PathBuf::from(format!("/proc/self/fd/{}", self.source_fd.as_raw_fd()));
        if rel.as_os_str().is_empty() {
            // Append "." so that lstat() resolves through the procfs symlink
            // and returns directory metadata rather than symlink metadata.
            fd_root.join(".")
        } else {
            fd_root.join(rel)
        }
    }

    fn remove_inode(&mut self, rel_path: &Path) {
        if let Some(ino) = self.path_to_inode.remove(rel_path) {
            self.inode_to_path.remove(&ino);
        }
    }

    fn get_or_assign_inode(&mut self, rel_path: PathBuf) -> u64 {
        if let Some(&ino) = self.path_to_inode.get(&rel_path) {
            return ino;
        }
        let ino = self.next_inode;
        self.next_inode += 1;
        self.inode_to_path.insert(ino, rel_path.clone());
        self.path_to_inode.insert(rel_path, ino);
        ino
    }

    fn metadata_to_attr(ino: u64, meta: &fs::Metadata) -> FileAttr {
        let kind = if meta.is_dir() {
            FileType::Directory
        } else if meta.file_type().is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        FileAttr {
            ino,
            size: meta.size(),
            blocks: meta.blocks(),
            atime: system_time(meta.atime(), meta.atime_nsec()),
            mtime: system_time(meta.mtime(), meta.mtime_nsec()),
            ctime: system_time(meta.ctime(), meta.ctime_nsec()),
            crtime: UNIX_EPOCH,
            kind,
            perm: (meta.mode() & 0o7777) as u16,
            nlink: meta.nlink() as u32,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: meta.rdev() as u32,
            blksize: 512,
            flags: 0,
        }
    }
}

fn system_time(secs: i64, nsecs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs as u32)
    } else {
        UNIX_EPOCH
    }
}

fn open_with_flags(path: &Path, flags: i32) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    let access_mode = flags & libc::O_ACCMODE;
    match access_mode {
        libc::O_RDONLY => {
            opts.read(true);
        }
        libc::O_WRONLY => {
            opts.write(true);
        }
        libc::O_RDWR => {
            opts.read(true).write(true);
        }
        _ => {
            opts.read(true);
        }
    }
    if flags & libc::O_APPEND != 0 {
        opts.append(true);
    }
    if flags & libc::O_TRUNC != 0 {
        opts.truncate(true);
    }
    opts.open(path)
}

fn is_write_flags(flags: i32) -> bool {
    let access_mode = flags & libc::O_ACCMODE;
    access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR
}

impl Filesystem for ShadowFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);
        let class = self.rules.classify(&child_rel, None);

        match class {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
            }
            PathClass::WritableOverlay => {
                let Some(overlay_path) = self.overlay.resolve_if_exists(&child_rel) else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let Ok(meta) = overlay_path.symlink_metadata() else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let ino = self.get_or_assign_inode(child_rel);
                let attr = Self::metadata_to_attr(ino, &meta);
                reply.entry(&TTL, &attr, 0);
            }
            PathClass::Blocked | PathClass::GitignoreFile | PathClass::Passthrough => {
                let real = self.real_path(&child_rel);
                let Ok(meta) = real.symlink_metadata() else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let ino = self.get_or_assign_inode(child_rel);
                let mut attr = Self::metadata_to_attr(ino, &meta);
                if class == PathClass::Blocked {
                    attr.perm = 0o000;
                }
                reply.entry(&TTL, &attr, 0);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(rel) = self.inode_to_path.get(&ino).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let class = self.rules.classify(&rel, None);

        match class {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::WritableOverlay => {
                let Some(overlay_path) = self.overlay.resolve_if_exists(&rel) else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let Ok(meta) = overlay_path.symlink_metadata() else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let attr = Self::metadata_to_attr(ino, &meta);
                reply.attr(&TTL, &attr);
                return;
            }
            _ => {}
        }

        let real = self.real_path(&rel);
        let Ok(meta) = real.symlink_metadata() else {
            reply.error(libc::ENOENT);
            return;
        };

        let mut attr = Self::metadata_to_attr(ino, &meta);
        if class == PathClass::Blocked {
            attr.perm = 0o000;
        }
        reply.attr(&TTL, &attr);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(rel) = self.inode_to_path.get(&ino).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let real = self.real_path(&rel);
        let Ok(entries) = fs::read_dir(&real) else {
            reply.error(libc::ENOENT);
            return;
        };

        let mut children: Vec<(PathBuf, String, FileType)> = Vec::new();
        let mut seen_names: HashSet<String> = HashSet::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let child_rel = rel.join(&name);
            let entry_is_dir = entry.file_type().ok().is_some_and(|ft| ft.is_dir());
            let class = self.rules.classify(&child_rel, Some(entry_is_dir));
            match class {
                PathClass::Hidden => continue,
                PathClass::WritableOverlay => {
                    let Some(overlay_path) = self.overlay.resolve_if_exists(&child_rel) else {
                        continue;
                    };
                    let ft = if overlay_path.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    seen_names.insert(name.clone());
                    children.push((child_rel, name, ft));
                }
                _ => {
                    let ft = match entry.file_type() {
                        Ok(ft) if ft.is_dir() => FileType::Directory,
                        Ok(ft) if ft.is_symlink() => FileType::Symlink,
                        _ => FileType::RegularFile,
                    };
                    seen_names.insert(name.clone());
                    children.push((child_rel, name, ft));
                }
            }
        }

        let overlay_dir = self.overlay.resolve(&rel);
        if overlay_dir.is_dir() {
            if let Ok(overlay_entries) = fs::read_dir(&overlay_dir) {
                for entry in overlay_entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if seen_names.contains(&name) {
                        continue;
                    }
                    let child_rel = rel.join(&name);
                    let entry_is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
                    if matches!(self.rules.classify(&child_rel, Some(entry_is_dir)), PathClass::WritableOverlay) {
                        let ft = if entry_is_dir {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        };
                        children.push((child_rel, name, ft));
                    }
                }
            }
        }

        let parent_ino = if rel.as_os_str().is_empty() {
            FUSE_ROOT_ID
        } else {
            let parent_rel = rel.parent().map(Path::to_path_buf).unwrap_or_default();
            *self.path_to_inode.get(&parent_rel).unwrap_or(&FUSE_ROOT_ID)
        };

        let mut idx: i64 = 0;

        idx += 1;
        if idx > offset && reply.add(ino, idx, FileType::Directory, ".") {
            reply.ok();
            return;
        }

        idx += 1;
        if idx > offset && reply.add(parent_ino, idx, FileType::Directory, "..") {
            reply.ok();
            return;
        }

        for (child_rel, name, ft) in children {
            idx += 1;
            if idx <= offset {
                continue;
            }
            let child_ino = self.get_or_assign_inode(child_rel);
            if reply.add(child_ino, idx, ft, &name) {
                reply.ok();
                return;
            }
        }

        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(rel) = self.inode_to_path.get(&ino).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let path = match self.rules.classify(&rel, Some(false)) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::WritableOverlay => {
                let Some(p) = self.overlay.resolve_if_exists(&rel) else {
                    reply.error(libc::ENOENT);
                    return;
                };
                p
            }
            PathClass::GitignoreFile => {
                if is_write_flags(flags) {
                    reply.error(libc::EACCES);
                    return;
                }
                self.real_path(&rel)
            }
            PathClass::Passthrough => self.real_path(&rel),
        };

        let file = match open_with_flags(&path, flags) {
            Ok(f) => f,
            Err(e) => {
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                return;
            }
        };

        let fh = self.next_fh;
        self.next_fh += 1;
        self.open_files.insert(fh, file);
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(file) = self.open_files.get_mut(&fh) else {
            reply.error(libc::ENOENT);
            return;
        };

        if file.seek(SeekFrom::Start(offset as u64)).is_err() {
            reply.error(libc::EIO);
            return;
        }

        let mut buf = vec![0u8; size as usize];
        match file.read(&mut buf) {
            Ok(n) => reply.data(&buf[..n]),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Some(file) = self.open_files.get_mut(&fh) else {
            reply.error(libc::ENOENT);
            return;
        };

        if file.seek(SeekFrom::Start(offset as u64)).is_err() {
            reply.error(libc::EIO);
            return;
        }

        match file.write(data) {
            Ok(n) => reply.written(n as u32),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);

        let path = match self.rules.classify(&child_rel, Some(false)) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::WritableOverlay => {
                let overlay_path = self.overlay.resolve(&child_rel);
                if let Some(p) = overlay_path.parent() {
                    if fs::create_dir_all(p).is_err() {
                        reply.error(libc::EIO);
                        return;
                    }
                }
                overlay_path
            }
            PathClass::Passthrough => self.real_path(&child_rel),
        };

        let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(flags & libc::O_TRUNC != 0)
            .open(&path)
        else {
            reply.error(libc::EIO);
            return;
        };

        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));

        let Ok(meta) = path.symlink_metadata() else {
            reply.error(libc::EIO);
            return;
        };

        let ino = self.get_or_assign_inode(child_rel);
        let attr = Self::metadata_to_attr(ino, &meta);
        let fh = self.next_fh;
        self.next_fh += 1;
        self.open_files.insert(fh, file);
        reply.created(&TTL, &attr, 0, fh, 0);
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(rel) = self.inode_to_path.get(&ino).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let real = self.real_path(&rel);
        let is_dir = real.is_dir();

        let path = match self.rules.classify(&rel, Some(is_dir)) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::WritableOverlay => {
                let Some(p) = self.overlay.resolve_if_exists(&rel) else {
                    reply.error(libc::ENOENT);
                    return;
                };
                p
            }
            PathClass::Passthrough => real,
        };

        if let Some(new_size) = size {
            if let Ok(file) = OpenOptions::new().write(true).open(&path) {
                let _ = file.set_len(new_size);
            }
        }

        if let Some(new_mode) = mode {
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(new_mode));
        }

        let Ok(meta) = path.symlink_metadata() else {
            reply.error(libc::EIO);
            return;
        };

        let attr = Self::metadata_to_attr(ino, &meta);
        reply.attr(&TTL, &attr);
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);

        match self.rules.classify(&child_rel, Some(true)) {
            PathClass::Passthrough => {}
            PathClass::Hidden | PathClass::WritableOverlay => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
                return;
            }
        }

        let real = self.real_path(&child_rel);
        if let Err(e) = fs::create_dir(&real) {
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }

        let _ = fs::set_permissions(&real, fs::Permissions::from_mode(mode));

        let Ok(meta) = real.symlink_metadata() else {
            reply.error(libc::EIO);
            return;
        };

        let ino = self.get_or_assign_inode(child_rel);
        let attr = Self::metadata_to_attr(ino, &meta);
        reply.entry(&TTL, &attr, 0);
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);

        match self.rules.classify(&child_rel, Some(true)) {
            PathClass::Passthrough => {}
            PathClass::Hidden | PathClass::WritableOverlay => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
                return;
            }
        }

        let real = self.real_path(&child_rel);
        if let Err(e) = fs::remove_dir(&real) {
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }

        self.remove_inode(&child_rel);

        reply.ok();
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);

        match self.rules.classify(&child_rel, Some(false)) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
            }
            PathClass::WritableOverlay => {
                let Some(overlay_path) = self.overlay.resolve_if_exists(&child_rel) else {
                    reply.error(libc::ENOENT);
                    return;
                };
                if let Err(e) = fs::remove_file(&overlay_path) {
                    reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                    return;
                }
                self.remove_inode(&child_rel);
                reply.ok();
            }
            PathClass::Passthrough => {
                let real = self.real_path(&child_rel);
                if let Err(e) = fs::remove_file(&real) {
                    reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                    return;
                }
                self.remove_inode(&child_rel);
                reply.ok();
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(new_parent_rel) = self.inode_to_path.get(&newparent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let old_rel = parent_rel.join(name);
        let new_rel = new_parent_rel.join(newname);

        if !matches!(self.rules.classify(&old_rel, None), PathClass::Passthrough)
            || !matches!(self.rules.classify(&new_rel, None), PathClass::Passthrough)
        {
            reply.error(libc::EACCES);
            return;
        }

        let old_real = self.real_path(&old_rel);
        let new_real = self.real_path(&new_rel);

        if let Err(e) = fs::rename(&old_real, &new_real) {
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }

        if let Some(ino) = self.path_to_inode.remove(&old_rel) {
            self.inode_to_path.insert(ino, new_rel.clone());
            self.path_to_inode.insert(new_rel, ino);
        }

        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        self.open_files.remove(&fh);
        reply.ok();
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let Some(rel) = self.inode_to_path.get(&ino).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        match self.rules.classify(&rel, Some(false)) {
            PathClass::Hidden | PathClass::WritableOverlay => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::GitignoreFile | PathClass::Passthrough => {}
        }

        let real = self.real_path(&rel);
        let Ok(target) = fs::read_link(&real) else {
            reply.error(libc::ENOENT);
            return;
        };

        let target = if target.is_absolute() {
            if let Ok(suffix) = target.strip_prefix(&self.source) {
                self.mountpoint.join(suffix)
            } else {
                target
            }
        } else {
            target
        };

        reply.data(target.as_os_str().as_encoded_bytes());
    }
}

pub fn mount_options() -> Vec<MountOption> {
    vec![
        MountOption::AutoUnmount,
        MountOption::FSName("fuseshadow".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::Overlay;
    use crate::rules::RuleSet;
    use fuser::{BackgroundSession, Session};
    use std::fs as stdfs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn dir_names(path: &Path) -> Vec<String> {
        stdfs::read_dir(path)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect()
    }

    fn writable_overlay_source() -> TempDir {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".env\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=hunter2").unwrap();
        source
    }

    fn test_mount(source: &Path, mountpoint: &Path) -> (BackgroundSession, PathBuf) {
        let rules = RuleSet::load(source).expect("failed to load rules");
        let overlay = Overlay::new().expect("failed to create overlay");
        let overlay_path = overlay.base_path().to_path_buf();
        let fs = ShadowFs::new(source.to_path_buf(), mountpoint.to_path_buf(), rules, overlay);
        let session = Session::new(fs, mountpoint, &mount_options())
            .expect("FUSE session failed — is the test runner using `unshare -r --user --mount`?");
        let bg = BackgroundSession::new(session).expect("background session failed");
        std::thread::sleep(Duration::from_millis(200));
        (bg, overlay_path)
    }

    // --- Phase 2: Read-only passthrough tests ---

    #[test]
    fn passthrough_file_content_matches_source() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("hello.txt"), "hello world").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let content = stdfs::read_to_string(mount.path().join("hello.txt")).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn passthrough_directory_listing_matches_source() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("a.txt"), "").unwrap();
        stdfs::write(source.path().join("b.txt"), "").unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(source.path().join("sub/c.txt"), "").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let mut source_names = dir_names(source.path());
        source_names.sort();

        let mut mount_names = dir_names(mount.path());
        mount_names.sort();

        assert_eq!(source_names, mount_names);
    }

    #[test]
    fn passthrough_nested_file_readable() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(source.path().join("sub/nested.txt"), "deep content").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let content = stdfs::read_to_string(mount.path().join("sub/nested.txt")).unwrap();
        assert_eq!(content, "deep content");
    }

    #[test]
    fn passthrough_symlink_readable() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("target.txt"), "linked content").unwrap();
        std::os::unix::fs::symlink("target.txt", source.path().join("link.txt")).unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let target = stdfs::read_link(mount.path().join("link.txt")).unwrap();
        assert_eq!(target.to_string_lossy(), "target.txt");

        let content = stdfs::read_to_string(mount.path().join("link.txt")).unwrap();
        assert_eq!(content, "linked content");
    }

    // --- Phase 3: Access rule enforcement tests ---

    #[test]
    fn blocked_file_visible_in_readdir_with_zero_permissions() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("data.secret"), "sensitive").unwrap();
        stdfs::write(source.path().join("normal.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(names.contains(&"data.secret".to_string()));
        assert!(names.contains(&"normal.txt".to_string()));

        let meta = stdfs::symlink_metadata(mount.path().join("data.secret")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
    }

    #[test]
    fn blocked_file_rejects_open() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("data.secret"), "sensitive").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let result = stdfs::read_to_string(mount.path().join("data.secret"));
        assert!(result.is_err());
    }

    #[test]
    fn hidden_files_absent_from_readdir() {
        let source = TempDir::new().unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[ignore]\npatterns = [\".git\"]\n",
        )
        .unwrap();
        stdfs::create_dir(source.path().join(".git")).unwrap();
        stdfs::write(source.path().join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        stdfs::write(source.path().join("visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(!names.contains(&".shadowconfig".to_string()));
        assert!(!names.contains(&".git".to_string()));
        assert!(names.contains(&"visible.txt".to_string()));
    }

    #[test]
    fn hidden_file_returns_enoent_on_lookup() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".shadowconfig"), "[ignore]\npatterns = []\n").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let result = stdfs::symlink_metadata(mount.path().join(".shadowconfig"));
        assert!(result.is_err());
    }

    #[test]
    fn gitignore_file_readable_through_mount() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.log\n").unwrap();
        stdfs::write(source.path().join("hello.txt"), "hi").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let content = stdfs::read_to_string(mount.path().join(".gitignore")).unwrap();
        assert_eq!(content, "*.log\n");
    }

    #[test]
    fn gitignore_file_visible_in_readdir() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.log\n").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(names.contains(&".gitignore".to_string()));
    }

    // --- Phase 4: Write support + writable overlay tests ---

    #[test]
    fn passthrough_create_and_write() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("existing.txt"), "original").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Create a new file through the mount
        stdfs::write(mount.path().join("new.txt"), "hello from mount").unwrap();
        assert_eq!(
            stdfs::read_to_string(source.path().join("new.txt")).unwrap(),
            "hello from mount"
        );

        // Overwrite existing file through the mount
        stdfs::write(mount.path().join("existing.txt"), "modified").unwrap();
        assert_eq!(
            stdfs::read_to_string(source.path().join("existing.txt")).unwrap(),
            "modified"
        );
    }

    #[test]
    fn passthrough_mkdir_rmdir_rename_unlink() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("old.txt"), "content").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // mkdir
        stdfs::create_dir(mount.path().join("newdir")).unwrap();
        assert!(source.path().join("newdir").is_dir());

        // rename
        stdfs::rename(
            mount.path().join("old.txt"),
            mount.path().join("renamed.txt"),
        )
        .unwrap();
        assert!(!source.path().join("old.txt").exists());
        assert_eq!(
            stdfs::read_to_string(source.path().join("renamed.txt")).unwrap(),
            "content"
        );

        // unlink
        stdfs::remove_file(mount.path().join("renamed.txt")).unwrap();
        assert!(!source.path().join("renamed.txt").exists());

        // rmdir
        stdfs::remove_dir(mount.path().join("newdir")).unwrap();
        assert!(!source.path().join("newdir").exists());
    }

    #[test]
    fn writable_overlay_invisible_before_write() {
        let source = writable_overlay_source();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(!names.contains(&".env".to_string()));

        let result = stdfs::symlink_metadata(mount.path().join(".env"));
        assert!(result.is_err());
    }

    #[test]
    fn writable_overlay_write_visible_and_readable() {
        let source = writable_overlay_source();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        stdfs::write(mount.path().join(".env"), "GENERATED=safe_value").unwrap();

        // Should be visible in directory listing
        let names = dir_names(mount.path());
        assert!(names.contains(&".env".to_string()));

        // Should return the overlay content, never the source secret
        let content = stdfs::read_to_string(mount.path().join(".env")).unwrap();
        assert_eq!(content, "GENERATED=safe_value");

        // Source file should be untouched
        assert_eq!(
            stdfs::read_to_string(source.path().join(".env")).unwrap(),
            "SECRET=hunter2"
        );
    }

    #[test]
    fn writable_overlay_unlink_makes_invisible_can_recreate() {
        let source = writable_overlay_source();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Write, then delete
        stdfs::write(mount.path().join(".env"), "first_write").unwrap();
        stdfs::remove_file(mount.path().join(".env")).unwrap();

        // Should be invisible again
        let result = stdfs::symlink_metadata(mount.path().join(".env"));
        assert!(result.is_err());

        // Re-create
        stdfs::write(mount.path().join(".env"), "second_write").unwrap();
        let content = stdfs::read_to_string(mount.path().join(".env")).unwrap();
        assert_eq!(content, "second_write");
    }

    #[test]
    fn unmount_removes_overlay_directory() {
        let source = writable_overlay_source();

        let mount = TempDir::new().unwrap();
        let (session, overlay_path) = test_mount(source.path(), mount.path());

        stdfs::write(mount.path().join(".env"), "content").unwrap();
        assert!(overlay_path.exists());

        drop(session);
        std::thread::sleep(Duration::from_millis(500));

        assert!(!overlay_path.exists());
    }

    #[test]
    fn blocked_path_rejects_write() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("data.secret"), "sensitive").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let result = stdfs::write(mount.path().join("data.secret"), "modified");
        assert!(result.is_err());
    }

    #[test]
    fn gitignore_file_rejects_write() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.log\n").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let result = stdfs::write(mount.path().join(".gitignore"), "modified");
        assert!(result.is_err());
    }

    // --- Phase 5: Symlink rewriting + hardening tests ---

    #[test]
    fn absolute_symlink_into_source_rewritten_to_mountpoint() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("target.txt"), "content").unwrap();
        std::os::unix::fs::symlink(
            source.path().join("target.txt"),
            source.path().join("abs_link.txt"),
        )
        .unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let target = stdfs::read_link(mount.path().join("abs_link.txt")).unwrap();
        assert_eq!(target, mount.path().join("target.txt"));

        let content = stdfs::read_to_string(mount.path().join("abs_link.txt")).unwrap();
        assert_eq!(content, "content");
    }

    #[test]
    fn absolute_symlink_outside_source_passes_through() {
        let source = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        stdfs::write(external.path().join("ext.txt"), "external").unwrap();
        std::os::unix::fs::symlink(
            external.path().join("ext.txt"),
            source.path().join("ext_link.txt"),
        )
        .unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let target = stdfs::read_link(mount.path().join("ext_link.txt")).unwrap();
        assert_eq!(target, external.path().join("ext.txt"));
    }

    #[test]
    fn relative_symlink_passes_through_unchanged() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("target.txt"), "content").unwrap();
        std::os::unix::fs::symlink("target.txt", source.path().join("rel_link.txt")).unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let target = stdfs::read_link(mount.path().join("rel_link.txt")).unwrap();
        assert_eq!(target.to_string_lossy(), "target.txt");

        let content = stdfs::read_to_string(mount.path().join("rel_link.txt")).unwrap();
        assert_eq!(content, "content");
    }

    // --- Inode cleanup + readdir dedup tests ---

    #[test]
    fn unlink_then_recreate_returns_new_content() {
        let source = TempDir::new().unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        stdfs::write(mount.path().join("ephemeral.txt"), "first").unwrap();
        assert_eq!(
            stdfs::read_to_string(mount.path().join("ephemeral.txt")).unwrap(),
            "first"
        );

        stdfs::remove_file(mount.path().join("ephemeral.txt")).unwrap();
        assert!(stdfs::metadata(mount.path().join("ephemeral.txt")).is_err());

        stdfs::write(mount.path().join("ephemeral.txt"), "second").unwrap();
        assert_eq!(
            stdfs::read_to_string(mount.path().join("ephemeral.txt")).unwrap(),
            "second"
        );
    }

    #[test]
    fn rmdir_then_recreate_works() {
        let source = TempDir::new().unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        stdfs::create_dir(mount.path().join("mydir")).unwrap();
        assert!(mount.path().join("mydir").is_dir());

        stdfs::remove_dir(mount.path().join("mydir")).unwrap();
        assert!(stdfs::metadata(mount.path().join("mydir")).is_err());

        stdfs::create_dir(mount.path().join("mydir")).unwrap();
        assert!(mount.path().join("mydir").is_dir());
    }

    #[test]
    fn unlink_then_absent_from_readdir() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("keep.txt"), "").unwrap();
        stdfs::write(source.path().join("remove.txt"), "").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(names.contains(&"remove.txt".to_string()));

        stdfs::remove_file(mount.path().join("remove.txt")).unwrap();

        let names = dir_names(mount.path());
        assert!(!names.contains(&"remove.txt".to_string()));
        assert!(names.contains(&"keep.txt".to_string()));
    }

    #[test]
    fn overlay_unlink_then_recreate_returns_new_content() {
        let source = writable_overlay_source();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        stdfs::write(mount.path().join(".env"), "VAL=first").unwrap();
        assert_eq!(
            stdfs::read_to_string(mount.path().join(".env")).unwrap(),
            "VAL=first"
        );

        stdfs::remove_file(mount.path().join(".env")).unwrap();
        assert!(stdfs::metadata(mount.path().join(".env")).is_err());

        stdfs::write(mount.path().join(".env"), "VAL=second").unwrap();
        assert_eq!(
            stdfs::read_to_string(mount.path().join(".env")).unwrap(),
            "VAL=second"
        );
    }

    // --- PRD scenario coverage tests ---

    #[test]
    fn nested_shadowconfig_applies_to_subtree() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(
            source.path().join("sub/.shadowconfig"),
            "[ignore]\npatterns = [\"internal\"]\n",
        )
        .unwrap();
        stdfs::create_dir(source.path().join("sub/internal")).unwrap();
        stdfs::write(source.path().join("sub/internal/secret.txt"), "hidden").unwrap();
        stdfs::write(source.path().join("sub/visible.txt"), "hello").unwrap();
        // "internal" at root level should NOT be hidden (shadowconfig is in sub/)
        stdfs::create_dir(source.path().join("internal")).unwrap();
        stdfs::write(source.path().join("internal/root.txt"), "visible").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // sub/internal should be hidden
        let sub_names = dir_names(&mount.path().join("sub"));
        assert!(!sub_names.contains(&"internal".to_string()));
        assert!(sub_names.contains(&"visible.txt".to_string()));
        assert!(!sub_names.contains(&".shadowconfig".to_string()));

        // root-level "internal" should still be visible
        let root_names = dir_names(mount.path());
        assert!(root_names.contains(&"internal".to_string()));

        // direct lookup of sub/internal should fail
        assert!(stdfs::metadata(mount.path().join("sub/internal")).is_err());

        // root-level internal/root.txt should be readable
        assert_eq!(
            stdfs::read_to_string(mount.path().join("internal/root.txt")).unwrap(),
            "visible"
        );
    }

    #[test]
    fn hidden_directory_blocks_child_access() {
        let source = TempDir::new().unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[ignore]\npatterns = [\".git\"]\n",
        )
        .unwrap();
        stdfs::create_dir(source.path().join(".git")).unwrap();
        stdfs::create_dir(source.path().join(".git/objects")).unwrap();
        stdfs::write(source.path().join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        stdfs::write(source.path().join(".git/objects/abc"), "blob").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // .git itself should be invisible
        assert!(stdfs::metadata(mount.path().join(".git")).is_err());

        // direct access to children should also fail
        assert!(stdfs::metadata(mount.path().join(".git/HEAD")).is_err());
        assert!(stdfs::metadata(mount.path().join(".git/objects")).is_err());
        assert!(stdfs::metadata(mount.path().join(".git/objects/abc")).is_err());
    }

    #[test]
    fn ignore_beats_writable_at_fuse_level() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".env\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[ignore]\npatterns = [\".env\"]\n\n[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=value").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // should be hidden, not writable-overlay
        let names = dir_names(mount.path());
        assert!(!names.contains(&".env".to_string()));
        assert!(stdfs::metadata(mount.path().join(".env")).is_err());

        // writing should also fail (ENOENT, not create in overlay)
        assert!(stdfs::write(mount.path().join(".env"), "attempt").is_err());
    }

    #[test]
    fn nested_gitignore_enforced_at_fuse_level() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(source.path().join("sub/.gitignore"), "*.log\n").unwrap();
        stdfs::write(source.path().join("sub/app.log"), "log data").unwrap();
        stdfs::write(source.path().join("sub/code.rs"), "fn main() {}").unwrap();
        // root-level .log should NOT be blocked (gitignore is in sub/)
        stdfs::write(source.path().join("root.log"), "root log").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // sub/app.log should be blocked (visible with 0o000 perms, unreadable)
        let sub_names = dir_names(&mount.path().join("sub"));
        assert!(sub_names.contains(&"app.log".to_string()));
        let meta = stdfs::symlink_metadata(mount.path().join("sub/app.log")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(stdfs::read_to_string(mount.path().join("sub/app.log")).is_err());

        // sub/code.rs should be readable
        assert_eq!(
            stdfs::read_to_string(mount.path().join("sub/code.rs")).unwrap(),
            "fn main() {}"
        );

        // root.log should be passthrough (not blocked)
        assert_eq!(
            stdfs::read_to_string(mount.path().join("root.log")).unwrap(),
            "root log"
        );
    }

    #[test]
    fn blocked_pattern_rejects_create() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // creating a new file matching a blocked pattern should fail
        assert!(stdfs::write(mount.path().join("new.secret"), "data").is_err());

        // the file should not exist in source either
        assert!(!source.path().join("new.secret").exists());
    }

    #[test]
    fn static_snapshot_ignores_new_gitignore_after_mount() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("keep.txt"), "visible").unwrap();
        stdfs::write(source.path().join("later.txt"), "also visible").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // both files visible before any gitignore exists
        assert_eq!(
            stdfs::read_to_string(mount.path().join("later.txt")).unwrap(),
            "also visible"
        );

        // add a .gitignore AFTER mount that would block later.txt
        stdfs::write(source.path().join(".gitignore"), "later.txt\n").unwrap();

        // later.txt should still be fully readable (rules are snapshot at mount time)
        assert_eq!(
            stdfs::read_to_string(mount.path().join("later.txt")).unwrap(),
            "also visible"
        );
        let names = dir_names(mount.path());
        assert!(names.contains(&"later.txt".to_string()));
    }

    #[test]
    fn subdirectory_readdir_lists_correct_entries() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(source.path().join("sub/a.txt"), "").unwrap();
        stdfs::write(source.path().join("sub/b.txt"), "").unwrap();
        stdfs::create_dir(source.path().join("sub/nested")).unwrap();
        stdfs::write(source.path().join("sub/nested/c.txt"), "").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let mut sub_names = dir_names(&mount.path().join("sub"));
        sub_names.sort();
        assert_eq!(sub_names, vec!["a.txt", "b.txt", "nested"]);

        let nested_names = dir_names(&mount.path().join("sub/nested"));
        assert_eq!(nested_names, vec!["c.txt"]);
    }

    // --- Gap coverage tests ---

    #[test]
    fn parent_gitignore_enforced_at_fuse_level() {
        // Create parent dir with .gitignore, source dir nested inside
        let parent = TempDir::new().unwrap();
        stdfs::write(parent.path().join(".gitignore"), "*.secret\n").unwrap();
        let source = parent.path().join("project");
        stdfs::create_dir(&source).unwrap();
        stdfs::write(source.join("data.secret"), "sensitive").unwrap();
        stdfs::write(source.join("normal.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(&source, mount.path());

        // Blocked by parent .gitignore: visible with 0o000 perms, unreadable
        let names = dir_names(mount.path());
        assert!(names.contains(&"data.secret".to_string()));
        let meta = stdfs::symlink_metadata(mount.path().join("data.secret")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(stdfs::read_to_string(mount.path().join("data.secret")).is_err());

        // Normal file still accessible
        assert_eq!(
            stdfs::read_to_string(mount.path().join("normal.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn nested_gitignore_readable_not_writable_at_fuse_level() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(source.path().join("sub/.gitignore"), "*.log\n").unwrap();
        stdfs::write(source.path().join("sub/code.rs"), "fn main() {}").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Nested .gitignore should be readable
        let content = stdfs::read_to_string(mount.path().join("sub/.gitignore")).unwrap();
        assert_eq!(content, "*.log\n");

        // Nested .gitignore should be visible in readdir
        let names = dir_names(&mount.path().join("sub"));
        assert!(names.contains(&".gitignore".to_string()));

        // Nested .gitignore should reject writes
        assert!(stdfs::write(mount.path().join("sub/.gitignore"), "modified").is_err());
    }

    #[test]
    fn writable_overlay_in_subdirectory() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("config")).unwrap();
        stdfs::write(source.path().join(".gitignore"), "config/.env\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[writable]\npatterns = [\"config/.env\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join("config/.env"), "SECRET=original").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Should be invisible before write
        let config_names = dir_names(&mount.path().join("config"));
        assert!(!config_names.contains(&".env".to_string()));

        // Write through the mount — overlay creates intermediate dirs
        stdfs::write(mount.path().join("config/.env"), "GENERATED=safe").unwrap();

        // Should now be visible and readable with overlay content
        let config_names = dir_names(&mount.path().join("config"));
        assert!(config_names.contains(&".env".to_string()));
        let content = stdfs::read_to_string(mount.path().join("config/.env")).unwrap();
        assert_eq!(content, "GENERATED=safe");

        // Source untouched
        assert_eq!(
            stdfs::read_to_string(source.path().join("config/.env")).unwrap(),
            "SECRET=original"
        );
    }

    #[test]
    fn blocked_directory_visible_with_zero_permissions() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "node_modules/\n").unwrap();
        stdfs::create_dir(source.path().join("node_modules")).unwrap();
        stdfs::write(source.path().join("node_modules/pkg.json"), "{}").unwrap();
        stdfs::write(source.path().join("app.js"), "").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Blocked directory should appear in readdir with 0o000 permissions
        let names = dir_names(mount.path());
        assert!(names.contains(&"node_modules".to_string()));
        let meta = stdfs::symlink_metadata(mount.path().join("node_modules")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);

        // Creating files inside a blocked directory should fail
        assert!(stdfs::write(mount.path().join("node_modules/evil.js"), "bad").is_err());
    }

    #[test]
    fn setattr_rejected_on_blocked_file() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("data.secret"), "sensitive").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // chmod on a blocked file should fail
        let result = stdfs::set_permissions(
            mount.path().join("data.secret"),
            stdfs::Permissions::from_mode(0o644),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rename_passthrough_into_blocked_pattern_rejected() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("normal.txt"), "content").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Renaming into a blocked pattern should fail
        let result = stdfs::rename(
            mount.path().join("normal.txt"),
            mount.path().join("normal.secret"),
        );
        assert!(result.is_err());

        // Original file should still exist
        assert_eq!(
            stdfs::read_to_string(mount.path().join("normal.txt")).unwrap(),
            "content"
        );
    }

    #[test]
    fn rename_blocked_file_rejected() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("data.secret"), "sensitive").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Renaming a blocked file should fail
        let result = stdfs::rename(
            mount.path().join("data.secret"),
            mount.path().join("data.txt"),
        );
        assert!(result.is_err());

        // Source file should be unchanged
        assert_eq!(
            stdfs::read_to_string(source.path().join("data.secret")).unwrap(),
            "sensitive"
        );
    }

    #[test]
    fn multiple_shadowconfigs_compose_at_fuse_level() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".env\ncredentials.json\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[ignore]\npatterns = [\".git\"]\n[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::create_dir(source.path().join(".git")).unwrap();
        stdfs::write(source.path().join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=x").unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(
            source.path().join("sub/.shadowconfig"),
            "[ignore]\npatterns = [\"internal\"]\n[writable]\npatterns = [\"credentials.json\"]\n",
        )
        .unwrap();
        stdfs::create_dir(source.path().join("sub/internal")).unwrap();
        stdfs::write(source.path().join("sub/internal/notes.txt"), "hidden").unwrap();
        stdfs::write(source.path().join("sub/credentials.json"), "{}").unwrap();
        stdfs::write(source.path().join("sub/visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Root [ignore] hides .git
        let root_names = dir_names(mount.path());
        assert!(!root_names.contains(&".git".to_string()));
        assert!(stdfs::metadata(mount.path().join(".git")).is_err());

        // Root [writable] makes .env writable overlay (invisible before write)
        assert!(!root_names.contains(&".env".to_string()));
        stdfs::write(mount.path().join(".env"), "GENERATED=y").unwrap();
        assert_eq!(
            stdfs::read_to_string(mount.path().join(".env")).unwrap(),
            "GENERATED=y"
        );

        // Sub [ignore] hides sub/internal
        let sub_names = dir_names(&mount.path().join("sub"));
        assert!(!sub_names.contains(&"internal".to_string()));
        assert!(stdfs::metadata(mount.path().join("sub/internal")).is_err());

        // Sub [writable] makes sub/credentials.json writable overlay (invisible before write)
        assert!(!sub_names.contains(&"credentials.json".to_string()));
        stdfs::write(mount.path().join("sub/credentials.json"), "{\"gen\":true}").unwrap();
        assert_eq!(
            stdfs::read_to_string(mount.path().join("sub/credentials.json")).unwrap(),
            "{\"gen\":true}"
        );

        // Normal file still accessible
        assert!(sub_names.contains(&"visible.txt".to_string()));
    }

    // --- fd-pinning tests ---

    #[test]
    fn fd_pinning_survives_source_path_rename() {
        let parent = TempDir::new().unwrap();
        let source = parent.path().join("original");
        stdfs::create_dir(&source).unwrap();
        stdfs::write(source.join("hello.txt"), "pinned content").unwrap();
        stdfs::create_dir(source.join("sub")).unwrap();
        stdfs::write(source.join("sub/deep.txt"), "deep pinned").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(&source, mount.path());

        // Verify files accessible before rename
        assert_eq!(
            stdfs::read_to_string(mount.path().join("hello.txt")).unwrap(),
            "pinned content"
        );

        // Rename the source directory — breaks path-based access but
        // the fd still points to the original directory inode.
        let moved = parent.path().join("moved");
        stdfs::rename(&source, &moved).unwrap();
        assert!(!source.exists());

        // Mount should still serve the original content via the pinned fd
        assert_eq!(
            stdfs::read_to_string(mount.path().join("hello.txt")).unwrap(),
            "pinned content"
        );
        let names = dir_names(mount.path());
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));

        assert_eq!(
            stdfs::read_to_string(mount.path().join("sub/deep.txt")).unwrap(),
            "deep pinned"
        );
    }
}

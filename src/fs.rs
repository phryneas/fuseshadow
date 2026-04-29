use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

        Self {
            source,
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
        self.source.join(rel)
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

        match self.rules.classify(&child_rel) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
            }
            PathClass::WritableOverlay => {
                if !self.overlay.exists(&child_rel) {
                    reply.error(libc::ENOENT);
                    return;
                }
                let overlay_path = self.overlay.resolve(&child_rel);
                let Ok(meta) = overlay_path.symlink_metadata() else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let ino = self.get_or_assign_inode(child_rel);
                let attr = Self::metadata_to_attr(ino, &meta);
                reply.entry(&TTL, &attr, 0);
            }
            PathClass::Blocked => {
                let real = self.real_path(&child_rel);
                let Ok(meta) = real.symlink_metadata() else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let ino = self.get_or_assign_inode(child_rel);
                let mut attr = Self::metadata_to_attr(ino, &meta);
                attr.perm = 0o000;
                reply.entry(&TTL, &attr, 0);
            }
            PathClass::GitignoreFile | PathClass::Passthrough => {
                let real = self.real_path(&child_rel);
                let Ok(meta) = real.symlink_metadata() else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let ino = self.get_or_assign_inode(child_rel);
                let attr = Self::metadata_to_attr(ino, &meta);
                reply.entry(&TTL, &attr, 0);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(rel) = self.inode_to_path.get(&ino).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let class = self.rules.classify(&rel);

        match class {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::WritableOverlay => {
                if !self.overlay.exists(&rel) {
                    reply.error(libc::ENOENT);
                    return;
                }
                let overlay_path = self.overlay.resolve(&rel);
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
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let child_rel = rel.join(&name);
            let class = self.rules.classify(&child_rel);
            match class {
                PathClass::Hidden => continue,
                PathClass::WritableOverlay => {
                    if !self.overlay.exists(&child_rel) {
                        continue;
                    }
                    let overlay_path = self.overlay.resolve(&child_rel);
                    let ft = if overlay_path.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    children.push((child_rel, name, ft));
                }
                _ => {
                    let ft = match entry.file_type() {
                        Ok(ft) if ft.is_dir() => FileType::Directory,
                        Ok(ft) if ft.is_symlink() => FileType::Symlink,
                        _ => FileType::RegularFile,
                    };
                    children.push((child_rel, name, ft));
                }
            }
        }

        // Include overlay-only WritableOverlay files not present in source
        let overlay_dir = self.overlay.resolve(&rel);
        if overlay_dir.is_dir() {
            if let Ok(overlay_entries) = fs::read_dir(&overlay_dir) {
                for entry in overlay_entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if children.iter().any(|(_, n, _)| *n == name) {
                        continue;
                    }
                    let child_rel = rel.join(&name);
                    if matches!(self.rules.classify(&child_rel), PathClass::WritableOverlay) {
                        let ft = if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
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

        let path = match self.rules.classify(&rel) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::WritableOverlay => {
                if !self.overlay.exists(&rel) {
                    reply.error(libc::ENOENT);
                    return;
                }
                self.overlay.resolve(&rel)
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

        let Ok(file) = open_with_flags(&path, flags) else {
            reply.error(libc::EACCES);
            return;
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

        let path = match self.rules.classify(&child_rel) {
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

        let path = match self.rules.classify(&rel) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::WritableOverlay => {
                if !self.overlay.exists(&rel) {
                    reply.error(libc::ENOENT);
                    return;
                }
                self.overlay.resolve(&rel)
            }
            PathClass::Passthrough => self.real_path(&rel),
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

        match self.rules.classify(&child_rel) {
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
        if fs::create_dir(&real).is_err() {
            reply.error(libc::EIO);
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

        match self.rules.classify(&child_rel) {
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
        if fs::remove_dir(&real).is_err() {
            reply.error(libc::EIO);
            return;
        }

        reply.ok();
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);

        match self.rules.classify(&child_rel) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
            }
            PathClass::WritableOverlay => {
                if !self.overlay.exists(&child_rel) {
                    reply.error(libc::ENOENT);
                    return;
                }
                let overlay_path = self.overlay.resolve(&child_rel);
                if fs::remove_file(&overlay_path).is_err() {
                    reply.error(libc::EIO);
                    return;
                }
                reply.ok();
            }
            PathClass::Passthrough => {
                let real = self.real_path(&child_rel);
                if fs::remove_file(&real).is_err() {
                    reply.error(libc::EIO);
                    return;
                }
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

        if !matches!(self.rules.classify(&old_rel), PathClass::Passthrough)
            || !matches!(self.rules.classify(&new_rel), PathClass::Passthrough)
        {
            reply.error(libc::EACCES);
            return;
        }

        let old_real = self.real_path(&old_rel);
        let new_real = self.real_path(&new_rel);

        if fs::rename(&old_real, &new_real).is_err() {
            reply.error(libc::EIO);
            return;
        }

        if let Some(&ino) = self.path_to_inode.get(&old_rel) {
            self.path_to_inode.remove(&old_rel);
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

        match self.rules.classify(&rel) {
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

        let mut source_names: Vec<String> = stdfs::read_dir(source.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        source_names.sort();

        let mut mount_names: Vec<String> = stdfs::read_dir(mount.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
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

        let names: Vec<String> = stdfs::read_dir(mount.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
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

        let names: Vec<String> = stdfs::read_dir(mount.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
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

        let names: Vec<String> = stdfs::read_dir(mount.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
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
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".env\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=hunter2").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        let names: Vec<String> = stdfs::read_dir(mount.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(!names.contains(&".env".to_string()));

        let result = stdfs::symlink_metadata(mount.path().join(".env"));
        assert!(result.is_err());
    }

    #[test]
    fn writable_overlay_write_visible_and_readable() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".env\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=hunter2").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        stdfs::write(mount.path().join(".env"), "GENERATED=safe_value").unwrap();

        // Should be visible in directory listing
        let names: Vec<String> = stdfs::read_dir(mount.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
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
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".env\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=hunter2").unwrap();

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
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".env\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=hunter2").unwrap();

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
}

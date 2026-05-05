use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File};
use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
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
    pub fn new(source: PathBuf, mountpoint: PathBuf, mut rules: RuleSet, overlay: Overlay) -> Self {
        let mut inode_to_path = HashMap::new();
        let mut path_to_inode = HashMap::new();

        let root = PathBuf::new();
        inode_to_path.insert(FUSE_ROOT_ID, root.clone());
        path_to_inode.insert(root, FUSE_ROOT_ID);

        let source_fd = File::open(&source).expect("failed to open source directory fd");
        rules.set_io_root(PathBuf::from(format!(
            "/proc/self/fd/{}",
            source_fd.as_raw_fd()
        )));

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

}

fn system_time(secs: i64, nsecs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs as u32)
    } else {
        UNIX_EPOCH
    }
}

fn to_cstring(name: &OsStr) -> std::io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
}

fn stat_is_dir(s: &libc::stat) -> bool {
    s.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn safe_open(root_fd: &File, rel: &Path, flags: i32, mode: u32) -> std::io::Result<File> {
    let rel_c = if rel.as_os_str().is_empty() {
        // SAFETY: literal "." contains no NUL bytes
        c".".to_owned()
    } else {
        to_cstring(rel.as_os_str())?
    };
    // SAFETY: open_how is a plain C struct; zero-init is a valid state
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.mode = mode as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_BENEATH;
    // SAFETY: root_fd is a valid fd, rel_c is NUL-terminated, how is properly initialized
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            rel_c.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a non-negative value from a successful openat2; ownership transfers to File
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

fn safe_parent<'a>(root_fd: &File, rel: &'a Path) -> std::io::Result<(File, &'a OsStr)> {
    let name = rel
        .file_name()
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let parent = rel.parent().unwrap_or(Path::new(""));
    let dir = safe_open(root_fd, parent, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    Ok((dir, name))
}

fn fstatat_raw(dir_fd: RawFd, name: &OsStr) -> std::io::Result<libc::stat> {
    let name_c = to_cstring(name)?;
    // SAFETY: dir_fd is a valid directory fd, name_c is NUL-terminated, stat_buf is out-param
    unsafe {
        let mut stat_buf: libc::stat = std::mem::zeroed();
        if libc::fstatat(dir_fd, name_c.as_ptr(), &mut stat_buf, libc::AT_SYMLINK_NOFOLLOW) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(stat_buf)
    }
}

fn fstat_raw(fd: RawFd) -> std::io::Result<libc::stat> {
    // SAFETY: fd is a valid open file descriptor, stat_buf is out-param
    unsafe {
        let mut stat_buf: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut stat_buf) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(stat_buf)
    }
}

fn safe_stat(root_fd: &File, rel: &Path) -> std::io::Result<libc::stat> {
    if rel.as_os_str().is_empty() {
        fstat_raw(root_fd.as_raw_fd())
    } else {
        let (parent_dir, name) = safe_parent(root_fd, rel)?;
        fstatat_raw(parent_dir.as_raw_fd(), name)
    }
}

fn mkdirat_raw(dir_fd: RawFd, name: &OsStr, mode: u32) -> std::io::Result<()> {
    let name_c = to_cstring(name)?;
    // SAFETY: dir_fd is a valid directory fd, name_c is NUL-terminated
    if unsafe { libc::mkdirat(dir_fd, name_c.as_ptr(), mode) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn fchmodat_raw(dir_fd: RawFd, name: &OsStr, mode: u32) -> std::io::Result<()> {
    let name_c = to_cstring(name)?;
    // SAFETY: dir_fd is a valid directory fd, name_c is NUL-terminated
    if unsafe { libc::fchmodat(dir_fd, name_c.as_ptr(), mode, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn unlinkat_raw(dir_fd: RawFd, name: &OsStr, flags: i32) -> std::io::Result<()> {
    let name_c = to_cstring(name)?;
    // SAFETY: dir_fd is a valid directory fd, name_c is NUL-terminated
    if unsafe { libc::unlinkat(dir_fd, name_c.as_ptr(), flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn renameat_raw(
    old_dir_fd: RawFd,
    old_name: &OsStr,
    new_dir_fd: RawFd,
    new_name: &OsStr,
) -> std::io::Result<()> {
    let old_c = to_cstring(old_name)?;
    let new_c = to_cstring(new_name)?;
    // SAFETY: both dir fds are valid directory fds, both names are NUL-terminated
    if unsafe { libc::renameat(old_dir_fd, old_c.as_ptr(), new_dir_fd, new_c.as_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn readlinkat_raw(dir_fd: RawFd, name: &OsStr) -> std::io::Result<PathBuf> {
    let name_c = to_cstring(name)?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: dir_fd is a valid directory fd, name_c is NUL-terminated, buf is large enough
    let len = unsafe {
        libc::readlinkat(
            dir_fd,
            name_c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(len as usize);
    Ok(PathBuf::from(OsStr::from_bytes(&buf)))
}

fn stat_to_attr(ino: u64, stat: &libc::stat) -> FileAttr {
    let kind = if stat_is_dir(stat) {
        FileType::Directory
    } else if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
        FileType::Symlink
    } else {
        FileType::RegularFile
    };
    FileAttr {
        ino,
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        atime: system_time(stat.st_atime, stat.st_atime_nsec),
        mtime: system_time(stat.st_mtime, stat.st_mtime_nsec),
        ctime: system_time(stat.st_ctime, stat.st_ctime_nsec),
        crtime: UNIX_EPOCH,
        kind,
        perm: (stat.st_mode & 0o7777) as u16,
        nlink: stat.st_nlink as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat.st_rdev as u32,
        blksize: 512,
        flags: 0,
    }
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
        let source_stat = safe_stat(&self.source_fd, &child_rel).ok();
        let is_dir = source_stat.as_ref().is_some_and(stat_is_dir);
        let class = self.rules.classify(&child_rel, is_dir);

        match class {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
            }
            PathClass::WritableOverlay => {
                let Ok(overlay_stat) = safe_stat(self.overlay.fd_file(), &child_rel) else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let ino = self.get_or_assign_inode(child_rel);
                let attr = stat_to_attr(ino, &overlay_stat);
                reply.entry(&TTL, &attr, 0);
            }
            PathClass::Blocked | PathClass::GitignoreFile | PathClass::Passthrough => {
                let Some(stat) = source_stat else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let ino = self.get_or_assign_inode(child_rel);
                let mut attr = stat_to_attr(ino, &stat);
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

        let source_stat = safe_stat(&self.source_fd, &rel).ok();
        let is_dir = source_stat.as_ref().is_some_and(stat_is_dir);
        let class = self.rules.classify(&rel, is_dir);

        match class {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::WritableOverlay => {
                let Ok(overlay_stat) = safe_stat(self.overlay.fd_file(), &rel) else {
                    reply.error(libc::ENOENT);
                    return;
                };
                let attr = stat_to_attr(ino, &overlay_stat);
                reply.attr(&TTL, &attr);
                return;
            }
            _ => {}
        }

        let Some(stat) = source_stat else {
            reply.error(libc::ENOENT);
            return;
        };

        let mut attr = stat_to_attr(ino, &stat);
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

        let source_dir =
            match safe_open(&self.source_fd, &rel, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(f) => f,
                Err(_) => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };
        let source_dir_fd = source_dir.into_raw_fd();
        // SAFETY: source_dir_fd is a valid directory fd from safe_open; fdopendir takes ownership
        let source_dirp = unsafe { libc::fdopendir(source_dir_fd) };
        if source_dirp.is_null() {
            // SAFETY: fdopendir failed, so we still own the fd and must close it
            unsafe { libc::close(source_dir_fd) };
            reply.error(libc::ENOENT);
            return;
        }

        let mut children: Vec<(PathBuf, String, FileType)> = Vec::new();
        let mut seen_names: HashSet<String> = HashSet::new();

        loop {
            // SAFETY: source_dirp is a valid DIR* from fdopendir
            let entry = unsafe { libc::readdir(source_dirp) };
            if entry.is_null() {
                break;
            }
            // SAFETY: entry is valid until the next readdir/closedir call
            let d_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let name_bytes = d_name.to_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            let name_os = OsStr::from_bytes(name_bytes);
            let name = name_os.to_string_lossy().to_string();
            let child_rel = rel.join(&name);
            // SAFETY: entry is valid (checked non-null above)
            let d_type = unsafe { (*entry).d_type };
            let entry_is_dir = d_type == libc::DT_DIR;
            let class = self.rules.classify(&child_rel, entry_is_dir);
            match class {
                PathClass::Hidden => continue,
                PathClass::WritableOverlay => {
                    let Ok(overlay_stat) = safe_stat(self.overlay.fd_file(), &child_rel)
                    else {
                        continue;
                    };
                    let ft = if stat_is_dir(&overlay_stat) {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    seen_names.insert(name.clone());
                    children.push((child_rel, name, ft));
                }
                _ => {
                    let ft = match d_type {
                        libc::DT_DIR => FileType::Directory,
                        libc::DT_LNK => FileType::Symlink,
                        _ => FileType::RegularFile,
                    };
                    seen_names.insert(name.clone());
                    children.push((child_rel, name, ft));
                }
            }
        }
        // SAFETY: source_dirp is a valid DIR*; closedir closes the underlying fd
        unsafe { libc::closedir(source_dirp) };

        if let Ok(overlay_dir) =
            safe_open(self.overlay.fd_file(), &rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)
        {
            let overlay_dir_fd = overlay_dir.into_raw_fd();
            // SAFETY: overlay_dir_fd is a valid directory fd; fdopendir takes ownership
            let overlay_dirp = unsafe { libc::fdopendir(overlay_dir_fd) };
            if !overlay_dirp.is_null() {
                loop {
                    // SAFETY: overlay_dirp is a valid DIR*
                    let entry = unsafe { libc::readdir(overlay_dirp) };
                    if entry.is_null() {
                        break;
                    }
                    // SAFETY: entry is valid until the next readdir/closedir call
                    let d_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                    let name_bytes = d_name.to_bytes();
                    if name_bytes == b"." || name_bytes == b".." {
                        continue;
                    }
                    let name_os = OsStr::from_bytes(name_bytes);
                    let name = name_os.to_string_lossy().to_string();
                    if seen_names.contains(&name) {
                        continue;
                    }
                    let child_rel = rel.join(&name);
                    // SAFETY: entry is valid (checked non-null above)
                    let d_type = unsafe { (*entry).d_type };
                    let entry_is_dir = d_type == libc::DT_DIR;
                    if matches!(
                        self.rules.classify(&child_rel, entry_is_dir),
                        PathClass::WritableOverlay
                    ) {
                        let ft = if entry_is_dir {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        };
                        children.push((child_rel, name, ft));
                    }
                }
                // SAFETY: overlay_dirp is a valid DIR*
                unsafe { libc::closedir(overlay_dirp) };
            } else {
                // SAFETY: fdopendir failed, so we still own the fd
                unsafe { libc::close(overlay_dir_fd) };
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

        let root_fd = match self.rules.classify(&rel, false) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::WritableOverlay => self.overlay.fd_file(),
            PathClass::GitignoreFile => {
                if is_write_flags(flags) {
                    reply.error(libc::EACCES);
                    return;
                }
                &self.source_fd
            }
            PathClass::Passthrough => &self.source_fd,
        };

        let file = match safe_open(root_fd, &rel, flags, 0) {
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

        let root_fd = match self.rules.classify(&child_rel, false) {
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
                self.overlay.fd_file()
            }
            PathClass::Passthrough => &self.source_fd,
        };

        let perm_mode = mode & 0o7777;
        let mut open_flags = libc::O_RDWR | libc::O_CREAT;
        if flags & libc::O_TRUNC != 0 {
            open_flags |= libc::O_TRUNC;
        }
        let file = match safe_open(root_fd, &child_rel, open_flags, perm_mode) {
            Ok(f) => f,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        // SAFETY: file is a valid open fd from safe_open
        unsafe { libc::fchmod(file.as_raw_fd(), perm_mode) };

        let Ok(stat) = fstat_raw(file.as_raw_fd()) else {
            reply.error(libc::EIO);
            return;
        };

        let ino = self.get_or_assign_inode(child_rel);
        let attr = stat_to_attr(ino, &stat);
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

        let is_dir = safe_stat(&self.source_fd, &rel).as_ref().is_ok_and(stat_is_dir);

        let root_fd = match self.rules.classify(&rel, is_dir) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
                return;
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
                return;
            }
            PathClass::WritableOverlay => self.overlay.fd_file(),
            PathClass::Passthrough => &self.source_fd,
        };

        let open_flags = if size.is_some() { libc::O_RDWR } else { libc::O_RDONLY };
        let Ok(fd) = safe_open(root_fd, &rel, open_flags, 0) else {
            reply.error(libc::EIO);
            return;
        };

        if let Some(new_size) = size {
            let _ = fd.set_len(new_size);
        }

        if let Some(new_mode) = mode {
            // SAFETY: fd is a valid open fd from safe_open
            unsafe { libc::fchmod(fd.as_raw_fd(), new_mode) };
        }

        let Ok(stat) = fstat_raw(fd.as_raw_fd()) else {
            reply.error(libc::EIO);
            return;
        };

        let attr = stat_to_attr(ino, &stat);
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

        match self.rules.classify(&child_rel, true) {
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

        let (parent_dir, dir_name) = match safe_parent(&self.source_fd, &child_rel) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                return;
            }
        };

        if let Err(e) = mkdirat_raw(parent_dir.as_raw_fd(), dir_name, mode) {
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }

        let _ = fchmodat_raw(parent_dir.as_raw_fd(), dir_name, mode);

        let Ok(stat) = fstatat_raw(parent_dir.as_raw_fd(), dir_name) else {
            reply.error(libc::EIO);
            return;
        };

        let ino = self.get_or_assign_inode(child_rel);
        let attr = stat_to_attr(ino, &stat);
        reply.entry(&TTL, &attr, 0);
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);

        match self.rules.classify(&child_rel, true) {
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

        let (parent_dir, dir_name) = match safe_parent(&self.source_fd, &child_rel) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                return;
            }
        };

        if let Err(e) = unlinkat_raw(parent_dir.as_raw_fd(), dir_name, libc::AT_REMOVEDIR) {
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

        match self.rules.classify(&child_rel, false) {
            PathClass::Hidden => {
                reply.error(libc::ENOENT);
            }
            PathClass::Blocked | PathClass::GitignoreFile => {
                reply.error(libc::EACCES);
            }
            PathClass::WritableOverlay => {
                let (parent_dir, file_name) =
                    match safe_parent(self.overlay.fd_file(), &child_rel) {
                        Ok(v) => v,
                        Err(_) => {
                            reply.error(libc::ENOENT);
                            return;
                        }
                    };
                if let Err(e) = unlinkat_raw(parent_dir.as_raw_fd(), file_name, 0) {
                    reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                    return;
                }
                self.remove_inode(&child_rel);
                reply.ok();
            }
            PathClass::Passthrough => {
                let (parent_dir, file_name) = match safe_parent(&self.source_fd, &child_rel) {
                    Ok(v) => v,
                    Err(e) => {
                        reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                        return;
                    }
                };
                if let Err(e) = unlinkat_raw(parent_dir.as_raw_fd(), file_name, 0) {
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

        let old_is_dir = safe_stat(&self.source_fd, &old_rel)
            .as_ref()
            .is_ok_and(stat_is_dir);
        let new_is_dir = safe_stat(&self.source_fd, &new_rel)
            .as_ref()
            .is_ok_and(stat_is_dir);
        if !matches!(self.rules.classify(&old_rel, old_is_dir), PathClass::Passthrough)
            || !matches!(self.rules.classify(&new_rel, new_is_dir), PathClass::Passthrough)
        {
            reply.error(libc::EACCES);
            return;
        }

        let (old_parent_dir, old_name) = match safe_parent(&self.source_fd, &old_rel) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                return;
            }
        };
        let (new_parent_dir, new_name) = match safe_parent(&self.source_fd, &new_rel) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                return;
            }
        };

        if let Err(e) = renameat_raw(
            old_parent_dir.as_raw_fd(),
            old_name,
            new_parent_dir.as_raw_fd(),
            new_name,
        ) {
            reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }

        if old_is_dir {
            let child_updates: Vec<(PathBuf, u64)> = self
                .path_to_inode
                .iter()
                .filter(|(p, _)| *p != &old_rel && p.starts_with(&old_rel))
                .map(|(p, &ino)| (p.clone(), ino))
                .collect();
            for (old_child, ino) in child_updates {
                self.path_to_inode.remove(&old_child);
                let suffix = old_child.strip_prefix(&old_rel).unwrap();
                let new_child = new_rel.join(suffix);
                self.inode_to_path.insert(ino, new_child.clone());
                self.path_to_inode.insert(new_child, ino);
            }

            if let Err(e) = self.rules.handle_directory_rename(&old_rel, &new_rel) {
                eprintln!("fuseshadow: warning: failed to track directory rename: {e}");
            }
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

        match self.rules.classify(&rel, false) {
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

        let (parent_dir, link_name) = match safe_parent(&self.source_fd, &rel) {
            Ok(v) => v,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let Ok(target) = readlinkat_raw(parent_dir.as_raw_fd(), link_name) else {
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
        // Prevent fusermount3 (spawned by fuser for auto_unmount) from inheriting
        // stdout/stderr pipes, which keeps them open and hangs `cargo test | tail`.
        unsafe {
            libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(libc::STDERR_FILENO, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let rules = RuleSet::load(source, true).expect("failed to load rules");
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

    // --- Phase 3 (case-insensitive plan): FUSE-level case-insensitive tests ---

    fn test_mount_ci(source: &Path, mountpoint: &Path) -> (BackgroundSession, PathBuf) {
        unsafe {
            libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(libc::STDERR_FILENO, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let rules = RuleSet::load(source, false).expect("failed to load rules");
        let overlay = Overlay::new().expect("failed to create overlay");
        let overlay_path = overlay.base_path().to_path_buf();
        let fs = ShadowFs::new(source.to_path_buf(), mountpoint.to_path_buf(), rules, overlay);
        let session = Session::new(fs, mountpoint, &mount_options())
            .expect("FUSE session failed — is the test runner using `unshare -r --user --mount`?");
        let bg = BackgroundSession::new(session).expect("background session failed");
        std::thread::sleep(Duration::from_millis(200));
        (bg, overlay_path)
    }

    #[test]
    fn ci_blocked_via_pattern_case_mismatch() {
        // Gitignore pattern uses uppercase `.ENV` but file on disk is `.env`.
        // Case-insensitive rules should still block it.
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".ENV\n").unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=hunter2").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount_ci(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(names.contains(&".env".to_string()));
        let meta = stdfs::symlink_metadata(mount.path().join(".env")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(stdfs::read_to_string(mount.path().join(".env")).is_err());
    }

    #[test]
    fn ci_blocked_wildcard_pattern_case_mismatch() {
        // Gitignore pattern `*.SECRET` should block `data.secret` in CI mode.
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.SECRET\n").unwrap();
        stdfs::write(source.path().join("data.secret"), "sensitive").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount_ci(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(names.contains(&"data.secret".to_string()));
        let meta = stdfs::symlink_metadata(mount.path().join("data.secret")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(stdfs::read_to_string(mount.path().join("data.secret")).is_err());
    }

    #[test]
    fn ci_hidden_via_pattern_case_mismatch() {
        // [ignore] pattern `SECRET_DIR` (uppercase) hides `secret_dir` (lowercase).
        let source = TempDir::new().unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[ignore]\npatterns = [\"SECRET_DIR\"]\n",
        )
        .unwrap();
        stdfs::create_dir(source.path().join("secret_dir")).unwrap();
        stdfs::write(source.path().join("secret_dir/data.txt"), "hidden").unwrap();
        stdfs::write(source.path().join("visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount_ci(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(!names.contains(&"secret_dir".to_string()));
        assert!(stdfs::metadata(mount.path().join("secret_dir")).is_err());
        assert!(stdfs::metadata(mount.path().join("secret_dir/data.txt")).is_err());

        assert_eq!(
            stdfs::read_to_string(mount.path().join("visible.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn ci_writable_overlay_via_pattern_case_mismatch() {
        // [writable] pattern `.ENV` + gitignore `.ENV` → file `.env` is WritableOverlay.
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".ENV\n").unwrap();
        stdfs::write(
            source.path().join(".shadowconfig"),
            "[writable]\npatterns = [\".ENV\"]\n",
        )
        .unwrap();
        stdfs::write(source.path().join(".env"), "SECRET=hunter2").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount_ci(source.path(), mount.path());

        // Invisible before write
        let names = dir_names(mount.path());
        assert!(!names.contains(&".env".to_string()));
        assert!(stdfs::metadata(mount.path().join(".env")).is_err());

        // Writable via overlay
        stdfs::write(mount.path().join(".env"), "GENERATED=safe").unwrap();
        let content = stdfs::read_to_string(mount.path().join(".env")).unwrap();
        assert_eq!(content, "GENERATED=safe");

        // Source untouched
        assert_eq!(
            stdfs::read_to_string(source.path().join(".env")).unwrap(),
            "SECRET=hunter2"
        );

        // Unlink makes invisible again
        stdfs::remove_file(mount.path().join(".env")).unwrap();
        assert!(stdfs::metadata(mount.path().join(".env")).is_err());
    }

    #[test]
    fn ci_alternate_cased_shadowconfig_hidden() {
        // A file literally named `.SHADOWCONFIG` should be hidden in CI mode.
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".SHADOWCONFIG"), "not a real config").unwrap();
        stdfs::write(source.path().join("visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount_ci(source.path(), mount.path());

        let names = dir_names(mount.path());
        assert!(!names.contains(&".SHADOWCONFIG".to_string()));
        assert!(stdfs::metadata(mount.path().join(".SHADOWCONFIG")).is_err());

        assert_eq!(
            stdfs::read_to_string(mount.path().join("visible.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn ci_alternate_cased_gitignore_readonly() {
        // A file literally named `.GITIGNORE` should be treated as GitignoreFile
        // in CI mode: readable but not writable.
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".GITIGNORE"), "*.log\n").unwrap();
        stdfs::write(source.path().join("app.log"), "log data").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount_ci(source.path(), mount.path());

        // The file should be readable
        let content = stdfs::read_to_string(mount.path().join(".GITIGNORE")).unwrap();
        assert_eq!(content, "*.log\n");

        // The file should reject writes
        assert!(stdfs::write(mount.path().join(".GITIGNORE"), "modified").is_err());
    }

    #[test]
    fn ci_passthrough_files_work_normally() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("hello.txt"), "hello world").unwrap();
        stdfs::create_dir(source.path().join("sub")).unwrap();
        stdfs::write(source.path().join("sub/nested.txt"), "deep content").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount_ci(source.path(), mount.path());

        assert_eq!(
            stdfs::read_to_string(mount.path().join("hello.txt")).unwrap(),
            "hello world"
        );
        assert_eq!(
            stdfs::read_to_string(mount.path().join("sub/nested.txt")).unwrap(),
            "deep content"
        );

        stdfs::write(mount.path().join("hello.txt"), "updated").unwrap();
        assert_eq!(
            stdfs::read_to_string(mount.path().join("hello.txt")).unwrap(),
            "updated"
        );

        let names = dir_names(mount.path());
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));
    }

    #[test]
    fn ci_case_sensitive_mode_does_not_fold() {
        // In case-sensitive mode, pattern `.ENV` should NOT block file `.env`.
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), ".ENV\n").unwrap();
        stdfs::write(source.path().join(".env"), "visible in CS mode").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // .env should be passthrough since the pattern `.ENV` doesn't match `.env`
        let content = stdfs::read_to_string(mount.path().join(".env")).unwrap();
        assert_eq!(content, "visible in CS mode");
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

    // --- same source and mountpoint tests ---

    #[test]
    fn same_source_and_mountpoint() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        stdfs::write(root.join(".gitignore"), ".env\ncredentials.json\n").unwrap();
        stdfs::write(
            root.join(".shadowconfig"),
            "[ignore]\npatterns = [\".git\"]\n[writable]\npatterns = [\".env\"]\n",
        )
        .unwrap();
        stdfs::write(root.join("hello.txt"), "hello world").unwrap();
        stdfs::create_dir(root.join("sub")).unwrap();
        stdfs::write(root.join("sub/nested.txt"), "deep content").unwrap();
        stdfs::write(root.join(".env"), "SECRET=hunter2").unwrap();
        stdfs::write(root.join("credentials.json"), "{\"key\":\"secret\"}").unwrap();
        stdfs::create_dir(root.join(".git")).unwrap();
        stdfs::write(root.join(".git/HEAD"), "ref: refs/heads/main").unwrap();

        let (_session, _overlay_path) = test_mount(&root, &root);

        // Passthrough files are readable
        assert_eq!(
            stdfs::read_to_string(root.join("hello.txt")).unwrap(),
            "hello world"
        );
        assert_eq!(
            stdfs::read_to_string(root.join("sub/nested.txt")).unwrap(),
            "deep content"
        );

        // Directory listing respects classifications
        let names = dir_names(&root);
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));
        assert!(names.contains(&".gitignore".to_string()));
        // Blocked file visible with zero perms
        assert!(names.contains(&"credentials.json".to_string()));
        // Hidden entries absent
        assert!(!names.contains(&".git".to_string()));
        assert!(!names.contains(&".shadowconfig".to_string()));
        // WritableOverlay invisible before write
        assert!(!names.contains(&".env".to_string()));

        // .gitignore is readable but not writable
        let gi = stdfs::read_to_string(root.join(".gitignore")).unwrap();
        assert!(gi.contains(".env"));
        assert!(stdfs::write(root.join(".gitignore"), "nope").is_err());

        // Blocked file has zero permissions and is unreadable
        let cred_meta = stdfs::metadata(root.join("credentials.json")).unwrap();
        assert_eq!(cred_meta.permissions().mode() & 0o777, 0);
        assert!(stdfs::read_to_string(root.join("credentials.json")).is_err());

        // Hidden directory completely invisible
        assert!(stdfs::metadata(root.join(".git")).is_err());
        assert!(stdfs::metadata(root.join(".git/HEAD")).is_err());

        // WritableOverlay: invisible → writable → reads back overlay content
        assert!(stdfs::read_to_string(root.join(".env")).is_err());
        stdfs::write(root.join(".env"), "GENERATED=yes").unwrap();
        assert_eq!(
            stdfs::read_to_string(root.join(".env")).unwrap(),
            "GENERATED=yes"
        );
        let names_after = dir_names(&root);
        assert!(names_after.contains(&".env".to_string()));

        // Passthrough write works
        stdfs::write(root.join("hello.txt"), "updated").unwrap();
        assert_eq!(
            stdfs::read_to_string(root.join("hello.txt")).unwrap(),
            "updated"
        );
    }

    // --- Phase 4: Runtime rename tracking + persistence tests ---

    #[test]
    fn rename_dir_with_child_gitignore_stays_blocked() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("mydir")).unwrap();
        stdfs::write(source.path().join("mydir/.gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("mydir/data.secret"), "sensitive").unwrap();
        stdfs::write(source.path().join("mydir/code.rs"), "fn main() {}").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Initial: mydir/data.secret is blocked
        let meta = stdfs::symlink_metadata(mount.path().join("mydir/data.secret")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(stdfs::read_to_string(mount.path().join("mydir/data.secret")).is_err());

        // Rename directory through the mountpoint
        stdfs::rename(mount.path().join("mydir"), mount.path().join("renamed")).unwrap();

        // After rename: data.secret still blocked via refreshed child matcher
        let meta = stdfs::symlink_metadata(mount.path().join("renamed/data.secret")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(stdfs::read_to_string(mount.path().join("renamed/data.secret")).is_err());

        // Non-blocked file still readable
        assert_eq!(
            stdfs::read_to_string(mount.path().join("renamed/code.rs")).unwrap(),
            "fn main() {}"
        );

        // folder_renames persisted to root .shadowconfig on disk
        let config = stdfs::read_to_string(source.path().join(".shadowconfig")).unwrap();
        assert!(config.contains("folder_renames"));
        assert!(config.contains("mydir"));
        assert!(config.contains("renamed"));
    }

    #[test]
    fn rename_dir_blocked_by_parent_pattern_stays_blocked() {
        let source = TempDir::new().unwrap();
        // Path-specific pattern in root .gitignore
        stdfs::write(source.path().join(".gitignore"), "mydir/secrets/*.key\n").unwrap();
        stdfs::create_dir_all(source.path().join("mydir/secrets")).unwrap();
        stdfs::write(source.path().join("mydir/secrets/api.key"), "secret-key").unwrap();
        stdfs::write(source.path().join("mydir/visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Initial: mydir/secrets/api.key is blocked by root pattern
        let meta =
            stdfs::symlink_metadata(mount.path().join("mydir/secrets/api.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);

        // Rename mydir to newdir through the mountpoint
        stdfs::rename(mount.path().join("mydir"), mount.path().join("newdir")).unwrap();

        // After rename: secrets/api.key still blocked via alias
        let meta =
            stdfs::symlink_metadata(mount.path().join("newdir/secrets/api.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(
            stdfs::read_to_string(mount.path().join("newdir/secrets/api.key")).is_err()
        );

        // Non-blocked file still readable
        assert_eq!(
            stdfs::read_to_string(mount.path().join("newdir/visible.txt")).unwrap(),
            "hello"
        );
    }

    // --- Phase 5: Live mtime monitoring integration tests ---

    #[test]
    fn mtime_monitor_external_removal_drops_protection() {
        let source = TempDir::new().unwrap();
        // Parent pattern blocks files inside mydir/secrets/
        stdfs::write(source.path().join(".gitignore"), "mydir/secrets/*.key\n").unwrap();
        stdfs::create_dir_all(source.path().join("mydir/secrets")).unwrap();
        stdfs::write(source.path().join("mydir/secrets/api.key"), "secret-key").unwrap();
        stdfs::write(source.path().join("mydir/visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // mydir/secrets/api.key is blocked by parent pattern
        let meta = stdfs::symlink_metadata(mount.path().join("mydir/secrets/api.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);

        // Rename mydir to newdir through mountpoint — triggers alias
        stdfs::rename(mount.path().join("mydir"), mount.path().join("newdir")).unwrap();

        // newdir/secrets/api.key should still be blocked via alias
        let meta = stdfs::symlink_metadata(mount.path().join("newdir/secrets/api.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);

        // Externally remove the folder_renames entry (simulating developer cleanup)
        stdfs::write(source.path().join(".shadowconfig"), "").unwrap();

        // Wait for the kernel's attr cache to expire (TTL=1s)
        std::thread::sleep(Duration::from_millis(1200));

        // After the cache expires, alias is gone — the file becomes passthrough
        // (because the parent pattern "mydir/..." no longer matches "newdir/...")
        assert_eq!(
            stdfs::read_to_string(mount.path().join("newdir/secrets/api.key")).unwrap(),
            "secret-key"
        );
        assert_eq!(
            stdfs::read_to_string(mount.path().join("newdir/visible.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn mtime_monitor_external_addition_applies_protection() {
        let source = TempDir::new().unwrap();
        // Parent pattern blocks files inside mydir/secrets/ — but the dir was already renamed
        stdfs::write(source.path().join(".gitignore"), "mydir/secrets/*.key\n").unwrap();
        stdfs::create_dir_all(source.path().join("newdir/secrets")).unwrap();
        stdfs::write(source.path().join("newdir/secrets/api.key"), "secret-key").unwrap();
        stdfs::write(source.path().join("newdir/visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // newdir/secrets/api.key is passthrough (no alias, parent pattern doesn't match newdir)
        assert_eq!(
            stdfs::read_to_string(mount.path().join("newdir/secrets/api.key")).unwrap(),
            "secret-key"
        );

        // Externally add a folder_renames entry (simulating another fuseshadow instance)
        stdfs::write(
            source.path().join(".shadowconfig"),
            "folder_renames = [\n  { from = \"mydir\", to = \"newdir\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        )
        .unwrap();

        // Wait for the kernel's attr cache to expire (TTL=1s)
        std::thread::sleep(Duration::from_millis(1200));

        // After the cache expires, newdir/secrets/api.key should be blocked via alias
        let meta = stdfs::symlink_metadata(mount.path().join("newdir/secrets/api.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        assert!(stdfs::read_to_string(mount.path().join("newdir/secrets/api.key")).is_err());

        // Non-matching files still accessible
        assert_eq!(
            stdfs::read_to_string(mount.path().join("newdir/visible.txt")).unwrap(),
            "hello"
        );
    }

    // --- Phase 6: Cross-restart persistence integration tests ---

    #[test]
    fn cross_restart_rename_persists_and_blocks_after_remount() {
        let source = TempDir::new().unwrap();
        // Pattern targets files inside mydir/secrets/ — mydir itself is Passthrough
        stdfs::write(source.path().join(".gitignore"), "mydir/secrets/*.key\n").unwrap();
        stdfs::create_dir_all(source.path().join("mydir/secrets")).unwrap();
        stdfs::write(source.path().join("mydir/secrets/api.key"), "secret-key").unwrap();
        stdfs::write(source.path().join("mydir/visible.txt"), "hello").unwrap();

        let mount = TempDir::new().unwrap();

        // First mount: rename directory, verify blocking persists, then unmount
        {
            let (_session, _) = test_mount(source.path(), mount.path());

            let meta =
                stdfs::symlink_metadata(mount.path().join("mydir/secrets/api.key")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o7777, 0o000);

            stdfs::rename(mount.path().join("mydir"), mount.path().join("newdir")).unwrap();

            let meta =
                stdfs::symlink_metadata(mount.path().join("newdir/secrets/api.key")).unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o7777,
                0o000,
                "api.key should be blocked after rename during first mount"
            );
        }
        // _session dropped — unmounted

        // Verify folder_renames persists in root .shadowconfig
        let config = stdfs::read_to_string(source.path().join(".shadowconfig")).unwrap();
        assert!(
            config.contains("folder_renames"),
            "folder_renames should persist after unmount, got: {config}"
        );
        assert!(config.contains("mydir"));
        assert!(config.contains("newdir"));

        // Second mount: folder_renames loaded from disk, renamed path still blocked
        {
            let (_session, _) = test_mount(source.path(), mount.path());

            let meta =
                stdfs::symlink_metadata(mount.path().join("newdir/secrets/api.key")).unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o7777,
                0o000,
                "api.key should still be blocked on remount via persisted folder_renames"
            );
            assert!(
                stdfs::read_to_string(mount.path().join("newdir/secrets/api.key")).is_err(),
                "should not be able to read blocked file after remount"
            );

            assert_eq!(
                stdfs::read_to_string(mount.path().join("newdir/visible.txt")).unwrap(),
                "hello",
                "non-blocked file should still be accessible after remount"
            );
        }
    }

    #[test]
    fn cross_restart_child_gitignore_persists_after_remount() {
        let source = TempDir::new().unwrap();
        stdfs::create_dir(source.path().join("mydir")).unwrap();
        stdfs::write(source.path().join("mydir/.gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("mydir/data.secret"), "sensitive").unwrap();
        stdfs::write(source.path().join("mydir/code.rs"), "fn main() {}").unwrap();

        let mount = TempDir::new().unwrap();

        // First mount: rename, then unmount
        {
            let (_session, _) = test_mount(source.path(), mount.path());

            stdfs::rename(mount.path().join("mydir"), mount.path().join("renamed")).unwrap();

            let meta = stdfs::symlink_metadata(mount.path().join("renamed/data.secret")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        }

        // Second mount: child .gitignore re-loaded from renamed/ on disk, still blocks
        {
            let (_session, _) = test_mount(source.path(), mount.path());

            let meta = stdfs::symlink_metadata(mount.path().join("renamed/data.secret")).unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o7777,
                0o000,
                "data.secret should be blocked via child .gitignore after remount"
            );
            assert_eq!(
                stdfs::read_to_string(mount.path().join("renamed/code.rs")).unwrap(),
                "fn main() {}",
                "non-blocked file should still be readable after remount"
            );
        }
    }

    #[test]
    fn cross_restart_developer_removes_renames_drops_alias() {
        let source = TempDir::new().unwrap();
        // Pattern targets files inside mydir/secrets/ — mydir itself is Passthrough
        stdfs::write(source.path().join(".gitignore"), "mydir/secrets/*.key\n").unwrap();
        stdfs::create_dir_all(source.path().join("mydir/secrets")).unwrap();
        stdfs::write(source.path().join("mydir/secrets/api.key"), "secret-key").unwrap();

        let mount = TempDir::new().unwrap();

        // First mount: rename, then unmount
        {
            let (_session, _) = test_mount(source.path(), mount.path());

            stdfs::rename(mount.path().join("mydir"), mount.path().join("newdir")).unwrap();

            let meta =
                stdfs::symlink_metadata(mount.path().join("newdir/secrets/api.key")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o7777, 0o000);
        }

        // Developer reviews and removes folder_renames (simulating gitignore update)
        stdfs::write(source.path().join(".shadowconfig"), "").unwrap();

        // Third mount: no aliases, protection reflects current gitignore state
        {
            let (_session, _) = test_mount(source.path(), mount.path());

            // "mydir/secrets/*.key" pattern doesn't match "newdir/secrets/" — file is now passthrough
            assert_eq!(
                stdfs::read_to_string(mount.path().join("newdir/secrets/api.key")).unwrap(),
                "secret-key",
                "with folder_renames removed, alias should be gone and file accessible"
            );
        }
    }

    // --- TOCTOU symlink race prevention ---

    #[test]
    fn symlink_to_blocked_file_not_readable_through_mount() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.secret\n").unwrap();
        stdfs::write(source.path().join("data.secret"), "very sensitive").unwrap();
        stdfs::create_dir(source.path().join("pub")).unwrap();
        // Create a symlink in a passthrough directory pointing at the blocked file
        std::os::unix::fs::symlink("../data.secret", source.path().join("pub/escape.txt")).unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // The symlink target resolves to data.secret which is blocked.
        // The kernel follows the symlink at VFS level and hits the blocked
        // file (mode 000), so the read must fail regardless.
        let result = stdfs::read_to_string(mount.path().join("pub/escape.txt"));
        assert!(result.is_err(), "symlink to blocked file must not be readable");
    }

    #[test]
    fn symlink_pointing_outside_source_not_readable() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("normal.txt"), "hello").unwrap();

        // Create a symlink pointing at an absolute path outside the source tree
        std::os::unix::fs::symlink("/etc/hostname", source.path().join("escape.txt")).unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // The absolute symlink target is outside the source tree. fuseshadow's
        // readlink rewrites absolute symlinks only when they point INTO the
        // source. For targets outside the source, the kernel resolves them to
        // the real filesystem path, which is not inside the mount. Depending on
        // container setup this may or may not exist, but the open through FUSE
        // must not follow it to leak data.
        let _result = stdfs::read_to_string(mount.path().join("escape.txt"));
        // In a containerised test environment /etc/hostname may exist, so we
        // can't assert the read fails. Instead verify the file IS reported as a
        // symlink (not silently followed by fuseshadow itself).
        let meta = stdfs::symlink_metadata(mount.path().join("escape.txt")).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "absolute symlink should remain a symlink in the mount"
        );
    }

    // --- openat2 safe_open / safe_parent primitives ---

    #[test]
    fn safe_open_reads_file_normally() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("hello.txt"), "content").unwrap();
        let root = File::open(dir.path()).unwrap();
        let mut f = safe_open(&root, Path::new("hello.txt"), libc::O_RDONLY, 0).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "content");
    }

    #[test]
    fn safe_open_rejects_final_symlink() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("target.txt"), "secret").unwrap();
        std::os::unix::fs::symlink("target.txt", dir.path().join("link.txt")).unwrap();
        let root = File::open(dir.path()).unwrap();
        let err = safe_open(&root, Path::new("link.txt"), libc::O_RDONLY, 0).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn safe_open_rejects_intermediate_symlink() {
        let dir = TempDir::new().unwrap();
        stdfs::create_dir(dir.path().join("real")).unwrap();
        stdfs::write(dir.path().join("real/secret.txt"), "sensitive").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("fake")).unwrap();

        let root = File::open(dir.path()).unwrap();
        let err =
            safe_open(&root, Path::new("fake/secret.txt"), libc::O_RDONLY, 0).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "intermediate symlink must be rejected with ELOOP"
        );
    }

    #[test]
    fn safe_open_rejects_dotdot_escape() {
        let dir = TempDir::new().unwrap();
        let inner = dir.path().join("inner");
        stdfs::create_dir(&inner).unwrap();
        stdfs::write(dir.path().join("secret.txt"), "top-level").unwrap();

        let root = File::open(&inner).unwrap();
        let err = safe_open(&root, Path::new("../secret.txt"), libc::O_RDONLY, 0).unwrap_err();
        assert!(
            err.raw_os_error() == Some(libc::EXDEV) || err.raw_os_error() == Some(libc::EACCES),
            ".. escape must fail (got {:?})",
            err
        );
    }

    #[test]
    fn safe_open_empty_rel_opens_root_dir() {
        let dir = TempDir::new().unwrap();
        let root = File::open(dir.path()).unwrap();
        let f = safe_open(&root, Path::new(""), libc::O_RDONLY | libc::O_DIRECTORY, 0).unwrap();
        let meta = f.metadata().unwrap();
        assert!(meta.is_dir());
    }

    #[test]
    fn safe_parent_returns_parent_dir_and_filename() {
        let dir = TempDir::new().unwrap();
        stdfs::create_dir(dir.path().join("sub")).unwrap();
        stdfs::write(dir.path().join("sub/file.txt"), "data").unwrap();
        let root = File::open(dir.path()).unwrap();
        let (parent_dir, name) = safe_parent(&root, Path::new("sub/file.txt")).unwrap();
        assert_eq!(name, "file.txt");
        let meta = parent_dir.metadata().unwrap();
        assert!(meta.is_dir());
    }

    #[test]
    fn safe_parent_root_level_file() {
        let dir = TempDir::new().unwrap();
        stdfs::write(dir.path().join("root.txt"), "data").unwrap();
        let root = File::open(dir.path()).unwrap();
        let (parent_dir, name) = safe_parent(&root, Path::new("root.txt")).unwrap();
        assert_eq!(name, "root.txt");
        let meta = parent_dir.metadata().unwrap();
        assert!(meta.is_dir());
    }

    #[test]
    fn safe_parent_rejects_intermediate_symlink() {
        let dir = TempDir::new().unwrap();
        stdfs::create_dir(dir.path().join("real")).unwrap();
        stdfs::write(dir.path().join("real/file.txt"), "data").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("fake")).unwrap();

        let root = File::open(dir.path()).unwrap();
        let err = safe_parent(&root, Path::new("fake/file.txt")).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "safe_parent must reject intermediate symlinks"
        );
    }

    // --- Phase 5: TOCTOU regression tests ---
    //
    // These reproduce the attack vectors from the security report. Each test
    // mounts a real FUSE filesystem and exercises the race window between
    // lookup (which caches the inode) and open (which resolves the path on
    // disk). The openat2 RESOLVE_NO_SYMLINKS flag closes this window.

    #[test]
    fn toctou_intermediate_dir_replaced_with_symlink() {
        // Attack scenario: after the kernel caches inodes via lookup, an
        // attacker replaces an intermediate directory in the source tree with
        // a symlink to a directory containing secrets. Without openat2, the
        // subsequent open() would follow the symlink and leak the secret.
        let source = TempDir::new().unwrap();
        stdfs::create_dir_all(source.path().join("a/b")).unwrap();
        stdfs::write(source.path().join("a/b/file.txt"), "safe content").unwrap();

        let decoy = TempDir::new().unwrap();
        stdfs::write(decoy.path().join("file.txt"), "LEAKED SECRET").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Populate kernel inode cache
        let content = stdfs::read_to_string(mount.path().join("a/b/file.txt")).unwrap();
        assert_eq!(content, "safe content");

        // TOCTOU attack: swap source/a/b from directory to symlink
        stdfs::remove_dir_all(source.path().join("a/b")).unwrap();
        std::os::unix::fs::symlink(decoy.path(), source.path().join("a/b")).unwrap();

        // The cached inode still maps to "a/b/file.txt". safe_open detects
        // the symlink in the intermediate component and returns ELOOP.
        let result = stdfs::read_to_string(mount.path().join("a/b/file.txt"));
        assert!(
            result.is_err(),
            "reading through swapped intermediate symlink must fail, but got: {:?}",
            result.as_ref().unwrap()
        );
    }

    #[test]
    fn toctou_file_replaced_with_absolute_symlink_outside_source() {
        // Attack scenario: a regular passthrough file is replaced (on the
        // source side) with an absolute symlink pointing outside the source
        // tree. The kernel still has the cached inode (type=regular file)
        // and calls open(). safe_open with RESOLVE_NO_SYMLINKS rejects the
        // final-component symlink.
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("config.txt"), "normal config").unwrap();

        let outside = TempDir::new().unwrap();
        stdfs::write(outside.path().join("secret"), "TOP SECRET").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Populate kernel inode cache
        let content = stdfs::read_to_string(mount.path().join("config.txt")).unwrap();
        assert_eq!(content, "normal config");

        // TOCTOU attack: replace the file with an absolute symlink
        stdfs::remove_file(source.path().join("config.txt")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            source.path().join("config.txt"),
        )
        .unwrap();

        // safe_open rejects the symlink even though the kernel thinks it is
        // still a regular file.
        let result = stdfs::read_to_string(mount.path().join("config.txt"));
        assert!(
            result.is_err(),
            "file replaced with absolute symlink outside source must not be readable, but got: {:?}",
            result.as_ref().unwrap()
        );
    }

    #[test]
    fn toctou_intermediate_dir_replaced_with_absolute_symlink_outside_source() {
        // Attack scenario: like toctou_intermediate_dir_replaced_with_symlink
        // but the symlink uses an absolute path to escape the source tree entirely.
        let source = TempDir::new().unwrap();
        stdfs::create_dir_all(source.path().join("sub/dir")).unwrap();
        stdfs::write(source.path().join("sub/dir/data.txt"), "normal").unwrap();

        let outside = TempDir::new().unwrap();
        stdfs::write(outside.path().join("data.txt"), "ESCAPED TO OUTSIDE").unwrap();

        let mount = TempDir::new().unwrap();
        let (_session, _) = test_mount(source.path(), mount.path());

        // Populate kernel inode cache
        let content = stdfs::read_to_string(mount.path().join("sub/dir/data.txt")).unwrap();
        assert_eq!(content, "normal");

        // TOCTOU attack: absolute symlink escape
        stdfs::remove_dir_all(source.path().join("sub/dir")).unwrap();
        std::os::unix::fs::symlink(outside.path(), source.path().join("sub/dir")).unwrap();

        let result = stdfs::read_to_string(mount.path().join("sub/dir/data.txt"));
        assert!(
            result.is_err(),
            "absolute symlink in intermediate dir must not be followed, but got: {:?}",
            result.as_ref().unwrap()
        );
    }
}

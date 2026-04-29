use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read as _, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, Request, FUSE_ROOT_ID,
};

use crate::rules::{PathClass, RuleSet};

const TTL: Duration = Duration::from_secs(1);

pub struct ShadowFs {
    source: PathBuf,
    rules: RuleSet,
    next_inode: u64,
    inode_to_path: HashMap<u64, PathBuf>,
    path_to_inode: HashMap<PathBuf, u64>,
    next_fh: u64,
    open_files: HashMap<u64, File>,
}

impl ShadowFs {
    pub fn new(source: PathBuf, rules: RuleSet) -> Self {
        let mut inode_to_path = HashMap::new();
        let mut path_to_inode = HashMap::new();

        let root = PathBuf::new();
        inode_to_path.insert(FUSE_ROOT_ID, root.clone());
        path_to_inode.insert(root, FUSE_ROOT_ID);

        Self {
            source,
            rules,
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

impl Filesystem for ShadowFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_rel) = self.inode_to_path.get(&parent).cloned() else {
            reply.error(libc::ENOENT);
            return;
        };

        let child_rel = parent_rel.join(name);

        match self.rules.classify(&child_rel) {
            PathClass::Hidden | PathClass::WritableOverlay => {
                reply.error(libc::ENOENT);
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
        if matches!(class, PathClass::Hidden | PathClass::WritableOverlay) {
            reply.error(libc::ENOENT);
            return;
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
            if matches!(
                self.rules.classify(&child_rel),
                PathClass::Hidden | PathClass::WritableOverlay
            ) {
                continue;
            }
            let ft = match entry.file_type() {
                Ok(ft) if ft.is_dir() => FileType::Directory,
                Ok(ft) if ft.is_symlink() => FileType::Symlink,
                _ => FileType::RegularFile,
            };
            children.push((child_rel, name, ft));
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

    fn open(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
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
        let Ok(file) = File::open(&real) else {
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

        reply.data(target.as_os_str().as_encoded_bytes());
    }
}

pub fn mount_options() -> Vec<MountOption> {
    vec![
        MountOption::AutoUnmount,
        MountOption::FSName("fuseshadow".to_string()),
    ]
}

pub fn mount(fs: ShadowFs, mountpoint: &Path) -> anyhow::Result<()> {
    fuser::mount2(fs, mountpoint, &mount_options())
        .map_err(|e| anyhow::anyhow!("FUSE mount failed: {e}. Is FUSE3 available?"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;
    use fuser::{BackgroundSession, Session};
    use std::fs as stdfs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn test_mount(source: &Path, mountpoint: &Path) -> BackgroundSession {
        let rules = RuleSet::load(source).expect("failed to load rules");
        let fs = ShadowFs::new(source.to_path_buf(), rules);
        let session = Session::new(fs, mountpoint, &mount_options())
            .expect("FUSE session failed — is the test runner using `unshare -r --user --mount`?");
        let bg = BackgroundSession::new(session).expect("background session failed");
        std::thread::sleep(Duration::from_millis(200));
        bg
    }

    #[test]
    fn passthrough_file_content_matches_source() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("hello.txt"), "hello world").unwrap();

        let mount = TempDir::new().unwrap();
        let _session = test_mount(source.path(), mount.path());

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
        let _session = test_mount(source.path(), mount.path());

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
        let _session = test_mount(source.path(), mount.path());

        let content = stdfs::read_to_string(mount.path().join("sub/nested.txt")).unwrap();
        assert_eq!(content, "deep content");
    }

    #[test]
    fn passthrough_symlink_readable() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join("target.txt"), "linked content").unwrap();
        std::os::unix::fs::symlink("target.txt", source.path().join("link.txt")).unwrap();

        let mount = TempDir::new().unwrap();
        let _session = test_mount(source.path(), mount.path());

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
        let _session = test_mount(source.path(), mount.path());

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
        let _session = test_mount(source.path(), mount.path());

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
        let _session = test_mount(source.path(), mount.path());

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
        let _session = test_mount(source.path(), mount.path());

        let result = stdfs::symlink_metadata(mount.path().join(".shadowconfig"));
        assert!(result.is_err());
    }

    #[test]
    fn gitignore_file_readable_through_mount() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.log\n").unwrap();
        stdfs::write(source.path().join("hello.txt"), "hi").unwrap();

        let mount = TempDir::new().unwrap();
        let _session = test_mount(source.path(), mount.path());

        let content = stdfs::read_to_string(mount.path().join(".gitignore")).unwrap();
        assert_eq!(content, "*.log\n");
    }

    #[test]
    fn gitignore_file_visible_in_readdir() {
        let source = TempDir::new().unwrap();
        stdfs::write(source.path().join(".gitignore"), "*.log\n").unwrap();

        let mount = TempDir::new().unwrap();
        let _session = test_mount(source.path(), mount.path());

        let names: Vec<String> = stdfs::read_dir(mount.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&".gitignore".to_string()));
    }
}

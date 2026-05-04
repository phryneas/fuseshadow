use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fuseshadow"))
}

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
}

fn is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn mount_daemon(source: &std::path::Path, mountpoint: &std::path::Path) -> u32 {
    let mut child = bin()
        .args([
            "-d",
            source.to_str().unwrap(),
            mountpoint.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stderr = child.stderr.take().unwrap();
    let reader = BufReader::new(stderr);
    let daemon_pid = reader
        .lines()
        .next()
        .expect("expected a line on stderr")
        .unwrap()
        .strip_prefix("fuseshadow: mounted (pid ")
        .and_then(|s| s.strip_suffix(')'))
        .and_then(|s| s.parse::<u32>().ok())
        .expect("should have printed daemon pid");

    let status = child.wait().unwrap();
    assert!(status.success(), "parent should exit 0");
    assert!(is_process_alive(daemon_pid), "daemon should be alive");

    daemon_pid
}

fn kill_daemon(pid: u32) {
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    for _ in 0..50 {
        if !is_process_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon {pid} did not exit after SIGTERM");
}

#[test]
fn rename_dir_children_accessible_at_new_path() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    // Create a directory with child files
    std::fs::create_dir(root.join("mydir")).unwrap();
    std::fs::write(root.join("mydir/child.txt"), "hello from child").unwrap();
    std::fs::create_dir(root.join("mydir/nested")).unwrap();
    std::fs::write(root.join("mydir/nested/deep.txt"), "deep content").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // Verify children are accessible before rename
    assert_eq!(
        std::fs::read_to_string(mp.join("mydir/child.txt")).unwrap(),
        "hello from child"
    );
    assert_eq!(
        std::fs::read_to_string(mp.join("mydir/nested/deep.txt")).unwrap(),
        "deep content"
    );

    // Rename the directory through the mountpoint
    std::fs::rename(mp.join("mydir"), mp.join("renamed")).unwrap();

    // Children should be accessible at the new path
    assert_eq!(
        std::fs::read_to_string(mp.join("renamed/child.txt")).unwrap(),
        "hello from child",
        "child.txt should be readable at renamed path"
    );
    assert_eq!(
        std::fs::read_to_string(mp.join("renamed/nested/deep.txt")).unwrap(),
        "deep content",
        "nested/deep.txt should be readable at renamed path"
    );

    // readdir on the new path should show correct children
    let entries: Vec<String> = std::fs::read_dir(mp.join("renamed"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        entries.contains(&"child.txt".to_string()),
        "readdir should list child.txt, got: {entries:?}"
    );
    assert!(
        entries.contains(&"nested".to_string()),
        "readdir should list nested, got: {entries:?}"
    );

    // Old path should not exist
    assert!(
        std::fs::metadata(mp.join("mydir")).is_err(),
        "old path should not exist after rename"
    );

    kill_daemon(pid);
}

#[test]
fn rename_dir_no_stale_inodes() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    std::fs::create_dir(root.join("orig")).unwrap();
    std::fs::write(root.join("orig/file.txt"), "content").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // Access the file to ensure its inode is in the mapping
    let _ = std::fs::read_to_string(mp.join("orig/file.txt")).unwrap();

    // Rename the directory
    std::fs::rename(mp.join("orig"), mp.join("moved")).unwrap();

    // Write through the new path to verify full read/write access
    std::fs::write(mp.join("moved/file.txt"), "updated").unwrap();
    assert_eq!(
        std::fs::read_to_string(mp.join("moved/file.txt")).unwrap(),
        "updated",
        "should be able to write through renamed path"
    );

    // Create a new directory at the old name — should work without conflicts
    std::fs::create_dir(mp.join("orig")).unwrap();
    std::fs::write(mp.join("orig/file.txt"), "new content").unwrap();
    assert_eq!(
        std::fs::read_to_string(mp.join("orig/file.txt")).unwrap(),
        "new content",
        "new directory at old name should work independently"
    );

    kill_daemon(pid);
}

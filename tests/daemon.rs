use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fuseshadow"))
}

#[test]
fn dry_run_with_daemon_flag_warns() {
    let tmp = TempDir::new().unwrap();
    let out = bin()
        .args(["--dry-run", "-d", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--daemon has no effect with --dry-run"),
        "expected warning on stderr, got: {stderr}"
    );
}

#[test]
fn dry_run_with_daemon_flag_still_produces_output() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("hello.txt"), "hi").unwrap();

    let out = bin()
        .args(["--dry-run", "-d", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello.txt"),
        "dry-run should still list files, got: {stdout}"
    );
}

#[test]
fn daemon_requires_mountpoint() {
    let tmp = TempDir::new().unwrap();
    let out = bin()
        .args(["-d", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "should fail without mountpoint"
    );
}

#[test]
fn daemon_exits_parent_after_mount() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    std::fs::write(source.path().join("file.txt"), "content").unwrap();

    let mountpoint = TempDir::new().unwrap();

    let mut child = bin()
        .args([
            "-d",
            source.path().to_str().unwrap(),
            mountpoint.path().to_str().unwrap(),
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
        .and_then(|s| s.parse::<u32>().ok());

    let status = child.wait().unwrap();
    assert!(status.success(), "parent should exit 0");

    let pid = daemon_pid.expect("should have printed daemon pid");

    // Verify the daemon is running
    assert!(
        is_process_alive(pid),
        "daemon process {pid} should be alive"
    );

    // Verify mount is functional
    let entries: Vec<_> = std::fs::read_dir(mountpoint.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.iter().any(|e| e.file_name() == "file.txt"),
        "mounted fs should contain file.txt"
    );

    // Clean up: signal the daemon to unmount
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };

    // Wait for unmount
    for _ in 0..50 {
        if !is_process_alive(pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    assert!(
        !is_process_alive(pid),
        "daemon should have exited after SIGTERM"
    );
}

fn fuse_available() -> bool {
    std::path::Path::new("/dev/fuse").exists()
}

fn is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

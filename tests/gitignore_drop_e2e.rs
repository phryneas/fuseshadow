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
fn dropped_pattern_makes_file_readable_and_writable() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    std::fs::write(root.join(".gitignore"), "*.out\n*.log\n").unwrap();
    std::fs::write(
        root.join(".shadowconfig"),
        "[[gitignore_drop]]\npatterns = [\"*.out\"]\n",
    )
    .unwrap();
    std::fs::write(root.join("build.out"), "build output").unwrap();
    std::fs::write(root.join("debug.log"), "log data").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // Dropped pattern: *.out should be readable (Passthrough)
    assert_eq!(
        std::fs::read_to_string(mp.join("build.out")).unwrap(),
        "build output",
        "file matching dropped gitignore pattern should be readable"
    );

    // Dropped pattern: *.out should be writable
    std::fs::write(mp.join("build.out"), "updated output").unwrap();
    assert_eq!(
        std::fs::read_to_string(mp.join("build.out")).unwrap(),
        "updated output",
        "file matching dropped gitignore pattern should be writable"
    );

    // Non-dropped pattern: *.log should still be blocked
    use std::os::unix::fs::PermissionsExt;
    let log_meta = std::fs::metadata(mp.join("debug.log")).unwrap();
    assert_eq!(
        log_meta.permissions().mode() & 0o777,
        0,
        "file matching non-dropped pattern should have zero permissions"
    );
    assert!(
        std::fs::read_to_string(mp.join("debug.log")).is_err(),
        "file matching non-dropped pattern should not be readable"
    );

    kill_daemon(pid);
}

#[test]
fn ignore_beats_dropped_gitignore_pattern() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    std::fs::write(root.join(".gitignore"), "*.out\n").unwrap();
    std::fs::write(
        root.join(".shadowconfig"),
        "[ignore]\npatterns = [\"*.out\"]\n\n[[gitignore_drop]]\npatterns = [\"*.out\"]\n",
    )
    .unwrap();
    std::fs::write(root.join("test.out"), "data").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // [ignore] takes priority over gitignore_drop — file should be Hidden (ENOENT)
    assert!(
        std::fs::metadata(mp.join("test.out")).is_err(),
        "file matching [ignore] should be Hidden even if gitignore pattern was dropped"
    );

    // Also should not appear in directory listing
    let names: Vec<String> = std::fs::read_dir(&mp)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        !names.contains(&"test.out".to_string()),
        "Hidden file should not appear in readdir, got: {names:?}"
    );

    kill_daemon(pid);
}

#[test]
fn drop_targeting_subdirectory_gitignore_only_affects_that_file() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    // Root .gitignore blocks *.tmp
    std::fs::write(root.join(".gitignore"), "*.tmp\n").unwrap();

    // sub/.gitignore also blocks *.tmp
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/.gitignore"), "*.tmp\n").unwrap();

    // Drop *.tmp only from sub/.gitignore
    std::fs::write(
        root.join(".shadowconfig"),
        "[[gitignore_drop]]\ngitignore = \"sub/.gitignore\"\npatterns = [\"*.tmp\"]\n",
    )
    .unwrap();

    std::fs::write(root.join("root.tmp"), "root temp").unwrap();
    std::fs::write(root.join("sub/child.tmp"), "sub temp").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // root.tmp is still blocked by root .gitignore (not targeted by drop)
    use std::os::unix::fs::PermissionsExt;
    let root_meta = std::fs::metadata(mp.join("root.tmp")).unwrap();
    assert_eq!(
        root_meta.permissions().mode() & 0o777,
        0,
        "root.tmp should still be blocked by root .gitignore"
    );

    // sub/child.tmp: the sub/.gitignore pattern was dropped, but root .gitignore
    // also matches *.tmp — so it should still be blocked by the root pattern.
    let sub_meta = std::fs::metadata(mp.join("sub/child.tmp")).unwrap();
    assert_eq!(
        sub_meta.permissions().mode() & 0o777,
        0,
        "sub/child.tmp should still be blocked by root .gitignore even though sub/.gitignore pattern was dropped"
    );

    kill_daemon(pid);
}

#[test]
fn drop_targeting_subdirectory_gitignore_unblocks_unique_pattern() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    // Root .gitignore blocks *.log
    std::fs::write(root.join(".gitignore"), "*.log\n").unwrap();

    // sub/.gitignore blocks *.dat (unique to this file)
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/.gitignore"), "*.dat\n").unwrap();

    // Drop *.dat from sub/.gitignore
    std::fs::write(
        root.join(".shadowconfig"),
        "[[gitignore_drop]]\ngitignore = \"sub/.gitignore\"\npatterns = [\"*.dat\"]\n",
    )
    .unwrap();

    std::fs::write(root.join("sub/data.dat"), "important data").unwrap();
    std::fs::write(root.join("app.log"), "log line").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // sub/data.dat should be unblocked — *.dat only existed in sub/.gitignore
    assert_eq!(
        std::fs::read_to_string(mp.join("sub/data.dat")).unwrap(),
        "important data",
        "file blocked only by dropped subdirectory pattern should be readable"
    );

    // app.log should still be blocked by root .gitignore
    use std::os::unix::fs::PermissionsExt;
    let log_meta = std::fs::metadata(mp.join("app.log")).unwrap();
    assert_eq!(
        log_meta.permissions().mode() & 0o777,
        0,
        "app.log should still be blocked"
    );

    kill_daemon(pid);
}

#[test]
fn rename_preserves_protection_with_gitignore_drop() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    // Root .gitignore blocks *.secret and *.out
    std::fs::write(root.join(".gitignore"), "*.secret\n*.out\n").unwrap();

    // Drop *.out so those files are passthrough
    std::fs::write(
        root.join(".shadowconfig"),
        "[[gitignore_drop]]\npatterns = [\"*.out\"]\n",
    )
    .unwrap();

    // Create a directory with both file types
    std::fs::create_dir(root.join("proj")).unwrap();
    std::fs::write(root.join("proj/build.out"), "build output").unwrap();
    std::fs::write(root.join("proj/api.secret"), "secret key").unwrap();
    std::fs::write(root.join("proj/code.rs"), "fn main() {}").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // Before rename: verify initial state
    assert_eq!(
        std::fs::read_to_string(mp.join("proj/build.out")).unwrap(),
        "build output",
        "dropped pattern file should be readable before rename"
    );
    assert_eq!(
        std::fs::read_to_string(mp.join("proj/code.rs")).unwrap(),
        "fn main() {}",
        "passthrough file should be readable before rename"
    );

    use std::os::unix::fs::PermissionsExt;
    let secret_meta = std::fs::metadata(mp.join("proj/api.secret")).unwrap();
    assert_eq!(
        secret_meta.permissions().mode() & 0o777,
        0,
        "secret file should be blocked before rename"
    );

    // Rename the directory
    std::fs::rename(mp.join("proj"), mp.join("proj_renamed")).unwrap();

    // After rename: *.secret should still be blocked at new path
    let renamed_secret = std::fs::metadata(mp.join("proj_renamed/api.secret")).unwrap();
    assert_eq!(
        renamed_secret.permissions().mode() & 0o777,
        0,
        "secret file should remain blocked after directory rename"
    );
    assert!(
        std::fs::read_to_string(mp.join("proj_renamed/api.secret")).is_err(),
        "secret file should be unreadable after directory rename"
    );

    // After rename: passthrough files should still work
    assert_eq!(
        std::fs::read_to_string(mp.join("proj_renamed/code.rs")).unwrap(),
        "fn main() {}",
        "passthrough file should be readable after rename"
    );

    // After rename: dropped-pattern files should still be passthrough
    assert_eq!(
        std::fs::read_to_string(mp.join("proj_renamed/build.out")).unwrap(),
        "build output",
        "dropped-pattern file should remain readable after rename"
    );

    kill_daemon(pid);
}

#[test]
fn case_insensitive_gitignore_drop_e2e() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    // .gitignore blocks *.out (lowercase)
    std::fs::write(root.join(".gitignore"), "*.out\n").unwrap();

    // Drop *.out
    std::fs::write(
        root.join(".shadowconfig"),
        "[[gitignore_drop]]\npatterns = [\"*.out\"]\n",
    )
    .unwrap();

    // Create file with mixed case
    std::fs::write(root.join("BUILD.Out"), "mixed case output").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();

    // Mount with default case-insensitive mode (no --case-sensitive-rules flag)
    let pid = mount_daemon(&root, &mp);

    // With case-insensitive matching, BUILD.Out matches *.out, and since *.out
    // was dropped, the file should be accessible as Passthrough
    assert_eq!(
        std::fs::read_to_string(mp.join("BUILD.Out")).unwrap(),
        "mixed case output",
        "case-insensitive drop should make mixed-case file accessible"
    );

    // Should also be writable
    std::fs::write(mp.join("BUILD.Out"), "updated").unwrap();
    assert_eq!(
        std::fs::read_to_string(mp.join("BUILD.Out")).unwrap(),
        "updated",
        "case-insensitive dropped file should be writable"
    );

    kill_daemon(pid);
}

#[test]
fn shadowconfig_with_gitignore_drop_is_hidden() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let source = TempDir::new().unwrap();
    let root = source.path().canonicalize().unwrap();

    std::fs::write(root.join(".gitignore"), "*.out\n").unwrap();
    std::fs::write(
        root.join(".shadowconfig"),
        "[[gitignore_drop]]\npatterns = [\"*.out\"]\n",
    )
    .unwrap();
    std::fs::write(root.join("hello.txt"), "visible").unwrap();

    let mountpoint = TempDir::new().unwrap();
    let mp = mountpoint.path().canonicalize().unwrap();
    let pid = mount_daemon(&root, &mp);

    // .shadowconfig should be completely invisible
    assert!(
        std::fs::metadata(mp.join(".shadowconfig")).is_err(),
        ".shadowconfig should be Hidden (ENOENT)"
    );

    // Should not appear in directory listing
    let names: Vec<String> = std::fs::read_dir(&mp)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        !names.contains(&".shadowconfig".to_string()),
        ".shadowconfig should not appear in readdir, got: {names:?}"
    );

    // But normal files should still work
    assert_eq!(
        std::fs::read_to_string(mp.join("hello.txt")).unwrap(),
        "visible"
    );

    kill_daemon(pid);
}

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

#[test]
fn same_source_and_target() {
    if !fuse_available() {
        eprintln!("skipping: FUSE not available");
        return;
    }

    let dir = TempDir::new().unwrap();
    let root = dir.path().canonicalize().unwrap();

    std::fs::write(root.join(".gitignore"), ".env\ncredentials.json\n").unwrap();
    std::fs::write(
        root.join(".shadowconfig"),
        "[ignore]\npatterns = [\".git\"]\n[writable]\npatterns = [\".env\"]\n",
    )
    .unwrap();
    std::fs::write(root.join("hello.txt"), "hello world").unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/nested.txt"), "deep content").unwrap();
    std::fs::write(root.join(".env"), "SECRET=hunter2").unwrap();
    std::fs::write(root.join("credentials.json"), r#"{"key":"secret"}"#).unwrap();
    std::fs::create_dir(root.join(".git")).unwrap();
    std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main").unwrap();

    // Launch daemon with source == mountpoint
    let root_str = root.to_str().unwrap();
    let mut child = bin()
        .args(["-d", root_str, root_str])
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
    assert!(is_process_alive(pid), "daemon should be alive");

    // Passthrough files are readable
    assert_eq!(
        std::fs::read_to_string(root.join("hello.txt")).unwrap(),
        "hello world"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("sub/nested.txt")).unwrap(),
        "deep content"
    );

    // Directory listing respects classifications
    let names: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(names.contains(&"hello.txt".to_string()));
    assert!(names.contains(&"sub".to_string()));
    assert!(names.contains(&".gitignore".to_string()));
    assert!(names.contains(&"credentials.json".to_string()));
    assert!(!names.contains(&".git".to_string()));
    assert!(!names.contains(&".shadowconfig".to_string()));
    assert!(!names.contains(&".env".to_string()));

    // .gitignore is readable
    let gi = std::fs::read_to_string(root.join(".gitignore")).unwrap();
    assert!(gi.contains(".env"));

    // Blocked file has zero permissions and is unreadable
    use std::os::unix::fs::PermissionsExt;
    let cred_meta = std::fs::metadata(root.join("credentials.json")).unwrap();
    assert_eq!(cred_meta.permissions().mode() & 0o777, 0);
    assert!(std::fs::read_to_string(root.join("credentials.json")).is_err());

    // Hidden directory completely invisible
    assert!(std::fs::metadata(root.join(".git")).is_err());

    // WritableOverlay: invisible → writable → reads overlay content
    assert!(std::fs::read_to_string(root.join(".env")).is_err());
    std::fs::write(root.join(".env"), "GENERATED=yes").unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join(".env")).unwrap(),
        "GENERATED=yes"
    );

    // Passthrough write works
    std::fs::write(root.join("hello.txt"), "updated").unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("hello.txt")).unwrap(),
        "updated"
    );

    // Clean up
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
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

use std::process::Command;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fuseshadow"))
}

fn setup_tree() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    std::fs::write(root.join(".gitignore"), ".env\n").unwrap();
    std::fs::write(root.join(".env"), "SECRET=x").unwrap();
    std::fs::write(root.join("hello.txt"), "hi").unwrap();
    tmp
}

#[test]
fn case_sensitive_rules_flag_accepted() {
    let tmp = setup_tree();
    let out = bin()
        .args([
            "--dry-run",
            "--case-sensitive-rules",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "--case-sensitive-rules should be accepted, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn dry_run_shows_case_insensitive_mode_by_default() {
    let tmp = setup_tree();
    let out = bin()
        .args(["--dry-run", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("case-insensitive"),
        "should show case-insensitive mode header, got: {stdout}"
    );
}

#[test]
fn dry_run_shows_case_sensitive_mode_when_flag_set() {
    let tmp = setup_tree();
    let out = bin()
        .args([
            "--dry-run",
            "--case-sensitive-rules",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("case-sensitive") && !stdout.contains("case-insensitive"),
        "should show case-sensitive mode header, got: {stdout}"
    );
}

#[test]
fn dry_run_default_blocks_alternate_case() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    std::fs::write(root.join(".gitignore"), ".env\n").unwrap();
    std::fs::write(root.join(".env"), "SECRET=x").unwrap();
    std::fs::write(root.join(".ENV"), "SECRET=x").unwrap();

    let out = bin()
        .args(["--dry-run", root.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if line.contains(".ENV") || line.contains(".env") {
            assert!(
                line.contains("Blocked") || line.contains("WritableOverlay"),
                ".env/.ENV should be Blocked in case-insensitive mode, got: {line}"
            );
        }
    }
}

#[test]
fn help_documents_case_sensitive_rules() {
    let out = bin().args(["--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--case-sensitive-rules"),
        "--help should document the flag, got: {stdout}"
    );
}

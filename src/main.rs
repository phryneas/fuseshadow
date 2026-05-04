use anyhow::{bail, Context, Result};
use clap::Parser;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::Duration;
use walkdir::WalkDir;

mod fs;
mod overlay;

mod rules;

use rules::RuleSet;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// SAFETY: Only performs a single atomic store, which is async-signal-safe.
unsafe extern "C" fn signal_handler(_: libc::c_int) {
    SHUTDOWN.store(true, Relaxed);
}

#[derive(Parser)]
#[command(
    name = "fuseshadow",
    about = "Mount a source directory with layered access policy to protect secrets from AI agents"
)]
struct Cli {
    /// Source directory to expose through the mount
    source: PathBuf,
    /// Mountpoint (required unless --dry-run is passed)
    #[arg(required_unless_present = "dry_run")]
    mountpoint: Option<PathBuf>,
    /// Walk source directory and print path classifications without mounting
    #[arg(long)]
    dry_run: bool,
    /// Daemonize after mounting (fork into background)
    #[arg(short, long)]
    daemon: bool,
    /// Use case-sensitive pattern matching (default is case-insensitive)
    #[arg(long)]
    case_sensitive_rules: bool,
}

/// Fork into background. Returns the write-end of a notification pipe
/// in the child; the parent waits for a ready byte and exits.
fn daemonize() -> Result<OwnedFd> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid 2-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded; fds[0] and fds[1] are valid, distinct descriptors.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    // SAFETY: No other threads are running yet (BackgroundSession hasn't been created).
    match unsafe { libc::fork() } {
        -1 => bail!("fork: {}", std::io::Error::last_os_error()),
        0 => {
            drop(r);
            // SAFETY: Standard POSIX call; no preconditions beyond being a process.
            if unsafe { libc::setsid() } == -1 {
                bail!("setsid: {}", std::io::Error::last_os_error());
            }
            Ok(w)
        }
        child_pid => {
            drop(w);
            let mut buf = [1u8];
            // SAFETY: r is a valid fd from pipe2; buf is a valid 1-byte buffer.
            let n =
                unsafe { libc::read(r.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, 1) };
            drop(r);
            if n == 1 && buf[0] == 0 {
                eprintln!("fuseshadow: mounted (pid {child_pid})");
                std::process::exit(0);
            }
            eprintln!("fuseshadow: daemon failed to start");
            std::process::exit(1);
        }
    }
}

fn detach_stdio() {
    // SAFETY: /dev/null path is a valid C string; O_RDWR is a valid flag.
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if devnull >= 0 {
        // SAFETY: devnull is a valid fd; STDIN/STDOUT/STDERR are valid target fds.
        unsafe {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.source.exists() {
        bail!("source path does not exist: {}", cli.source.display());
    }
    if !cli.source.is_dir() {
        bail!(
            "source path is not a directory: {}",
            cli.source.display()
        );
    }

    let source = cli
        .source
        .canonicalize()
        .with_context(|| format!("cannot resolve source: {}", cli.source.display()))?;

    let rule_set =
        RuleSet::load(&source, cli.case_sensitive_rules).context("failed to load access rules")?;

    if cli.dry_run {
        if cli.daemon {
            eprintln!("warning: --daemon has no effect with --dry-run");
        }
        if cli.case_sensitive_rules {
            println!("Matching mode: case-sensitive");
        } else {
            println!("Matching mode: case-insensitive (default)");
        }
        for entry in WalkDir::new(&source)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.depth() > 0)
        {
            let Ok(rel) = entry.path().strip_prefix(&source) else {
                continue;
            };
            let class = rule_set.classify(rel, entry.file_type().is_dir());
            println!("{:<20} {}", format!("{class:?}"), rel.display());
        }
        return Ok(());
    }

    let mountpoint = cli.mountpoint.unwrap();
    if !mountpoint.exists() {
        bail!("mountpoint does not exist: {}", mountpoint.display());
    }
    if !mountpoint.is_dir() {
        bail!(
            "mountpoint is not a directory: {}",
            mountpoint.display()
        );
    }

    let mountpoint = mountpoint
        .canonicalize()
        .with_context(|| format!("cannot resolve mountpoint: {}", mountpoint.display()))?;

    let notify_fd = if cli.daemon {
        Some(daemonize()?)
    } else {
        None
    };

    // SAFETY: signal_handler only performs an atomic store, which is async-signal-safe.
    // The handler pointer is valid for the program's lifetime (static function).
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
    }

    if notify_fd.is_some() {
        detach_stdio();
    }

    let overlay = overlay::Overlay::new().context("failed to create overlay")?;
    let shadow_fs = fs::ShadowFs::new(source, mountpoint.clone(), rule_set, overlay);

    let session = fuser::Session::new(shadow_fs, &mountpoint, &fs::mount_options())
        .map_err(|e| anyhow::anyhow!("FUSE mount failed: {e}. Is FUSE3 available?"))?;
    let bg = fuser::BackgroundSession::new(session)
        .context("failed to start FUSE background session")?;

    if let Some(fd) = notify_fd {
        // SAFETY: fd is a valid pipe write-end from daemonize(); buf is a 1-byte slice.
        unsafe { libc::write(fd.as_raw_fd(), [0u8].as_ptr() as *const libc::c_void, 1) };
        drop(fd);
    }

    while !SHUTDOWN.load(Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
    }

    drop(bg);
    Ok(())
}

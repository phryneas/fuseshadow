use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use walkdir::WalkDir;

mod fs;
mod overlay;

mod rules;

use rules::RuleSet;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn signal_handler(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
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

    let rule_set = RuleSet::load(&source).context("failed to load access rules")?;

    if cli.dry_run {
        for entry in WalkDir::new(&source)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.depth() > 0)
        {
            let rel = entry.path().strip_prefix(&source).unwrap();
            let class = rule_set.classify(rel);
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

    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
    }

    let overlay = overlay::Overlay::new().context("failed to create overlay")?;
    let shadow_fs = fs::ShadowFs::new(source, mountpoint.clone(), rule_set, overlay);

    let session = fuser::Session::new(shadow_fs, &mountpoint, &fs::mount_options())
        .map_err(|e| anyhow::anyhow!("FUSE mount failed: {e}. Is FUSE3 available?"))?;
    let bg = fuser::BackgroundSession::new(session)
        .context("failed to start FUSE background session")?;

    while !SHUTDOWN.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }

    drop(bg);
    Ok(())
}

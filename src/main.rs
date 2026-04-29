use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use walkdir::WalkDir;

mod fs;
// Phase 4 will wire Overlay into the FUSE layer; suppress dead-code for now.
#[allow(dead_code)]
mod overlay;
mod rules;

use rules::RuleSet;

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

    let shadow_fs = fs::ShadowFs::new(source, rule_set);
    fs::mount(shadow_fs, &mountpoint)
}

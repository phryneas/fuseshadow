use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathClass {
    Hidden,
    Blocked,
    WritableOverlay,
    GitignoreFile,
    Passthrough,
}

#[derive(Debug, Default, Deserialize)]
struct ShadowConfig {
    #[serde(default)]
    ignore: ShadowSection,
    #[serde(default)]
    writable: ShadowSection,
}

#[derive(Debug, Default, Deserialize)]
struct ShadowSection {
    #[serde(default)]
    patterns: Vec<String>,
}

struct DirMatcher {
    dir: PathBuf,
    matcher: Gitignore,
}

impl DirMatcher {
    fn matches(&self, abs_path: &Path, is_dir: bool) -> bool {
        match abs_path.strip_prefix(&self.dir) {
            Ok(rel) => self
                .matcher
                .matched_path_or_any_parents(rel, is_dir)
                .is_ignore(),
            Err(_) => false,
        }
    }
}

pub struct RuleSet {
    source_root: PathBuf,
    gitignore_matchers: Vec<DirMatcher>,
    shadow_ignore_matchers: Vec<DirMatcher>,
    shadow_writable_matchers: Vec<DirMatcher>,
}

impl RuleSet {
    pub fn load(source_root: &Path) -> Result<Self> {
        let source_root = source_root
            .canonicalize()
            .with_context(|| format!("cannot canonicalize {}", source_root.display()))?;

        let mut gitignore_matchers = Vec::new();
        let mut shadow_ignore_matchers = Vec::new();
        let mut shadow_writable_matchers = Vec::new();

        // Walk UP from source root to filesystem root for parent .gitignore files.
        // This naturally picks up ~/.gitignore when it exists.
        let mut current = source_root.parent();
        while let Some(dir) = current {
            let gi_path = dir.join(".gitignore");
            if gi_path.is_file() {
                let mut b = GitignoreBuilder::new(dir);
                b.add(&gi_path);
                if let Ok(m) = b.build() {
                    gitignore_matchers.push(DirMatcher {
                        dir: dir.to_path_buf(),
                        matcher: m,
                    });
                }
            }
            current = dir.parent();
        }

        // Walk DOWN through source tree for .gitignore and .shadowconfig files.
        for entry in walkdir::WalkDir::new(&source_root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = entry.file_name();
            let dir = entry
                .path()
                .parent()
                .unwrap_or(source_root.as_path());

            if name == ".gitignore" {
                let mut b = GitignoreBuilder::new(dir);
                b.add(entry.path());
                if let Ok(m) = b.build() {
                    gitignore_matchers.push(DirMatcher {
                        dir: dir.to_path_buf(),
                        matcher: m,
                    });
                }
            } else if name == ".shadowconfig" {
                let content = std::fs::read_to_string(entry.path())
                    .with_context(|| format!("reading {}", entry.path().display()))?;
                let config: ShadowConfig = toml::from_str(&content)
                    .with_context(|| format!("parsing {}", entry.path().display()))?;

                if !config.ignore.patterns.is_empty() {
                    let mut b = GitignoreBuilder::new(dir);
                    for p in &config.ignore.patterns {
                        let _ = b.add_line(None, p);
                    }
                    if let Ok(m) = b.build() {
                        shadow_ignore_matchers.push(DirMatcher {
                            dir: dir.to_path_buf(),
                            matcher: m,
                        });
                    }
                }

                if !config.writable.patterns.is_empty() {
                    let mut b = GitignoreBuilder::new(dir);
                    for p in &config.writable.patterns {
                        let _ = b.add_line(None, p);
                    }
                    if let Ok(m) = b.build() {
                        shadow_writable_matchers.push(DirMatcher {
                            dir: dir.to_path_buf(),
                            matcher: m,
                        });
                    }
                }
            }
        }

        Ok(Self {
            source_root,
            gitignore_matchers,
            shadow_ignore_matchers,
            shadow_writable_matchers,
        })
    }

    /// Classify a path relative to the source root.
    pub fn classify(&self, rel_path: &Path) -> PathClass {
        let abs_path = self.source_root.join(rel_path);
        let is_dir = abs_path.is_dir();

        // Priority 1: .shadowconfig is always Hidden
        if rel_path.file_name().is_some_and(|n| n == ".shadowconfig") {
            return PathClass::Hidden;
        }

        // Priority 2: matches [ignore] → Hidden
        if self
            .shadow_ignore_matchers
            .iter()
            .any(|m| m.matches(&abs_path, is_dir))
        {
            return PathClass::Hidden;
        }

        let gitignored = self
            .gitignore_matchers
            .iter()
            .any(|m| m.matches(&abs_path, is_dir));

        // Priority 3: matches [writable] AND gitignored → WritableOverlay
        if gitignored
            && self
                .shadow_writable_matchers
                .iter()
                .any(|m| m.matches(&abs_path, is_dir))
        {
            return PathClass::WritableOverlay;
        }

        // Priority 4: gitignored → Blocked
        if gitignored {
            return PathClass::Blocked;
        }

        // Priority 5: .gitignore → GitignoreFile
        if rel_path.file_name().is_some_and(|n| n == ".gitignore") {
            return PathClass::GitignoreFile;
        }

        PathClass::Passthrough
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(base: &Path, rel: &str, content: &str) {
        let path = base.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn mkdir(base: &Path, rel: &str) {
        fs::create_dir_all(base.join(rel)).unwrap();
    }

    #[test]
    fn gitignored_path_should_be_blocked() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "*.log\n");
        write(root, "app.log", "");
        write(root, "main.rs", "");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(rs.classify(Path::new("app.log")), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("main.rs")), PathClass::Passthrough);
    }

    #[test]
    fn nested_gitignore_should_apply_only_to_its_subtree() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, "sub/.gitignore", "*.log\n");
        write(root, "sub/foo.log", "");
        write(root, "foo.log", "");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new("sub/foo.log")),
            PathClass::Blocked
        );
        assert_eq!(rs.classify(Path::new("foo.log")), PathClass::Passthrough);
    }

    #[test]
    fn parent_gitignore_should_apply_to_source_root() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path();
        let root = parent.join("source");
        fs::create_dir(&root).unwrap();
        write(parent, ".gitignore", "*.secret\n");
        write(&root, "config.secret", "");

        let rs = RuleSet::load(&root).unwrap();
        assert_eq!(
            rs.classify(Path::new("config.secret")),
            PathClass::Blocked
        );
    }

    #[test]
    fn shadowconfig_ignore_pattern_should_hide_matching_paths() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = [\".git\"]\n");
        mkdir(root, ".git");
        write(root, ".git/HEAD", "ref: refs/heads/main");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(rs.classify(Path::new(".git")), PathClass::Hidden);
    }

    #[test]
    fn writable_gitignored_path_should_be_writable_overlay() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\n");
        write(
            root,
            ".shadowconfig",
            "[writable]\npatterns = [\".env\"]\n",
        );
        write(root, ".env", "SECRET=value");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(rs.classify(Path::new(".env")), PathClass::WritableOverlay);
    }

    #[test]
    fn writable_not_gitignored_should_be_passthrough() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            root,
            ".shadowconfig",
            "[writable]\npatterns = [\"config.json\"]\n",
        );
        write(root, "config.json", "{}");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new("config.json")),
            PathClass::Passthrough
        );
    }

    #[test]
    fn ignore_should_beat_writable_when_both_match() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\n");
        write(
            root,
            ".shadowconfig",
            "[ignore]\npatterns = [\".env\"]\n\n[writable]\npatterns = [\".env\"]\n",
        );
        write(root, ".env", "SECRET=value");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(rs.classify(Path::new(".env")), PathClass::Hidden);
    }

    #[test]
    fn shadowconfig_itself_should_always_be_hidden() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = []\n");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new(".shadowconfig")),
            PathClass::Hidden
        );
    }

    #[test]
    fn gitignore_file_should_be_gitignore_class() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "*.log\n");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new(".gitignore")),
            PathClass::GitignoreFile
        );
    }

    #[test]
    fn unmatched_file_should_be_passthrough() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, "src/main.rs", "fn main() {}");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new("src/main.rs")),
            PathClass::Passthrough
        );
    }
}

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::Deserialize;

const GITIGNORE_FILENAME: &str = ".gitignore";
const SHADOWCONFIG_FILENAME: &str = ".shadowconfig";

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
    fn from_gitignore_file(dir: &Path, file: &Path) -> Option<Self> {
        let mut b = GitignoreBuilder::new(dir);
        b.add(file);
        b.build().ok().map(|matcher| Self {
            dir: dir.to_path_buf(),
            matcher,
        })
    }

    fn from_patterns(dir: &Path, patterns: &[String]) -> Option<Self> {
        if patterns.is_empty() {
            return None;
        }
        let mut b = GitignoreBuilder::new(dir);
        for p in patterns {
            let _ = b.add_line(None, p);
        }
        b.build().ok().map(|matcher| Self {
            dir: dir.to_path_buf(),
            matcher,
        })
    }

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

        // Picks up ~/.gitignore and other ancestor .gitignore files
        let mut current = source_root.parent();
        while let Some(dir) = current {
            let gi_path = dir.join(GITIGNORE_FILENAME);
            if gi_path.is_file() {
                if let Some(m) = DirMatcher::from_gitignore_file(dir, &gi_path) {
                    gitignore_matchers.push(m);
                }
            }
            current = dir.parent();
        }

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

            if name == GITIGNORE_FILENAME {
                if let Some(m) = DirMatcher::from_gitignore_file(dir, entry.path()) {
                    gitignore_matchers.push(m);
                }
            } else if name == SHADOWCONFIG_FILENAME {
                let content = std::fs::read_to_string(entry.path())
                    .with_context(|| format!("reading {}", entry.path().display()))?;
                let config: ShadowConfig = toml::from_str(&content)
                    .with_context(|| format!("parsing {}", entry.path().display()))?;

                if let Some(m) = DirMatcher::from_patterns(dir, &config.ignore.patterns) {
                    shadow_ignore_matchers.push(m);
                }
                if let Some(m) = DirMatcher::from_patterns(dir, &config.writable.patterns) {
                    shadow_writable_matchers.push(m);
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

    /// Classification priority (highest wins):
    /// 1. .shadowconfig → Hidden
    /// 2. [ignore] match → Hidden
    /// 3. [writable] match + gitignored → WritableOverlay
    /// 4. gitignored → Blocked
    /// 5. .gitignore → GitignoreFile
    /// 6. Otherwise → Passthrough
    pub fn classify(&self, rel_path: &Path, is_dir: Option<bool>) -> PathClass {
        if rel_path.file_name().is_some_and(|n| n == SHADOWCONFIG_FILENAME) {
            return PathClass::Hidden;
        }

        let abs_path = self.source_root.join(rel_path);
        let is_dir = is_dir.unwrap_or_else(|| abs_path.is_dir());

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

        if gitignored
            && self
                .shadow_writable_matchers
                .iter()
                .any(|m| m.matches(&abs_path, is_dir))
        {
            return PathClass::WritableOverlay;
        }

        if gitignored {
            return PathClass::Blocked;
        }

        if rel_path.file_name().is_some_and(|n| n == GITIGNORE_FILENAME) {
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
        assert_eq!(rs.classify(Path::new("app.log"), None), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("main.rs"), None), PathClass::Passthrough);
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
            rs.classify(Path::new("sub/foo.log"), None),
            PathClass::Blocked
        );
        assert_eq!(rs.classify(Path::new("foo.log"), None), PathClass::Passthrough);
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
            rs.classify(Path::new("config.secret"), None),
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
        assert_eq!(rs.classify(Path::new(".git"), None), PathClass::Hidden);
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
        assert_eq!(rs.classify(Path::new(".env"), None), PathClass::WritableOverlay);
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
            rs.classify(Path::new("config.json"), None),
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
        assert_eq!(rs.classify(Path::new(".env"), None), PathClass::Hidden);
    }

    #[test]
    fn shadowconfig_itself_should_always_be_hidden() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = []\n");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new(".shadowconfig"), None),
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
            rs.classify(Path::new(".gitignore"), None),
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
            rs.classify(Path::new("src/main.rs"), None),
            PathClass::Passthrough
        );
    }

    #[test]
    fn dir_only_gitignore_pattern_respects_is_dir_hint() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "build/\n");
        mkdir(root, "build");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new("build"), Some(true)),
            PathClass::Blocked
        );
        assert_eq!(
            rs.classify(Path::new("build"), Some(false)),
            PathClass::Passthrough
        );
    }

    #[test]
    fn is_dir_none_falls_back_to_filesystem() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "build/\n");
        mkdir(root, "build");
        write(root, "build/out.o", "");

        let rs = RuleSet::load(root).unwrap();
        // build/ exists as a directory — None should stat and find is_dir=true
        assert_eq!(
            rs.classify(Path::new("build"), None),
            PathClass::Blocked
        );
        // build/out.o is a file — None should stat and find is_dir=false,
        // but it still matches via matched_path_or_any_parents (parent is ignored)
        assert_eq!(
            rs.classify(Path::new("build/out.o"), None),
            PathClass::Blocked
        );
    }

    #[test]
    fn hint_true_blocks_nonexistent_dir_pattern() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "output/\n");
        // "output" directory does NOT exist on disk

        let rs = RuleSet::load(root).unwrap();
        // None falls back to stat — path doesn't exist, is_dir() returns false
        assert_eq!(
            rs.classify(Path::new("output"), None),
            PathClass::Passthrough
        );
        // Hint true forces the directory match
        assert_eq!(
            rs.classify(Path::new("output"), Some(true)),
            PathClass::Blocked
        );
    }

    #[test]
    fn nested_shadowconfig_itself_should_be_hidden() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        mkdir(root, "sub");
        write(root, "sub/.shadowconfig", "[ignore]\npatterns = []\n");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new("sub/.shadowconfig"), None),
            PathClass::Hidden
        );
    }

    #[test]
    fn nested_gitignore_should_be_gitignore_class() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        mkdir(root, "sub");
        write(root, "sub/.gitignore", "*.tmp\n");

        let rs = RuleSet::load(root).unwrap();
        assert_eq!(
            rs.classify(Path::new("sub/.gitignore"), None),
            PathClass::GitignoreFile
        );
    }

    #[test]
    fn multiple_shadowconfigs_compose_across_levels() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\ncredentials.json\n");
        write(root, ".shadowconfig", "[ignore]\npatterns = [\".git\"]\n[writable]\npatterns = [\".env\"]\n");
        write(root, "sub/.shadowconfig", "[ignore]\npatterns = [\"internal\"]\n[writable]\npatterns = [\"credentials.json\"]\n");
        mkdir(root, ".git");
        write(root, ".env", "SECRET=x");
        mkdir(root, "sub");
        mkdir(root, "sub/internal");
        write(root, "sub/credentials.json", "{}");

        let rs = RuleSet::load(root).unwrap();
        // Root [ignore] hides .git
        assert_eq!(rs.classify(Path::new(".git"), None), PathClass::Hidden);
        // Root [writable] + gitignored → WritableOverlay
        assert_eq!(rs.classify(Path::new(".env"), None), PathClass::WritableOverlay);
        // Sub [ignore] hides sub/internal
        assert_eq!(rs.classify(Path::new("sub/internal"), None), PathClass::Hidden);
        // Sub [writable] + gitignored → WritableOverlay
        assert_eq!(rs.classify(Path::new("sub/credentials.json"), None), PathClass::WritableOverlay);
        // Root [ignore] doesn't apply to sub/internal's name at root level
        assert_eq!(rs.classify(Path::new(".env"), None), PathClass::WritableOverlay);
    }
}

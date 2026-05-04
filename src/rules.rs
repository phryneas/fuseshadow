use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::Deserialize;

const GITIGNORE_FILENAME: &str = ".gitignore";
const SHADOWCONFIG_FILENAME: &str = ".shadowconfig";

fn lower_path(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

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
    #[serde(default)]
    folder_renames: Vec<FolderRename>,
}

#[derive(Debug, Default, Deserialize)]
struct ShadowSection {
    #[serde(default)]
    patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FolderRename {
    pub from: String,
    pub to: String,
    pub at: String,
}

fn build_alias_map(renames: &[FolderRename]) -> HashMap<PathBuf, PathBuf> {
    let mut aliases: HashMap<PathBuf, PathBuf> = HashMap::new();
    for entry in renames {
        let from = PathBuf::from(&entry.from);
        let to = PathBuf::from(&entry.to);
        let original = aliases.get(&from).cloned().unwrap_or(from);
        aliases.insert(to, original);
    }
    aliases
}

struct DirMatcher {
    dir: PathBuf,
    matcher: Gitignore,
}

impl DirMatcher {
    fn from_gitignore_file(dir: &Path, file: &Path, case_sensitive: bool) -> Option<Self> {
        let anchor = if case_sensitive { dir.to_path_buf() } else { lower_path(dir) };
        let mut b = GitignoreBuilder::new(&anchor);
        if case_sensitive {
            b.add(file);
        } else {
            let content = std::fs::read_to_string(file).ok()?;
            for line in content.lines() {
                let _ = b.add_line(None, &line.to_lowercase());
            }
        }
        b.build().ok().map(|matcher| Self {
            dir: anchor,
            matcher,
        })
    }

    fn from_patterns(dir: &Path, patterns: &[String], case_sensitive: bool) -> Option<Self> {
        if patterns.is_empty() {
            return None;
        }
        let anchor = if case_sensitive { dir.to_path_buf() } else { lower_path(dir) };
        let mut b = GitignoreBuilder::new(&anchor);
        for p in patterns {
            if case_sensitive {
                let _ = b.add_line(None, p);
            } else {
                let _ = b.add_line(None, &p.to_lowercase());
            }
        }
        b.build().ok().map(|matcher| Self {
            dir: anchor,
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
    match_root: PathBuf,
    case_sensitive: bool,
    gitignore_matchers: Vec<DirMatcher>,
    shadow_ignore_matchers: Vec<DirMatcher>,
    shadow_writable_matchers: Vec<DirMatcher>,
    rename_aliases: HashMap<PathBuf, PathBuf>,
}

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSet")
            .field("source_root", &self.source_root)
            .field("case_sensitive", &self.case_sensitive)
            .field("rename_aliases", &self.rename_aliases)
            .finish_non_exhaustive()
    }
}

impl RuleSet {
    pub fn load(source_root: &Path, case_sensitive: bool) -> Result<Self> {
        let source_root = source_root
            .canonicalize()
            .with_context(|| format!("cannot canonicalize {}", source_root.display()))?;
        let match_root = if case_sensitive {
            source_root.clone()
        } else {
            lower_path(&source_root)
        };

        let mut gitignore_matchers = Vec::new();
        let mut shadow_ignore_matchers = Vec::new();
        let mut shadow_writable_matchers = Vec::new();
        let mut rename_aliases = HashMap::new();

        // Picks up ~/.gitignore and other ancestor .gitignore files
        let mut current = source_root.parent();
        while let Some(dir) = current {
            let gi_path = dir.join(GITIGNORE_FILENAME);
            if gi_path.is_file() {
                if let Some(m) = DirMatcher::from_gitignore_file(dir, &gi_path, case_sensitive) {
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
                if let Some(m) = DirMatcher::from_gitignore_file(dir, entry.path(), case_sensitive) {
                    gitignore_matchers.push(m);
                }
            } else if name == SHADOWCONFIG_FILENAME {
                let content = std::fs::read_to_string(entry.path())
                    .with_context(|| format!("reading {}", entry.path().display()))?;
                let config: ShadowConfig = toml::from_str(&content)
                    .with_context(|| format!("parsing {}", entry.path().display()))?;

                let is_root = dir == source_root.as_path();

                if !is_root && !config.folder_renames.is_empty() {
                    bail!(
                        "{} contains folder_renames, which is only allowed in the root .shadowconfig. \
                         Please move these entries to {} or remove them.",
                        entry.path().display(),
                        source_root.join(SHADOWCONFIG_FILENAME).display()
                    );
                }

                if is_root {
                    rename_aliases = build_alias_map(&config.folder_renames);
                }

                if let Some(m) = DirMatcher::from_patterns(dir, &config.ignore.patterns, case_sensitive) {
                    shadow_ignore_matchers.push(m);
                }
                if let Some(m) = DirMatcher::from_patterns(dir, &config.writable.patterns, case_sensitive) {
                    shadow_writable_matchers.push(m);
                }
            }
        }

        Ok(Self {
            source_root,
            match_root,
            case_sensitive,
            gitignore_matchers,
            shadow_ignore_matchers,
            shadow_writable_matchers,
            rename_aliases,
        })
    }

    /// Classification priority (highest wins):
    /// 1. .shadowconfig → Hidden
    /// 2. [ignore] match → Hidden
    /// 3. [writable] match + gitignored → WritableOverlay
    /// 4. gitignored → Blocked
    /// 5. .gitignore → GitignoreFile
    /// 6. Otherwise → Passthrough
    pub fn classify(&self, rel_path: &Path, is_dir: bool) -> PathClass {
        let file_name_matches = |target: &str| -> bool {
            rel_path.file_name().is_some_and(|n| {
                if self.case_sensitive {
                    n == target
                } else {
                    n.to_string_lossy().to_lowercase() == target
                }
            })
        };

        if file_name_matches(SHADOWCONFIG_FILENAME) {
            return PathClass::Hidden;
        }

        let match_path = if self.case_sensitive {
            self.source_root.join(rel_path)
        } else {
            self.match_root.join(lower_path(rel_path))
        };

        if self
            .shadow_ignore_matchers
            .iter()
            .any(|m| m.matches(&match_path, is_dir))
        {
            return PathClass::Hidden;
        }

        let gitignored = self
            .gitignore_matchers
            .iter()
            .any(|m| m.matches(&match_path, is_dir));

        if gitignored
            && self
                .shadow_writable_matchers
                .iter()
                .any(|m| m.matches(&match_path, is_dir))
        {
            return PathClass::WritableOverlay;
        }

        if gitignored {
            return PathClass::Blocked;
        }

        if file_name_matches(GITIGNORE_FILENAME) {
            return PathClass::GitignoreFile;
        }

        PathClass::Passthrough
    }

    pub fn rename_aliases(&self) -> &HashMap<PathBuf, PathBuf> {
        &self.rename_aliases
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

    // ---- Case-sensitive tests (existing behavior) ----

    #[test]
    fn gitignored_path_should_be_blocked() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "*.log\n");
        write(root, "app.log", "");
        write(root, "main.rs", "");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new("app.log"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("main.rs"), false), PathClass::Passthrough);
    }

    #[test]
    fn nested_gitignore_should_apply_only_to_its_subtree() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, "sub/.gitignore", "*.log\n");
        write(root, "sub/foo.log", "");
        write(root, "foo.log", "");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("sub/foo.log"), false),
            PathClass::Blocked
        );
        assert_eq!(rs.classify(Path::new("foo.log"), false), PathClass::Passthrough);
    }

    #[test]
    fn parent_gitignore_should_apply_to_source_root() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path();
        let root = parent.join("source");
        fs::create_dir(&root).unwrap();
        write(parent, ".gitignore", "*.secret\n");
        write(&root, "config.secret", "");

        let rs = RuleSet::load(&root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("config.secret"), false),
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

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
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

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::WritableOverlay);
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

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("config.json"), false),
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

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::Hidden);
    }

    #[test]
    fn shadowconfig_itself_should_always_be_hidden() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = []\n");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new(".shadowconfig"), false),
            PathClass::Hidden
        );
    }

    #[test]
    fn gitignore_file_should_be_gitignore_class() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "*.log\n");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new(".gitignore"), false),
            PathClass::GitignoreFile
        );
    }

    #[test]
    fn unmatched_file_should_be_passthrough() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, "src/main.rs", "fn main() {}");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("src/main.rs"), false),
            PathClass::Passthrough
        );
    }

    #[test]
    fn dir_only_gitignore_pattern_respects_is_dir_hint() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "build/\n");
        mkdir(root, "build");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("build"), true),
            PathClass::Blocked
        );
        assert_eq!(
            rs.classify(Path::new("build"), false),
            PathClass::Passthrough
        );
    }

    #[test]
    fn hint_true_blocks_nonexistent_dir_pattern() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "output/\n");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("output"), false),
            PathClass::Passthrough
        );
        assert_eq!(
            rs.classify(Path::new("output"), true),
            PathClass::Blocked
        );
    }

    #[test]
    fn nested_shadowconfig_itself_should_be_hidden() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        mkdir(root, "sub");
        write(root, "sub/.shadowconfig", "[ignore]\npatterns = []\n");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("sub/.shadowconfig"), false),
            PathClass::Hidden
        );
    }

    #[test]
    fn nested_gitignore_should_be_gitignore_class() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        mkdir(root, "sub");
        write(root, "sub/.gitignore", "*.tmp\n");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("sub/.gitignore"), false),
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

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::WritableOverlay);
        assert_eq!(rs.classify(Path::new("sub/internal"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new("sub/credentials.json"), false), PathClass::WritableOverlay);
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::WritableOverlay);
    }

    // ---- Case-insensitive tests ----

    #[test]
    fn ci_gitignored_blocked_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\n");
        write(root, ".env", "SECRET=x");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new(".ENV"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new(".Env"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new(".eNv"), false), PathClass::Blocked);
    }

    #[test]
    fn ci_writable_overlay_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\n");
        write(root, ".shadowconfig", "[writable]\npatterns = [\".env\"]\n");
        write(root, ".env", "SECRET=x");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::WritableOverlay);
        assert_eq!(rs.classify(Path::new(".ENV"), false), PathClass::WritableOverlay);
        assert_eq!(rs.classify(Path::new(".Env"), false), PathClass::WritableOverlay);
    }

    #[test]
    fn ci_ignore_hides_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = [\".git\"]\n");
        mkdir(root, ".git");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".GIT"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".Git"), true), PathClass::Hidden);
    }

    #[test]
    fn ci_shadowconfig_hidden_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = []\n");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".shadowconfig"), false), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".SHADOWCONFIG"), false), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".ShadowConfig"), false), PathClass::Hidden);
    }

    #[test]
    fn ci_gitignore_file_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "*.log\n");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".gitignore"), false), PathClass::GitignoreFile);
        assert_eq!(rs.classify(Path::new(".GITIGNORE"), false), PathClass::GitignoreFile);
        assert_eq!(rs.classify(Path::new(".GitIgnore"), false), PathClass::GitignoreFile);
    }

    #[test]
    fn ci_glob_pattern_matches_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "*.LOG\n");
        write(root, "app.log", "");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new("app.log"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("APP.LOG"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("App.Log"), false), PathClass::Blocked);
    }

    #[test]
    fn cs_does_not_match_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\n");
        write(root, ".env", "SECRET=x");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new(".ENV"), false), PathClass::Passthrough);
        assert_eq!(rs.classify(Path::new(".Env"), false), PathClass::Passthrough);
    }

    #[test]
    fn ci_ignore_beats_writable_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\n");
        write(root, ".shadowconfig", "[ignore]\npatterns = [\".env\"]\n\n[writable]\npatterns = [\".env\"]\n");
        write(root, ".env", "SECRET=x");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".ENV"), false), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".Env"), false), PathClass::Hidden);
    }

    #[test]
    fn ci_nested_gitignore_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, "sub/.gitignore", "*.secret\n");
        write(root, "sub/data.secret", "");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new("sub/data.secret"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("sub/DATA.SECRET"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("SUB/data.secret"), false), PathClass::Blocked);
    }

    #[test]
    fn ci_parent_gitignore_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path();
        let root = parent.join("source");
        fs::create_dir(&root).unwrap();
        write(parent, ".gitignore", "*.secret\n");
        write(&root, "config.secret", "");

        let rs = RuleSet::load(&root, false).unwrap();
        assert_eq!(rs.classify(Path::new("config.secret"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("CONFIG.SECRET"), false), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("Config.Secret"), false), PathClass::Blocked);
    }

    #[test]
    fn ci_dir_only_pattern_with_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "build/\n");
        mkdir(root, "build");

        let rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new("build"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("BUILD"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("Build"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("BUILD"), false), PathClass::Passthrough);
    }

    // ---- folder_renames tests ----

    #[test]
    fn folder_renames_single_entry_builds_alias() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"A/B\", to = \"A/D\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.rename_aliases().get(Path::new("A/D")),
            Some(&PathBuf::from("A/B"))
        );
        assert_eq!(rs.rename_aliases().len(), 1);
    }

    #[test]
    fn folder_renames_chain_resolves_to_flat_map() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(
            root,
            ".shadowconfig",
            concat!(
                "folder_renames = [\n",
                "  { from = \"A\", to = \"B\", at = \"2026-05-04T14:00:00Z\" },\n",
                "  { from = \"B\", to = \"C\", at = \"2026-05-04T14:01:00Z\" },\n",
                "]\n",
            ),
        );

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.rename_aliases().get(Path::new("B")),
            Some(&PathBuf::from("A"))
        );
        assert_eq!(
            rs.rename_aliases().get(Path::new("C")),
            Some(&PathBuf::from("A"))
        );
        assert_eq!(rs.rename_aliases().len(), 2);
    }

    #[test]
    fn folder_renames_nested_shadowconfig_rejected() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = []\n");
        write(
            root,
            "sub/.shadowconfig",
            "folder_renames = [\n  { from = \"X\", to = \"Y\", at = \"2026-05-04T14:00:00Z\" },\n]\n",
        );
        mkdir(root, "sub");

        let err = RuleSet::load(root, true).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("folder_renames"),
            "expected error about folder_renames, got: {msg}"
        );
        assert!(
            msg.contains("root"),
            "expected mention of root .shadowconfig, got: {msg}"
        );
    }

    #[test]
    fn folder_renames_missing_field_is_noop() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = [\".git\"]\n");
        mkdir(root, ".git");

        let rs = RuleSet::load(root, true).unwrap();
        assert!(rs.rename_aliases().is_empty());
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
    }

    #[test]
    fn folder_renames_empty_list_is_noop() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "folder_renames = []\n");

        let rs = RuleSet::load(root, true).unwrap();
        assert!(rs.rename_aliases().is_empty());
    }

    #[test]
    fn folder_renames_preserves_existing_config_sections() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", ".env\n");
        // folder_renames must appear before section headers in TOML
        write(
            root,
            ".shadowconfig",
            concat!(
                "folder_renames = [\n",
                "  { from = \"old\", to = \"new\", at = \"2026-05-04T14:00:00Z\" },\n",
                "]\n\n",
                "[ignore]\npatterns = [\".git\"]\n\n",
                "[writable]\npatterns = [\".env\"]\n",
            ),
        );
        mkdir(root, ".git");
        write(root, ".env", "SECRET=x");

        let rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::WritableOverlay);
        assert_eq!(
            rs.rename_aliases().get(Path::new("new")),
            Some(&PathBuf::from("old"))
        );
    }
}

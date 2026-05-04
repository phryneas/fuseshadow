use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Seek, SeekFrom, Write as _};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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

fn build_alias_map(renames: &[FolderRename], case_sensitive: bool) -> HashMap<PathBuf, PathBuf> {
    let mut aliases: HashMap<PathBuf, PathBuf> = HashMap::new();
    for entry in renames {
        let raw_from = PathBuf::from(&entry.from);
        let raw_to = PathBuf::from(&entry.to);
        let from = if case_sensitive { raw_from } else { lower_path(&raw_from) };
        let to = if case_sensitive { raw_to } else { lower_path(&raw_to) };
        let original = aliases.get(&from).cloned().unwrap_or(from);
        aliases.insert(to, original);
    }
    aliases
}

fn utc_now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::gmtime_r(&secs, &mut tm) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

fn serialize_shadowconfig(config: &ShadowConfig) -> String {
    let mut out = String::new();

    if !config.folder_renames.is_empty() {
        out.push_str("# fuseshadow: directory renames detected during agent session.\n");
        out.push_str("# Review and update your .gitignore files, then remove entries below.\n");
        out.push_str("folder_renames = [\n");
        for entry in &config.folder_renames {
            out.push_str(&format!(
                "  {{ from = \"{}\", to = \"{}\", at = \"{}\" }},\n",
                entry.from, entry.to, entry.at
            ));
        }
        out.push_str("]\n");
    }

    if !config.ignore.patterns.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("[ignore]\n");
        out.push_str("patterns = [");
        for (i, p) in config.ignore.patterns.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push('"');
            out.push_str(p);
            out.push('"');
        }
        out.push_str("]\n");
    }

    if !config.writable.patterns.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("[writable]\n");
        out.push_str("patterns = [");
        for (i, p) in config.writable.patterns.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push('"');
            out.push_str(p);
            out.push('"');
        }
        out.push_str("]\n");
    }

    out
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
    io_root: Option<PathBuf>,
    gitignore_matchers: Vec<DirMatcher>,
    shadow_ignore_matchers: Vec<DirMatcher>,
    shadow_writable_matchers: Vec<DirMatcher>,
    rename_aliases: HashMap<PathBuf, PathBuf>,
    shadowconfig_mtime: Option<SystemTime>,
    shadowconfig_size: u64,
    known_rename_pairs: HashSet<(String, String)>,
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
        let mut known_rename_pairs = HashSet::new();

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
                    known_rename_pairs = config
                        .folder_renames
                        .iter()
                        .map(|r| (r.from.clone(), r.to.clone()))
                        .collect();
                    rename_aliases = build_alias_map(&config.folder_renames, case_sensitive);
                }

                if let Some(m) = DirMatcher::from_patterns(dir, &config.ignore.patterns, case_sensitive) {
                    shadow_ignore_matchers.push(m);
                }
                if let Some(m) = DirMatcher::from_patterns(dir, &config.writable.patterns, case_sensitive) {
                    shadow_writable_matchers.push(m);
                }
            }
        }

        let shadowconfig_meta = std::fs::metadata(source_root.join(SHADOWCONFIG_FILENAME)).ok();
        let shadowconfig_mtime = shadowconfig_meta.as_ref().and_then(|m| m.modified().ok());
        let shadowconfig_size = shadowconfig_meta.map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            source_root,
            match_root,
            case_sensitive,
            io_root: None,
            gitignore_matchers,
            shadow_ignore_matchers,
            shadow_writable_matchers,
            rename_aliases,
            shadowconfig_mtime,
            shadowconfig_size,
            known_rename_pairs,
        })
    }

    /// Classification priority (highest wins):
    /// 1. .shadowconfig → Hidden
    /// 2. [ignore] match → Hidden
    /// 3. [writable] match + gitignored → WritableOverlay
    /// 4. gitignored → Blocked
    /// 5. .gitignore → GitignoreFile
    /// 6. Otherwise → Passthrough
    pub fn classify(&mut self, rel_path: &Path, is_dir: bool) -> PathClass {
        self.check_shadowconfig_changes();
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
            .any(|m| m.matches(&match_path, is_dir))
            || self.is_gitignored_via_alias(&match_path, is_dir);

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

    fn is_gitignored_via_alias(&self, match_path: &Path, is_dir: bool) -> bool {
        if self.rename_aliases.is_empty() {
            return false;
        }
        if let Some(aliased) = self.aliased_match_path(match_path) {
            return self
                .gitignore_matchers
                .iter()
                .any(|m| m.matches(&aliased, is_dir));
        }
        false
    }

    fn aliased_match_path(&self, match_path: &Path) -> Option<PathBuf> {
        let rel = match_path.strip_prefix(&self.match_root).ok()?;
        for (to_path, from_path) in &self.rename_aliases {
            if let Ok(suffix) = rel.strip_prefix(to_path) {
                return Some(self.match_root.join(from_path.join(suffix)));
            }
        }
        None
    }

    pub fn rename_aliases(&self) -> &HashMap<PathBuf, PathBuf> {
        &self.rename_aliases
    }

    pub fn set_io_root(&mut self, root: PathBuf) {
        self.io_root = Some(root);
    }

    fn io_path(&self, rel: &Path) -> PathBuf {
        let root = self.io_root.as_ref().unwrap_or(&self.source_root);
        if rel.as_os_str().is_empty() {
            root.join(".")
        } else {
            root.join(rel)
        }
    }

    pub fn handle_directory_rename(&mut self, old_rel: &Path, new_rel: &Path) -> Result<()> {
        self.refresh_child_matchers(old_rel, new_rel);
        self.add_rename_alias(old_rel, new_rel);
        self.persist_rename(old_rel, new_rel)?;

        self.known_rename_pairs.insert((
            old_rel.to_string_lossy().to_string(),
            new_rel.to_string_lossy().to_string(),
        ));
        let config_path = self.io_path(Path::new(SHADOWCONFIG_FILENAME));
        let meta = std::fs::metadata(&config_path).ok();
        self.shadowconfig_mtime = meta.as_ref().and_then(|m| m.modified().ok());
        self.shadowconfig_size = meta.map(|m| m.len()).unwrap_or(0);

        Ok(())
    }

    fn refresh_child_matchers(&mut self, old_rel: &Path, new_rel: &Path) {
        let old_match_abs = if self.case_sensitive {
            self.source_root.join(old_rel)
        } else {
            self.match_root.join(lower_path(old_rel))
        };

        self.gitignore_matchers
            .retain(|m| !m.dir.starts_with(&old_match_abs));
        self.shadow_ignore_matchers
            .retain(|m| !m.dir.starts_with(&old_match_abs));
        self.shadow_writable_matchers
            .retain(|m| !m.dir.starts_with(&old_match_abs));

        let new_io_abs = self.io_path(new_rel);
        let new_src_abs = self.source_root.join(new_rel);

        for entry in walkdir::WalkDir::new(&new_io_abs)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = entry.file_name();
            let io_dir = entry.path().parent().unwrap_or(&new_io_abs);
            let rel_from_new = io_dir.strip_prefix(&new_io_abs).unwrap_or(Path::new(""));
            let src_dir = new_src_abs.join(rel_from_new);

            if name == GITIGNORE_FILENAME {
                if let Some(m) =
                    DirMatcher::from_gitignore_file(&src_dir, entry.path(), self.case_sensitive)
                {
                    self.gitignore_matchers.push(m);
                }
            } else if name == SHADOWCONFIG_FILENAME {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Ok(config) = toml::from_str::<ShadowConfig>(&content) {
                        if let Some(m) = DirMatcher::from_patterns(
                            &src_dir,
                            &config.ignore.patterns,
                            self.case_sensitive,
                        ) {
                            self.shadow_ignore_matchers.push(m);
                        }
                        if let Some(m) = DirMatcher::from_patterns(
                            &src_dir,
                            &config.writable.patterns,
                            self.case_sensitive,
                        ) {
                            self.shadow_writable_matchers.push(m);
                        }
                    }
                }
            }
        }
    }

    fn add_rename_alias(&mut self, old_rel: &Path, new_rel: &Path) {
        let from = if self.case_sensitive {
            old_rel.to_path_buf()
        } else {
            lower_path(old_rel)
        };
        let to = if self.case_sensitive {
            new_rel.to_path_buf()
        } else {
            lower_path(new_rel)
        };
        let original = self.rename_aliases.get(&from).cloned().unwrap_or(from);
        self.rename_aliases.insert(to, original);
    }

    fn persist_rename(&self, old_rel: &Path, new_rel: &Path) -> Result<()> {
        let config_path = self.io_path(Path::new(SHADOWCONFIG_FILENAME));

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&config_path)
            .with_context(|| format!("opening {}", config_path.display()))?;

        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            bail!("flock: {}", std::io::Error::last_os_error());
        }

        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let mut config: ShadowConfig = if content.trim().is_empty() {
            ShadowConfig::default()
        } else {
            toml::from_str(&content).with_context(|| "parsing root .shadowconfig")?
        };

        config.folder_renames.push(FolderRename {
            from: old_rel.to_string_lossy().to_string(),
            to: new_rel.to_string_lossy().to_string(),
            at: utc_now_iso8601(),
        });

        let output = serialize_shadowconfig(&config);

        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(output.as_bytes())?;

        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };

        Ok(())
    }

    fn check_shadowconfig_changes(&mut self) {
        let config_path = self.io_path(Path::new(SHADOWCONFIG_FILENAME));

        let meta = std::fs::metadata(&config_path).ok();
        let current_mtime = meta.as_ref().and_then(|m| m.modified().ok());
        let current_size = meta.map(|m| m.len()).unwrap_or(0);

        if current_mtime == self.shadowconfig_mtime && current_size == self.shadowconfig_size {
            return;
        }

        self.shadowconfig_mtime = current_mtime;
        self.shadowconfig_size = current_size;

        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => {
                self.rename_aliases.clear();
                self.known_rename_pairs.clear();
                return;
            }
        };

        let config: ShadowConfig = match toml::from_str(&content) {
            Ok(c) => c,
            Err(_) => return,
        };

        self.rename_aliases = build_alias_map(&config.folder_renames, self.case_sensitive);

        let new_pairs: HashSet<(String, String)> = config
            .folder_renames
            .iter()
            .map(|r| (r.from.clone(), r.to.clone()))
            .collect();

        for (from, to) in &new_pairs {
            if !self.known_rename_pairs.contains(&(from.clone(), to.clone())) {
                self.refresh_child_matchers_for_external(
                    &PathBuf::from(from),
                    &PathBuf::from(to),
                );
            }
        }

        self.known_rename_pairs = new_pairs;
    }

    fn refresh_child_matchers_for_external(&mut self, old_rel: &Path, new_rel: &Path) {
        let old_match_abs = if self.case_sensitive {
            self.source_root.join(old_rel)
        } else {
            self.match_root.join(lower_path(old_rel))
        };
        let new_match_abs = if self.case_sensitive {
            self.source_root.join(new_rel)
        } else {
            self.match_root.join(lower_path(new_rel))
        };

        let should_drop =
            |dir: &Path| dir.starts_with(&old_match_abs) || dir.starts_with(&new_match_abs);
        self.gitignore_matchers.retain(|m| !should_drop(&m.dir));
        self.shadow_ignore_matchers
            .retain(|m| !should_drop(&m.dir));
        self.shadow_writable_matchers
            .retain(|m| !should_drop(&m.dir));

        let new_io_abs = self.io_path(new_rel);
        let new_src_abs = self.source_root.join(new_rel);

        for entry in walkdir::WalkDir::new(&new_io_abs)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = entry.file_name();
            let io_dir = entry.path().parent().unwrap_or(&new_io_abs);
            let rel_from_new = io_dir.strip_prefix(&new_io_abs).unwrap_or(Path::new(""));
            let src_dir = new_src_abs.join(rel_from_new);

            if name == GITIGNORE_FILENAME {
                if let Some(m) =
                    DirMatcher::from_gitignore_file(&src_dir, entry.path(), self.case_sensitive)
                {
                    self.gitignore_matchers.push(m);
                }
            } else if name == SHADOWCONFIG_FILENAME {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Ok(config) = toml::from_str::<ShadowConfig>(&content) {
                        if let Some(m) = DirMatcher::from_patterns(
                            &src_dir,
                            &config.ignore.patterns,
                            self.case_sensitive,
                        ) {
                            self.shadow_ignore_matchers.push(m);
                        }
                        if let Some(m) = DirMatcher::from_patterns(
                            &src_dir,
                            &config.writable.patterns,
                            self.case_sensitive,
                        ) {
                            self.shadow_writable_matchers.push(m);
                        }
                    }
                }
            }
        }
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(&root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::Hidden);
    }

    #[test]
    fn shadowconfig_itself_should_always_be_hidden() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = []\n");

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, false).unwrap();
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

        let mut rs = RuleSet::load(root, false).unwrap();
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

        let mut rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".GIT"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".Git"), true), PathClass::Hidden);
    }

    #[test]
    fn ci_shadowconfig_hidden_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "[ignore]\npatterns = []\n");

        let mut rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".shadowconfig"), false), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".SHADOWCONFIG"), false), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".ShadowConfig"), false), PathClass::Hidden);
    }

    #[test]
    fn ci_gitignore_file_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "*.log\n");

        let mut rs = RuleSet::load(root, false).unwrap();
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

        let mut rs = RuleSet::load(root, false).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new(".ENV"), false), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".Env"), false), PathClass::Hidden);
    }

    #[test]
    fn ci_nested_gitignore_via_alternate_case() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, "sub/.gitignore", "*.secret\n");
        write(root, "sub/data.secret", "");

        let mut rs = RuleSet::load(root, false).unwrap();
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

        let mut rs = RuleSet::load(&root, false).unwrap();
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

        let mut rs = RuleSet::load(root, false).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
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

        let mut rs = RuleSet::load(root, true).unwrap();
        assert!(rs.rename_aliases().is_empty());
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
    }

    #[test]
    fn folder_renames_empty_list_is_noop() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".shadowconfig", "folder_renames = []\n");

        let mut rs = RuleSet::load(root, true).unwrap();
        assert!(rs.rename_aliases().is_empty());
    }

    // ---- Alias-aware classification tests (Phase 3) ----

    #[test]
    fn alias_blocks_renamed_dir_via_parent_gitignore() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Root .gitignore blocks "creds/" directory
        write(root, ".gitignore", "creds/\n");
        // On disk, "creds" was renamed to "secrets"
        mkdir(root, "secrets");
        write(root, "secrets/api.key", "secret-key");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
        assert_eq!(
            rs.classify(Path::new("secrets/api.key"), false),
            PathClass::Blocked
        );
    }

    #[test]
    fn alias_original_path_still_blocked() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        // Both old and new dirs exist (edge case)
        mkdir(root, "creds");
        write(root, "creds/api.key", "secret-key");
        mkdir(root, "secrets");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        // Original path is blocked by direct gitignore match (no alias needed)
        assert_eq!(rs.classify(Path::new("creds"), true), PathClass::Blocked);
        assert_eq!(
            rs.classify(Path::new("creds/api.key"), false),
            PathClass::Blocked
        );
    }

    #[test]
    fn alias_chain_blocks_final_renamed_path() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "original/\n");
        mkdir(root, "final_name");
        write(root, "final_name/secret.txt", "");
        write(
            root,
            ".shadowconfig",
            concat!(
                "folder_renames = [\n",
                "  { from = \"original\", to = \"intermediate\", at = \"2026-05-04T14:00:00Z\" },\n",
                "  { from = \"intermediate\", to = \"final_name\", at = \"2026-05-04T14:01:00Z\" },\n",
                "]\n",
            ),
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        // final_name → original via chain; should be blocked
        assert_eq!(
            rs.classify(Path::new("final_name"), true),
            PathClass::Blocked
        );
        assert_eq!(
            rs.classify(Path::new("final_name/secret.txt"), false),
            PathClass::Blocked
        );
        // intermediate → original; also blocked
        assert_eq!(
            rs.classify(Path::new("intermediate"), true),
            PathClass::Blocked
        );
    }

    #[test]
    fn alias_unrelated_paths_unaffected() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "secrets");
        mkdir(root, "src");
        write(root, "src/main.rs", "fn main() {}");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("src"), true),
            PathClass::Passthrough
        );
        assert_eq!(
            rs.classify(Path::new("src/main.rs"), false),
            PathClass::Passthrough
        );
    }

    #[test]
    fn ci_alias_blocks_renamed_path() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "Creds/\n");
        mkdir(root, "secrets");
        write(root, "secrets/api.key", "");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"Creds\", to = \"Secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, false).unwrap();
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("SECRETS"), true), PathClass::Blocked);
        assert_eq!(
            rs.classify(Path::new("Secrets/api.key"), false),
            PathClass::Blocked
        );
    }

    #[test]
    fn alias_nested_gitignore_pattern_blocks_via_parent() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Pattern in root .gitignore references a path under a directory
        write(root, ".gitignore", "config/secrets/*.key\n");
        // "config" was renamed to "settings" on disk
        mkdir(root, "settings/secrets");
        write(root, "settings/secrets/api.key", "");
        write(root, "settings/secrets/readme.txt", "");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"config\", to = \"settings\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        // *.key under the renamed path should be blocked
        assert_eq!(
            rs.classify(Path::new("settings/secrets/api.key"), false),
            PathClass::Blocked
        );
        // Non-matching files should still be passthrough
        assert_eq!(
            rs.classify(Path::new("settings/secrets/readme.txt"), false),
            PathClass::Passthrough
        );
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

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new(".git"), true), PathClass::Hidden);
        assert_eq!(rs.classify(Path::new(".env"), false), PathClass::WritableOverlay);
        assert_eq!(
            rs.rename_aliases().get(Path::new("new")),
            Some(&PathBuf::from("old"))
        );
    }

    // ---- Phase 4: Runtime rename tracking + persistence tests ----

    #[test]
    fn handle_rename_adds_alias_and_blocks_new_path() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "creds");
        write(root, "creds/secret.key", "secret");

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new("creds"), true), PathClass::Blocked);

        fs::rename(root.join("creds"), root.join("secrets")).unwrap();
        rs.handle_directory_rename(Path::new("creds"), Path::new("secrets"))
            .unwrap();

        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
        assert_eq!(
            rs.classify(Path::new("secrets/secret.key"), false),
            PathClass::Blocked
        );
    }

    #[test]
    fn handle_rename_refreshes_child_gitignore_matchers() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        mkdir(root, "mydir");
        write(root, "mydir/.gitignore", "*.secret\n");
        write(root, "mydir/data.secret", "sensitive");
        write(root, "mydir/code.rs", "fn main() {}");

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(
            rs.classify(Path::new("mydir/data.secret"), false),
            PathClass::Blocked
        );

        fs::rename(root.join("mydir"), root.join("renamed")).unwrap();
        rs.handle_directory_rename(Path::new("mydir"), Path::new("renamed"))
            .unwrap();

        assert_eq!(
            rs.classify(Path::new("renamed/data.secret"), false),
            PathClass::Blocked
        );
        assert_eq!(
            rs.classify(Path::new("renamed/code.rs"), false),
            PathClass::Passthrough
        );
    }

    #[test]
    fn handle_rename_persists_to_shadowconfig() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "creds");

        let mut rs = RuleSet::load(root, true).unwrap();
        fs::rename(root.join("creds"), root.join("secrets")).unwrap();
        rs.handle_directory_rename(Path::new("creds"), Path::new("secrets"))
            .unwrap();

        let content = fs::read_to_string(root.join(".shadowconfig")).unwrap();
        assert!(content.contains("folder_renames"));
        assert!(content.contains("creds"));
        assert!(content.contains("secrets"));
        assert!(content.contains("T"));
        assert!(content.contains("Z"));
    }

    #[test]
    fn handle_rename_creates_shadowconfig_if_missing() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "creds");

        let mut rs = RuleSet::load(root, true).unwrap();
        assert!(!root.join(".shadowconfig").exists());

        fs::rename(root.join("creds"), root.join("secrets")).unwrap();
        rs.handle_directory_rename(Path::new("creds"), Path::new("secrets"))
            .unwrap();

        assert!(root.join(".shadowconfig").exists());
        let content = fs::read_to_string(root.join(".shadowconfig")).unwrap();
        assert!(content.contains("folder_renames"));
    }

    #[test]
    fn handle_rename_preserves_existing_config() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n.env\n");
        write(
            root,
            ".shadowconfig",
            "[ignore]\npatterns = [\".git\"]\n\n[writable]\npatterns = [\".env\"]\n",
        );
        mkdir(root, ".git");
        write(root, ".env", "SECRET=x");
        mkdir(root, "creds");

        let mut rs = RuleSet::load(root, true).unwrap();
        fs::rename(root.join("creds"), root.join("secrets")).unwrap();
        rs.handle_directory_rename(Path::new("creds"), Path::new("secrets"))
            .unwrap();

        let content = fs::read_to_string(root.join(".shadowconfig")).unwrap();
        assert!(content.contains("folder_renames"));
        assert!(content.contains("[ignore]"));
        assert!(content.contains(".git"));
        assert!(content.contains("[writable]"));
        assert!(content.contains(".env"));

        // Verify the rewritten config still works when reloaded
        let mut new_rs = RuleSet::load(root, true).unwrap();
        assert_eq!(new_rs.classify(Path::new(".git"), true), PathClass::Hidden);
        assert_eq!(
            new_rs.classify(Path::new(".env"), false),
            PathClass::WritableOverlay
        );
        assert_eq!(
            new_rs.rename_aliases().get(Path::new("secrets")),
            Some(&PathBuf::from("creds"))
        );
    }

    #[test]
    fn handle_rename_uses_flock_for_concurrent_access() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "a/\nb/\n");
        mkdir(root, "a");
        mkdir(root, "b");

        let mut rs = RuleSet::load(root, true).unwrap();

        fs::rename(root.join("a"), root.join("x")).unwrap();
        rs.handle_directory_rename(Path::new("a"), Path::new("x"))
            .unwrap();

        fs::rename(root.join("b"), root.join("y")).unwrap();
        rs.handle_directory_rename(Path::new("b"), Path::new("y"))
            .unwrap();

        // Both renames should be persisted
        let content = fs::read_to_string(root.join(".shadowconfig")).unwrap();
        assert!(content.contains("\"a\""));
        assert!(content.contains("\"x\""));
        assert!(content.contains("\"b\""));
        assert!(content.contains("\"y\""));

        // Both aliases should work
        assert_eq!(rs.classify(Path::new("x"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("y"), true), PathClass::Blocked);
    }

    // ---- Phase 5: Live mtime monitoring tests ----

    #[test]
    fn mtime_monitor_removes_alias_on_external_deletion() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "secrets");
        write(root, "secrets/api.key", "secret-key");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);

        // Externally remove the folder_renames entry
        fs::write(root.join(".shadowconfig"), "").unwrap();

        // Next classify should detect the change and drop the alias
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Passthrough);
        assert!(rs.rename_aliases().is_empty());
    }

    #[test]
    fn mtime_monitor_adds_alias_on_external_addition() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "secrets");
        write(root, "secrets/api.key", "secret-key");

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Passthrough);

        // Externally add a folder_renames entry
        fs::write(
            root.join(".shadowconfig"),
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        )
        .unwrap();

        // Next classify should detect the change and add the alias
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
        assert_eq!(
            rs.classify(Path::new("secrets/api.key"), false),
            PathClass::Blocked
        );
    }

    #[test]
    fn mtime_monitor_refreshes_child_matchers_for_new_entry() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // A directory was renamed externally before we mounted, but no folder_renames existed at mount time
        // The child .gitignore matchers were loaded from "renamed/" at mount time
        mkdir(root, "renamed");
        write(root, "renamed/.gitignore", "*.secret\n");
        write(root, "renamed/data.secret", "sensitive");
        write(root, "renamed/code.rs", "fn main() {}");

        let mut rs = RuleSet::load(root, true).unwrap();
        // Child matchers from renamed/.gitignore work directly
        assert_eq!(
            rs.classify(Path::new("renamed/data.secret"), false),
            PathClass::Blocked
        );

        // Externally add a folder_renames entry (simulating another instance)
        fs::write(
            root.join(".shadowconfig"),
            "folder_renames = [\n  { from = \"original\", to = \"renamed\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        )
        .unwrap();

        // After mtime refresh, child matchers should be re-read and still work
        assert_eq!(
            rs.classify(Path::new("renamed/data.secret"), false),
            PathClass::Blocked
        );
        assert_eq!(
            rs.classify(Path::new("renamed/code.rs"), false),
            PathClass::Passthrough
        );
    }

    #[test]
    fn mtime_monitor_no_reparse_when_unchanged() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "secrets");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        // Multiple classify calls without file change should be consistent
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
    }

    #[test]
    fn mtime_monitor_handles_shadowconfig_deletion() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\n");
        mkdir(root, "secrets");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:32:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);

        // Delete the .shadowconfig entirely
        fs::remove_file(root.join(".shadowconfig")).unwrap();

        // Alias should be gone
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Passthrough);
    }

    #[test]
    fn mtime_monitor_new_entry_among_existing_only_refreshes_new() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write(root, ".gitignore", "creds/\ndata/\n");
        mkdir(root, "secrets");
        mkdir(root, "info");
        write(root, "info/.gitignore", "*.key\n");
        write(root, "info/api.key", "secret");
        write(
            root,
            ".shadowconfig",
            "folder_renames = [\n  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:00:00Z\" },\n]\n",
        );

        let mut rs = RuleSet::load(root, true).unwrap();
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);

        // Externally add a second entry while keeping the first
        fs::write(
            root.join(".shadowconfig"),
            concat!(
                "folder_renames = [\n",
                "  { from = \"creds\", to = \"secrets\", at = \"2026-05-04T14:00:00Z\" },\n",
                "  { from = \"data\", to = \"info\", at = \"2026-05-04T14:01:00Z\" },\n",
                "]\n",
            ),
        )
        .unwrap();

        // Both aliases should work
        assert_eq!(rs.classify(Path::new("secrets"), true), PathClass::Blocked);
        assert_eq!(rs.classify(Path::new("info"), true), PathClass::Blocked);
        // Child matchers from info/ should still work after re-read
        assert_eq!(
            rs.classify(Path::new("info/api.key"), false),
            PathClass::Blocked
        );
    }
}

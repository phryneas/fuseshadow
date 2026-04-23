use std::path::{Path, PathBuf};

use anyhow::Result;
use tempfile::TempDir;

pub struct Overlay {
    temp_dir: TempDir,
}

impl Overlay {
    pub fn new() -> Result<Self> {
        Ok(Self {
            temp_dir: TempDir::new()?,
        })
    }

    /// Returns the path inside the temp overlay directory for `rel_path`.
    /// The file need not exist yet.
    pub fn resolve(&self, rel_path: &Path) -> PathBuf {
        self.temp_dir.path().join(rel_path)
    }

    /// Returns true if `rel_path` has been written to the overlay.
    pub fn exists(&self, rel_path: &Path) -> bool {
        self.resolve(rel_path).exists()
    }

    pub fn base_path(&self) -> &Path {
        self.temp_dir.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn resolve_should_return_path_inside_temp_dir() {
        let overlay = Overlay::new().unwrap();
        let p = overlay.resolve(Path::new("sub/file.txt"));
        assert!(p.starts_with(overlay.base_path()));
        assert!(p.ends_with("sub/file.txt"));
    }

    #[test]
    fn exists_should_return_false_before_file_is_written() {
        let overlay = Overlay::new().unwrap();
        assert!(!overlay.exists(Path::new("file.txt")));
    }

    #[test]
    fn exists_should_return_true_after_file_is_written() {
        let overlay = Overlay::new().unwrap();
        let path = overlay.resolve(Path::new("file.txt"));
        fs::write(&path, "content").unwrap();
        assert!(overlay.exists(Path::new("file.txt")));
    }
}

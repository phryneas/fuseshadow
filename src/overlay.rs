use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tempfile::TempDir;

pub struct Overlay {
    temp_dir: TempDir,
    overlay_fd: File,
}

impl Overlay {
    pub fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let overlay_fd = File::open(temp_dir.path())?;
        Ok(Self {
            temp_dir,
            overlay_fd,
        })
    }

    pub fn fd_file(&self) -> &File {
        &self.overlay_fd
    }

    /// Returns the path inside the temp overlay directory for `rel_path`.
    /// The file need not exist yet.
    pub fn resolve(&self, rel_path: &Path) -> PathBuf {
        self.temp_dir.path().join(rel_path)
    }

    #[cfg(test)]
    pub fn base_path(&self) -> &Path {
        self.temp_dir.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_should_return_path_inside_temp_dir() {
        let overlay = Overlay::new().unwrap();
        let p = overlay.resolve(Path::new("sub/file.txt"));
        assert!(p.starts_with(overlay.base_path()));
        assert!(p.ends_with("sub/file.txt"));
    }

}

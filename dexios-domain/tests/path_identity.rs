use std::fs;
use std::path::{Path, PathBuf};

struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Self { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[test]
fn path_identity_harness_creates_disposable_real_fs_dir() {
    let test_dir = TestDir::new("path-identity");
    let input = test_dir.path().join("input.txt");

    fs::write(&input, b"path identity fixture").unwrap();

    // D-17 requires real filesystem evidence for aliasing and identity edges.
    let temp_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(test_dir.path().starts_with(&temp_root));
    assert_eq!(fs::read(&input).unwrap(), b"path identity fixture");
}

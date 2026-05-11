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
fn cleanup_receipt_harness_uses_disposable_targets() {
    let test_dir = TestDir::new("cleanup-receipts");
    let committed_output = test_dir.path().join("committed.dexios");
    let cleanup_target = test_dir.path().join("source.txt");

    fs::write(&committed_output, b"committed output").unwrap();
    fs::write(&cleanup_target, b"cleanup target").unwrap();
    fs::remove_file(&cleanup_target).unwrap();

    // D-17 requires delete-after-success tests to use real cleanup targets.
    assert_eq!(fs::read(&committed_output).unwrap(), b"committed output");
    assert!(!cleanup_target.exists());
}

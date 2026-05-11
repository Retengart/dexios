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
fn transaction_harness_creates_final_and_staged_paths() {
    let test_dir = TestDir::new("transactions");
    let final_output = test_dir.path().join("output.dexios");
    let staged_output = test_dir.path().join("output.dexios.staged");

    fs::write(&final_output, b"existing output").unwrap();
    fs::write(&staged_output, b"candidate output").unwrap();

    // D-17 requires overwrite-preservation tests to use real filesystem paths.
    assert_eq!(fs::read(&final_output).unwrap(), b"existing output");
    assert_eq!(fs::read(&staged_output).unwrap(), b"candidate output");
}

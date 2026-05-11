use std::fs;
use std::path::{Path, PathBuf};

use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};

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

#[test]
fn failure_hooks_select_transaction_failure_points() {
    let points = [
        FailurePoint::Write,
        FailurePoint::Flush,
        FailurePoint::Sync,
        FailurePoint::Persist,
    ];

    for selected in points {
        let hooks = FailureHooks::fail_on(selected);

        for point in points {
            let result = hooks.check(point);
            if point == selected {
                let error = result.expect_err("selected point should fail");
                assert_eq!(error.point(), selected);
            } else {
                assert!(result.is_ok(), "non-selected point should pass");
            }
        }
    }

    let hooks = FailureHooks::none();
    for point in points {
        assert!(hooks.check(point).is_ok());
    }
}

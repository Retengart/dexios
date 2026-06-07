use std::fs;
use std::path::PathBuf;

pub(crate) fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = fs::canonicalize(dir.path()).expect("canonical temp dir");
    (dir, path)
}

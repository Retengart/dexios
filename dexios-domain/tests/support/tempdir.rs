use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    canonical_tempdir_with_prefix("dexios-domain-")
}

pub(crate) fn canonical_tempdir_with_prefix(prefix: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("temp dir");
    let path = fs::canonicalize(dir.path()).expect("canonical temp dir");
    (dir, path)
}

pub(crate) struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

pub(crate) type DomainTestDir = TestDir;

impl TestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        let (dir, path) = canonical_tempdir_with_prefix(&format!("dexios-domain-{prefix}-"));
        Self { _dir: dir, path }
    }

    pub(crate) fn new_under_workdir<P>(workdir: P, prefix: &str) -> Self
    where
        P: AsRef<Path>,
    {
        fs::create_dir_all(workdir.as_ref()).expect("test workdir");
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-domain-{prefix}-"))
            .tempdir_in(workdir)
            .expect("temp dir in workdir");
        let path = fs::canonicalize(dir.path()).expect("canonical temp dir");
        Self { _dir: dir, path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

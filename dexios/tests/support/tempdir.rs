use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEST_NAME: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .expect("temp dir");
        let path = fs::canonicalize(dir.path()).expect("canonical temp dir");
        Self { _dir: dir, path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) struct KeyTestDir {
    inner: TestDir,
}

impl KeyTestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        Self {
            inner: TestDir::new(&format!("key-{prefix}")),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        self.inner.path()
    }
}

pub(crate) struct KeyForceTestDir {
    inner: TestDir,
}

impl KeyForceTestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        Self {
            inner: TestDir::new(&format!("key-force-{prefix}")),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        self.inner.path()
    }
}

pub(crate) fn unique_file_name(prefix: &str, extension: &str) -> String {
    let seq = NEXT_TEST_NAME.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    format!("{prefix}-{seq}-{nanos}.{extension}")
}

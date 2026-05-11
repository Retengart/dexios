use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PASSWORD: &str = "correct-password";
static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let seq = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dexios-{prefix}-{}-{seq}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_cli(current_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", PASSWORD)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn encrypt_rejects_same_file_alias_before_opening_output() {
    let test_dir = TestDir::new("encrypt-same-file-alias");
    let plain = test_dir.path().join("plain.txt");
    let sentinel = b"do not truncate";
    fs::write(&plain, sentinel).unwrap();

    let output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "./plain.txt"],
    );

    assert!(
        !output.status.success(),
        "encrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&plain).unwrap(), sentinel.as_slice());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Unsafe path:"),
        "unsafe path failures must be routed through map_encrypt_error: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn encrypt_force_replaces_existing_output_at_commit() {
    let test_dir = TestDir::new("encrypt-force-replace");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    fs::write(&plain, b"new plaintext").unwrap();
    fs::write(&encrypted, b"old ciphertext sentinel").unwrap();

    let output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );

    assert!(
        output.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let encrypted_bytes = fs::read(&encrypted).unwrap();
    assert_ne!(encrypted_bytes, b"old ciphertext sentinel");
    assert!(
        encrypted_bytes.starts_with(b"DXIO"),
        "replaced output should be a Dexios encrypted artifact"
    );
}

#[test]
fn encrypt_transaction_commit_failures_use_typed_mapping() {
    let test_dir = TestDir::new("encrypt-commit-failure");
    let plain = test_dir.path().join("plain.txt");
    let output_dir = test_dir.path().join("output-dir");
    fs::write(&plain, b"new plaintext").unwrap();
    fs::create_dir(&output_dir).unwrap();

    let output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "output-dir"],
    );

    assert!(
        !output.status.success(),
        "encrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Unable to commit encrypted output"),
        "transaction failures must be routed through map_encrypt_error: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_dir.is_dir());
}

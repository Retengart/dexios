use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PASSWORD: &str = "12345678";
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
fn storage_transaction_cli_harness_runs_in_disposable_real_fs_dir() {
    let test_dir = TestDir::new("storage-transactions-cli");
    let fixture = test_dir.path().join("fixture.txt");
    fs::write(&fixture, b"cli fixture").unwrap();

    let output = run_cli(test_dir.path(), &["--help"]);

    assert!(
        output.status.success(),
        "dexios --help failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.exists());
}

#[test]
fn encrypt_force_replaces_existing_output_after_success() {
    let test_dir = TestDir::new("encrypt-force-transaction");
    let plain = test_dir.path().join("plain.txt");
    let output_path = test_dir.path().join("plain.enc");
    fs::write(&plain, b"transactional plaintext").unwrap();
    fs::write(&output_path, b"existing encrypted output").unwrap();

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
    assert_eq!(fs::read(&plain).unwrap(), b"transactional plaintext");
    assert_ne!(
        fs::read(&output_path).unwrap(),
        b"existing encrypted output"
    );
}

#[test]
fn decrypt_wrong_key_failure_preserves_existing_output() {
    let test_dir = TestDir::new("decrypt-wrong-key-transaction");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output_path = test_dir.path().join("plain.out");
    fs::write(&plain, b"top secret").unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    assert!(encrypted.exists());

    fs::write(&output_path, b"existing output").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    let decrypt_output = command
        .current_dir(test_dir.path())
        .env("DEXIOS_KEY", "wrong-password")
        .args(["decrypt", "--force", "plain.enc", "plain.out"])
        .output()
        .unwrap();

    assert!(
        !decrypt_output.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_output.stdout),
        String::from_utf8_lossy(&decrypt_output.stderr)
    );
    assert_eq!(fs::read(&output_path).unwrap(), b"existing output");
}

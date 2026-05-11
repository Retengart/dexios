use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CORRECT_PASSWORD: &str = "correct-password";
const WRONG_PASSWORD: &str = "wrong-password";
const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
const SUBCOMMANDS_SOURCE: &str = include_str!("../src/subcommands.rs");
const ENCRYPT_SOURCE: &str = include_str!("../src/subcommands/encrypt.rs");
const DECRYPT_SOURCE: &str = include_str!("../src/subcommands/decrypt.rs");
const HEADER_SOURCE: &str = include_str!("../src/subcommands/header.rs");
const KEY_SOURCE: &str = include_str!("../src/subcommands/key.rs");
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

fn run_cli(current_dir: &Path, key: &str, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", key)
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn encrypt_fixture(test_dir: &TestDir) {
    fs::write(test_dir.path().join("plain.txt"), b"top secret").unwrap();
    let output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );

    assert!(
        output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
}

fn write_legacy_header(path: &Path) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(&[0xDE, 0x05]).unwrap();
    file.write_all(&[7u8; 126]).unwrap();
    file.flush().unwrap();
}

fn write_malformed_v1_header(path: &Path) {
    let mut bytes = [0u8; 416];
    bytes[0..4].copy_from_slice(b"DXIO");
    bytes[4..6].copy_from_slice(&[0x00, 0x01]);
    bytes[7] = 1;
    fs::write(path, bytes).unwrap();
}

#[test]
fn cli_workflow_errors_are_routed_through_mapping_helpers() {
    assert!(SUBCOMMANDS_SOURCE.contains("pub mod errors;"));
    assert!(ERRORS_SOURCE.contains("map_encrypt_error"));
    assert!(ERRORS_SOURCE.contains("map_decrypt_error"));
    assert!(ERRORS_SOURCE.contains("map_header_error"));
    assert!(ERRORS_SOURCE.contains("map_key_error"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::TransactionCommitFailure"));
    assert!(ENCRYPT_SOURCE.contains("map_encrypt_error"));
    assert!(DECRYPT_SOURCE.contains("map_decrypt_error"));
    assert!(HEADER_SOURCE.contains("map_header_error"));
    assert!(KEY_SOURCE.contains("map_key_error"));
    assert!(!ERRORS_SOURCE.contains("to_string()"));
    assert!(!ERRORS_SOURCE.contains("contains("));
}

#[test]
fn malformed_and_unsupported_headers_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-header");
    let malformed = test_dir.path().join("malformed.enc");
    let legacy = test_dir.path().join("legacy.hdr");
    write_malformed_v1_header(&malformed);
    write_legacy_header(&legacy);

    let malformed_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "details", "malformed.enc"],
    );
    assert!(!malformed_output.status.success());
    let malformed_stderr = stderr(&malformed_output);
    assert!(
        malformed_stderr.contains("Malformed Dexios V1 header"),
        "stderr did not expose the malformed header class: {malformed_stderr}"
    );

    let legacy_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "details", "legacy.hdr"],
    );
    assert!(!legacy_output.status.success());
    let legacy_stderr = stderr(&legacy_output);
    assert!(
        legacy_stderr.contains("Unsupported Dexios format"),
        "stderr did not expose the unsupported format class: {legacy_stderr}"
    );
}

#[test]
fn unsafe_path_and_transaction_errors_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-path-transaction");
    fs::write(test_dir.path().join("plain.txt"), b"do not truncate").unwrap();

    let alias_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "./plain.txt"],
    );
    assert!(!alias_output.status.success());
    let alias_stderr = stderr(&alias_output);
    assert!(
        alias_stderr.contains("Unsafe path"),
        "stderr did not expose the unsafe path class: {alias_stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("plain.txt")).unwrap(),
        b"do not truncate"
    );

    fs::create_dir(test_dir.path().join("out-dir")).unwrap();
    let transaction_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "out-dir"],
    );
    assert!(!transaction_output.status.success());
    let transaction_stderr = stderr(&transaction_output);
    assert!(
        transaction_stderr.contains("commit"),
        "stderr did not expose the transaction failure class: {transaction_stderr}"
    );
}

#[test]
fn incorrect_key_and_unsupported_workflow_messages_stay_terse() {
    let test_dir = TestDir::new("workflow-error-key");
    encrypt_fixture(&test_dir);

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["decrypt", "--force", "plain.enc", "plain.out"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    assert!(
        wrong_key_stderr.contains("Authentication failed"),
        "stderr did not expose the terse authentication class: {wrong_key_stderr}"
    );
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));

    fs::write(test_dir.path().join("old.key"), CORRECT_PASSWORD).unwrap();
    let add_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "add", "--keyfile-old", "old.key", "plain.enc"],
    );
    assert!(!add_output.status.success());
    let add_stderr = stderr(&add_output);
    assert!(
        add_stderr.contains("Cannot add a V1 keyslot"),
        "stderr did not expose the unsupported workflow class: {add_stderr}"
    );
    assert!(!add_stderr.contains(CORRECT_PASSWORD));
}

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CORRECT_PASSWORD: &str = "correct-password";
const WRONG_PASSWORD: &str = "wrong-password";
const DECRYPT_SOURCE: &str = include_str!("../src/subcommands/decrypt.rs");
const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
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

#[test]
fn decrypt_wrong_key_preserves_existing_output() {
    let test_dir = TestDir::new("decrypt-wrong-key-preserves-output");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output_path = test_dir.path().join("plain.out");
    let sentinel = b"existing output must survive";
    fs::write(&plain, b"top secret").unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    assert!(encrypted.exists());

    fs::write(&output_path, sentinel).unwrap();

    let decrypt_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["decrypt", "--force", "plain.enc", "plain.out"],
    );

    assert!(
        !decrypt_output.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_output.stdout),
        String::from_utf8_lossy(&decrypt_output.stderr)
    );
    assert!(
        stderr(&decrypt_output).contains("Authentication failed"),
        "wrong-key stderr should use terse typed mapping: {}",
        stderr(&decrypt_output)
    );
    assert_eq!(fs::read(&output_path).unwrap(), sentinel.as_slice());
}

#[test]
fn decrypt_with_detached_header_round_trips() {
    let test_dir = TestDir::new("decrypt-detached-header");
    fs::write(test_dir.path().join("plain.txt"), b"detached secret").unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "encrypt",
            "--force",
            "--header",
            "plain.hdr",
            "plain.txt",
            "plain.enc",
        ],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt detached fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );

    let decrypt_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "decrypt",
            "--force",
            "--header",
            "plain.hdr",
            "plain.enc",
            "plain.out",
        ],
    );
    assert!(
        decrypt_output.status.success(),
        "decrypt detached fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_output.stdout),
        String::from_utf8_lossy(&decrypt_output.stderr)
    );

    assert_eq!(fs::read(test_dir.path().join("plain.out")).unwrap(), b"detached secret");
}

#[test]
fn decrypt_malformed_and_legacy_formats_use_typed_mapping() {
    let test_dir = TestDir::new("decrypt-format-mapping");
    fs::write(test_dir.path().join("malformed.enc"), b"DXIO\x00\x01short").unwrap();
    fs::write(test_dir.path().join("legacy.enc"), [0xDE, 0x01, 0, 0, 0, 0]).unwrap();

    let malformed_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["decrypt", "--force", "malformed.enc", "malformed.out"],
    );
    assert!(
        !malformed_output.status.success(),
        "malformed decrypt unexpectedly succeeded"
    );
    assert!(
        stderr(&malformed_output).contains("Malformed Dexios encrypted data"),
        "malformed stderr should use map_decrypt_error: {}",
        stderr(&malformed_output)
    );

    let legacy_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["decrypt", "--force", "legacy.enc", "legacy.out"],
    );
    assert!(
        !legacy_output.status.success(),
        "legacy decrypt unexpectedly succeeded"
    );
    assert!(
        stderr(&legacy_output).contains("Unsupported Dexios format"),
        "legacy stderr should use map_decrypt_error: {}",
        stderr(&legacy_output)
    );
}

#[test]
fn decrypt_cli_source_uses_checked_intent_and_typed_mapping() {
    assert!(
        ERRORS_SOURCE.contains("map_decrypt_error"),
        "CLI error helpers must keep a dedicated decrypt mapper"
    );
    assert!(
        DECRYPT_SOURCE.contains("DecryptIntent::new"),
        "decrypt CLI must construct the checked domain intent"
    );
    assert!(
        DECRYPT_SOURCE.contains("map_decrypt_error"),
        "decrypt CLI must map domain errors through map_decrypt_error"
    );

    for forbidden in [
        "stor.read_file(input)",
        "try_reader()?",
        "domain::decrypt::Request",
        "domain::decrypt::TransactionalRequest",
        "header_file.as_ref()",
    ] {
        assert!(
            !DECRYPT_SOURCE.contains(forbidden),
            "decrypt CLI must not keep validation-bypassing reader path `{forbidden}`"
        );
    }
}

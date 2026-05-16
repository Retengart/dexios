use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::HEADER_LEN;
use core::primitives::BLOCK_SIZE;
use zip::write::SimpleFileOptions;

const PASSWORD: &str = "12345678";
const DEXIOS_SUBCOMMANDS_RS: &str = include_str!("../src/subcommands.rs");
const STREAM_TAG_LEN: usize = 16;
const TRUNCATED_CANONICAL_V1_PREFIX: &[u8] = b"DXIO\x00\x01CV1\x00";
const RETIRED_CURRENT_V1_PREFIX: &[u8] = b"DXIO\x00\x01\x01\x00\x07\x07";
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
        .args(args);
    command.output().unwrap()
}

fn write_zip_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut zip_writer = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755);

    for (name, body) in entries {
        zip_writer.start_file(*name, options).unwrap();
        zip_writer.write_all(body).unwrap();
    }

    zip_writer.finish().unwrap();
}

fn multichunk_plaintext() -> Vec<u8> {
    (0..(BLOCK_SIZE * 3 + 37))
        .map(|index| (index % 251) as u8)
        .collect()
}

fn corrupt_final_chunk(bytes: &mut [u8]) {
    let final_offset = HEADER_LEN + (3 * (BLOCK_SIZE + STREAM_TAG_LEN));
    bytes[final_offset] ^= 0x40;
}

fn assert_source_contains(source_name: &str, source: &str, needle: &str) {
    assert!(
        source.contains(needle),
        "{source_name} must contain {needle:?}"
    );
}

#[test]
fn encrypt_delete_input_removes_plaintext_after_success() {
    let test_dir = TestDir::new("delete-input-encrypt");
    let input = test_dir.path().join("plain.txt");
    let output = test_dir.path().join("plain.enc");
    fs::write(&input, b"top secret").unwrap();

    let output_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            "--delete-input",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );

    assert!(
        output_cmd.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_cmd.stdout),
        String::from_utf8_lossy(&output_cmd.stderr)
    );
    assert!(!input.exists());
    assert!(output.exists());
}

#[test]
fn encrypt_delete_input_waits_for_hash_success() {
    let test_dir = TestDir::new("delete-input-encrypt-hash");
    let input = test_dir.path().join("plain.txt");
    let output = test_dir.path().join("plain.enc");
    fs::write(&input, b"top secret").unwrap();

    let output_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            "--hash",
            "--delete-input",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );

    assert!(
        output_cmd.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_cmd.stdout),
        String::from_utf8_lossy(&output_cmd.stderr)
    );
    let stdout = String::from_utf8_lossy(&output_cmd.stdout);
    assert!(stdout.contains(output.to_str().unwrap()), "stdout={stdout}");
    assert!(!input.exists());
    assert!(output.exists());
}

#[test]
fn encrypt_delete_input_keeps_plaintext_on_failure() {
    let test_dir = TestDir::new("delete-input-encrypt-fail");
    let input = test_dir.path().join("plain.txt");
    fs::write(&input, b"top secret").unwrap();

    let output_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "--delete-input",
            input.to_str().unwrap(),
            input.to_str().unwrap(),
        ],
    );

    assert!(
        !output_cmd.status.success(),
        "encrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_cmd.stdout),
        String::from_utf8_lossy(&output_cmd.stderr)
    );
    assert!(input.exists());
}

#[test]
fn decrypt_delete_input_waits_for_commit_success() {
    let test_dir = TestDir::new("delete-input-decrypt-commit-failure");
    let input = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output = test_dir.path().join("plain.out");
    fs::write(&input, b"top secret").unwrap();

    let encrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );
    assert!(encrypt_cmd.status.success());
    fs::write(&output, b"existing output").unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    let decrypt_cmd = command
        .current_dir(test_dir.path())
        .env("DEXIOS_KEY", "wrong-password")
        .args([
            "decrypt",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !decrypt_cmd.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stdout),
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(encrypted.exists());
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
}

#[test]
fn decrypt_delete_input_removes_encrypted_input_after_success() {
    let test_dir = TestDir::new("delete-input-decrypt");
    let input = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output = test_dir.path().join("plain.out");
    fs::write(&input, b"top secret").unwrap();

    let encrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );
    assert!(encrypt_cmd.status.success());

    let decrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "decrypt",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );

    assert!(
        decrypt_cmd.status.success(),
        "decrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stdout),
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(!encrypted.exists());
    assert_eq!(fs::read_to_string(output).unwrap(), "top secret");
}

#[test]
fn decrypt_delete_input_preserves_source_and_output_on_final_auth_failure() {
    let test_dir = TestDir::new("delete-input-decrypt-final-auth-fail");
    let input = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output = test_dir.path().join("plain.out");
    fs::write(&input, multichunk_plaintext()).unwrap();

    let encrypt_cmd = run_cli(
        test_dir.path(),
        &["encrypt", "-f", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_cmd.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_cmd.stdout),
        String::from_utf8_lossy(&encrypt_cmd.stderr)
    );
    let mut encrypted_bytes = fs::read(&encrypted).unwrap();
    corrupt_final_chunk(&mut encrypted_bytes);
    fs::write(&encrypted, encrypted_bytes).unwrap();
    fs::write(&output, b"existing output").unwrap();

    let decrypt_cmd = run_cli(
        test_dir.path(),
        &["decrypt", "-f", "--delete-input", "plain.enc", "plain.out"],
    );

    assert!(
        !decrypt_cmd.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stdout),
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(
        String::from_utf8_lossy(&decrypt_cmd.stderr).contains("Authentication failed"),
        "stderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(encrypted.exists());
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
}

#[test]
fn decrypt_delete_input_preserves_source_on_malformed_and_retired_v1_rejection() {
    let test_dir = TestDir::new("delete-input-decrypt-format-fail");
    fs::write(
        test_dir.path().join("malformed.enc"),
        TRUNCATED_CANONICAL_V1_PREFIX,
    )
    .unwrap();
    fs::write(
        test_dir.path().join("retired-current-v1.enc"),
        RETIRED_CURRENT_V1_PREFIX,
    )
    .unwrap();

    for (input, output, expected_stderr) in [
        (
            "malformed.enc",
            "malformed.out",
            "Malformed Dexios encrypted data",
        ),
        (
            "retired-current-v1.enc",
            "retired-current-v1.out",
            "Unsupported Dexios format",
        ),
    ] {
        let output_cmd = run_cli(
            test_dir.path(),
            &["decrypt", "-f", "--delete-input", input, output],
        );

        assert!(
            !output_cmd.status.success(),
            "{input} unexpectedly decrypted: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output_cmd.stdout),
            String::from_utf8_lossy(&output_cmd.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output_cmd.stderr).contains(expected_stderr),
            "{input} stderr did not contain {expected_stderr:?}: {}",
            String::from_utf8_lossy(&output_cmd.stderr)
        );
        assert!(test_dir.path().join(input).exists());
        assert!(!test_dir.path().join(output).exists());
    }
}

#[test]
fn unpack_delete_input_removes_encrypted_archive_after_success() {
    let test_dir = TestDir::new("delete-input-unpack");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_zip_with_entries(&plain_zip, &[("payload/file.txt", b"top secret")]);

    let encrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            plain_zip.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );
    assert!(encrypt_cmd.status.success());

    let unpack_cmd = run_cli(
        test_dir.path(),
        &[
            "unpack",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        ],
    );

    assert!(
        unpack_cmd.status.success(),
        "unpack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&unpack_cmd.stdout),
        String::from_utf8_lossy(&unpack_cmd.stderr)
    );
    assert!(!encrypted.exists());
    assert_eq!(
        fs::read_to_string(output_dir.join("payload/file.txt")).unwrap(),
        "top secret"
    );
}

#[test]
fn unpack_delete_input_preserves_archive_on_archive_validation_failure() {
    let test_dir = TestDir::new("delete-input-unpack-validation-fail");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_zip_with_entries(
        &plain_zip,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );
    let encrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            plain_zip.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );
    assert!(encrypt_cmd.status.success());
    let original_archive = fs::read(&encrypted).unwrap();

    let unpack_cmd = run_cli(
        test_dir.path(),
        &[
            "unpack",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        ],
    );

    assert!(
        !unpack_cmd.status.success(),
        "unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&unpack_cmd.stdout),
        String::from_utf8_lossy(&unpack_cmd.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unpack_cmd.stderr).contains("Unsafe archive path"),
        "stderr={}",
        String::from_utf8_lossy(&unpack_cmd.stderr)
    );
    assert_eq!(fs::read(&encrypted).unwrap(), original_archive);
    assert!(!output_dir.join("safe.txt").exists());
    assert!(!test_dir.path().join("escape.txt").exists());
}

#[test]
fn pack_delete_source_removes_source_directory_after_success() {
    let test_dir = TestDir::new("delete-source-pack");
    let source = test_dir.path().join("source");
    let nested = source.join("nested");
    let encrypted = test_dir.path().join("archive.enc");
    fs::create_dir_all(&nested).unwrap();
    fs::write(source.join("hello.txt"), b"hello").unwrap();
    fs::write(nested.join("world.txt"), b"world").unwrap();

    let pack_cmd = run_cli(
        test_dir.path(),
        &[
            "pack",
            "-f",
            "--delete-source",
            source.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );

    assert!(
        pack_cmd.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&pack_cmd.stdout),
        String::from_utf8_lossy(&pack_cmd.stderr)
    );
    assert!(!source.exists());
    assert!(encrypted.exists());
}

#[cfg(unix)]
#[test]
fn pack_delete_source_reports_partial_cleanup_failure() {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = TestDir::new("delete-source-pack-partial-cleanup");
    let ok_source = test_dir.path().join("ok-source");
    let locked_parent = test_dir.path().join("locked-parent");
    let locked_source = locked_parent.join("locked-source");
    let encrypted = test_dir.path().join("archive.enc");
    fs::create_dir_all(&ok_source).unwrap();
    fs::create_dir_all(&locked_source).unwrap();
    fs::write(ok_source.join("ok.txt"), b"ok").unwrap();
    fs::write(locked_source.join("locked.txt"), b"locked").unwrap();
    fs::set_permissions(&locked_parent, fs::Permissions::from_mode(0o555)).unwrap();

    let pack_cmd = run_cli(
        test_dir.path(),
        &[
            "pack",
            "-f",
            "--delete-source",
            ok_source.to_str().unwrap(),
            locked_source.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );

    fs::set_permissions(&locked_parent, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        !pack_cmd.status.success(),
        "pack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&pack_cmd.stdout),
        String::from_utf8_lossy(&pack_cmd.stderr)
    );
    assert!(
        pack_cmd.stdout.is_empty(),
        "cleanup failure must not print normal-output success text: stdout={}",
        String::from_utf8_lossy(&pack_cmd.stdout)
    );
    assert_eq!(
        String::from_utf8_lossy(&pack_cmd.stderr),
        "Cleanup failed after output commit; committed outputs remain in place\n"
    );
    assert!(encrypted.exists());
    assert!(!ok_source.exists());
    assert!(locked_source.exists());
}

#[test]
fn cli_delete_after_success_hash_failure_and_identity_mismatch_are_source_gated() {
    for required in [
        "CleanupAfterCommitError",
        "CleanupFailed(CleanupResult)",
        "result.failures",
        "CleanupFailure",
        "HashVerification::Failed",
        "changed cleanup identity",
        "cleanup target identity",
        "ordinary delete-after-success cleanup",
        "PostCommitSuccess",
        "committed outputs remain in place",
    ] {
        assert_source_contains("dexios/src/subcommands.rs", DEXIOS_SUBCOMMANDS_RS, required);
    }
}

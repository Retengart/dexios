#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::string_slice,
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::match_same_arms,
        clippy::items_after_statements,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_collect,
        clippy::manual_let_else,
        clippy::format_collect,
        clippy::case_sensitive_file_extension_comparisons,
        clippy::struct_excessive_bools,
        reason = "integration tests assert exact behavior and may panic on failure"
    )
)]
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::HEADER_LEN;
use core::primitives::BLOCK_SIZE;

const CORRECT_PASSWORD: &str = "correct-password";
const WRONG_PASSWORD: &str = "wrong-password";
const DECRYPT_SOURCE: &str = include_str!("../src/subcommands/decrypt.rs");
const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
const STREAM_TAG_LEN: usize = 16;
const TRUNCATED_CANONICAL_V1_PREFIX: &[u8] = b"DXIO\x00\x01CV1\x00";
const RETIRED_CURRENT_V1_PREFIX: &[u8] = b"DXIO\x00\x01\x01\x00\x07\x07";
const LEGACY_DEXIOS_PREFIX: [u8; 10] = [0xDE, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
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
        .arg("--env-key")
        .args(args)
        .output()
        .unwrap()
}

fn run_cli_with_stdin(current_dir: &Path, args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dexios"))
        .current_dir(current_dir)
        .env_remove("DEXIOS_KEY")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let write_result = child.stdin.as_mut().unwrap().write_all(stdin);
    if let Err(error) = write_result {
        assert_eq!(
            error.kind(),
            ErrorKind::BrokenPipe,
            "unexpected stdin write error: {error}"
        );
    }
    child.wait_with_output().unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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

fn truncate_one_byte(bytes: &mut Vec<u8>) {
    bytes.pop().expect("encrypted fixture has payload bytes");
}

fn reorder_normal_chunks(bytes: &mut [u8]) {
    let payload = &mut bytes[HEADER_LEN..];
    let normal_chunk_len = BLOCK_SIZE + STREAM_TAG_LEN;
    let (first, remaining) = payload.split_at_mut(normal_chunk_len);
    let second = &mut remaining[..normal_chunk_len];
    first.swap_with_slice(second);
}

// fs-5: committed plaintext outputs are published owner-only (0o600) as a deliberate
// defense-in-depth choice (see book/src/Threat-Model.md), not the umask default.
#[cfg(unix)]
#[test]
fn decrypted_output_is_published_owner_only_0o600() {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = TestDir::new("decrypt-output-mode");
    fs::write(test_dir.path().join("plain.txt"), b"secret plaintext").unwrap();

    let enc = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(enc.status.success(), "encrypt failed: {}", stderr(&enc));

    let dec = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["decrypt", "--force", "plain.enc", "plain.out"],
    );
    assert!(dec.status.success(), "decrypt failed: {}", stderr(&dec));

    let mode = fs::metadata(test_dir.path().join("plain.out"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "decrypted plaintext must be published owner-only (0o600), got {mode:o}"
    );
}

#[test]
fn decrypt_cli_corrupted_stream_variants_preserve_existing_output() {
    let test_dir = TestDir::new("decrypt-cli-corrupted-stream");
    let sentinel = b"existing output must survive corrupted CLI decrypt";

    for (label, corrupt) in [
        ("final-tamper", corrupt_final_chunk as fn(&mut [u8])),
        (
            "reordered-normal-chunks",
            reorder_normal_chunks as fn(&mut [u8]),
        ),
    ] {
        let plain = format!("{label}.txt");
        let encrypted = format!("{label}.enc");
        let output_path = test_dir.path().join(format!("{label}.out"));
        fs::write(test_dir.path().join(&plain), multichunk_plaintext()).unwrap();

        let encrypt_output = run_cli(
            test_dir.path(),
            CORRECT_PASSWORD,
            &["encrypt", "--force", plain.as_str(), encrypted.as_str()],
        );
        assert!(
            encrypt_output.status.success(),
            "{label}: encrypt fixture failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&encrypt_output.stdout),
            String::from_utf8_lossy(&encrypt_output.stderr)
        );

        let encrypted_path = test_dir.path().join(&encrypted);
        let mut encrypted_bytes = fs::read(&encrypted_path).unwrap();
        corrupt(&mut encrypted_bytes);
        fs::write(&encrypted_path, encrypted_bytes).unwrap();
        fs::write(&output_path, sentinel).unwrap();

        let decrypt_output = run_cli(
            test_dir.path(),
            CORRECT_PASSWORD,
            &[
                "decrypt",
                "--force",
                encrypted.as_str(),
                output_path.file_name().unwrap().to_str().unwrap(),
            ],
        );

        assert!(
            !decrypt_output.status.success(),
            "{label}: corrupted decrypt unexpectedly succeeded: stdout={}\nstderr={}",
            String::from_utf8_lossy(&decrypt_output.stdout),
            String::from_utf8_lossy(&decrypt_output.stderr)
        );
        let stderr = stderr(&decrypt_output);
        assert!(
            stderr.contains("Authentication failed")
                || stderr.contains("Malformed Dexios encrypted data"),
            "{label}: stderr should stay terse and typed: {stderr}"
        );
        assert_eq!(
            fs::read(&output_path).unwrap(),
            sentinel.as_slice(),
            "{label}: CLI decrypt must preserve an existing final output"
        );
    }

    let plain = "one-byte-truncation.txt";
    let encrypted = "one-byte-truncation.enc";
    let output = "one-byte-truncation.out";
    fs::write(test_dir.path().join(plain), multichunk_plaintext()).unwrap();
    let encrypt_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", plain, encrypted],
    );
    assert!(
        encrypt_output.status.success(),
        "truncation encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    let encrypted_path = test_dir.path().join(encrypted);
    let mut encrypted_bytes = fs::read(&encrypted_path).unwrap();
    truncate_one_byte(&mut encrypted_bytes);
    fs::write(&encrypted_path, encrypted_bytes).unwrap();
    let output_path = test_dir.path().join(output);
    fs::write(&output_path, sentinel).unwrap();

    let decrypt_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["decrypt", "--force", encrypted, output],
    );

    assert!(
        !decrypt_output.status.success(),
        "truncated decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_output.stdout),
        String::from_utf8_lossy(&decrypt_output.stderr)
    );
    let stderr = stderr(&decrypt_output);
    assert!(
        stderr.contains("Authentication failed")
            || stderr.contains("Malformed Dexios encrypted data"),
        "truncated stream stderr should stay terse and typed: {stderr}"
    );
    assert_eq!(fs::read(output_path).unwrap(), sentinel.as_slice());
}

#[test]
fn decrypt_keyfile_stdin_fails_before_interactive_overwrite_prompt() {
    let test_dir = TestDir::new("decrypt-keyfile-stdin-overwrite");
    fs::write(test_dir.path().join("plain.txt"), b"plain").unwrap();
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
    fs::write(test_dir.path().join("plain.out"), b"existing output").unwrap();

    let output = run_cli_with_stdin(
        test_dir.path(),
        &["decrypt", "--keyfile", "-", "plain.enc", "plain.out"],
        b"secret-from-stdin\n",
    );

    assert!(
        !output.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("--keyfile - cannot be combined with interactive overwrite prompts"),
        "stderr did not explain stdin/prompt conflict: {stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("plain.out")).unwrap(),
        b"existing output"
    );
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

    assert_eq!(
        fs::read(test_dir.path().join("plain.out")).unwrap(),
        b"detached secret"
    );
}

#[test]
fn decrypt_malformed_and_legacy_formats_use_typed_mapping() {
    let test_dir = TestDir::new("decrypt-format-mapping");
    fs::write(
        test_dir.path().join("malformed.enc"),
        TRUNCATED_CANONICAL_V1_PREFIX,
    )
    .unwrap();
    fs::write(test_dir.path().join("legacy.enc"), LEGACY_DEXIOS_PREFIX).unwrap();
    fs::write(
        test_dir.path().join("retired-current-v1.enc"),
        RETIRED_CURRENT_V1_PREFIX,
    )
    .unwrap();

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

    let retired_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "decrypt",
            "--force",
            "retired-current-v1.enc",
            "retired-current-v1.out",
        ],
    );
    assert!(
        !retired_output.status.success(),
        "retired current-V1 decrypt unexpectedly succeeded"
    );
    assert!(
        stderr(&retired_output).contains("Unsupported Dexios format"),
        "retired current-V1 stderr should use map_decrypt_error: {}",
        stderr(&retired_output)
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

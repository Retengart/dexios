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
#[expect(dead_code, reason = "shared tempdir test helper")]
#[path = "support/tempdir.rs"]
mod tempdir;

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use tempdir::TestDir;

const PASSWORD: &str = "correct-password";

fn run_cli(current_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", PASSWORD)
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

#[test]
fn encrypt_auto_generated_passphrase_disclosure_uses_stderr_not_stdout() {
    let test_dir = TestDir::new("encrypt-auto-stderr");
    let plain = test_dir.path().join("plain.txt");
    let plaintext = b"generated passphrase plaintext";
    fs::write(&plain, plaintext).unwrap();

    let output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "--auto=4", "plain.txt", "plain.enc"],
    );

    assert!(
        output.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(test_dir.path().join("plain.enc").is_file());

    let disclosure_prefix = "Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: ";
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_prefix = format!("[-] {disclosure_prefix}");

    assert!(
        stderr.contains(&stderr_prefix),
        "generated passphrase disclosure must be in stderr: stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        !stdout.contains(disclosure_prefix),
        "generated passphrase disclosure must not be in stdout: stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        !stdout.contains("[-]"),
        "warning diagnostics must not be in stdout: stdout={stdout}\nstderr={stderr}"
    );

    let generated_passphrase = stderr
        .lines()
        .find_map(|line| line.strip_prefix(&stderr_prefix))
        .expect("stderr should include generated passphrase disclosure")
        .to_owned();

    let mut decrypt_command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    let decrypt_output = decrypt_command
        .current_dir(test_dir.path())
        .env("DEXIOS_KEY", generated_passphrase)
        .arg("--env-key")
        .args(["decrypt", "--force", "plain.enc", "plain.out"])
        .output()
        .unwrap();

    assert!(
        decrypt_output.status.success(),
        "decrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_output.stdout),
        String::from_utf8_lossy(&decrypt_output.stderr)
    );
    assert_eq!(
        fs::read(test_dir.path().join("plain.out")).unwrap(),
        plaintext
    );
}

#[test]
fn encrypt_with_dexios_key_env_warns_about_environment_exposure() {
    let test_dir = TestDir::new("encrypt-env-key-warn");
    fs::write(test_dir.path().join("plain.txt"), b"env key plaintext").unwrap();

    // run_cli sets DEXIOS_KEY, so this exercises the Key::Env path (mem-1/cli-1).
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Using DEXIOS_KEY from the environment"),
        "env-key exposure warning must be emitted on stderr: stderr={stderr}"
    );
}

#[test]
fn encrypt_auto_word_count_is_capped_at_64() {
    let test_dir = TestDir::new("encrypt-auto-cap");
    fs::write(test_dir.path().join("plain.txt"), b"x").unwrap();

    let over = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "--auto=70", "plain.txt", "over.enc"],
    );
    assert!(!over.status.success(), "--auto=70 must be rejected");
    let stderr = String::from_utf8_lossy(&over.stderr);
    assert!(
        stderr.contains("between 1 and 64"),
        "expected cap message, got: {stderr}"
    );

    let ok = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "--auto=64", "plain.txt", "ok.enc"],
    );
    assert!(
        ok.status.success(),
        "--auto=64 must be accepted: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
}

#[test]
fn encrypt_keyfile_stdin_fails_before_interactive_overwrite_prompt() {
    let test_dir = TestDir::new("encrypt-keyfile-stdin-overwrite");
    fs::write(test_dir.path().join("plain.txt"), b"plain").unwrap();
    fs::write(test_dir.path().join("plain.enc"), b"existing").unwrap();

    let output = run_cli_with_stdin(
        test_dir.path(),
        &["encrypt", "--keyfile", "-", "plain.txt", "plain.enc"],
        b"secret-from-stdin\n",
    );

    assert!(
        !output.status.success(),
        "encrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--keyfile - cannot be combined with interactive overwrite prompts"),
        "stderr did not explain stdin/prompt conflict: {stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("plain.enc")).unwrap(),
        b"existing"
    );
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
fn encrypt_directory_target_fails_during_staging_preflight() {
    let test_dir = TestDir::new("encrypt-directory-target");
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
        String::from_utf8_lossy(&output.stderr).contains("I/O failure while encrypting data"),
        "directory target preflight failures must stay in the encrypt I/O class: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_dir.is_dir());
}

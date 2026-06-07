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
#[allow(dead_code)]
#[path = "support/tempdir.rs"]
mod tempdir;

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use core::kdf::Kdf;
use core::protected::Protected;
use domain::encrypt;
use tempdir::KeyForceTestDir as TestDir;

// Regression coverage for cli-3: `key del` and `key change` mutate keyslots
// destructively. Each must prompt for confirmation (default No) before the
// mutation and must bypass that prompt when `--force`/`-f` is supplied.

const PASSWORD: &str = "old-pass";
const SECOND_PASSWORD: &str = "second-pass";

fn run_cli(current_dir: &Path, args: &[&str], key: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .stdin(Stdio::null())
        .args(args);
    match key {
        Some(key) => {
            command.env("DEXIOS_KEY", key).arg("--env-key");
        }
        None => {
            command.env_remove("DEXIOS_KEY");
        }
    }
    command.output().unwrap()
}

fn run_cli_with_stdin(
    current_dir: &Path,
    args: &[&str],
    key: Option<&str>,
    stdin: &[u8],
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args);
    match key {
        Some(key) => {
            command.env("DEXIOS_KEY", key).arg("--env-key");
        }
        None => {
            command.env_remove("DEXIOS_KEY");
        }
    }

    let mut child = command.spawn().unwrap();
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

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn encrypt_fixture(dir: &Path, name: &str) -> PathBuf {
    let input_path = dir.join(format!("{name}.txt"));
    let output_path = dir.join(format!("{name}.enc"));
    fs::write(&input_path, b"Hello world").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &input_path,
        &output_path,
        domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        Protected::new(PASSWORD.as_bytes().to_vec()),
        Kdf::Argon2id,
    )
    .expect("build encrypt intent");
    encrypt::execute(intent).expect("encrypt fixture");

    output_path
}

fn write_keyfile(dir: &Path, name: &str, key: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, key.as_bytes()).unwrap();
    path
}

// Builds an encrypted file carrying two keyslots so a `key del` can succeed
// without hitting the "cannot remove the final keyslot" guard.
fn encrypt_fixture_two_keyslots(dir: &Path, name: &str) -> PathBuf {
    let encrypted = encrypt_fixture(dir, name);
    let new_keyfile = write_keyfile(dir, &format!("{name}-second.key"), SECOND_PASSWORD);

    let add = run_cli(
        dir,
        &[
            "key",
            "add",
            "--keyfile-new",
            new_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );
    assert!(
        add.status.success(),
        "fixture setup: adding second keyslot failed: stdout={}\nstderr={}",
        stdout(&add),
        stderr(&add)
    );

    encrypted
}

#[test]
fn key_del_without_force_declined_does_not_mutate_keyslots() {
    let test_dir = TestDir::new("del-decline");
    let encrypted = encrypt_fixture_two_keyslots(test_dir.path(), "del");
    let before = fs::read(&encrypted).unwrap();

    // Answer "n" to the destructive-action confirmation.
    let output = run_cli_with_stdin(
        test_dir.path(),
        &["key", "del", encrypted.to_str().unwrap()],
        Some(PASSWORD),
        b"n\n",
    );

    assert!(
        output.status.success(),
        "declined key del should exit cleanly: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(
        fs::read(&encrypted).unwrap(),
        before,
        "declined key del must not mutate the encrypted file"
    );
}

#[test]
fn key_del_without_force_default_answer_does_not_mutate_keyslots() {
    let test_dir = TestDir::new("del-default");
    let encrypted = encrypt_fixture_two_keyslots(test_dir.path(), "del");
    let before = fs::read(&encrypted).unwrap();

    // Empty line accepts the default, which must be No.
    let output = run_cli_with_stdin(
        test_dir.path(),
        &["key", "del", encrypted.to_str().unwrap()],
        Some(PASSWORD),
        b"\n",
    );

    assert!(
        output.status.success(),
        "default-declined key del should exit cleanly: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(
        fs::read(&encrypted).unwrap(),
        before,
        "default key del answer must be No and must not mutate the file"
    );
}

#[test]
fn key_del_with_force_bypasses_prompt_and_mutates() {
    let test_dir = TestDir::new("del-force");
    let encrypted = encrypt_fixture_two_keyslots(test_dir.path(), "del");
    let before = fs::read(&encrypted).unwrap();

    // No stdin is provided; --force must skip the prompt entirely.
    let output = run_cli(
        test_dir.path(),
        &["key", "del", "--force", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );

    assert!(
        output.status.success(),
        "forced key del should succeed without a prompt: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_ne!(
        fs::read(&encrypted).unwrap(),
        before,
        "forced key del must mutate the keyslots"
    );

    // The deleted slot's password must no longer verify.
    let verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );
    assert!(
        !verify.status.success(),
        "deleted key should no longer verify after forced del"
    );
}

#[test]
fn key_del_force_short_flag_bypasses_prompt() {
    let test_dir = TestDir::new("del-force-short");
    let encrypted = encrypt_fixture_two_keyslots(test_dir.path(), "del");
    let before = fs::read(&encrypted).unwrap();

    let output = run_cli(
        test_dir.path(),
        &["key", "del", "-f", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );

    assert!(
        output.status.success(),
        "forced key del (-f) should succeed without a prompt: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_ne!(
        fs::read(&encrypted).unwrap(),
        before,
        "forced key del (-f) must mutate the keyslots"
    );
}

#[test]
fn key_change_without_force_declined_does_not_mutate_keyslots() {
    let test_dir = TestDir::new("change-decline");
    let encrypted = encrypt_fixture(test_dir.path(), "change");
    let new_keyfile = write_keyfile(test_dir.path(), "new.key", "new-pass");
    let before = fs::read(&encrypted).unwrap();

    let output = run_cli_with_stdin(
        test_dir.path(),
        &[
            "key",
            "change",
            "--keyfile-new",
            new_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        Some(PASSWORD),
        b"n\n",
    );

    assert!(
        output.status.success(),
        "declined key change should exit cleanly: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(
        fs::read(&encrypted).unwrap(),
        before,
        "declined key change must not mutate the encrypted file"
    );

    // The original key must still verify since nothing changed.
    let verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );
    assert!(
        verify.status.success(),
        "original key must still verify after a declined change"
    );
}

#[test]
fn key_change_without_force_default_answer_does_not_mutate_keyslots() {
    let test_dir = TestDir::new("change-default");
    let encrypted = encrypt_fixture(test_dir.path(), "change");
    let new_keyfile = write_keyfile(test_dir.path(), "new.key", "new-pass");
    let before = fs::read(&encrypted).unwrap();

    let output = run_cli_with_stdin(
        test_dir.path(),
        &[
            "key",
            "change",
            "--keyfile-new",
            new_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        Some(PASSWORD),
        b"\n",
    );

    assert!(
        output.status.success(),
        "default-declined key change should exit cleanly: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(
        fs::read(&encrypted).unwrap(),
        before,
        "default key change answer must be No and must not mutate the file"
    );
}

#[test]
fn key_change_with_force_bypasses_prompt_and_mutates() {
    let test_dir = TestDir::new("change-force");
    let encrypted = encrypt_fixture(test_dir.path(), "change");
    let new_keyfile = write_keyfile(test_dir.path(), "new.key", "new-pass");
    let before = fs::read(&encrypted).unwrap();

    let output = run_cli(
        test_dir.path(),
        &[
            "key",
            "change",
            "--force",
            "--keyfile-new",
            new_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );

    assert!(
        output.status.success(),
        "forced key change should succeed without a prompt: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_ne!(
        fs::read(&encrypted).unwrap(),
        before,
        "forced key change must mutate the keyslots"
    );

    let new_verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some("new-pass"),
    );
    assert!(
        new_verify.status.success(),
        "new key must verify after a forced change"
    );

    let old_verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );
    assert!(
        !old_verify.status.success(),
        "old key must no longer verify after a forced change"
    );
}

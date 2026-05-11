use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::{HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN};
use core::kdf::Kdf;
use core::protected::Protected;
use domain::encrypt;

const PASSWORD: &str = "old-pass";
const KEY_SUBCOMMAND_SOURCE: &str = include_str!("../src/subcommands/key.rs");
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
            "dexios-key-{prefix}-{}-{seq}-{nanos}",
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

fn run_cli(current_dir: &Path, args: &[&str], key: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .stdin(Stdio::null())
        .args(args);
    match key {
        Some(key) => {
            command.env("DEXIOS_KEY", key);
        }
        None => {
            command.env_remove("DEXIOS_KEY");
        }
    }

    command.output().unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_no_prompt(output: &std::process::Output) {
    let stderr = stderr(output);
    let stdout = stdout(output);
    assert!(
        !stderr.contains("Please enter") && !stdout.contains("Please enter"),
        "command prompted before typed preflight failed: stdout={stdout}\nstderr={stderr}"
    );
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
        Kdf::Blake3Balloon,
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

fn mark_keyslot_unsupported_argon2id(path: &Path, index: usize) {
    let mut bytes = fs::read(path).unwrap();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
    bytes[offset..offset + 2].copy_from_slice(&[0xDF, 0x02]);
    fs::write(path, bytes).unwrap();
}

fn write_malformed_v1_fixture(path: &Path) {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[0..4].copy_from_slice(b"DXIO");
    bytes[4..6].copy_from_slice(&[0x00, 0x01]);
    bytes[7] = 1;
    fs::write(path, bytes).unwrap();
}

#[test]
fn key_add_valid_v1_returns_unsupported_without_key_source() {
    let test_dir = TestDir::new("add-no-key-source");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");

    let output = run_cli(
        test_dir.path(),
        &["key", "add", encrypted.to_str().unwrap()],
        None,
    );

    assert!(
        !output.status.success(),
        "key add unexpectedly succeeded: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("Cannot add a V1 keyslot without re-encrypting the payload"),
        "unsupported add did not use typed key mapping: {}",
        stderr(&output)
    );
    assert_no_prompt(&output);
}

#[test]
fn key_add_rejects_malformed_and_unsupported_kdf_before_prompting() {
    let test_dir = TestDir::new("add-preflight-errors");
    let malformed = test_dir.path().join("malformed.enc");
    write_malformed_v1_fixture(&malformed);

    let malformed_output = run_cli(
        test_dir.path(),
        &["key", "add", malformed.to_str().unwrap()],
        None,
    );
    assert!(!malformed_output.status.success());
    assert!(
        stderr(&malformed_output).contains("Malformed Dexios V1 header"),
        "malformed add did not use typed mapping: {}",
        stderr(&malformed_output)
    );
    assert_no_prompt(&malformed_output);

    let unsupported_kdf = encrypt_fixture(test_dir.path(), "unsupported-kdf");
    mark_keyslot_unsupported_argon2id(&unsupported_kdf, 0);
    let unsupported_output = run_cli(
        test_dir.path(),
        &["key", "add", unsupported_kdf.to_str().unwrap()],
        None,
    );
    assert!(!unsupported_output.status.success());
    assert!(
        stderr(&unsupported_output).contains("Unsupported keyslot KDF tag: [DF, 02]"),
        "unsupported KDF add did not use typed mapping: {}",
        stderr(&unsupported_output)
    );
    assert_no_prompt(&unsupported_output);
}

#[test]
fn key_verify_rejects_malformed_and_unsupported_kdf_before_prompting() {
    let test_dir = TestDir::new("verify-preflight-errors");
    let malformed = test_dir.path().join("malformed.enc");
    write_malformed_v1_fixture(&malformed);

    let malformed_output = run_cli(
        test_dir.path(),
        &["key", "verify", malformed.to_str().unwrap()],
        None,
    );
    assert!(!malformed_output.status.success());
    assert!(
        stderr(&malformed_output).contains("Malformed Dexios V1 header"),
        "malformed verify did not use typed mapping: {}",
        stderr(&malformed_output)
    );
    assert_no_prompt(&malformed_output);

    let unsupported_kdf = encrypt_fixture(test_dir.path(), "unsupported-kdf");
    mark_keyslot_unsupported_argon2id(&unsupported_kdf, 0);
    let unsupported_output = run_cli(
        test_dir.path(),
        &["key", "verify", unsupported_kdf.to_str().unwrap()],
        None,
    );
    assert!(!unsupported_output.status.success());
    assert!(
        stderr(&unsupported_output).contains("Unsupported keyslot KDF tag: [DF, 02]"),
        "unsupported KDF verify did not use typed mapping: {}",
        stderr(&unsupported_output)
    );
    assert_no_prompt(&unsupported_output);
}

#[test]
fn key_verify_maps_success_and_incorrect_key_after_read_only_preparation() {
    let test_dir = TestDir::new("verify-valid");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");

    let success = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );
    assert!(
        success.status.success(),
        "key verify failed with the correct key: stdout={}\nstderr={}",
        stdout(&success),
        stderr(&success)
    );

    let wrong = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some("wrong-pass"),
    );
    assert!(
        !wrong.status.success(),
        "key verify unexpectedly accepted the wrong key"
    );
    assert!(
        stderr(&wrong).contains("Incorrect key"),
        "incorrect key did not use typed key mapping: {}",
        stderr(&wrong)
    );
}

#[test]
fn key_change_rejects_preflight_errors_before_prompting_for_secrets() {
    let test_dir = TestDir::new("change-preflight-errors");

    let malformed = test_dir.path().join("malformed.enc");
    write_malformed_v1_fixture(&malformed);
    let malformed_output = run_cli(
        test_dir.path(),
        &["key", "change", malformed.to_str().unwrap()],
        None,
    );
    assert!(!malformed_output.status.success());
    assert!(
        stderr(&malformed_output).contains("Malformed Dexios V1 header"),
        "malformed change did not use typed mapping: {}",
        stderr(&malformed_output)
    );
    assert_no_prompt(&malformed_output);

    let missing = test_dir.path().join("missing.enc");
    let missing_output = run_cli(
        test_dir.path(),
        &["key", "change", missing.to_str().unwrap()],
        None,
    );
    assert!(!missing_output.status.success());
    assert!(
        stderr(&missing_output).contains("I/O failure while reading key workflow target"),
        "missing change target did not use typed key mapping: {}",
        stderr(&missing_output)
    );
    assert_no_prompt(&missing_output);

    let unsupported_kdf = encrypt_fixture(test_dir.path(), "change-unsupported-kdf");
    mark_keyslot_unsupported_argon2id(&unsupported_kdf, 0);
    let unsupported_output = run_cli(
        test_dir.path(),
        &["key", "change", unsupported_kdf.to_str().unwrap()],
        None,
    );
    assert!(!unsupported_output.status.success());
    assert!(
        stderr(&unsupported_output).contains("Unsupported keyslot KDF tag: [DF, 02]"),
        "unsupported KDF change did not use typed mapping: {}",
        stderr(&unsupported_output)
    );
    assert_no_prompt(&unsupported_output);
}

#[test]
fn key_change_wrong_old_key_does_not_read_new_key_source() {
    let test_dir = TestDir::new("change-wrong-old");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");
    let original = fs::read(&encrypted).unwrap();
    let old_keyfile = write_keyfile(test_dir.path(), "wrong-old.key", "wrong-pass");
    let missing_new_keyfile = test_dir.path().join("missing-new.key");

    let output = run_cli(
        test_dir.path(),
        &[
            "key",
            "change",
            "--keyfile-old",
            old_keyfile.to_str().unwrap(),
            "--keyfile-new",
            missing_new_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        None,
    );

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("Incorrect key"),
        "wrong old key did not use typed key mapping: {}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("Unable to read file"),
        "new key source was read before old-key verification: {}",
        stderr(&output)
    );
    assert_eq!(fs::read(&encrypted).unwrap(), original);
    assert_no_prompt(&output);
}

#[test]
fn key_change_reads_new_key_after_old_key_verification_succeeds() {
    let test_dir = TestDir::new("change-valid");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");
    let old_keyfile = write_keyfile(test_dir.path(), "old.key", PASSWORD);
    let new_keyfile = write_keyfile(test_dir.path(), "new.key", "new-pass");

    let output = run_cli(
        test_dir.path(),
        &[
            "key",
            "change",
            "--keyfile-old",
            old_keyfile.to_str().unwrap(),
            "--keyfile-new",
            new_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        None,
    );

    assert!(
        output.status.success(),
        "key change failed with correct old/new keyfiles: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );

    let new_verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some("new-pass"),
    );
    assert!(
        new_verify.status.success(),
        "changed file did not verify with new key: stdout={}\nstderr={}",
        stdout(&new_verify),
        stderr(&new_verify)
    );

    let old_verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );
    assert!(!old_verify.status.success());
    assert!(stderr(&old_verify).contains("Incorrect key"));
}

#[test]
fn key_delete_maps_failures_without_remaining_key_collection() {
    let test_dir = TestDir::new("delete-failures");

    let malformed = test_dir.path().join("malformed.enc");
    write_malformed_v1_fixture(&malformed);
    let malformed_output = run_cli(
        test_dir.path(),
        &["key", "del", malformed.to_str().unwrap()],
        None,
    );
    assert!(!malformed_output.status.success());
    assert!(stderr(&malformed_output).contains("Malformed Dexios V1 header"));
    assert_no_prompt(&malformed_output);

    let missing = test_dir.path().join("missing.enc");
    let missing_output = run_cli(
        test_dir.path(),
        &["key", "del", missing.to_str().unwrap()],
        None,
    );
    assert!(!missing_output.status.success());
    assert!(
        stderr(&missing_output).contains("I/O failure while reading key workflow target"),
        "missing delete target did not use typed key mapping: {}",
        stderr(&missing_output)
    );
    assert_no_prompt(&missing_output);

    let unsupported_kdf = encrypt_fixture(test_dir.path(), "delete-unsupported-kdf");
    mark_keyslot_unsupported_argon2id(&unsupported_kdf, 0);
    let unsupported_output = run_cli(
        test_dir.path(),
        &["key", "del", unsupported_kdf.to_str().unwrap()],
        None,
    );
    assert!(!unsupported_output.status.success());
    assert!(stderr(&unsupported_output).contains("Unsupported keyslot KDF tag: [DF, 02]"));
    assert_no_prompt(&unsupported_output);

    let encrypted = encrypt_fixture(test_dir.path(), "delete-final");
    let old_keyfile = write_keyfile(test_dir.path(), "old.key", PASSWORD);
    let final_slot_output = run_cli(
        test_dir.path(),
        &[
            "key",
            "del",
            "--keyfile",
            old_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        None,
    );
    assert!(!final_slot_output.status.success());
    assert!(stderr(&final_slot_output).contains("Cannot remove the final V1 keyslot"));
    assert!(
        !stderr(&final_slot_output).contains("remaining"),
        "delete must not ask for a remaining verification key: {}",
        stderr(&final_slot_output)
    );

    let wrong_keyfile = write_keyfile(test_dir.path(), "wrong.key", "wrong-pass");
    let wrong_output = run_cli(
        test_dir.path(),
        &[
            "key",
            "del",
            "--keyfile",
            wrong_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        None,
    );
    assert!(!wrong_output.status.success());
    assert!(stderr(&wrong_output).contains("Incorrect key"));
}

#[test]
fn key_mutation_cli_source_orders_secrets_through_domain_intents() {
    let old_key_secret = KEY_SUBCOMMAND_SOURCE
        .find("params.key_old.get_secret")
        .expect("change should still read the old key");
    let old_key_proof = KEY_SUBCOMMAND_SOURCE
        .find("verify_old_key")
        .expect("change should verify the old key before reading the new key");
    let new_key_secret = KEY_SUBCOMMAND_SOURCE
        .find("params.key_new.get_secret")
        .expect("change should still read the new key after old proof");

    assert!(
        old_key_secret < old_key_proof && old_key_proof < new_key_secret,
        "key change must read old key, verify it in domain, then read the new key"
    );
    assert!(
        !KEY_SUBCOMMAND_SOURCE.contains("execute_transactional"),
        "CLI key mutation adapters must not call removed raw transactional request paths"
    );
    assert!(
        !KEY_SUBCOMMAND_SOURCE.contains("remaining verification")
            && !KEY_SUBCOMMAND_SOURCE.contains("remaining_key"),
        "CLI key delete must not collect a remaining verification key"
    );
}

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::{
    CANONICAL_V1_DISCRIMINATOR, HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN,
    RETIRED_CURRENT_V1_HEADER_LEN,
};
use core::kdf::Kdf;
use core::protected::Protected;
use domain::encrypt;

const PASSWORD: &str = "old-pass";
const KEY_SUBCOMMAND_SOURCE: &str = include_str!("../src/subcommands/key.rs");
const ERROR_MAPPING_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
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

fn run_cli_with_stdin(current_dir: &Path, args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dexios"))
        .current_dir(current_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("DEXIOS_KEY")
        .args(args)
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

fn assert_sanitized_key_stderr(stderr: &str) {
    for forbidden in [
        "Error:",
        "Caused by:",
        "source chain",
        "Stack backtrace",
        "TransactionError::",
        "WorkflowErrorClass::",
        PASSWORD,
        "keyslot internals",
        "master key:",
    ] {
        assert!(
            !stderr.contains(forbidden),
            "key workflow stderr must stay sanitized: {stderr}"
        );
    }
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

#[test]
fn key_add_rejects_old_and_new_keyfiles_both_reading_stdin() {
    let test_dir = TestDir::new("key-add-dual-stdin");
    let encrypted_path = test_dir.path().join("cipher.enc");

    let output = run_cli_with_stdin(
        test_dir.path(),
        &[
            "key",
            "add",
            "--keyfile-old",
            "-",
            "--keyfile-new",
            "-",
            encrypted_path.to_str().unwrap(),
        ],
        b"old-pass\nnew-pass\n",
    );

    assert!(!output.status.success());
    assert_no_prompt(&output);
    assert!(
        stderr(&output).contains("--keyfile-old - and --keyfile-new - cannot both read from stdin"),
        "unexpected stderr: {}",
        stderr(&output)
    );
}

#[test]
fn key_stale_target_error_mapping_is_sanitized() {
    for required in [
        "domain::key::Error::TargetChanged =>",
        "Key workflow target changed before commit",
    ] {
        assert!(
            ERROR_MAPPING_SOURCE.contains(required),
            "missing key stale CLI mapping token: {required}"
        );
    }

    assert_sanitized_key_stderr("Key workflow target changed before commit");
}

#[test]
fn key_change_rejects_old_and_new_keyfiles_both_reading_stdin() {
    let test_dir = TestDir::new("key-change-dual-stdin");
    let encrypted_path = test_dir.path().join("cipher.enc");

    let output = run_cli_with_stdin(
        test_dir.path(),
        &[
            "key",
            "change",
            "--keyfile-old",
            "-",
            "--keyfile-new",
            "-",
            encrypted_path.to_str().unwrap(),
        ],
        b"old-pass\nnew-pass\n",
    );

    assert!(!output.status.success());
    assert_no_prompt(&output);
    assert!(
        stderr(&output).contains("--keyfile-old - and --keyfile-new - cannot both read from stdin"),
        "unexpected stderr: {}",
        stderr(&output)
    );
}

fn mark_keyslot_unsupported_argon2id(path: &Path, index: usize) {
    let mut bytes = fs::read(path).unwrap();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + 2;
    bytes[offset..offset + 2].copy_from_slice(&[0xDF, 0x02]);
    fs::write(path, bytes).unwrap();
}

fn write_malformed_v1_fixture(path: &Path) {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[0..4].copy_from_slice(b"DXIO");
    bytes[4..6].copy_from_slice(&[0x00, 0x01]);
    bytes[6..10].copy_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    bytes[10] = 0x01;
    bytes[11] = 0x01;
    bytes[12] = 0x01;
    bytes[13] = 0x01;
    bytes[14] = 0x04;
    bytes[15] = 1;
    fs::write(path, bytes).unwrap();
}

fn decode_hex_fixture(path: &Path) -> Vec<u8> {
    let fixture = fs::read_to_string(path).unwrap();
    let nibbles: Vec<u8> = fixture
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .map(|ch| ch.to_digit(16).unwrap() as u8)
        .collect();

    assert!(nibbles.len().is_multiple_of(2));
    nibbles
        .chunks_exact(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

fn retired_v1_fixture_bytes() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("dexios-core")
        .join("tests")
        .join("testdata")
        .join("v1_valid_single_keyslot.hex");
    let bytes = decode_hex_fixture(&path);
    assert_eq!(bytes.len(), RETIRED_CURRENT_V1_HEADER_LEN);
    bytes
}

fn write_retired_v1_fixture(path: &Path) {
    fs::write(path, retired_v1_fixture_bytes()).unwrap();
}

#[test]
fn key_add_reads_new_key_after_old_key_verification_succeeds() {
    let test_dir = TestDir::new("add-valid");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");
    let old_keyfile = write_keyfile(test_dir.path(), "old.key", PASSWORD);
    let new_keyfile = write_keyfile(test_dir.path(), "new.key", "new-pass");

    let output = run_cli(
        test_dir.path(),
        &[
            "key",
            "add",
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
        "key add failed with correct old/new keyfiles: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );

    let old_verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some(PASSWORD),
    );
    assert!(
        old_verify.status.success(),
        "added file did not verify with original key: stdout={}\nstderr={}",
        stdout(&old_verify),
        stderr(&old_verify)
    );

    let new_verify = run_cli(
        test_dir.path(),
        &["key", "verify", encrypted.to_str().unwrap()],
        Some("new-pass"),
    );
    assert!(
        new_verify.status.success(),
        "added file did not verify with new key: stdout={}\nstderr={}",
        stdout(&new_verify),
        stderr(&new_verify)
    );
}

#[test]
fn key_add_uses_dexios_key_for_old_key_when_old_keyfile_is_absent() {
    let test_dir = TestDir::new("add-old-env");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");
    let new_keyfile = write_keyfile(test_dir.path(), "new.key", "new-pass");

    let output = run_cli(
        test_dir.path(),
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
        output.status.success(),
        "key add did not use DEXIOS_KEY as the old key fallback: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_no_prompt(&output);
}

#[test]
fn key_commands_report_retired_416_byte_v1_as_unsupported_format_before_prompting() {
    let test_dir = TestDir::new("retired-v1-key-commands");
    let retired = test_dir.path().join("retired-current-v1.enc");
    write_retired_v1_fixture(&retired);
    let retired = retired.to_str().unwrap();

    for (case, args) in [
        ("add", vec!["key", "add", retired]),
        ("change", vec!["key", "change", retired]),
        ("delete", vec!["key", "del", retired]),
        ("verify", vec!["key", "verify", retired]),
    ] {
        let output = run_cli(test_dir.path(), &args, None);
        let stderr = stderr(&output);
        assert!(
            !output.status.success(),
            "{case} unexpectedly accepted retired 416-byte V1"
        );
        assert!(
            stderr.contains("Unsupported Dexios format"),
            "{case} did not use unsupported-format mapping: {stderr}"
        );
        assert!(
            !stderr.contains("Malformed Dexios V1 header"),
            "{case} misclassified retired 416-byte V1 as malformed: {stderr}"
        );
        assert_no_prompt(&output);
    }
}

#[test]
fn key_add_wrong_old_key_does_not_read_new_key_source() {
    let test_dir = TestDir::new("add-wrong-old");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");
    let original = fs::read(&encrypted).unwrap();
    let old_keyfile = write_keyfile(test_dir.path(), "wrong-old.key", "wrong-pass");
    let missing_new_keyfile = test_dir.path().join("missing-new.key");

    let output = run_cli(
        test_dir.path(),
        &[
            "key",
            "add",
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
    assert_sanitized_key_stderr(&stderr(&wrong));
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
    assert_sanitized_key_stderr(&stderr(&unsupported_output));
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
fn key_change_uses_dexios_key_for_old_key_when_old_keyfile_is_absent() {
    let test_dir = TestDir::new("change-old-env");
    let encrypted = encrypt_fixture(test_dir.path(), "plain");
    let new_keyfile = write_keyfile(test_dir.path(), "new.key", "new-pass");

    let output = run_cli(
        test_dir.path(),
        &[
            "key",
            "change",
            "--keyfile-new",
            new_keyfile.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );

    assert!(
        output.status.success(),
        "key change did not use DEXIOS_KEY as the old key fallback: stdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert_no_prompt(&output);
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
    assert_sanitized_key_stderr(&stderr(&wrong_output));
}

#[test]
fn key_mutation_cli_source_orders_secrets_through_domain_intents() {
    let add_old_key_secret = KEY_SUBCOMMAND_SOURCE
        .find("params.key_old.get_secret")
        .expect("add/change should read the old key");
    let add_old_key_proof = KEY_SUBCOMMAND_SOURCE
        .find("verify_old_key")
        .expect("add/change should verify the old key before reading the new key");
    let add_new_key_secret = KEY_SUBCOMMAND_SOURCE
        .find("params.key_new.get_secret")
        .expect("add/change should read the new key after old proof");
    let old_key_secret = KEY_SUBCOMMAND_SOURCE
        .rfind("params.key_old.get_secret")
        .expect("change should still read the old key");
    let old_key_proof = KEY_SUBCOMMAND_SOURCE
        .rfind("verify_old_key")
        .expect("change should verify the old key before reading the new key");
    let new_key_secret = KEY_SUBCOMMAND_SOURCE
        .rfind("params.key_new.get_secret")
        .expect("change should still read the new key after old proof");

    assert!(
        add_old_key_secret < add_old_key_proof && add_old_key_proof < add_new_key_secret,
        "key add must read old key, verify it in domain, then read the new key"
    );
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

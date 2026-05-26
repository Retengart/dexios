use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::cipher::wrap_v1_master_key;
use core::header::common::{
    CANONICAL_V1_DISCRIMINATOR, HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN, KeyslotNonce,
    PayloadNonce, RETIRED_CURRENT_V1_HEADER_LEN, Salt as HeaderSalt,
};
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use core::payload::{ArchiveBodyFrame, ArchiveManifest, ManifestEntry, ManifestFirstPayload};
use core::primitives::{MasterKey, WrappingKey};
use core::protected::Protected;
use core::stream::V1PayloadStream;
use domain::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use domain::storage::transaction::{LinkedOutputTransaction, TransactionError};
use domain::workflow_error::WorkflowErrorClass;

#[allow(dead_code)]
#[path = "../src/subcommands/errors.rs"]
mod cli_error_mappers;

const CORRECT_PASSWORD: &str = "correct-password";
const WRONG_PASSWORD: &str = "wrong-password";
const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
const SUBCOMMANDS_SOURCE: &str = include_str!("../src/subcommands.rs");
const ENCRYPT_SOURCE: &str = include_str!("../src/subcommands/encrypt.rs");
const DECRYPT_SOURCE: &str = include_str!("../src/subcommands/decrypt.rs");
const HEADER_SOURCE: &str = include_str!("../src/subcommands/header.rs");
const KEY_SOURCE: &str = include_str!("../src/subcommands/key.rs");
const PACK_SOURCE: &str = include_str!("../src/subcommands/pack.rs");
const UNPACK_SOURCE: &str = include_str!("../src/subcommands/unpack.rs");
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

fn production_mapper_source() -> &'static str {
    ERRORS_SOURCE
        .split("#[cfg(test)]")
        .next()
        .expect("production mapper source")
}

fn assert_no_default_source_chain(stderr: &str) {
    for forbidden in [
        "Caused by:",
        "caused by:",
        "source chain",
        "Stack backtrace",
    ] {
        assert!(
            !stderr.contains(forbidden),
            "normal CLI stderr must stay terse and omit source-chain text: {stderr}"
        );
    }
}

fn assert_no_default_debug_rendering(stderr: &str) {
    for forbidden in [
        "Error:",
        "TransactionError::",
        "WorkflowErrorClass::",
        "HeaderReadError",
        "PayloadError",
        "DecryptData",
        "Debug",
        "DXAR",
        "DXBF",
    ] {
        assert!(
            !stderr.contains(forbidden),
            "normal CLI stderr must render only the sanitized Display message: {stderr}"
        );
    }
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

fn write_manifest_archive_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let (header, encrypted_payload) = encrypted_manifest_archive_bytes(entries);
    let mut bytes = header;
    bytes.extend_from_slice(&encrypted_payload);
    fs::write(path, bytes).unwrap();
}

fn encrypted_manifest_archive_bytes(entries: &[(&str, &[u8])]) -> (Vec<u8>, Vec<u8>) {
    let mut manifest_entries = Vec::with_capacity(entries.len());
    let mut body_frames = Vec::new();
    for (index, (path, body)) in entries.iter().enumerate() {
        let normalized_path = path.trim_end_matches('/').as_bytes().to_vec();
        if path.ends_with('/') {
            manifest_entries.push(ManifestEntry::directory(normalized_path).unwrap());
        } else {
            manifest_entries.push(
                ManifestEntry::file(
                    normalized_path,
                    u64::try_from(body.len()).expect("test body length fits in u64"),
                )
                .unwrap(),
            );
            body_frames.push(
                ArchiveBodyFrame::new(
                    u32::try_from(index).expect("test entry index fits in u32"),
                    body.to_vec(),
                )
                .unwrap(),
            );
        }
    }

    let payload =
        ManifestFirstPayload::new(ArchiveManifest::new(manifest_entries).unwrap(), body_frames)
            .unwrap()
            .serialize()
            .unwrap();
    let (header, master_key) = manifest_archive_header_and_master_key();
    let mut encrypted_payload = Vec::new();
    V1PayloadStream::encrypt_file(
        master_key,
        &header,
        &mut Cursor::new(payload),
        &mut encrypted_payload,
    )
    .unwrap();

    (header.serialize().unwrap(), encrypted_payload)
}

fn manifest_archive_header_and_master_key() -> (V1Header, MasterKey) {
    let raw_key = Protected::new(CORRECT_PASSWORD.as_bytes().to_vec());
    let header_salt = HeaderSalt::new([17u8; 16]);
    let kdf_salt = header_salt.to_kdf_salt();
    let wrapping_key = Kdf::Blake3Balloon.derive(&raw_key, &kdf_salt).unwrap();
    let master_key = MasterKey::new([31u8; 32]);
    let keyslot_nonce = KeyslotNonce::new([13u8; 24]);
    let payload_nonce = PayloadNonce::new([7u8; 20]);
    let placeholder_keyslot =
        V1Keyslot::new(Kdf::Blake3Balloon, [0u8; 48], keyslot_nonce, header_salt);
    let placeholder_header =
        V1Header::new_manifest_archive(payload_nonce, V1Keyslots::single(placeholder_keyslot))
            .unwrap();
    let slot_wrapping_aad = placeholder_header
        .slot_wrapping_aad_for_physical_slot(
            core::header::v1::V1KeyslotIndex::try_from_physical_index(0).expect("slot zero index"),
        )
        .unwrap();
    let encrypted_master_key = wrap_v1_master_key(
        WrappingKey::from(wrapping_key),
        &master_key,
        &keyslot_nonce,
        &slot_wrapping_aad,
    )
    .unwrap();
    let keyslot = V1Keyslot::new(
        Kdf::Blake3Balloon,
        *encrypted_master_key.as_bytes(),
        keyslot_nonce,
        header_salt,
    );
    let header =
        V1Header::new_manifest_archive(payload_nonce, V1Keyslots::single(keyslot)).unwrap();
    (header, master_key)
}

fn write_legacy_header(path: &Path) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(&[0xDE, 0x05]).unwrap();
    file.write_all(&[7u8; 126]).unwrap();
    file.flush().unwrap();
}

fn write_malformed_v1_header(path: &Path) {
    let mut bytes = vec![0u8; HEADER_LEN];
    bytes[0..4].copy_from_slice(b"DXIO");
    bytes[4..6].copy_from_slice(&[0x00, 0x01]);
    bytes[6..10].copy_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    bytes[10] = 0x01;
    bytes[11] = 0x01;
    bytes[12] = 0x01;
    bytes[13] = 0x01;
    bytes[14] = 0x04;
    bytes[15] = 1;
    bytes.extend_from_slice(b"payload");
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

fn partial_commit_error() -> TransactionError {
    let test_dir = TestDir::new("partial-commit-error");
    let output_path = test_dir.path().join("committed.out");
    let header_path = test_dir.path().join("failed.header");
    fs::write(&header_path, b"existing header").unwrap();

    let mut graph = PathIdentityGraph::new();
    let output = graph
        .add_output(&output_path, PathRole::Output, OverwritePolicy::CreateNew)
        .unwrap();
    let header = graph
        .add_output(
            &header_path,
            PathRole::DetachedHeader,
            OverwritePolicy::CreateNew,
        )
        .unwrap();
    let mut transaction = LinkedOutputTransaction::new();
    let output_index = transaction.stage(output).unwrap();
    let header_index = transaction.stage(header).unwrap();
    transaction
        .staged_output_mut(output_index)
        .unwrap()
        .write_all(b"committed")
        .unwrap();
    transaction
        .staged_output_mut(header_index)
        .unwrap()
        .write_all(b"failed")
        .unwrap();
    transaction.commit_all().unwrap_err()
}

fn mark_keyslot_unsupported_argon2id(path: &Path, index: usize) {
    let mut bytes = fs::read(path).unwrap();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + 2;
    bytes[offset..offset + 2].copy_from_slice(&[0xDF, 0x02]);
    fs::write(path, bytes).unwrap();
}

#[test]
fn partial_commit_keeps_commit_failure_cli_mapping() {
    let pack_error = domain::pack::Error::Transaction(partial_commit_error());
    assert_eq!(
        pack_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_pack_error(pack_error).to_string();
    assert_eq!(mapped, "Unable to commit packed archive");
    assert!(
        !mapped.contains("Not enough temporary or output storage"),
        "partial commit evidence must not collapse into resource-pressure wording: {mapped}"
    );

    let unpack_error = domain::unpack::Error::Transaction(partial_commit_error());
    assert_eq!(
        unpack_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_unpack_error(unpack_error).to_string();
    assert_eq!(mapped, "Unable to commit unpacked output");
    assert!(
        !mapped.contains("Not enough temporary or output storage"),
        "partial commit evidence must not collapse into resource-pressure wording: {mapped}"
    );
}

#[test]
fn detached_encrypt_partial_publication_names_committed_and_failed_artifacts() {
    let encrypt_error = domain::encrypt::Error::DetachedPublication(partial_commit_error());
    assert_eq!(
        encrypt_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_encrypt_error(encrypt_error).to_string();
    assert_eq!(
        mapped,
        "Detached publication incomplete: payload committed, header failed; source cleanup was not authorized"
    );
    assert!(
        !mapped.contains("Unable to commit encrypted output"),
        "detached partial publication must not collapse into generic commit wording: {mapped}"
    );
}

#[test]
fn detached_pack_partial_publication_names_committed_and_failed_artifacts() {
    let pack_error = domain::pack::Error::DetachedPublication(partial_commit_error());
    assert_eq!(
        pack_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_pack_error(pack_error).to_string();
    assert_eq!(
        mapped,
        "Detached publication incomplete: payload committed, header failed; source cleanup was not authorized"
    );
    assert!(
        !mapped.contains("Unable to commit packed archive"),
        "detached partial publication must not collapse into generic commit wording: {mapped}"
    );
}

#[test]
fn cli_workflow_errors_are_routed_through_mapping_helpers() {
    assert!(SUBCOMMANDS_SOURCE.contains("pub mod errors;"));
    let mapper_source = production_mapper_source();
    assert!(ERRORS_SOURCE.contains("map_encrypt_error"));
    assert!(ERRORS_SOURCE.contains("map_decrypt_error"));
    assert!(ERRORS_SOURCE.contains("map_pack_error"));
    assert!(ERRORS_SOURCE.contains("map_unpack_error"));
    assert!(ERRORS_SOURCE.contains("Not enough temporary or output storage while packing archive"));
    assert!(
        ERRORS_SOURCE.contains("Not enough temporary or output storage while unpacking archive")
    );
    assert!(ERRORS_SOURCE.contains("error.is_resource_pressure()"));
    assert!(ERRORS_SOURCE.contains("map_header_error"));
    assert!(ERRORS_SOURCE.contains("map_key_error"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::TransactionCommitFailure"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::CleanupFailure"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::ResourcePressure"));
    assert_eq!(
        mapper_source
            .matches("match error.workflow_class()")
            .count(),
        6,
        "all six CLI workflow mappers should route by typed WorkflowErrorClass"
    );
    assert!(ENCRYPT_SOURCE.contains("map_encrypt_error"));
    assert!(DECRYPT_SOURCE.contains("map_decrypt_error"));
    assert!(PACK_SOURCE.contains("map_pack_error"));
    assert!(UNPACK_SOURCE.contains("map_unpack_error"));
    assert!(HEADER_SOURCE.contains("map_header_error"));
    assert!(KEY_SOURCE.contains("map_key_error"));
    for forbidden in [
        "clap::Error",
        "Command::error",
        ".to_string().contains(",
        "format!(",
        ".contains(",
        ".chain()",
        ".source()",
        "{error:#}",
        "{error:?}",
    ] {
        assert!(
            !mapper_source.contains(forbidden),
            "production workflow mappers must not use {forbidden} for post-parse error rendering"
        );
    }
}

#[test]
fn main_uses_display_only_error_boundary_for_workflow_failures() {
    assert!(
        MAIN_SOURCE.contains("fn run() -> Result<()>"),
        "main.rs should keep dispatch in a private run() that returns Result"
    );
    assert!(
        MAIN_SOURCE.contains("eprintln!(\"{error}\")"),
        "main.rs should render normal workflow errors with Display only"
    );
    assert!(
        MAIN_SOURCE.contains("std::process::exit(1)"),
        "main.rs should exit non-zero after rendering Display-only stderr"
    );
    assert!(
        !MAIN_SOURCE.contains("fn main() -> Result<()>"),
        "main() must not return Result because default error reporting is outside CLI control"
    );
    assert!(!MAIN_SOURCE.contains("{error:#}"));
    assert!(!MAIN_SOURCE.contains("{error:?}"));
    assert!(!MAIN_SOURCE.contains(".chain()"));
    assert!(!MAIN_SOURCE.contains(".source()"));
}

#[test]
fn wrong_key_decrypt_default_stderr_is_display_only() {
    let test_dir = TestDir::new("workflow-error-display-only");
    encrypt_fixture(&test_dir);

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["decrypt", "--force", "plain.enc", "plain.out"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    assert_eq!(
        wrong_key_stderr, "Authentication failed\n",
        "default workflow stderr should be the sanitized Display message only"
    );
    assert_no_default_source_chain(&wrong_key_stderr);
    assert_no_default_debug_rendering(&wrong_key_stderr);
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains(CORRECT_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
}

#[test]
fn malformed_and_unsupported_headers_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-header");
    let malformed = test_dir.path().join("malformed.enc");
    let legacy = test_dir.path().join("legacy.hdr");
    let retired = test_dir.path().join("retired-current-v1.enc");
    write_malformed_v1_header(&malformed);
    write_legacy_header(&legacy);
    write_retired_v1_fixture(&retired);

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
    assert!(
        malformed_stderr.contains("non-zero reserved bytes in V1 header"),
        "header details should preserve safe V1 parse classes: {malformed_stderr}"
    );

    let dump_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "header",
            "dump",
            "--force",
            "malformed.enc",
            "malformed.hdr",
        ],
    );
    assert!(!dump_output.status.success());
    let dump_stderr = stderr(&dump_output);
    assert!(
        dump_stderr.contains("Malformed Dexios V1 header"),
        "header dump did not expose the malformed header class: {dump_stderr}"
    );
    assert!(
        !dump_stderr.contains("non-zero reserved bytes in V1 header"),
        "header dump must keep malformed parser details terse: {dump_stderr}"
    );
    assert!(!test_dir.path().join("malformed.hdr").exists());

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

    let retired_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "details", "retired-current-v1.enc"],
    );
    assert!(!retired_output.status.success());
    let retired_stderr = stderr(&retired_output);
    assert!(
        retired_stderr.contains("Unsupported Dexios format"),
        "retired 416-byte V1 did not expose the unsupported format class: {retired_stderr}"
    );
    assert!(
        !retired_stderr.contains("Malformed Dexios V1 header"),
        "retired 416-byte V1 was misclassified as malformed: {retired_stderr}"
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

    let mapped_commit_error = cli_error_mappers::map_encrypt_error(
        domain::encrypt::Error::Transaction(TransactionError::Persist {
            path: PathBuf::from("cipher.enc"),
            source: None,
        }),
    )
    .to_string();
    assert_eq!(mapped_commit_error, "Unable to commit encrypted output");

    fs::create_dir(test_dir.path().join("out-dir")).unwrap();
    let transaction_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "out-dir"],
    );
    assert!(!transaction_output.status.success());
    let transaction_stderr = stderr(&transaction_output);
    assert!(
        transaction_stderr.contains("I/O failure while encrypting data"),
        "directory target preflight failure did not stay in the encrypt I/O class: {transaction_stderr}"
    );
}

#[test]
fn archive_pack_errors_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-pack");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();

    let alias_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["pack", "--force", "source", "source/archive.enc"],
    );
    assert!(!alias_output.status.success());
    let alias_stderr = stderr(&alias_output);
    assert!(
        alias_stderr.contains("Unsafe path"),
        "pack alias did not expose typed unsafe path class: {alias_stderr}"
    );
}

#[test]
fn archive_unpack_errors_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-unpack");
    let unsafe_archive = test_dir.path().join("unsafe.enc");
    write_manifest_archive_with_entries(&unsafe_archive, &[("../escape.txt", b"escape")]);

    let unsafe_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["unpack", "--force", "unsafe.enc", "out"],
    );
    assert!(!unsafe_output.status.success());
    let unsafe_stderr = stderr(&unsafe_output);
    assert!(
        unsafe_stderr.contains("Unsafe archive path"),
        "unsafe unpack did not expose typed unsafe path class: {unsafe_stderr}"
    );
    assert_no_default_source_chain(&unsafe_stderr);
    assert_no_default_debug_rendering(&unsafe_stderr);
    assert!(!test_dir.path().join("escape.txt").exists());

    let collision_archive = test_dir.path().join("collision.enc");
    write_manifest_archive_with_entries(&collision_archive, &[("a", b"file"), ("a/b", b"child")]);

    let collision_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["unpack", "--force", "collision.enc", "collision-out"],
    );
    assert!(!collision_output.status.success());
    let collision_stderr = stderr(&collision_output);
    assert!(
        collision_stderr.contains("Unsafe archive path"),
        "collision unpack did not expose typed unsafe path class: {collision_stderr}"
    );
    assert_no_default_source_chain(&collision_stderr);
    assert_no_default_debug_rendering(&collision_stderr);

    fs::write(
        test_dir.path().join("legacy.zip"),
        b"PK\x03\x04legacy zip bytes",
    )
    .unwrap();
    let legacy_encrypt_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "legacy.zip", "legacy.enc"],
    );
    assert!(
        legacy_encrypt_output.status.success(),
        "legacy raw archive fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&legacy_encrypt_output.stdout),
        stderr(&legacy_encrypt_output)
    );
    let legacy_unpack_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["unpack", "--force", "legacy.enc", "legacy-out"],
    );
    assert!(!legacy_unpack_output.status.success());
    let legacy_stderr = stderr(&legacy_unpack_output);
    assert!(
        legacy_stderr.contains("Malformed archive data")
            || legacy_stderr.contains("Unsupported archive format"),
        "legacy raw archive payload must fail as a terse archive class: {legacy_stderr}"
    );
    assert_no_default_source_chain(&legacy_stderr);
    assert_no_default_debug_rendering(&legacy_stderr);
    assert!(!test_dir.path().join("legacy-out").exists());

    fs::create_dir_all(test_dir.path().join("packed-source")).unwrap();
    fs::write(
        test_dir.path().join("packed-source/plain.txt"),
        b"top secret",
    )
    .unwrap();
    let pack_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["pack", "--force", "packed-source", "packed.enc"],
    );
    assert!(
        pack_output.status.success(),
        "pack fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&pack_output.stdout),
        stderr(&pack_output)
    );

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["unpack", "--force", "packed.enc", "wrong-key-out"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    assert!(
        wrong_key_stderr.contains("Authentication failed"),
        "wrong-key unpack did not expose terse auth class: {wrong_key_stderr}"
    );
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
    assert_no_default_source_chain(&wrong_key_stderr);
    assert_no_default_debug_rendering(&wrong_key_stderr);
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
    assert_no_default_source_chain(&wrong_key_stderr);

    fs::write(test_dir.path().join("old.key"), CORRECT_PASSWORD).unwrap();
    let delete_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "del", "--keyfile", "old.key", "plain.enc"],
    );
    assert!(!delete_output.status.success());
    let delete_stderr = stderr(&delete_output);
    assert!(
        delete_stderr.contains("Cannot remove the final V1 keyslot"),
        "stderr did not expose the unsupported workflow class: {delete_stderr}"
    );
    assert!(!delete_stderr.contains(CORRECT_PASSWORD));
    assert_no_default_source_chain(&delete_stderr);
}

#[test]
fn key_verify_wrong_key_and_unsupported_kdf_use_typed_mapping() {
    let test_dir = TestDir::new("workflow-error-key-verify");
    encrypt_fixture(&test_dir);

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["key", "verify", "plain.enc"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    assert!(
        wrong_key_stderr.contains("Incorrect key"),
        "stderr did not expose the terse incorrect-key class: {wrong_key_stderr}"
    );
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains(CORRECT_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
    assert_no_default_source_chain(&wrong_key_stderr);

    mark_keyslot_unsupported_argon2id(&test_dir.path().join("plain.enc"), 0);
    let unsupported_kdf_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "verify", "plain.enc"],
    );
    assert!(!unsupported_kdf_output.status.success());
    let unsupported_kdf_stderr = stderr(&unsupported_kdf_output);
    assert!(
        unsupported_kdf_stderr.contains("Unsupported keyslot KDF tag"),
        "stderr did not expose the typed unsupported-KDF class: {unsupported_kdf_stderr}"
    );
    assert!(!unsupported_kdf_stderr.contains(CORRECT_PASSWORD));

    write_retired_v1_fixture(&test_dir.path().join("retired-current-v1.enc"));
    let retired_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "verify", "retired-current-v1.enc"],
    );
    assert!(!retired_output.status.success());
    let retired_stderr = stderr(&retired_output);
    assert!(
        retired_stderr.contains("Unsupported Dexios format"),
        "retired 416-byte V1 did not expose key unsupported-format class: {retired_stderr}"
    );
    assert!(
        !retired_stderr.contains("Malformed Dexios V1 header"),
        "key verify misclassified retired 416-byte V1 as malformed: {retired_stderr}"
    );
    assert_no_default_source_chain(&retired_stderr);
}

#[test]
fn header_exact_failures_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-header-exact");
    encrypt_fixture(&test_dir);

    let dump_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "dump", "plain.enc", "plain.hdr"],
    );
    assert!(
        dump_output.status.success(),
        "header dump fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&dump_output.stdout),
        stderr(&dump_output)
    );

    let header_only_dump = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "dump", "--force", "plain.hdr", "second.hdr"],
    );
    assert!(!header_only_dump.status.success());
    let header_only_stderr = stderr(&header_only_dump);
    assert!(
        header_only_stderr.contains("missing payload"),
        "header-only dump did not expose the missing-payload class: {header_only_stderr}"
    );
    assert!(!test_dir.path().join("second.hdr").exists());

    let header_bytes = fs::read(test_dir.path().join("plain.hdr")).unwrap();
    let encrypted_bytes = fs::read(test_dir.path().join("plain.enc")).unwrap();
    let mut stripped_bytes = vec![0u8; HEADER_LEN];
    stripped_bytes.extend_from_slice(&encrypted_bytes[HEADER_LEN..]);

    fs::write(
        test_dir.path().join("short.hdr"),
        &header_bytes[..HEADER_LEN - 1],
    )
    .unwrap();
    fs::write(test_dir.path().join("short-target.enc"), &stripped_bytes).unwrap();
    let short_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "header",
            "restore",
            "--force",
            "short.hdr",
            "short-target.enc",
        ],
    );
    assert!(!short_output.status.success());
    let short_stderr = stderr(&short_output);
    assert!(
        short_stderr.contains("too short"),
        "short detached header did not expose the exact-length class: {short_stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("short-target.enc")).unwrap(),
        stripped_bytes
    );

    let mut trailing = header_bytes.clone();
    trailing.push(0xAA);
    fs::write(test_dir.path().join("trailing.hdr"), trailing).unwrap();
    fs::write(test_dir.path().join("trailing-target.enc"), &stripped_bytes).unwrap();
    let trailing_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "header",
            "restore",
            "--force",
            "trailing.hdr",
            "trailing-target.enc",
        ],
    );
    assert!(!trailing_output.status.success());
    let trailing_stderr = stderr(&trailing_output);
    assert!(
        trailing_stderr.contains("trailing bytes"),
        "trailing detached header did not expose the exact-length class: {trailing_stderr}"
    );

    let not_stripped_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "restore", "--force", "plain.hdr", "plain.enc"],
    );
    assert!(!not_stripped_output.status.success());
    let not_stripped_stderr = stderr(&not_stripped_output);
    assert!(
        not_stripped_stderr.contains("not stripped"),
        "restore into a non-stripped target did not expose the target-state class: {not_stripped_stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("plain.enc")).unwrap(),
        encrypted_bytes
    );
}

#[test]
fn io_and_overwrite_classes_are_explicitly_mapped() {
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::IoFailure"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::OverwriteDenied"));
    assert!(ERRORS_SOURCE.contains("Output already exists"));

    let test_dir = TestDir::new("workflow-error-io");
    let missing_header_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "dump", "missing.enc", "missing.hdr"],
    );
    assert!(!missing_header_output.status.success());
    let missing_header_stderr = stderr(&missing_header_output);
    assert!(
        missing_header_stderr.contains("I/O failure"),
        "missing header input did not expose the typed IO class: {missing_header_stderr}"
    );

    let missing_key_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "verify", "missing.enc"],
    );
    assert!(!missing_key_output.status.success());
    let missing_key_stderr = stderr(&missing_key_output);
    assert!(
        missing_key_stderr.contains("I/O failure while reading key workflow target"),
        "missing key target did not expose the typed IO class: {missing_key_stderr}"
    );
}

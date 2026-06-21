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
        clippy::allow_attributes,
        clippy::redundant_pub_crate,
        reason = "shared test-support helpers assert exact behavior and may panic on failure"
    )
)]
#![allow(
    dead_code,
    unused_imports,
    reason = "shared CLI workflow-error helpers are imported selectively across test crates"
)]

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use std::process::Command;

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

#[path = "keyfile_cli.rs"]
mod keyfile_cli;
#[path = "tempdir.rs"]
#[expect(dead_code, reason = "shared tempdir test helper")]
mod tempdir;

pub(crate) use tempdir::TestDir;

pub(crate) const CORRECT_PASSWORD: &str = "correct-password";
pub(crate) const WRONG_PASSWORD: &str = "wrong-password";

fn keyslot_nonce(bytes: [u8; 24]) -> KeyslotNonce {
    KeyslotNonce::try_from_slice(&bytes).expect("valid keyslot nonce")
}

fn payload_nonce(bytes: [u8; 20]) -> PayloadNonce {
    PayloadNonce::try_from_slice(&bytes).expect("valid payload nonce")
}

pub(crate) fn run_cli(current_dir: &Path, key: &str, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command.current_dir(current_dir);
    keyfile_cli::append_keyed_args(&mut command, current_dir, key, args);
    command.output().unwrap()
}

pub(crate) fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub(crate) fn assert_no_default_source_chain(stderr: &str) {
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

pub(crate) fn assert_no_default_debug_rendering(stderr: &str) {
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

pub(crate) fn encrypt_fixture(test_dir: &TestDir) {
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

pub(crate) fn write_manifest_archive_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
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
    let wrapping_key = Kdf::Argon2id.derive(&raw_key, &kdf_salt).unwrap();
    let master_key = MasterKey::new([31u8; 32]);
    let keyslot_nonce = keyslot_nonce([13u8; 24]);
    let payload_nonce = payload_nonce([7u8; 20]);
    let placeholder_keyslot = V1Keyslot::new(Kdf::Argon2id, [0u8; 48], keyslot_nonce, header_salt);
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
        Kdf::Argon2id,
        *encrypted_master_key.as_bytes(),
        keyslot_nonce,
        header_salt,
    );
    let header =
        V1Header::new_manifest_archive(payload_nonce, V1Keyslots::single(keyslot)).unwrap();
    (header, master_key)
}

pub(crate) fn write_legacy_header(path: &Path) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(&[0xDE, 0x05]).unwrap();
    file.write_all(&[7u8; 126]).unwrap();
    file.flush().unwrap();
}

pub(crate) fn write_malformed_v1_header(path: &Path) {
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

pub(crate) fn write_retired_v1_fixture(path: &Path) {
    fs::write(path, retired_v1_fixture_bytes()).unwrap();
}

pub(crate) fn partial_commit_error() -> TransactionError {
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

pub(crate) fn mark_keyslot_unsupported_argon2id(path: &Path, index: usize) {
    let mut bytes = fs::read(path).unwrap();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + 2;
    bytes[offset..offset + 2].copy_from_slice(&[0xDF, 0x02]);
    fs::write(path, bytes).unwrap();
}

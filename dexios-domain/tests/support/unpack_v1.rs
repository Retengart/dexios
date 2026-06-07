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
    reason = "shared unpack helpers are imported selectively across test crates"
)]

pub(super) use std::fs;
pub(super) use std::io::Cursor;
pub(super) use std::path::{Path, PathBuf};
pub(super) use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

pub(super) use core::cipher::wrap_v1_master_key;
pub(super) use core::header::common::{HEADER_LEN, KeyslotNonce, PayloadNonce, Salt as HeaderSalt};
pub(super) use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
pub(super) use core::kdf::Kdf;
pub(super) use core::payload::{
    ArchiveBodyFrame, ArchiveManifest, ManifestEntry, ManifestFirstPayload, PayloadError,
};
pub(super) use core::primitives::{BLOCK_SIZE, MasterKey, WrappingKey};
pub(super) use core::protected::Protected;
pub(super) use core::stream::V1PayloadStream;
pub(super) use dexios_domain::decrypt;
pub(super) use dexios_domain::storage::identity::IdentityError;
#[cfg(feature = "test-support")]
pub(super) use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};
#[cfg(feature = "test-support")]
pub(super) use dexios_domain::storage::transaction::TransactionError;
pub(super) use dexios_domain::unpack;
#[allow(dead_code)]
#[path = "tempdir.rs"]
mod tempdir;
pub(super) use tempdir::DomainTestDir as TestDir;

pub(super) fn keyslot_nonce(bytes: [u8; 24]) -> KeyslotNonce {
    KeyslotNonce::try_from_slice(&bytes).expect("valid keyslot nonce")
}

pub(super) fn payload_nonce(bytes: [u8; 20]) -> PayloadNonce {
    PayloadNonce::try_from_slice(&bytes).expect("valid payload nonce")
}

pub(super) const PASSWORD: &[u8; 8] = b"12345678";
pub(super) const STREAM_TAG_LEN: usize = 16;
pub(super) type TestOnArchiveFile =
    Box<dyn Fn(PathBuf) -> Result<bool, unpack::ArchiveFileCallbackError>>;

pub(super) fn write_manifest_archive_without_directory_entries(path: &Path) {
    write_manifest_archive_with_entries(path, &[("nested/inner/file.txt", b"nested hello")]);
}

pub(super) fn write_manifest_archive_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let (header, encrypted_payload) = encrypted_manifest_archive_bytes(entries);
    let mut bytes = header;
    bytes.extend_from_slice(&encrypted_payload);
    fs::write(path, bytes).unwrap();
}

pub(super) fn write_detached_manifest_archive_with_entries(
    archive_path: &Path,
    detached_header_path: &Path,
    entries: &[(&str, &[u8])],
) {
    let (header, encrypted_payload) = encrypted_manifest_archive_bytes(entries);
    fs::write(detached_header_path, header).unwrap();
    let mut archive = vec![0u8; HEADER_LEN];
    archive.extend_from_slice(&encrypted_payload);
    fs::write(archive_path, archive).unwrap();
}

pub(super) fn write_malformed_manifest_archive_payload(path: &Path, payload: Vec<u8>) {
    let (header, master_key) = manifest_archive_header_and_master_key();
    let mut encrypted_payload = Vec::new();
    V1PayloadStream::encrypt_file(
        master_key,
        &header,
        &mut Cursor::new(payload),
        &mut encrypted_payload,
    )
    .unwrap();
    let mut bytes = header.serialize().unwrap();
    bytes.extend_from_slice(&encrypted_payload);
    fs::write(path, bytes).unwrap();
}

pub(super) fn raw_manifest_payload_with_file(path: &str, body: &[u8]) -> Vec<u8> {
    let mut payload = raw_manifest_payload(&[(path, body.len() as u64)]);
    append_raw_body_frame(&mut payload, 0, body.len() as u64, body);
    payload
}

pub(super) fn raw_manifest_payload(entries: &[(&str, u64)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"DXAR");
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(
        &u32::try_from(entries.len())
            .expect("test entry count fits in u32")
            .to_le_bytes(),
    );
    for (path, body_len) in entries {
        payload.push(0x01);
        payload.extend_from_slice(
            &u16::try_from(path.len())
                .expect("test path length fits in u16")
                .to_le_bytes(),
        );
        payload.extend_from_slice(&body_len.to_le_bytes());
        payload.extend_from_slice(path.as_bytes());
    }
    payload
}

pub(super) fn append_raw_body_frame(
    payload: &mut Vec<u8>,
    index: u32,
    declared_len: u64,
    body: &[u8],
) {
    payload.extend_from_slice(b"DXBF");
    payload.extend_from_slice(&index.to_le_bytes());
    payload.extend_from_slice(&declared_len.to_le_bytes());
    payload.extend_from_slice(body);
}

pub(super) fn encrypted_manifest_archive_bytes(entries: &[(&str, &[u8])]) -> (Vec<u8>, Vec<u8>) {
    let mut manifest_entries = Vec::with_capacity(entries.len());
    let mut body_frames = Vec::new();
    for (index, (path, body)) in entries.iter().enumerate() {
        let normalized_path = path.trim_end_matches('/').as_bytes().to_vec();
        if path.ends_with('/') {
            manifest_entries.push(ManifestEntry::directory(normalized_path).unwrap());
        } else {
            manifest_entries.push(ManifestEntry::file(normalized_path, body.len() as u64).unwrap());
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

pub(super) fn manifest_archive_header_and_master_key() -> (V1Header, MasterKey) {
    let raw_key = Protected::new(PASSWORD.to_vec());
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

pub(super) fn archive_path_with_depth(depth: usize) -> String {
    let mut path = PathBuf::new();
    for index in 0..depth {
        path.push(format!("dir{index}"));
    }
    path.push("file.txt");
    path.to_string_lossy().into_owned()
}

pub(super) fn archive_path_with_wide_components(depth: usize, component_len: usize) -> String {
    let mut path = PathBuf::new();
    for index in 0..depth {
        path.push(format!("{index:02}-{}", "a".repeat(component_len)));
    }
    path.to_string_lossy().into_owned()
}

pub(super) fn tamper_final_stream_chunk(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let final_offset = HEADER_LEN + (bytes[HEADER_LEN..].len().saturating_sub(STREAM_TAG_LEN));
    bytes[final_offset] ^= 0x40;
    fs::write(path, bytes).unwrap();
}

pub(super) fn truncate_stream(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes.pop().expect("encrypted archive has payload bytes");
    fs::write(path, bytes).unwrap();
}

pub(super) fn unpack_archive(
    encrypted_archive: &Path,
    output_dir: &Path,
    on_archive_file: Option<TestOnArchiveFile>,
) -> Result<dexios_domain::storage::transaction::CommitReceipt, unpack::Error> {
    let intent = unpack::UnpackIntent::new(
        encrypted_archive,
        None,
        output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        on_archive_file,
    )?;

    unpack::execute(intent)
}

#[cfg(feature = "test-support")]
pub(super) fn unpack_archive_with_failure_hooks(
    encrypted_archive: &Path,
    output_dir: &Path,
    hooks: FailureHooks,
) -> Result<dexios_domain::storage::transaction::CommitReceipt, unpack::Error> {
    let intent = unpack::UnpackIntent::new(
        encrypted_archive,
        None,
        output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    )?;

    unpack::execute_with_failure_hooks(intent, hooks)
}

#[cfg(feature = "test-support")]
pub(super) fn assert_first_persist_failure(result: Result<impl std::fmt::Debug, unpack::Error>) {
    assert!(
        matches!(
            result,
            Err(unpack::Error::Transaction(TransactionError::Persist { .. }))
        ),
        "expected first-file persist transaction failure, got {result:?}"
    );
}

pub(super) fn unpack_archive_with_detached_header(
    encrypted_archive: &Path,
    detached_header: &Path,
    output_dir: &Path,
) -> Result<dexios_domain::storage::transaction::CommitReceipt, unpack::Error> {
    let intent = unpack::UnpackIntent::new(
        encrypted_archive,
        Some(detached_header),
        output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    )?;

    unpack::execute(intent)
}

pub(super) fn assert_unpack_intent_rejects_unsafe_path(
    result: Result<unpack::UnpackIntent, unpack::Error>,
) {
    match result {
        Err(unpack::Error::PathIdentity(IdentityError::UnsafePath(_))) => {}
        Err(error) => panic!("expected intent unsafe path rejection, got {error:?}"),
        Ok(_) => panic!("expected intent unsafe path rejection, got Ok"),
    }
}

#[cfg(unix)]
pub(super) fn symlink_dir(src: &Path, dst: &Path) {
    std::os::unix::fs::symlink(src, dst).unwrap();
}

#[cfg(windows)]
pub(super) fn symlink_dir(src: &Path, dst: &Path) {
    std::os::windows::fs::symlink_dir(src, dst).unwrap();
}

#[cfg(unix)]
pub(super) fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink input check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
pub(super) fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_file(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink input check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn symlink_file_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping unpack symlink input check: symlink helper unsupported on this platform");
    false
}

#[cfg(unix)]
pub(super) fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink parent check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
pub(super) fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_dir(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink parent check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn symlink_dir_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping unpack symlink parent check: symlink helper unsupported on this platform");
    false
}

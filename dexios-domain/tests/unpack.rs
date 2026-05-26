use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use core::cipher::wrap_v1_master_key;
use core::header::common::{HEADER_LEN, KeyslotNonce, PayloadNonce, Salt as HeaderSalt};
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use core::payload::{
    ArchiveBodyFrame, ArchiveManifest, ManifestEntry, ManifestFirstPayload, PayloadError,
};
use core::primitives::{BLOCK_SIZE, MasterKey, WrappingKey};
use core::protected::Protected;
use core::stream::V1PayloadStream;
use dexios_domain::decrypt;
use dexios_domain::storage::identity::IdentityError;
#[cfg(feature = "test-support")]
use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};
#[cfg(feature = "test-support")]
use dexios_domain::storage::transaction::TransactionError;
use dexios_domain::unpack;

const PASSWORD: &[u8; 8] = b"12345678";
const STREAM_TAG_LEN: usize = 16;
type TestOnArchiveFile = Box<dyn Fn(PathBuf) -> Result<bool, String>>;

struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Self { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[test]
fn test_dir_uses_system_temp_root() {
    let dir = TestDir::new("unpack-temp-root");

    let temp_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(dir.path().starts_with(&temp_root));
    assert!(!dir.path().starts_with(Path::new("target/test-artifacts")));
}

fn write_manifest_archive_without_directory_entries(path: &Path) {
    write_manifest_archive_with_entries(path, &[("nested/inner/file.txt", b"nested hello")]);
}

fn write_manifest_archive_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let (header, encrypted_payload) = encrypted_manifest_archive_bytes(entries);
    let mut bytes = header;
    bytes.extend_from_slice(&encrypted_payload);
    fs::write(path, bytes).unwrap();
}

fn write_detached_manifest_archive_with_entries(
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

fn write_malformed_manifest_archive_payload(path: &Path, payload: Vec<u8>) {
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

fn raw_manifest_payload_with_file(path: &str, body: &[u8]) -> Vec<u8> {
    let mut payload = raw_manifest_payload(&[(path, body.len() as u64)]);
    append_raw_body_frame(&mut payload, 0, body.len() as u64, body);
    payload
}

fn raw_manifest_payload(entries: &[(&str, u64)]) -> Vec<u8> {
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

fn append_raw_body_frame(payload: &mut Vec<u8>, index: u32, declared_len: u64, body: &[u8]) {
    payload.extend_from_slice(b"DXBF");
    payload.extend_from_slice(&index.to_le_bytes());
    payload.extend_from_slice(&declared_len.to_le_bytes());
    payload.extend_from_slice(body);
}

fn encrypted_manifest_archive_bytes(entries: &[(&str, &[u8])]) -> (Vec<u8>, Vec<u8>) {
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

fn manifest_archive_header_and_master_key() -> (V1Header, MasterKey) {
    let raw_key = Protected::new(PASSWORD.to_vec());
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

fn archive_path_with_depth(depth: usize) -> String {
    let mut path = PathBuf::new();
    for index in 0..depth {
        path.push(format!("dir{index}"));
    }
    path.push("file.txt");
    path.to_string_lossy().into_owned()
}

fn archive_path_with_wide_components(depth: usize, component_len: usize) -> String {
    let mut path = PathBuf::new();
    for index in 0..depth {
        path.push(format!("{index:02}-{}", "a".repeat(component_len)));
    }
    path.to_string_lossy().into_owned()
}

fn tamper_final_stream_chunk(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let final_offset = HEADER_LEN + (bytes[HEADER_LEN..].len().saturating_sub(STREAM_TAG_LEN));
    bytes[final_offset] ^= 0x40;
    fs::write(path, bytes).unwrap();
}

fn truncate_stream(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes.pop().expect("encrypted archive has payload bytes");
    fs::write(path, bytes).unwrap();
}

fn unpack_archive(
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
fn unpack_archive_with_failure_hooks(
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
fn assert_first_persist_failure(result: Result<impl std::fmt::Debug, unpack::Error>) {
    assert!(
        matches!(
            result,
            Err(unpack::Error::Transaction(TransactionError::Persist { .. }))
        ),
        "expected first-file persist transaction failure, got {result:?}"
    );
}

#[cfg(feature = "test-support")]
#[test]
fn unpack_commit_failure_removes_created_selected_directories() {
    let test_dir = TestDir::new("unpack-rollback-created-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("created-dir/", b""), ("payload.txt", b"payload")],
    );

    let result = unpack_archive_with_failure_hooks(
        &encrypted_archive,
        &output_dir,
        FailureHooks::fail_on(FailurePoint::Persist),
    );

    assert_first_persist_failure(result);
    assert!(
        !output_dir.join("created-dir").exists(),
        "current-run selected directory must be removed after first-file commit failure"
    );
}

#[cfg(feature = "test-support")]
#[test]
fn unpack_commit_failure_preserves_preexisting_selected_directories() {
    let test_dir = TestDir::new("unpack-rollback-preexisting-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let preexisting_dir = output_dir.join("preexisting");
    let sentinel = preexisting_dir.join("sentinel.txt");

    fs::create_dir_all(&preexisting_dir).unwrap();
    fs::write(&sentinel, b"keep me").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("preexisting/", b""), ("payload.txt", b"payload")],
    );

    let result = unpack_archive_with_failure_hooks(
        &encrypted_archive,
        &output_dir,
        FailureHooks::fail_on(FailurePoint::Persist),
    );

    assert_first_persist_failure(result);
    assert!(
        preexisting_dir.is_dir(),
        "pre-existing selected directory must survive rollback"
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"keep me");
}

#[cfg(feature = "test-support")]
#[test]
fn unpack_commit_failure_removes_nested_intermediates_in_reverse_order() {
    let test_dir = TestDir::new("unpack-rollback-nested-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("nested/created/", b""), ("payload.txt", b"payload")],
    );

    let result = unpack_archive_with_failure_hooks(
        &encrypted_archive,
        &output_dir,
        FailureHooks::fail_on(FailurePoint::Persist),
    );

    assert_first_persist_failure(result);
    assert!(
        !output_dir.join("nested/created").exists(),
        "created nested selected directory must be removed"
    );
    assert!(
        !output_dir.join("nested").exists(),
        "intermediate directory created by create_unpack_dir_all must be removed"
    );
}

#[test]
fn unpack_corrupted_stream_never_extracts_outputs() {
    let test_dir = TestDir::new("unpack-corrupted-stream");

    for (label, corrupt) in [
        ("final-tamper", tamper_final_stream_chunk as fn(&Path)),
        ("one-byte-truncation", truncate_stream as fn(&Path)),
    ] {
        let encrypted_archive = test_dir.path().join(format!("{label}.enc"));
        let output_dir = test_dir.path().join(format!("{label}-out"));
        let payload = vec![0xA5; BLOCK_SIZE + 37];

        write_manifest_archive_with_entries(
            &encrypted_archive,
            &[("safe.txt", payload.as_slice())],
        );
        corrupt(&encrypted_archive);

        let result = unpack_archive(&encrypted_archive, &output_dir, None);

        assert!(
            matches!(
                result,
                Err(unpack::Error::Decrypt(decrypt::Error::DecryptData))
            ),
            "{label}: expected corrupted encrypted archive to fail authentication, got {result:?}"
        );
        assert!(
            !output_dir.join("safe.txt").exists(),
            "{label}: corrupted archive must not extract safe entries"
        );
    }
}

#[test]
fn unpack_archive_final_auth_failure_preserves_final_outputs() {
    let test_dir = TestDir::new("unpack-final-auth-no-commit");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("safe.txt");
    let sentinel = b"existing archive final output";
    let payload = vec![0xA5; BLOCK_SIZE + 37];

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, sentinel).unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("safe.txt", payload.as_slice())]);
    tamper_final_stream_chunk(&encrypted_archive);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::Decrypt(decrypt::Error::DecryptData))
        ),
        "archive final-auth failure must be reported before extraction commit, got {result:?}"
    );
    assert_eq!(
        fs::read(&existing_file).unwrap(),
        sentinel.as_slice(),
        "unpack final output must remain unchanged until stream final auth succeeds"
    );
}

fn unpack_archive_with_detached_header(
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

fn assert_unpack_intent_rejects_unsafe_path(result: Result<unpack::UnpackIntent, unpack::Error>) {
    match result {
        Err(unpack::Error::PathIdentity(IdentityError::UnsafePath(_))) => {}
        Err(error) => panic!("expected intent unsafe path rejection, got {error:?}"),
        Ok(_) => panic!("expected intent unsafe path rejection, got Ok"),
    }
}

#[test]
fn should_unpack_archive_without_explicit_directory_entries() {
    let test_dir = TestDir::new("unpack-no-dirs");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_without_directory_entries(&encrypted_archive);

    unpack_archive(&encrypted_archive, &output_dir, None).unwrap();

    let restored = fs::read_to_string(output_dir.join("nested/inner/file.txt")).unwrap();
    assert_eq!(restored, "nested hello");
}

#[test]
fn unpack_directory_only_archive_returns_directory_commit_receipt() {
    let test_dir = TestDir::new("unpack-directory-only");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(&encrypted_archive, &[("empty-dir/", b"")]);

    let receipt = unpack_archive(&encrypted_archive, &output_dir, None).unwrap();

    assert!(output_dir.join("empty-dir").is_dir());
    assert_eq!(receipt.committed_artifacts().len(), 1);
    assert_eq!(
        receipt.committed_artifacts()[0].path(),
        output_dir.join("empty-dir")
    );
}

#[test]
fn should_unpack_exact_block_manifest_payload() {
    let test_dir = TestDir::new("unpack-exact-block");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let payload = vec![0x7Au8; BLOCK_SIZE];

    write_manifest_archive_with_entries(&encrypted_archive, &[("exact.bin", payload.as_slice())]);

    unpack_archive(&encrypted_archive, &output_dir, None).unwrap();

    assert_eq!(fs::read(output_dir.join("exact.bin")).unwrap(), payload);
}

#[test]
fn unpack_rejects_entry_that_aliases_encrypted_input_archive() {
    let test_dir = TestDir::new("unpack-input-alias");
    let encrypted_archive = test_dir.path().join("archive.enc");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("archive.enc", b"plaintext replacement"),
            ("safe.txt", b"safe"),
        ],
    );
    let original_archive = fs::read(&encrypted_archive).unwrap();

    let result = unpack_archive(&encrypted_archive, test_dir.path(), None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::PathIdentity(
                IdentityError::AliasedPath { .. }
            ))
        ),
        "expected input archive alias rejection, got {result:?}"
    );
    assert_eq!(fs::read(&encrypted_archive).unwrap(), original_archive);
    assert!(!test_dir.path().join("safe.txt").exists());
}

#[test]
fn unpack_rejects_entry_that_aliases_detached_header() {
    let test_dir = TestDir::new("unpack-header-alias");
    let encrypted_archive = test_dir.path().join("archive-detached.enc");
    let detached_header = test_dir.path().join("archive.hdr");

    write_detached_manifest_archive_with_entries(
        &encrypted_archive,
        &detached_header,
        &[
            ("archive.hdr", b"detached header replacement"),
            ("safe.txt", b"safe"),
        ],
    );
    let original_header = fs::read(&detached_header).unwrap();

    let result =
        unpack_archive_with_detached_header(&encrypted_archive, &detached_header, test_dir.path());

    assert!(
        matches!(
            result,
            Err(unpack::Error::PathIdentity(
                IdentityError::AliasedPath { .. }
            ))
        ),
        "expected detached header alias rejection, got {result:?}"
    );
    assert_eq!(fs::read(&detached_header).unwrap(), original_header);
    assert!(!test_dir.path().join("safe.txt").exists());
}

#[test]
fn unpack_rejects_unsafe_entry_without_extracting_safe_sibling() {
    let test_dir = TestDir::new("unpack-unsafe-sibling");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
    assert!(!test_dir.path().join("escape.txt").exists());
}

#[test]
fn unpack_arch_04_d16_temp_cleanup_on_validation_failure_commits_no_outputs() {
    let test_dir = TestDir::new("unpack-temp-cleanup-validation");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(matches!(result, Err(unpack::Error::UnsafeOutputPath(_))));
    assert!(!output_dir.join("safe.txt").exists());
    assert!(!test_dir.path().join("escape.txt").exists());
}

#[test]
fn unpack_rejects_unsafe_archive_before_overwrite_callback() {
    let test_dir = TestDir::new("unpack-unsafe-no-prompt");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let callback_count = Arc::new(AtomicUsize::new(0));

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );

    let callback_count_for_closure = Arc::clone(&callback_count);
    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new(move |_| {
            callback_count_for_closure.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert_eq!(callback_count.load(Ordering::SeqCst), 0);
    assert!(!output_dir.join("safe.txt").exists());
}

#[test]
fn unpack_rejects_file_prefix_collision_before_extraction() {
    let test_dir = TestDir::new("unpack-prefix-collision");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(&encrypted_archive, &[("a", b"file"), ("a/b", b"child")]);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::DuplicateOutputPath(_))),
        "expected duplicate output path error, got {result:?}"
    );
    assert!(!output_dir.join("a").exists());
    assert!(!output_dir.join("a/b").exists());
}

#[test]
fn unpack_declined_safe_overwrite_is_skipped_after_validation() {
    let test_dir = TestDir::new("unpack-declined-overwrite");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("existing.txt", b"candidate replacement"),
            ("new.txt", b"new contents"),
        ],
    );

    let receipt = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let existing_file = existing_file.clone();
            move |path| Ok(path != existing_file)
        })),
    )
    .unwrap();

    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert_eq!(
        fs::read_to_string(output_dir.join("new.txt")).unwrap(),
        "new contents"
    );
    assert_eq!(receipt.committed_artifacts().len(), 1);
}

#[test]
fn unpack_rejects_archive_path_deeper_than_structural_limit() {
    let test_dir = TestDir::new("unpack-depth-limit");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let too_deep_path = archive_path_with_depth(65);

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[(too_deep_path.as_str(), b"too deep")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::ArchiveLimit(_))),
        "expected archive depth limit failure, got {result:?}"
    );
    assert!(!output_dir.join("dir0").exists());
}

#[test]
fn unpack_rejects_archive_path_longer_than_structural_limit() {
    let test_dir = TestDir::new("unpack-path-bytes-limit");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let too_long_path = archive_path_with_wide_components(64, 70);

    write_malformed_manifest_archive_payload(
        &encrypted_archive,
        raw_manifest_payload_with_file(too_long_path.as_str(), b"too long"),
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::NormalizedPathLimitExceeded { .. }
            ))
        ),
        "expected archive path byte payload limit failure, got {result:?}"
    );
    assert!(!output_dir.exists());
}

#[test]
fn unpack_rejects_manifest_payload_with_trailing_bytes() {
    let test_dir = TestDir::new("unpack-trailing-payload");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let mut payload = raw_manifest_payload_with_file("safe.txt", b"safe");
    payload.extend_from_slice(b"trailing");

    write_malformed_manifest_archive_payload(&encrypted_archive, payload);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(PayloadError::TrailingBytes(
                8
            )))
        ),
        "expected trailing payload bytes, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
}

#[test]
fn unpack_rejects_manifest_payload_with_missing_body_frame() {
    let test_dir = TestDir::new("unpack-missing-frame");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_malformed_manifest_archive_payload(
        &encrypted_archive,
        raw_manifest_payload(&[("safe.txt", 4)]),
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::MissingBodyFrame(0)
            ))
        ),
        "expected missing body frame, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
}

#[test]
fn unpack_rejects_manifest_payload_with_body_length_mismatch() {
    let test_dir = TestDir::new("unpack-length-mismatch");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let mut payload = raw_manifest_payload(&[("safe.txt", 4)]);
    append_raw_body_frame(&mut payload, 0, 5, b"abcde");

    write_malformed_manifest_archive_payload(&encrypted_archive, payload);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::BodyFrameLengthMismatch {
                    expected: 4,
                    actual: 5
                }
            ))
        ),
        "expected body length mismatch, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
}

#[test]
fn unpack_rejects_manifest_payload_with_body_frame_order_mismatch() {
    let test_dir = TestDir::new("unpack-order-mismatch");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let mut payload = raw_manifest_payload(&[("first.txt", 5), ("second.txt", 6)]);
    append_raw_body_frame(&mut payload, 1, 6, b"second");
    append_raw_body_frame(&mut payload, 0, 5, b"first");

    write_malformed_manifest_archive_payload(&encrypted_archive, payload);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::BodyFrameOrderMismatch {
                    expected: 0,
                    actual: 1
                }
            ))
        ),
        "expected body frame order mismatch, got {result:?}"
    );
    assert!(!output_dir.join("first.txt").exists());
    assert!(!output_dir.join("second.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidates_symlinked_prefix_created_after_validation() {
    let test_dir = TestDir::new("unpack-toctou-symlink");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("payload/secret.txt", b"top secret")],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidation_failure_preserves_existing_outputs() {
    let test_dir = TestDir::new("unpack-toctou-preserve");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");

    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("existing.txt", b"candidate replacement"),
            ("payload/secret.txt", b"top secret"),
        ],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert!(!outside_dir.join("secret.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidation_failure_does_not_create_new_nested_output_parent() {
    let test_dir = TestDir::new("unpack-toctou-no-new-parent");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("safe/nested.txt", b"candidate"),
            ("payload/secret.txt", b"top secret"),
        ],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(
        !output_dir.join("safe").exists(),
        "new nested output parent must not become visible before extraction commit"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidation_failure_does_not_create_selected_directory_entries() {
    let test_dir = TestDir::new("unpack-toctou-no-selected-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("selected-dir/", b""),
            ("payload/secret.txt", b"top secret"),
        ],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(
        !output_dir.join("selected-dir").exists(),
        "selected directory entries must not become visible before final revalidation"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidates_directory_entry_prefix_created_after_validation() {
    let test_dir = TestDir::new("unpack-toctou-dir-entry");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("payload/created/", b"")]);

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/created") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("created").exists());
}

#[cfg(unix)]
fn symlink_dir(src: &Path, dst: &Path) {
    std::os::unix::fs::symlink(src, dst).unwrap();
}

#[cfg(windows)]
fn symlink_dir(src: &Path, dst: &Path) {
    std::os::windows::fs::symlink_dir(src, dst).unwrap();
}

#[cfg(unix)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink input check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_file(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink input check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_file_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping unpack symlink input check: symlink helper unsupported on this platform");
    false
}

#[cfg(unix)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink parent check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_dir(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping unpack symlink parent check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_dir_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping unpack symlink parent check: symlink helper unsupported on this platform");
    false
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_intent_rejects_final_symlink_archive_input_before_parsing() {
    let test_dir = TestDir::new("unpack-input-final-symlink");
    let archive_target = test_dir.path().join("not-an-archive.enc");
    let archive_link = test_dir.path().join("archive-link.enc");
    let output_dir = test_dir.path().join("out");

    fs::write(&archive_target, b"not a dexios archive").unwrap();
    if !symlink_file_or_skip(&archive_target, &archive_link) {
        return;
    }

    let result = unpack::UnpackIntent::new(
        &archive_link,
        None,
        &output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    );

    assert_unpack_intent_rejects_unsafe_path(result);
    assert!(!output_dir.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_intent_rejects_final_symlink_detached_header_before_parsing() {
    let test_dir = TestDir::new("unpack-header-final-symlink");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let header_target = test_dir.path().join("not-a-header.hdr");
    let header_link = test_dir.path().join("header-link.hdr");
    let output_dir = test_dir.path().join("out");

    fs::write(&encrypted_archive, b"not a dexios archive").unwrap();
    fs::write(&header_target, b"not a dexios header").unwrap();
    if !symlink_file_or_skip(&header_target, &header_link) {
        return;
    }

    let result = unpack::UnpackIntent::new(
        &encrypted_archive,
        Some(header_link.as_path()),
        &output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    );

    assert_unpack_intent_rejects_unsafe_path(result);
    assert!(!output_dir.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_intent_rejects_archive_input_with_symlinked_parent_before_parsing() {
    let test_dir = TestDir::new("unpack-input-parent-symlink");
    let outside_dir = test_dir.path().join("outside");
    let parent_link = test_dir.path().join("archive-parent-link");
    let output_dir = test_dir.path().join("out");

    fs::create_dir(&outside_dir).unwrap();
    fs::write(outside_dir.join("archive.enc"), b"not a dexios archive").unwrap();
    if !symlink_dir_or_skip(&outside_dir, &parent_link) {
        return;
    }

    let result = unpack::UnpackIntent::new(
        parent_link.join("archive.enc"),
        None,
        &output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    );

    assert_unpack_intent_rejects_unsafe_path(result);
    assert!(!output_dir.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_rejects_symlinked_intermediate_output_paths() {
    let test_dir = TestDir::new("unpack-symlink-escape");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    symlink_dir(&outside_dir, &output_dir.join("payload"));

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("payload/secret.txt", b"top secret")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::UnsafeOutputPath(ref path))
                if path.ends_with("payload/secret.txt")
        ),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_rejects_symlinked_output_directory_prefix() {
    let test_dir = TestDir::new("unpack-symlink-output-prefix");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_prefix = test_dir.path().join("out-link");
    let output_dir = output_prefix.join("nested");

    fs::create_dir_all(&outside_dir).unwrap();
    symlink_dir(&outside_dir, &output_prefix);

    write_manifest_archive_with_entries(&encrypted_archive, &[("secret.txt", b"top secret")]);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("nested/secret.txt").exists());
}

#[test]
fn unpack_rejects_duplicate_targets_after_path_normalization() {
    let test_dir = TestDir::new("unpack-duplicate-targets");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("collision.txt", b"first"), ("collision.txt", b"second")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::DuplicateOutputPath(ref path))
                if path == Path::new("collision.txt")
        ),
        "expected duplicate output path error, got {result:?}"
    );
    assert!(!output_dir.join("collision.txt").exists());
}

#[test]
fn unpack_preserves_existing_file_when_later_extraction_fails() {
    let test_dir = TestDir::new("unpack-staged-preserve");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");
    let blocked_target = output_dir.join("blocked");

    fs::create_dir_all(&blocked_target).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("existing.txt", b"candidate replacement"),
            ("blocked", b"cannot replace directory"),
        ],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::UnsafeOutputPath(ref path)) if path == &blocked_target
        ),
        "expected unsafe output path error, got {result:?}"
    );
    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert!(blocked_target.is_dir());
}

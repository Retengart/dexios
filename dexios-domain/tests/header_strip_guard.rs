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
//! Guard tests for `header strip`: stripping the embedded header must be gated on
//! a byte-equal, valid, 512-byte detached header backup. A mismatched, invalid, or
//! wrong-size detached header must yield `Error::DetachedHeaderMismatch` and leave the
//! embedded header byte-unchanged on disk (no mutation).

use core::header::common::{HEADER_LEN, KeyslotNonce, PayloadNonce, Salt};
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use dexios_domain::header::{self, strip};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
            "dexios-domain-{prefix}-{}-{seq}-{nanos}",
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

fn v1_header_bytes() -> Vec<u8> {
    let keyslot = V1Keyslot::new(
        Kdf::Argon2id,
        [1u8; 48],
        KeyslotNonce::new([2u8; 24]),
        Salt::new([3u8; 16]),
    );
    let header = V1Header::new(PayloadNonce::new([4u8; 20]), V1Keyslots::single(keyslot))
        .expect("create V1 header");

    header.serialize().expect("serialize V1 header")
}

/// A second, *valid* V1 header with different field values (distinct salt/nonce). It
/// parses fine but is NOT byte-equal to `v1_header_bytes`.
fn other_v1_header_bytes() -> Vec<u8> {
    let keyslot = V1Keyslot::new(
        Kdf::Argon2id,
        [9u8; 48],
        KeyslotNonce::new([8u8; 24]),
        Salt::new([7u8; 16]),
    );
    let header = V1Header::new(PayloadNonce::new([6u8; 20]), V1Keyslots::single(keyslot))
        .expect("create other V1 header");

    header.serialize().expect("serialize other V1 header")
}

fn encrypted_artifact_bytes(payload: &[u8]) -> Vec<u8> {
    let mut bytes = v1_header_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn strip_rejects_mismatched_detached_header_without_mutation() {
    let test_dir = TestDir::new("strip-guard-mismatch");
    let target_path = test_dir.path().join("plain.enc");
    let header_path = test_dir.path().join("backup.hdr");
    let original = encrypted_artifact_bytes(b"payload bytes");
    // A different yet valid 512-byte V1 header — a wrong backup, not the embedded one.
    fs::write(&header_path, other_v1_header_bytes()).unwrap();
    fs::write(&target_path, &original).unwrap();

    let intent =
        strip::StripIntent::new(&header_path, &target_path).expect("strip intent constructs");
    let error = strip::execute(intent).expect_err("mismatched detached header must be rejected");

    assert!(matches!(error, header::Error::DetachedHeaderMismatch));
    assert_eq!(
        fs::read(&target_path).unwrap(),
        original,
        "embedded header must stay byte-unchanged when the backup mismatches"
    );
}

#[test]
fn strip_rejects_wrong_size_detached_header_without_mutation() {
    let test_dir = TestDir::new("strip-guard-wrong-size");
    let target_path = test_dir.path().join("plain.enc");
    let header_path = test_dir.path().join("short.hdr");
    let original = encrypted_artifact_bytes(b"payload bytes");
    // A non-512-byte detached header (truncated by one byte): still byte-prefix equal
    // to the embedded header, but the wrong length.
    let embedded_header = &original[..HEADER_LEN];
    fs::write(&header_path, &embedded_header[..HEADER_LEN - 1]).unwrap();
    fs::write(&target_path, &original).unwrap();

    let intent =
        strip::StripIntent::new(&header_path, &target_path).expect("strip intent constructs");
    let error = strip::execute(intent).expect_err("wrong-size detached header must be rejected");

    assert!(matches!(error, header::Error::DetachedHeaderMismatch));
    assert_eq!(
        fs::read(&target_path).unwrap(),
        original,
        "embedded header must stay byte-unchanged when the backup is the wrong size"
    );
}

#[test]
fn strip_rejects_invalid_detached_header_without_mutation() {
    let test_dir = TestDir::new("strip-guard-invalid");
    let target_path = test_dir.path().join("plain.enc");
    let header_path = test_dir.path().join("garbage.hdr");
    let original = encrypted_artifact_bytes(b"payload bytes");
    // A 512-byte detached header that is structurally invalid (all zeroes -> bad magic).
    fs::write(&header_path, vec![0u8; HEADER_LEN]).unwrap();
    fs::write(&target_path, &original).unwrap();

    let intent =
        strip::StripIntent::new(&header_path, &target_path).expect("strip intent constructs");
    let error = strip::execute(intent).expect_err("invalid detached header must be rejected");

    assert!(matches!(error, header::Error::DetachedHeaderMismatch));
    assert_eq!(
        fs::read(&target_path).unwrap(),
        original,
        "embedded header must stay byte-unchanged when the backup is invalid"
    );
}

#[test]
fn strip_succeeds_and_zeroes_embedded_header_with_matching_backup() {
    let test_dir = TestDir::new("strip-guard-match");
    let target_path = test_dir.path().join("plain.enc");
    let header_path = test_dir.path().join("backup.hdr");
    let payload = b"payload bytes";
    let original = encrypted_artifact_bytes(payload);
    // Exact byte-copy of the embedded header is the correct backup.
    let embedded_header = original[..HEADER_LEN].to_vec();
    fs::write(&header_path, &embedded_header).unwrap();
    fs::write(&target_path, &original).unwrap();

    let intent =
        strip::StripIntent::new(&header_path, &target_path).expect("strip intent constructs");
    strip::execute(intent).expect("matching detached header must permit strip");

    let stripped = fs::read(&target_path).unwrap();
    assert_eq!(stripped.len(), original.len());
    assert_eq!(
        &stripped[..HEADER_LEN],
        vec![0u8; HEADER_LEN].as_slice(),
        "embedded header region must be zeroed after a verified strip"
    );
    assert_eq!(
        &stripped[HEADER_LEN..],
        payload.as_slice(),
        "payload bytes must be preserved verbatim"
    );
}

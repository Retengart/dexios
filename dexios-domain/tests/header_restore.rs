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
use core::header::common::{HEADER_LEN, KeyslotNonce, PayloadNonce, Salt};
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use dexios_domain::header::{self, restore, strip};
use dexios_domain::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use dexios_domain::storage::mutation::{MutationFreshnessError, MutationSnapshot};
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

fn encrypted_artifact_bytes(payload: &[u8]) -> Vec<u8> {
    let mut bytes = v1_header_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

fn stripped_artifact_bytes(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; HEADER_LEN];
    bytes.extend_from_slice(payload);
    bytes
}

fn resolved_mutation_target(path: &Path) -> dexios_domain::storage::identity::ResolvedTarget {
    let mut graph = PathIdentityGraph::new();
    let target = graph
        .add_output(
            path,
            PathRole::MutationTarget,
            OverwritePolicy::ReplaceAtCommit,
        )
        .expect("resolve mutation target");
    graph.validate().expect("validate graph");
    target
}

#[test]
fn mutation_snapshot_rejects_same_inode_content_rewrite() {
    let test_dir = TestDir::new("mutation-snapshot-content");
    let target_path = test_dir.path().join("target.enc");
    fs::write(&target_path, b"original bytes").unwrap();
    let snapshot =
        MutationSnapshot::read(resolved_mutation_target(&target_path)).expect("snapshot target");

    fs::write(&target_path, b"changed bytes").unwrap();

    let error = snapshot
        .ensure_fresh()
        .expect_err("content rewrite must stale the snapshot");
    assert!(matches!(
        error,
        MutationFreshnessError::ContentChanged {
            role: PathRole::MutationTarget,
            ..
        }
    ));
    assert_eq!(fs::read(&target_path).unwrap(), b"changed bytes");
}

#[test]
#[cfg(unix)]
fn mutation_snapshot_rejects_path_replacement_with_identical_bytes() {
    let test_dir = TestDir::new("mutation-snapshot-identity");
    let target_path = test_dir.path().join("target.enc");
    let replacement_path = test_dir.path().join("replacement.enc");
    fs::write(&target_path, b"same bytes").unwrap();
    fs::write(&replacement_path, b"same bytes").unwrap();
    let snapshot =
        MutationSnapshot::read(resolved_mutation_target(&target_path)).expect("snapshot target");

    fs::rename(&replacement_path, &target_path).unwrap();

    let error = snapshot
        .ensure_fresh()
        .expect_err("path replacement must stale the snapshot");
    assert!(matches!(
        error,
        MutationFreshnessError::IdentityChanged {
            role: PathRole::MutationTarget,
            ..
        }
    ));
    assert_eq!(fs::read(&target_path).unwrap(), b"same bytes");
}

#[test]
fn restores_valid_v1_header_into_stripped_artifact_with_payload() {
    let test_dir = TestDir::new("restore-valid");
    let header_path = test_dir.path().join("plain.hdr");
    let target_path = test_dir.path().join("plain.enc");
    let header_bytes = v1_header_bytes();
    let payload = b"ciphertext payload";
    let mut stripped = vec![0u8; HEADER_LEN];
    stripped.extend_from_slice(payload);
    fs::write(&header_path, &header_bytes).unwrap();
    fs::write(&target_path, &stripped).unwrap();

    let intent = restore::RestoreIntent::new(&header_path, &target_path).expect("restore intent");
    restore::execute(intent).expect("restore into stripped artifact");

    let restored = fs::read(&target_path).unwrap();
    assert_eq!(&restored[..HEADER_LEN], header_bytes.as_slice());
    assert_eq!(&restored[HEADER_LEN..], payload);
}

#[test]
fn header_strip_rejects_target_rewrite_after_snapshot() {
    let test_dir = TestDir::new("strip-stale-content");
    let target_path = test_dir.path().join("plain.enc");
    let header_path = test_dir.path().join("plain.hdr");
    let changed = b"changed target after strip intent".to_vec();
    fs::write(&header_path, v1_header_bytes()).unwrap();
    fs::write(&target_path, encrypted_artifact_bytes(b"payload")).unwrap();
    let intent = strip::StripIntent::new(&header_path, &target_path).expect("strip intent");

    fs::write(&target_path, &changed).unwrap();

    let error = strip::execute(intent).expect_err("stale strip target must fail");
    assert!(matches!(error, header::Error::TargetChanged));
    assert_eq!(fs::read(&target_path).unwrap(), changed);
}

#[test]
#[cfg(unix)]
fn header_strip_rejects_target_replacement_after_snapshot() {
    let test_dir = TestDir::new("strip-stale-identity");
    let target_path = test_dir.path().join("plain.enc");
    let header_path = test_dir.path().join("plain.hdr");
    let replacement_path = test_dir.path().join("replacement.enc");
    let original = encrypted_artifact_bytes(b"payload");
    fs::write(&header_path, v1_header_bytes()).unwrap();
    fs::write(&target_path, &original).unwrap();
    fs::write(&replacement_path, &original).unwrap();
    let intent = strip::StripIntent::new(&header_path, &target_path).expect("strip intent");

    fs::rename(&replacement_path, &target_path).unwrap();

    let error = strip::execute(intent).expect_err("replaced strip target must fail");
    assert!(matches!(error, header::Error::TargetChanged));
    assert_eq!(fs::read(&target_path).unwrap(), original);
}

#[test]
fn header_restore_rejects_target_rewrite_after_snapshot() {
    let test_dir = TestDir::new("restore-stale-target");
    let header_path = test_dir.path().join("plain.hdr");
    let target_path = test_dir.path().join("plain.enc");
    let changed = b"changed stripped target after restore intent".to_vec();
    fs::write(&header_path, v1_header_bytes()).unwrap();
    fs::write(&target_path, stripped_artifact_bytes(b"payload")).unwrap();
    let intent = restore::RestoreIntent::new(&header_path, &target_path).expect("restore intent");

    fs::write(&target_path, &changed).unwrap();

    let error = restore::execute(intent).expect_err("stale restore target must fail");
    assert!(matches!(error, header::Error::TargetChanged));
    assert_eq!(fs::read(&target_path).unwrap(), changed);
}

#[test]
fn header_restore_rejects_detached_header_append_after_snapshot() {
    let test_dir = TestDir::new("restore-stale-header");
    let header_path = test_dir.path().join("plain.hdr");
    let target_path = test_dir.path().join("plain.enc");
    let original_target = stripped_artifact_bytes(b"payload");
    let mut changed_header = v1_header_bytes();
    fs::write(&header_path, &changed_header).unwrap();
    fs::write(&target_path, &original_target).unwrap();
    let intent = restore::RestoreIntent::new(&header_path, &target_path).expect("restore intent");

    changed_header.push(0xAA);
    fs::write(&header_path, changed_header).unwrap();

    let error = restore::execute(intent).expect_err("stale detached header must fail");
    assert!(matches!(error, header::Error::DetachedHeaderChanged));
    assert_eq!(fs::read(&target_path).unwrap(), original_target);
}

#[test]
#[cfg(unix)]
fn header_restore_rejects_detached_header_replacement_after_snapshot() {
    let test_dir = TestDir::new("restore-stale-header-identity");
    let header_path = test_dir.path().join("plain.hdr");
    let replacement_header_path = test_dir.path().join("replacement.hdr");
    let target_path = test_dir.path().join("plain.enc");
    let header_bytes = v1_header_bytes();
    let original_target = stripped_artifact_bytes(b"payload");
    fs::write(&header_path, &header_bytes).unwrap();
    fs::write(&replacement_header_path, &header_bytes).unwrap();
    fs::write(&target_path, &original_target).unwrap();
    let intent = restore::RestoreIntent::new(&header_path, &target_path).expect("restore intent");

    fs::rename(&replacement_header_path, &header_path).unwrap();

    let error = restore::execute(intent).expect_err("replaced detached header must fail");
    assert!(matches!(error, header::Error::DetachedHeaderChanged));
    assert_eq!(fs::read(&target_path).unwrap(), original_target);
}

#[test]
fn header_restore_rejects_short_target_without_writing() {
    let test_dir = TestDir::new("restore-short-target");
    let header_path = test_dir.path().join("plain.hdr");
    let target_path = test_dir.path().join("plain.enc");
    let target = vec![0u8; HEADER_LEN - 1];
    fs::write(&header_path, v1_header_bytes()).unwrap();
    fs::write(&target_path, &target).unwrap();

    let intent = restore::RestoreIntent::new(&header_path, &target_path).expect("restore intent");
    let error = restore::execute(intent).expect_err("short restore target should be rejected");

    assert!(matches!(
        error,
        header::Error::TargetTooShort {
            actual_len
        } if actual_len == HEADER_LEN - 1
    ));
    assert_eq!(fs::read(&target_path).unwrap(), target);
}

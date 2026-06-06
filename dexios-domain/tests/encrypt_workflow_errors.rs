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
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::storage::identity::OverwritePolicy;
use dexios_domain::storage::transaction::TransactionError;
use dexios_domain::workflow_error::WorkflowErrorClass;
use dexios_domain::{decrypt, encrypt};

static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);
static CURRENT_DIR_LOCK: Mutex<()> = Mutex::new(());

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

struct CurrentDirGuard {
    original: PathBuf,
}

impl CurrentDirGuard {
    fn change_to(path: &Path) -> Self {
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        Self { original }
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

fn protected_key() -> Protected<Vec<u8>> {
    Protected::new(b"correct-password".to_vec())
}

fn assert_has_source<E>(error: &E, label: &str)
where
    E: std::error::Error + ?Sized,
{
    assert!(
        error.source().is_some(),
        "{label} must preserve a diagnostic source"
    );
}

fn assert_no_source<E>(error: &E, label: &str)
where
    E: std::error::Error + ?Sized,
{
    assert!(error.source().is_none(), "{label} must remain source-free");
}

#[test]
fn encrypt_intent_rejects_aliased_input_output_before_mutation() {
    let test_dir = TestDir::new("alias-input-output");
    let plain = test_dir.path().join("plain.txt");
    let sentinel = b"plain text must survive";
    fs::write(&plain, sentinel).unwrap();

    let result = encrypt::EncryptIntent::new(
        &plain,
        &plain,
        OverwritePolicy::ReplaceAtCommit,
        None,
        protected_key(),
        Kdf::Argon2id,
    );

    assert!(matches!(result, Err(encrypt::Error::PathIdentity(_))));
    let error = result.unwrap_err();
    assert_eq!(error.workflow_class(), WorkflowErrorClass::UnsafePath);
    assert_eq!(fs::read(&plain).unwrap(), sentinel);
}

#[test]
fn encrypt_intent_rejects_aliased_output_and_detached_header_targets() {
    let test_dir = TestDir::new("alias-output-header");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("same-target");
    fs::write(&plain, b"plain text").unwrap();

    let result = encrypt::EncryptIntent::new(
        &plain,
        &encrypted,
        OverwritePolicy::CreateNew,
        Some(encrypt::DetachedHeaderTarget::new(
            &encrypted,
            OverwritePolicy::CreateNew,
        )),
        protected_key(),
        Kdf::Argon2id,
    );

    assert!(matches!(result, Err(encrypt::Error::PathIdentity(_))));
    let error = result.unwrap_err();
    assert_eq!(error.workflow_class(), WorkflowErrorClass::UnsafePath);
    assert!(
        !encrypted.exists(),
        "validated intent construction must not create final outputs"
    );
}

#[test]
fn encrypt_intent_with_relative_input_opens_validated_target_after_cwd_change() {
    let _cwd_lock = CURRENT_DIR_LOCK.lock().unwrap();
    let test_dir = TestDir::new("relative-input-target");
    let validated_dir = test_dir.path().join("validated");
    let decoy_dir = test_dir.path().join("decoy");
    fs::create_dir_all(&validated_dir).unwrap();
    fs::create_dir_all(&decoy_dir).unwrap();

    fs::write(validated_dir.join("plain.txt"), b"validated plaintext").unwrap();
    fs::write(
        decoy_dir.join("plain.txt"),
        b"decoy plaintext must not be encrypted",
    )
    .unwrap();

    let output = test_dir.path().join("cipher.dexios");
    let decrypted = test_dir.path().join("plain.out");
    let _cwd_guard = CurrentDirGuard::change_to(&validated_dir);

    let intent = encrypt::EncryptIntent::new(
        "plain.txt",
        &output,
        OverwritePolicy::CreateNew,
        None,
        protected_key(),
        Kdf::Argon2id,
    )
    .expect("build encrypt intent from relative input");

    std::env::set_current_dir(&decoy_dir).unwrap();
    encrypt::execute(intent).expect("encrypt validated input target");

    let decrypt_intent = decrypt::DecryptIntent::new(
        &output,
        &decrypted,
        OverwritePolicy::CreateNew,
        None::<&Path>,
        protected_key(),
        None,
    )
    .expect("build decrypt intent");
    decrypt::execute(decrypt_intent).expect("decrypt encrypted output");

    assert_eq!(fs::read(&decrypted).unwrap(), b"validated plaintext");
}

#[test]
fn encrypt_error_classification_keeps_actionable_failure_classes() {
    let transaction_commit = encrypt::Error::Transaction(TransactionError::Persist {
        path: PathBuf::from("ciphertext.dexios"),
        source: None,
    });

    assert_eq!(
        encrypt::Error::HashKey.workflow_class(),
        WorkflowErrorClass::KdfFailure
    );
    assert_eq!(
        encrypt::Error::WriteHeader.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_eq!(
        encrypt::Error::EncryptFile.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_eq!(
        transaction_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
}

#[test]
fn encrypt_open_and_stream_failures_preserve_diagnostic_sources() {
    let test_dir = TestDir::new("encrypt-source-chain");
    let plain = test_dir.path().join("plain.txt");
    let output = test_dir.path().join("plain.enc");
    fs::write(&plain, b"plain text").unwrap();
    let intent = encrypt::EncryptIntent::new(
        &plain,
        &output,
        OverwritePolicy::CreateNew,
        None,
        protected_key(),
        Kdf::Argon2id,
    )
    .expect("build encrypt intent before removing input");
    fs::remove_file(&plain).expect("remove validated input");

    let open_error = encrypt::execute(intent).expect_err("removed input must fail open");
    assert_eq!(open_error.workflow_class(), WorkflowErrorClass::IoFailure);
    assert_has_source(&open_error, "encrypt open input failure");
    assert!(
        !output.exists(),
        "failed encrypt open must not publish ciphertext output"
    );

    let directory_input = test_dir.path().join("directory-input");
    fs::create_dir(&directory_input).unwrap();
    let directory_output = test_dir.path().join("directory.enc");
    let intent = encrypt::EncryptIntent::new(
        &directory_input,
        &directory_output,
        OverwritePolicy::CreateNew,
        None,
        protected_key(),
        Kdf::Argon2id,
    )
    .expect("build encrypt intent for existing directory input");

    let stream_error = encrypt::execute(intent).expect_err("directory input must fail stream read");
    assert_eq!(stream_error.workflow_class(), WorkflowErrorClass::IoFailure);
    assert_has_source(&stream_error, "encrypt stream read failure");
    assert!(
        !directory_output.exists(),
        "failed encrypt stream read must not publish ciphertext output"
    );
}

#[test]
fn encrypt_secret_and_crypto_failures_stay_source_free() {
    let hash = encrypt::Error::HashKey;
    assert_eq!(hash.workflow_class(), WorkflowErrorClass::KdfFailure);
    assert_no_source(&hash, "encrypt KDF failure");

    let master_key = encrypt::Error::EncryptMasterKey;
    assert_eq!(master_key.workflow_class(), WorkflowErrorClass::Other);
    assert_no_source(&master_key, "encrypt master-key wrapping failure");
}

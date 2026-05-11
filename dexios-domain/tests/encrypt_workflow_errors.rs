use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::encrypt;
use dexios_domain::storage::identity::OverwritePolicy;
use dexios_domain::storage::transaction::{CommitReceipt, CommittedArtifact, TransactionError};
use dexios_domain::workflow_error::WorkflowErrorClass;

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

fn protected_key() -> Protected<Vec<u8>> {
    Protected::new(b"correct-password".to_vec())
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
        Kdf::Blake3Balloon,
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
        Kdf::Blake3Balloon,
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
fn encrypt_error_classification_keeps_actionable_failure_classes() {
    let transaction_commit = encrypt::Error::Transaction(TransactionError::PartialCommit {
        receipt: CommitReceipt { artifacts: vec![] },
        failed: CommittedArtifact {
            role: dexios_domain::storage::identity::PathRole::Output,
            path: PathBuf::from("ciphertext.dexios"),
        },
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

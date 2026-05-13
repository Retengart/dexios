use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::{HEADER_LEN, HEADER_STATIC_LEN};
use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::storage::identity::{OverwritePolicy, PathRole};
use dexios_domain::storage::transaction::{CommitReceipt, CommittedArtifact, TransactionError};
use dexios_domain::workflow_error::WorkflowErrorClass;
use dexios_domain::{decrypt, encrypt};

const DOMAIN_DECRYPT_SOURCE: &str = include_str!("../src/decrypt.rs");
const CORRECT_PASSWORD: &[u8] = b"correct-password";
const WRONG_PASSWORD: &[u8] = b"wrong-password";

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

fn protected_key(secret: &[u8]) -> Protected<Vec<u8>> {
    Protected::new(secret.to_vec())
}

fn encrypted_fixture(test_dir: &TestDir, name: &str) -> PathBuf {
    let plain = test_dir.path().join(format!("{name}.txt"));
    let encrypted = test_dir.path().join(format!("{name}.enc"));
    fs::write(&plain, b"Hello world").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &plain,
        &encrypted,
        OverwritePolicy::CreateNew,
        None,
        protected_key(CORRECT_PASSWORD),
        Kdf::Blake3Balloon,
    )
    .expect("build encrypt intent");
    encrypt::execute(intent).expect("encrypt fixture");

    encrypted
}

fn detached_encrypted_fixture(test_dir: &TestDir) -> (PathBuf, PathBuf) {
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let header = test_dir.path().join("plain.hdr");
    fs::write(&plain, b"Hello detached world").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &plain,
        &encrypted,
        OverwritePolicy::CreateNew,
        Some(encrypt::DetachedHeaderTarget::new(
            &header,
            OverwritePolicy::CreateNew,
        )),
        protected_key(CORRECT_PASSWORD),
        Kdf::Blake3Balloon,
    )
    .expect("build detached encrypt intent");
    encrypt::execute(intent).expect("encrypt detached fixture");

    (encrypted, header)
}

fn mark_first_keyslot_unsupported_argon2id(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes[HEADER_STATIC_LEN..HEADER_STATIC_LEN + 2].copy_from_slice(&[0xDF, 0x02]);
    fs::write(path, bytes).unwrap();
}

#[test]
fn decrypt_intent_rejects_aliased_input_output_before_mutation() {
    let test_dir = TestDir::new("decrypt-alias-input-output");
    let encrypted = encrypted_fixture(&test_dir, "plain");
    let sentinel = fs::read(&encrypted).unwrap();

    let result = decrypt::DecryptIntent::new(
        &encrypted,
        &encrypted,
        OverwritePolicy::ReplaceAtCommit,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    );

    assert!(matches!(result, Err(decrypt::Error::PathIdentity(_))));
    let error = result.unwrap_err();
    assert_eq!(error.workflow_class(), WorkflowErrorClass::UnsafePath);
    assert_eq!(fs::read(&encrypted).unwrap(), sentinel);
}

#[test]
fn decrypt_intent_rejects_detached_header_aliases_before_output_creation() {
    let test_dir = TestDir::new("decrypt-alias-detached-header");
    let encrypted = encrypted_fixture(&test_dir, "plain");
    let output = test_dir.path().join("plain.out");

    let result = decrypt::DecryptIntent::new(
        &encrypted,
        &output,
        OverwritePolicy::CreateNew,
        Some(encrypted.as_path()),
        protected_key(CORRECT_PASSWORD),
        None,
    );

    assert!(matches!(result, Err(decrypt::Error::PathIdentity(_))));
    let error = result.unwrap_err();
    assert_eq!(error.workflow_class(), WorkflowErrorClass::UnsafePath);
    assert!(
        !output.exists(),
        "validated intent construction must not create final plaintext output"
    );
}

#[test]
fn decrypt_error_classification_keeps_format_key_auth_io_and_transaction_distinct() {
    let transaction_commit = decrypt::Error::Transaction(TransactionError::PartialCommit {
        receipt: CommitReceipt { artifacts: vec![] },
        failed: CommittedArtifact {
            role: PathRole::Output,
            path: PathBuf::from("plain.out"),
        },
        source: None,
    });

    assert_eq!(
        decrypt::Error::DeserializeHeader.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_eq!(
        decrypt::Error::UnsupportedFormat([0xDE, 0x01]).workflow_class(),
        WorkflowErrorClass::UnsupportedFormat
    );
    assert_eq!(
        decrypt::Error::UnsupportedKdf([0xDF, 0x02]).workflow_class(),
        WorkflowErrorClass::KdfFailure
    );
    assert_eq!(
        decrypt::Error::DecryptMasterKey.workflow_class(),
        WorkflowErrorClass::IncorrectKey
    );
    assert_eq!(
        decrypt::Error::DecryptData.workflow_class(),
        WorkflowErrorClass::AuthenticationFailure
    );
    assert_eq!(
        decrypt::Error::ReadEncryptedData.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_eq!(
        transaction_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
}

#[test]
fn decrypt_intent_maps_wrong_key_unsupported_kdf_and_header_format_errors() {
    let test_dir = TestDir::new("decrypt-execution-errors");
    let wrong_key_input = encrypted_fixture(&test_dir, "wrong-key");
    let wrong_key_output = test_dir.path().join("wrong-key.out");

    let wrong_key = decrypt::DecryptIntent::new(
        &wrong_key_input,
        &wrong_key_output,
        OverwritePolicy::CreateNew,
        None::<&Path>,
        protected_key(WRONG_PASSWORD),
        None,
    )
    .expect("build wrong-key decrypt intent");
    let wrong_key_result = decrypt::execute(wrong_key);
    assert!(matches!(
        wrong_key_result,
        Err(decrypt::Error::DecryptMasterKey)
    ));
    assert_eq!(
        wrong_key_result.unwrap_err().workflow_class(),
        WorkflowErrorClass::IncorrectKey
    );
    assert!(
        !wrong_key_output.exists(),
        "wrong-key plaintext scratch must not become final output"
    );

    let unsupported_kdf_input = encrypted_fixture(&test_dir, "unsupported-kdf");
    mark_first_keyslot_unsupported_argon2id(&unsupported_kdf_input);
    let unsupported_kdf = decrypt::DecryptIntent::new(
        &unsupported_kdf_input,
        test_dir.path().join("unsupported-kdf.out"),
        OverwritePolicy::CreateNew,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build unsupported-kdf decrypt intent");
    let unsupported_kdf_result = decrypt::execute(unsupported_kdf);
    assert!(matches!(
        unsupported_kdf_result,
        Err(decrypt::Error::UnsupportedKdf([0xDF, 0x02]))
    ));

    let malformed_input = test_dir.path().join("malformed.enc");
    fs::write(&malformed_input, b"DXIO\x00\x01short").unwrap();
    let malformed = decrypt::DecryptIntent::new(
        &malformed_input,
        test_dir.path().join("malformed.out"),
        OverwritePolicy::CreateNew,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build malformed decrypt intent");
    let malformed_result = decrypt::execute(malformed);
    assert!(matches!(
        malformed_result,
        Err(decrypt::Error::DeserializeHeader)
    ));
    assert_eq!(
        malformed_result.unwrap_err().workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );

    let unsupported_input = test_dir.path().join("legacy.enc");
    fs::write(&unsupported_input, [0xDE, 0x01, 0, 0, 0, 0]).unwrap();
    let unsupported = decrypt::DecryptIntent::new(
        &unsupported_input,
        test_dir.path().join("legacy.out"),
        OverwritePolicy::CreateNew,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build unsupported-format decrypt intent");
    let unsupported_result = decrypt::execute(unsupported);
    assert!(matches!(
        unsupported_result,
        Err(decrypt::Error::UnsupportedFormat([0xDE, 0x01]))
    ));
    assert_eq!(
        unsupported_result.unwrap_err().workflow_class(),
        WorkflowErrorClass::UnsupportedFormat
    );
}

#[test]
fn decrypt_intent_preserves_detached_zero_header_placeholder_positioning() {
    let test_dir = TestDir::new("decrypt-detached-placeholder");
    let (ciphertext, header) = detached_encrypted_fixture(&test_dir);
    let with_placeholder = test_dir.path().join("plain-with-placeholder.enc");
    let mut content = vec![0u8; HEADER_LEN];
    content.extend_from_slice(&fs::read(ciphertext).unwrap());
    fs::write(&with_placeholder, content).unwrap();

    let output = test_dir.path().join("plain.out");
    let intent = decrypt::DecryptIntent::new(
        &with_placeholder,
        &output,
        OverwritePolicy::CreateNew,
        Some(header.as_path()),
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build detached decrypt intent");

    decrypt::execute(intent).expect("decrypt detached fixture with zero placeholder");

    assert_eq!(fs::read(output).unwrap(), b"Hello detached world");
}

#[test]
fn decrypt_public_api_source_has_no_raw_refcell_request_contract() {
    assert!(
        DOMAIN_DECRYPT_SOURCE.contains("pub struct DecryptIntent"),
        "`dexios-domain/src/decrypt.rs` must expose a checked DecryptIntent"
    );

    for forbidden in [
        "pub struct Request",
        "pub struct TransactionalRequest",
        "pub reader:",
        "pub writer:",
        "pub header_reader:",
    ] {
        assert!(
            !DOMAIN_DECRYPT_SOURCE.contains(forbidden),
            "`dexios-domain/src/decrypt.rs` must not expose `{forbidden}` in public decrypt contracts"
        );
    }
}

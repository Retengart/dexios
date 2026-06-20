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

use core::header::common::{CANONICAL_V1_DISCRIMINATOR, HEADER_LEN, HEADER_STATIC_LEN};
use core::kdf::Kdf;
use core::primitives::BLOCK_SIZE;
use core::protected::Protected;
use dexios_domain::storage::identity::OverwritePolicy;
use dexios_domain::storage::transaction::TransactionError;
use dexios_domain::workflow_error::WorkflowErrorClass;
use dexios_domain::{decrypt, encrypt};
#[expect(dead_code, reason = "shared tempdir test helper")]
#[path = "support/tempdir.rs"]
mod tempdir;
use tempdir::DomainTestDir as TestDir;

const CORRECT_PASSWORD: &[u8] = b"correct-password";
const WRONG_PASSWORD: &[u8] = b"wrong-password";
const STREAM_TAG_LEN: usize = 16;

fn protected_key(secret: &[u8]) -> Protected<Vec<u8>> {
    Protected::new(secret.to_vec())
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
        Kdf::Argon2id,
    )
    .expect("build encrypt intent");
    encrypt::execute(intent).expect("encrypt fixture");

    encrypted
}

fn encrypted_multichunk_fixture(test_dir: &TestDir, name: &str) -> PathBuf {
    let plain = test_dir.path().join(format!("{name}.txt"));
    let encrypted = test_dir.path().join(format!("{name}.enc"));
    let plaintext: Vec<u8> = (0..(BLOCK_SIZE * 3 + 37))
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(&plain, plaintext).unwrap();

    let intent = encrypt::EncryptIntent::new(
        &plain,
        &encrypted,
        OverwritePolicy::CreateNew,
        None,
        protected_key(CORRECT_PASSWORD),
        Kdf::Argon2id,
    )
    .expect("build multichunk encrypt intent");
    encrypt::execute(intent).expect("encrypt multichunk fixture");

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
        Kdf::Argon2id,
    )
    .expect("build detached encrypt intent");
    encrypt::execute(intent).expect("encrypt detached fixture");

    (encrypted, header)
}

fn mark_first_keyslot_unsupported_argon2id(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes[HEADER_STATIC_LEN + 2..HEADER_STATIC_LEN + 4].copy_from_slice(&[0xDF, 0x02]);
    fs::write(path, bytes).unwrap();
}

fn corrupt_final_chunk(bytes: &mut [u8]) {
    let final_offset = HEADER_LEN + (3 * (BLOCK_SIZE + STREAM_TAG_LEN));
    bytes[final_offset] ^= 0x40;
}

fn truncate_one_byte(bytes: &mut Vec<u8>) {
    bytes.pop().expect("encrypted fixture has payload bytes");
}

fn reorder_normal_chunks(bytes: &mut [u8]) {
    let payload = &mut bytes[HEADER_LEN..];
    let normal_chunk_len = BLOCK_SIZE + STREAM_TAG_LEN;
    let (first, remaining) = payload.split_at_mut(normal_chunk_len);
    let second = &mut remaining[..normal_chunk_len];
    first.swap_with_slice(second);
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
fn decrypt_corrupted_stream_variants_never_commit_final_output() {
    let test_dir = TestDir::new("decrypt-corrupted-stream-preserve");
    let sentinel = b"existing final output must survive corrupted stream failure";

    for (label, corrupt) in [
        ("final-tamper", corrupt_final_chunk as fn(&mut [u8])),
        (
            "reordered-normal-chunks",
            reorder_normal_chunks as fn(&mut [u8]),
        ),
    ] {
        let encrypted = encrypted_multichunk_fixture(&test_dir, label);
        let output = test_dir.path().join(format!("{label}.out"));
        fs::write(&output, sentinel).unwrap();

        let mut encrypted_bytes = fs::read(&encrypted).unwrap();
        corrupt(&mut encrypted_bytes);
        fs::write(&encrypted, encrypted_bytes).unwrap();

        let intent = decrypt::DecryptIntent::new(
            &encrypted,
            &output,
            OverwritePolicy::ReplaceAtCommit,
            None::<&Path>,
            protected_key(CORRECT_PASSWORD),
            None,
        )
        .expect("build corrupted-stream decrypt intent");

        let error = decrypt::execute(intent)
            .err()
            .unwrap_or_else(|| panic!("{label}: corrupted stream decrypt unexpectedly succeeded"));
        assert_eq!(
            error.workflow_class(),
            WorkflowErrorClass::AuthenticationFailure,
            "{label}: corrupted stream must fail as authentication/malformed stream data"
        );
        assert_eq!(
            fs::read(&output).unwrap(),
            sentinel.as_slice(),
            "{label}: final output must remain the pre-existing sentinel"
        );
    }

    let encrypted = encrypted_multichunk_fixture(&test_dir, "one-byte-truncation");
    let output = test_dir.path().join("one-byte-truncation.out");
    fs::write(&output, sentinel).unwrap();

    let mut encrypted_bytes = fs::read(&encrypted).unwrap();
    truncate_one_byte(&mut encrypted_bytes);
    fs::write(&encrypted, encrypted_bytes).unwrap();

    let intent = decrypt::DecryptIntent::new(
        &encrypted,
        &output,
        OverwritePolicy::ReplaceAtCommit,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build truncated-stream decrypt intent");

    let error = decrypt::execute(intent).expect_err("truncated stream decrypt must fail");
    assert_eq!(
        error.workflow_class(),
        WorkflowErrorClass::AuthenticationFailure,
        "truncated stream must fail as authentication/malformed stream data"
    );
    assert_eq!(fs::read(&output).unwrap(), sentinel.as_slice());
}

#[test]
fn decrypt_final_auth_failure_preserves_final_output_after_staged_plaintext_exists() {
    let test_dir = TestDir::new("decrypt-final-auth-no-commit");
    let encrypted = encrypted_multichunk_fixture(&test_dir, "final-auth");
    let output = test_dir.path().join("final-auth.out");
    let sentinel = b"existing output must survive final authentication failure";
    fs::write(&output, sentinel).unwrap();

    let mut encrypted_bytes = fs::read(&encrypted).unwrap();
    corrupt_final_chunk(&mut encrypted_bytes);
    fs::write(&encrypted, encrypted_bytes).unwrap();

    let intent = decrypt::DecryptIntent::new(
        &encrypted,
        &output,
        OverwritePolicy::ReplaceAtCommit,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build final-auth failure decrypt intent");

    let error = decrypt::execute(intent).expect_err(
        "decrypt final-auth failure after staged plaintext must not commit final output",
    );
    assert_eq!(
        error.workflow_class(),
        WorkflowErrorClass::AuthenticationFailure
    );
    assert_no_source(&error, "final-authentication failure");
    assert_eq!(
        fs::read(&output).unwrap(),
        sentinel.as_slice(),
        "final output decrypt target must remain unchanged until V1FinalAuth exists"
    );
}

#[test]
fn decrypt_open_and_parser_failures_preserve_diagnostic_sources() {
    let test_dir = TestDir::new("decrypt-source-chain");
    let encrypted = encrypted_fixture(&test_dir, "open-source");
    let output = test_dir.path().join("open-source.out");
    let intent = decrypt::DecryptIntent::new(
        &encrypted,
        &output,
        OverwritePolicy::CreateNew,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build decrypt intent before removing input");
    fs::remove_file(&encrypted).expect("remove validated input");

    let open_error = decrypt::execute(intent).expect_err("removed input must fail open");
    assert_eq!(open_error.workflow_class(), WorkflowErrorClass::IoFailure);
    assert_has_source(&open_error, "decrypt open input failure");
    assert!(
        !output.exists(),
        "failed decrypt open must not publish plaintext output"
    );

    let malformed_input = test_dir.path().join("malformed-source.enc");
    let mut malformed_bytes = b"DXIO\x00\x01".to_vec();
    malformed_bytes.extend_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    malformed_bytes.extend_from_slice(b"short");
    fs::write(&malformed_input, malformed_bytes).unwrap();
    let malformed_output = test_dir.path().join("malformed-source.out");
    let malformed = decrypt::DecryptIntent::new(
        &malformed_input,
        &malformed_output,
        OverwritePolicy::CreateNew,
        None::<&Path>,
        protected_key(CORRECT_PASSWORD),
        None,
    )
    .expect("build malformed decrypt intent");

    let malformed_error =
        decrypt::execute(malformed).expect_err("malformed header must fail parsing");
    assert_eq!(
        malformed_error.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_has_source(&malformed_error, "decrypt malformed header parser failure");
    assert!(
        !malformed_output.exists(),
        "malformed decrypt must not publish plaintext output"
    );
}

#[test]
fn decrypt_error_classification_keeps_format_key_auth_io_and_transaction_distinct() {
    let transaction_commit = decrypt::Error::Transaction(TransactionError::Persist {
        path: PathBuf::from("plain.out"),
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
    let mut malformed_bytes = b"DXIO\x00\x01".to_vec();
    malformed_bytes.extend_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    malformed_bytes.extend_from_slice(b"short");
    fs::write(&malformed_input, malformed_bytes).unwrap();
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
        Err(decrypt::Error::DeserializeHeaderWithSource(_))
    ));
    assert_eq!(
        malformed_result.unwrap_err().workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );

    let unsupported_input = test_dir.path().join("legacy.enc");
    fs::write(&unsupported_input, [0xDE, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
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

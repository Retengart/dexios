use std::io;
use std::path::PathBuf;

use core::header::common::HeaderReadError;
use dexios_domain::{header, key};
use dexios_domain::storage::identity::{IdentityError, PathRole};
use dexios_domain::storage::transaction::{
    CommittedArtifact, PartialCommitReceipt, TransactionError,
};
use dexios_domain::workflow_error::WorkflowErrorClass;

fn path(name: &str) -> PathBuf {
    PathBuf::from(name)
}

fn transaction_commit_error() -> TransactionError {
    TransactionError::Persist {
        path: path("target.dexios"),
        source: None,
    }
}

fn source_transaction_error() -> TransactionError {
    TransactionError::Write {
        path: path("target.dexios"),
        source: Some(io::Error::from(io::ErrorKind::PermissionDenied)),
    }
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
    assert!(
        error.source().is_none(),
        "{label} must remain source-free"
    );
}

#[test]
fn header_operation_errors_keep_exact_failure_variants() {
    assert!(matches!(
        header::Error::ShortDetachedHeader { actual_len: 415 },
        header::Error::ShortDetachedHeader { actual_len: 415 }
    ));
    assert!(matches!(
        header::Error::TrailingDetachedHeader { actual_len: 417 },
        header::Error::TrailingDetachedHeader { actual_len: 417 }
    ));
    assert!(matches!(
        header::Error::MissingPayload { actual_len: 416 },
        header::Error::MissingPayload { actual_len: 416 }
    ));
    assert!(matches!(
        header::Error::TargetTooShort { actual_len: 415 },
        header::Error::TargetTooShort { actual_len: 415 }
    ));
    assert!(matches!(
        header::Error::TargetNotStripped,
        header::Error::TargetNotStripped
    ));
    assert!(matches!(
        header::Error::UnsupportedFormat([0xDE, 0x01]),
        header::Error::UnsupportedFormat([0xDE, 0x01])
    ));
    assert!(matches!(
        header::Error::MalformedV1Header(HeaderReadError::TruncatedHeader),
        header::Error::MalformedV1Header(HeaderReadError::TruncatedHeader)
    ));
    assert!(matches!(
        header::Error::PathIdentity(IdentityError::UnsafePath(path(".."))),
        header::Error::PathIdentity(IdentityError::UnsafePath(_))
    ));
    assert!(matches!(header::Error::ReadIo, header::Error::ReadIo));
    assert!(matches!(header::Error::WriteIo, header::Error::WriteIo));
    assert!(matches!(
        header::Error::Transaction(transaction_commit_error()),
        header::Error::Transaction(TransactionError::Persist { .. })
    ));
}

#[test]
fn header_operation_error_classes_are_typed_not_display_derived() {
    let unsupported = header::Error::UnsupportedFormat([0xDE, 0x01]);
    let malformed = header::Error::MalformedV1Header(HeaderReadError::NonZeroReservedBytes);
    let unsafe_path = header::Error::PathIdentity(IdentityError::AliasedPath {
        left: path("header.dexios"),
        right: path("./header.dexios"),
    });
    let identity_io = header::Error::PathIdentity(IdentityError::Io(io::ErrorKind::NotFound));
    let transaction_io = header::Error::Transaction(TransactionError::Write {
        path: path("target.dexios"),
        source: None,
    });
    let transaction_commit = header::Error::Transaction(transaction_commit_error());
    let partial_commit = header::Error::Transaction(TransactionError::PartialCommit {
        receipt: PartialCommitReceipt { artifacts: vec![] },
        failed: CommittedArtifact {
            role: PathRole::MutationTarget,
            path: path("target.dexios"),
        },
        source: None,
    });

    assert_eq!(
        header::Error::ShortDetachedHeader { actual_len: 12 }.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_eq!(
        header::Error::TrailingDetachedHeader { actual_len: 512 }.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_eq!(
        header::Error::MissingPayload { actual_len: 416 }.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_eq!(
        header::Error::TargetTooShort { actual_len: 12 }.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_eq!(
        header::Error::TargetNotStripped.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_eq!(
        unsupported.workflow_class(),
        WorkflowErrorClass::UnsupportedFormat
    );
    assert_eq!(
        malformed.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_eq!(unsafe_path.workflow_class(), WorkflowErrorClass::UnsafePath);
    assert_eq!(identity_io.workflow_class(), WorkflowErrorClass::IoFailure);
    assert_eq!(
        transaction_io.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_eq!(
        transaction_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
    assert_eq!(
        partial_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
    assert_eq!(
        header::Error::ReadIo.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_eq!(
        header::Error::WriteIo.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
}

#[test]
fn header_and_key_errors_forward_safe_diagnostic_sources() {
    let malformed_header =
        header::Error::MalformedV1Header(HeaderReadError::InvalidCanonicalDiscriminator(
            *b"BAD!",
        ));
    assert_eq!(
        malformed_header.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_has_source(&malformed_header, "header malformed V1 wrapper");

    let header_identity = header::Error::PathIdentity(IdentityError::from_io_error(
        io::Error::from(io::ErrorKind::PermissionDenied),
    ));
    assert_eq!(
        header_identity.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_has_source(&header_identity, "header path identity wrapper");

    let header_transaction = header::Error::Transaction(source_transaction_error());
    assert_eq!(
        header_transaction.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_has_source(&header_transaction, "header transaction wrapper");

    let key_malformed =
        key::Error::MalformedV1Header(HeaderReadError::InvalidKdfParamProfile(0xFF));
    assert_eq!(
        key_malformed.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert_has_source(&key_malformed, "key malformed V1 wrapper");

    let key_identity = key::Error::PathIdentity(IdentityError::from_io_error(
        io::Error::from(io::ErrorKind::PermissionDenied),
    ));
    assert_eq!(key_identity.workflow_class(), WorkflowErrorClass::IoFailure);
    assert_has_source(&key_identity, "key path identity wrapper");

    let key_transaction = key::Error::Transaction(source_transaction_error());
    assert_eq!(
        key_transaction.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_has_source(&key_transaction, "key transaction wrapper");
}

#[test]
fn header_and_key_unsupported_or_auth_failures_stay_source_free() {
    let header_unsupported = header::Error::UnsupportedFormat([0xDE, 0x01]);
    assert_eq!(
        header_unsupported.workflow_class(),
        WorkflowErrorClass::UnsupportedFormat
    );
    assert_no_source(&header_unsupported, "header unsupported format");

    let key_unsupported_kdf = key::Error::UnsupportedKdf([0xDF, 0x02]);
    assert_eq!(
        key_unsupported_kdf.workflow_class(),
        WorkflowErrorClass::KdfFailure
    );
    assert_no_source(&key_unsupported_kdf, "key unsupported KDF tag");

    let key_incorrect = key::Error::IncorrectKey;
    assert_eq!(key_incorrect.workflow_class(), WorkflowErrorClass::IncorrectKey);
    assert_no_source(&key_incorrect, "key incorrect-key authentication failure");
}

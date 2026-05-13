use std::io;
use std::path::PathBuf;

use core::header::common::HeaderReadError;
use dexios_domain::header;
use dexios_domain::storage::identity::{IdentityError, PathRole};
use dexios_domain::storage::transaction::{CommitReceipt, CommittedArtifact, TransactionError};
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
        receipt: CommitReceipt { artifacts: vec![] },
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

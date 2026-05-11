use std::io;
use std::path::PathBuf;

use core::header::common::HeaderReadError;
use dexios_domain::storage::identity::{IdentityError, PathRole};
use dexios_domain::storage::transaction::{
    CommitReceipt, CommittedArtifact, TransactionError,
};
use dexios_domain::workflow_error::WorkflowErrorClass;
use dexios_domain::{decrypt, encrypt, header, key};

fn path(name: &str) -> PathBuf {
    PathBuf::from(name)
}

fn partial_commit_error() -> TransactionError {
    TransactionError::PartialCommit {
        receipt: CommitReceipt {
            artifacts: vec![CommittedArtifact {
                role: PathRole::Output,
                path: path("written.out"),
            }],
        },
        failed: CommittedArtifact {
            role: PathRole::DetachedHeader,
            path: path("failed.header"),
        },
    }
}

#[test]
fn workflow_error_class_lists_required_phase5_categories() {
    let required = [
        WorkflowErrorClass::MalformedFormat,
        WorkflowErrorClass::UnsupportedFormat,
        WorkflowErrorClass::KdfFailure,
        WorkflowErrorClass::AuthenticationFailure,
        WorkflowErrorClass::UnsafePath,
        WorkflowErrorClass::IoFailure,
        WorkflowErrorClass::OverwriteDenied,
        WorkflowErrorClass::TransactionCommitFailure,
        WorkflowErrorClass::UnsupportedWorkflow,
        WorkflowErrorClass::IncorrectKey,
    ];

    for class in required {
        assert!(
            WorkflowErrorClass::ALL.contains(&class),
            "{class:?} must be part of the shared workflow error contract"
        );
    }
}

#[test]
fn domain_errors_classify_path_identity_without_display_strings() {
    let aliased = encrypt::Error::PathIdentity(IdentityError::AliasedPath {
        left: path("input"),
        right: path("output"),
    });
    assert_eq!(aliased.workflow_class(), WorkflowErrorClass::UnsafePath);

    let unsafe_path = decrypt::Error::PathIdentity(IdentityError::UnsafePath(path("..")));
    assert_eq!(unsafe_path.workflow_class(), WorkflowErrorClass::UnsafePath);

    let identity_io =
        encrypt::Error::PathIdentity(IdentityError::Io(io::ErrorKind::PermissionDenied));
    assert_eq!(identity_io.workflow_class(), WorkflowErrorClass::IoFailure);
}

#[test]
fn domain_errors_classify_transaction_failures_without_display_strings() {
    let write = encrypt::Error::Transaction(TransactionError::Write {
        path: path("target"),
    });
    assert_eq!(write.workflow_class(), WorkflowErrorClass::IoFailure);

    let persist = decrypt::Error::Transaction(TransactionError::Persist {
        path: path("target"),
    });
    assert_eq!(
        persist.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let partial = encrypt::Error::Transaction(partial_commit_error());
    assert_eq!(
        partial.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
}

#[test]
fn domain_errors_classify_format_kdf_authentication_and_key_failures() {
    let malformed = header::Error::MalformedV1Header(HeaderReadError::TruncatedHeader);
    assert_eq!(
        malformed.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );

    let unsupported = header::Error::UnsupportedVersion([0x00, 0x02]);
    assert_eq!(
        unsupported.workflow_class(),
        WorkflowErrorClass::UnsupportedFormat
    );

    let kdf = key::Error::UnsupportedKdf([0xDF, 0x02]);
    assert_eq!(kdf.workflow_class(), WorkflowErrorClass::KdfFailure);

    let auth = decrypt::Error::DecryptData;
    assert_eq!(
        auth.workflow_class(),
        WorkflowErrorClass::AuthenticationFailure
    );

    let wrong_key = decrypt::Error::DecryptMasterKey;
    assert_eq!(wrong_key.workflow_class(), WorkflowErrorClass::IncorrectKey);

    let key_wrong = key::Error::IncorrectKey;
    assert_eq!(key_wrong.workflow_class(), WorkflowErrorClass::IncorrectKey);

    let unsupported_workflow = key::Error::CannotAddV1KeyslotWithoutReencrypt;
    assert_eq!(
        unsupported_workflow.workflow_class(),
        WorkflowErrorClass::UnsupportedWorkflow
    );
}

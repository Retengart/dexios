#[allow(unused_imports)]
use std::error::Error as _;
use std::io;
use std::path::PathBuf;

use core::header::common::HeaderReadError;
use dexios_domain::archive::{ArchiveLimitError, ArchiveLimitKind};
use dexios_domain::storage;
use dexios_domain::storage::cleanup::{CleanupFailure, CleanupResult, CleanupTarget};
use dexios_domain::storage::identity::{IdentityError, PathRole};
use dexios_domain::storage::transaction::{
    CommittedArtifact, PartialCommitReceipt, TransactionError,
};
use dexios_domain::workflow_error::WorkflowErrorClass;
use dexios_domain::{decrypt, encrypt, header, key, pack, unpack};

const DOMAIN_WORKFLOW_ERROR_SOURCE: &str = include_str!("../src/workflow_error.rs");
const DOMAIN_PACK_SOURCE: &str = include_str!("../src/pack.rs");
const DOMAIN_UNPACK_SOURCE: &str = include_str!("../src/unpack.rs");
const CLI_ERROR_MAPPER_SOURCE: &str = include_str!("../../dexios/src/subcommands/errors.rs");

fn path(name: &str) -> PathBuf {
    PathBuf::from(name)
}

fn partial_commit_error_with_source(source: io::Error) -> TransactionError {
    TransactionError::PartialCommit {
        receipt: PartialCommitReceipt {
            artifacts: vec![CommittedArtifact {
                role: PathRole::Output,
                path: path("written.out"),
            }],
        },
        failed: CommittedArtifact {
            role: PathRole::DetachedHeader,
            path: path("failed.header"),
        },
        source: Some(source),
    }
}

fn partial_commit_error() -> TransactionError {
    partial_commit_error_with_source(io::Error::from(io::ErrorKind::AlreadyExists))
}

fn archive_limit_error() -> ArchiveLimitError {
    ArchiveLimitError {
        kind: ArchiveLimitKind::EntryCount,
        limit: 1,
        actual: 2,
    }
}

fn assert_source<E>(error: &E, label: &str)
where
    E: std::error::Error + ?Sized,
{
    assert!(
        error.source().is_some(),
        "{label} must preserve a diagnostic source"
    );
}

fn assert_encrypt_source(error: encrypt::Error, class: WorkflowErrorClass, label: &str) {
    assert_eq!(error.workflow_class(), class);
    assert_source(&error, label);
}

fn storage_full() -> io::Error {
    io::Error::from(io::ErrorKind::StorageFull)
}

fn production_source(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

fn assert_decrypt_source(error: decrypt::Error, class: WorkflowErrorClass, label: &str) {
    assert_eq!(error.workflow_class(), class);
    assert_source(&error, label);
}

fn assert_pack_source(error: pack::Error, class: WorkflowErrorClass, label: &str) {
    assert_eq!(error.workflow_class(), class);
    assert_source(&error, label);
}

fn assert_unpack_source(error: unpack::Error, class: WorkflowErrorClass, label: &str) {
    assert_eq!(error.workflow_class(), class);
    assert_source(&error, label);
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
        WorkflowErrorClass::CleanupFailure,
        WorkflowErrorClass::ResourcePressure,
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
fn domain_errors_preserve_source_chains_for_workflow_wrappers() {
    assert_encrypt_source(
        encrypt::Error::PathIdentity(IdentityError::Io(io::ErrorKind::PermissionDenied)),
        WorkflowErrorClass::IoFailure,
        "encrypt path identity wrapper",
    );
    assert_encrypt_source(
        encrypt::Error::Transaction(TransactionError::Write {
            path: path("encrypted.out"),
            source: None,
        }),
        WorkflowErrorClass::IoFailure,
        "encrypt transaction wrapper",
    );

    assert_decrypt_source(
        decrypt::Error::PathIdentity(IdentityError::Io(io::ErrorKind::PermissionDenied)),
        WorkflowErrorClass::IoFailure,
        "decrypt path identity wrapper",
    );
    assert_decrypt_source(
        decrypt::Error::Transaction(TransactionError::Persist {
            path: path("decrypted.out"),
            source: None,
        }),
        WorkflowErrorClass::TransactionCommitFailure,
        "decrypt transaction wrapper",
    );

    assert_pack_source(
        pack::Error::PathIdentity(IdentityError::Io(io::ErrorKind::PermissionDenied)),
        WorkflowErrorClass::IoFailure,
        "pack path identity wrapper",
    );
    assert_pack_source(
        pack::Error::Transaction(TransactionError::Flush {
            path: path("packed.out"),
            source: None,
        }),
        WorkflowErrorClass::IoFailure,
        "pack transaction wrapper",
    );
    assert_pack_source(
        pack::Error::Encrypt(encrypt::Error::HashKey),
        WorkflowErrorClass::KdfFailure,
        "pack encrypt wrapper",
    );
}

#[test]
fn unpack_errors_preserve_source_chains_for_workflow_wrappers() {
    assert_unpack_source(
        unpack::Error::PathIdentity(IdentityError::Io(io::ErrorKind::PermissionDenied)),
        WorkflowErrorClass::IoFailure,
        "unpack path identity wrapper",
    );
    assert_unpack_source(
        unpack::Error::Transaction(TransactionError::Sync {
            path: path("unpacked.out"),
            source: None,
        }),
        WorkflowErrorClass::IoFailure,
        "unpack transaction wrapper",
    );
    assert_unpack_source(
        unpack::Error::Decrypt(decrypt::Error::DecryptData),
        WorkflowErrorClass::AuthenticationFailure,
        "unpack decrypt wrapper",
    );
    assert_unpack_source(
        unpack::Error::Storage(storage::Error::CreateDir),
        WorkflowErrorClass::IoFailure,
        "unpack storage wrapper",
    );
    assert_unpack_source(
        unpack::Error::ArchiveLimit(archive_limit_error()),
        WorkflowErrorClass::UnsafePath,
        "unpack archive-limit wrapper",
    );
}

#[test]
fn storage_errors_preserve_io_sources() {
    let storage_error =
        storage::Error::CreateDirWithSource(io::Error::from(io::ErrorKind::PermissionDenied));
    let wrapped_storage = unpack::Error::Storage(storage_error);
    assert_eq!(
        wrapped_storage.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    let unpack::Error::Storage(inner) = &wrapped_storage else {
        unreachable!("wrapped storage fixture must stay storage-backed");
    };
    assert_source(inner, "storage::Error IO failure");
}

#[test]
fn resource_pressure_helpers_detect_storage_full_source_chains() {
    let storage_error = storage::Error::CreateFileWithSource(storage_full());
    assert!(storage_error.is_resource_pressure());

    let transaction_error = TransactionError::Write {
        path: path("packed.out"),
        source: Some(storage_full()),
    };
    assert!(transaction_error.is_resource_pressure());

    let partial_commit = TransactionError::PartialCommit {
        receipt: PartialCommitReceipt {
            artifacts: vec![CommittedArtifact {
                role: PathRole::Output,
                path: path("committed.out"),
            }],
        },
        failed: CommittedArtifact {
            role: PathRole::DetachedHeader,
            path: path("failed.header"),
        },
        source: Some(storage_full()),
    };
    assert!(partial_commit.is_resource_pressure());
    let pack_partial_commit = pack::Error::Transaction(partial_commit);
    assert_eq!(
        pack_partial_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
    assert!(pack_partial_commit.is_resource_pressure());

    let pack_error = pack::Error::Transaction(transaction_error);
    assert_eq!(
        pack_error.workflow_class(),
        WorkflowErrorClass::ResourcePressure
    );
    assert!(pack_error.is_resource_pressure());

    let pack_temp_error = pack::Error::WriteDataWithSource(storage_full());
    assert_eq!(
        pack_temp_error.workflow_class(),
        WorkflowErrorClass::ResourcePressure
    );
    assert!(pack_temp_error.is_resource_pressure());

    let unpack_error = unpack::Error::Storage(storage::Error::CreateFileWithSource(storage_full()));
    assert_eq!(
        unpack_error.workflow_class(),
        WorkflowErrorClass::ResourcePressure
    );
    assert!(unpack_error.is_resource_pressure());

    let unpack_commit_error = unpack::Error::Transaction(TransactionError::Persist {
        path: path("unpacked.out"),
        source: Some(storage_full()),
    });
    assert_eq!(
        unpack_commit_error.workflow_class(),
        WorkflowErrorClass::ResourcePressure
    );
    assert!(unpack_commit_error.is_resource_pressure());
}

#[test]
fn cleanup_failures_have_typed_workflow_classification() {
    let failure = CleanupFailure::without_source(
        CleanupTarget::unchecked_file_for_test(path("source.txt")),
        io::ErrorKind::PermissionDenied,
    );
    let result = CleanupResult {
        deleted: Vec::new(),
        failures: vec![failure],
    };

    assert_eq!(
        dexios_domain::workflow_error::classify_cleanup_failure(&result.failures[0]),
        WorkflowErrorClass::CleanupFailure
    );
    assert_eq!(
        dexios_domain::workflow_error::classify_cleanup_result(&result),
        WorkflowErrorClass::CleanupFailure
    );
}

#[test]
fn workflow_and_cli_classification_do_not_use_formatted_error_substrings() {
    let sources = [
        ("workflow_error.rs", DOMAIN_WORKFLOW_ERROR_SOURCE),
        ("pack.rs", DOMAIN_PACK_SOURCE),
        ("unpack.rs", DOMAIN_UNPACK_SOURCE),
        (
            "subcommands/errors.rs",
            production_source(CLI_ERROR_MAPPER_SOURCE),
        ),
    ];
    let forbidden = [
        ".to_string().contains(",
        "format!(\"{",
        "format!(\"{err",
        "format!(\"{error",
        ".contains(error.to_string",
        ".contains(err.to_string",
    ];

    for (path, source) in sources {
        for pattern in forbidden {
            assert!(
                !source.contains(pattern),
                "{path} must not classify workflow errors via formatted-error substring pattern {pattern:?}"
            );
        }
    }
}

#[test]
fn resource_pressure_helpers_do_not_relabel_format_or_authentication_errors() {
    let malformed = unpack::Error::OpenArchive;
    assert_eq!(
        malformed.workflow_class(),
        WorkflowErrorClass::MalformedFormat
    );
    assert!(!malformed.is_resource_pressure());

    let authentication = unpack::Error::Decrypt(decrypt::Error::DecryptData);
    assert_eq!(
        authentication.workflow_class(),
        WorkflowErrorClass::AuthenticationFailure
    );
    assert!(!authentication.is_resource_pressure());
}

#[test]
fn transaction_errors_preserve_io_sources() {
    let cases = [
        (
            TransactionError::Write {
                path: path("write.out"),
                source: Some(io::Error::from(io::ErrorKind::BrokenPipe)),
            },
            WorkflowErrorClass::IoFailure,
            "TransactionError::Write",
        ),
        (
            TransactionError::Flush {
                path: path("flush.out"),
                source: Some(io::Error::from(io::ErrorKind::PermissionDenied)),
            },
            WorkflowErrorClass::IoFailure,
            "TransactionError::Flush",
        ),
        (
            TransactionError::Sync {
                path: path("sync.out"),
                source: Some(io::Error::from(io::ErrorKind::Interrupted)),
            },
            WorkflowErrorClass::IoFailure,
            "TransactionError::Sync",
        ),
        (
            TransactionError::Persist {
                path: path("persist.out"),
                source: Some(io::Error::from(io::ErrorKind::AlreadyExists)),
            },
            WorkflowErrorClass::TransactionCommitFailure,
            "TransactionError::Persist",
        ),
    ];

    for (transaction_error, expected_class, label) in cases {
        let wrapped = encrypt::Error::Transaction(transaction_error);
        assert_eq!(wrapped.workflow_class(), expected_class);
        let encrypt::Error::Transaction(inner) = &wrapped else {
            unreachable!("transaction source fixture must stay transaction-backed");
        };
        assert_source(inner, label);
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

    let identity_io = encrypt::Error::PathIdentity(IdentityError::from_io_error(io::Error::from(
        io::ErrorKind::PermissionDenied,
    )));
    assert_eq!(identity_io.workflow_class(), WorkflowErrorClass::IoFailure);
    let encrypt::Error::PathIdentity(inner) = &identity_io else {
        unreachable!("identity source fixture must stay identity-backed");
    };
    assert_source(inner, "IdentityError source-bearing IO failure");
}

#[test]
fn domain_errors_classify_transactions_without_display_strings() {
    let write = encrypt::Error::Transaction(TransactionError::Write {
        path: path("target"),
        source: None,
    });
    assert_eq!(write.workflow_class(), WorkflowErrorClass::IoFailure);

    let persist = decrypt::Error::Transaction(TransactionError::Persist {
        path: path("target"),
        source: None,
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
    let encrypt::Error::Transaction(TransactionError::PartialCommit {
        receipt, failed, ..
    }) = &partial
    else {
        unreachable!("partial commit fixture must stay transaction-backed");
    };
    assert_eq!(receipt.artifacts.len(), 1);
    assert_eq!(receipt.artifacts[0].role, PathRole::Output);
    assert_eq!(receipt.artifacts[0].path, path("written.out"));
    assert_eq!(failed.role, PathRole::DetachedHeader);
    assert_eq!(failed.path, path("failed.header"));
    assert_source(&partial, "partial commit transaction wrapper");

    let partial_with_storage_full =
        unpack::Error::Transaction(partial_commit_error_with_source(storage_full()));
    assert!(partial_with_storage_full.is_resource_pressure());
    assert_eq!(
        partial_with_storage_full.workflow_class(),
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

#[test]
fn key_change_errors_classify_mutation_failures_without_display_strings() {
    let unsafe_path = key::Error::PathIdentity(IdentityError::UnsafePath(path("..")));
    assert_eq!(unsafe_path.workflow_class(), WorkflowErrorClass::UnsafePath);

    let identity_io = key::Error::PathIdentity(IdentityError::Io(io::ErrorKind::PermissionDenied));
    assert_eq!(identity_io.workflow_class(), WorkflowErrorClass::IoFailure);

    let transaction_write = key::Error::Transaction(TransactionError::Write {
        path: path("target"),
        source: None,
    });
    assert_eq!(
        transaction_write.workflow_class(),
        WorkflowErrorClass::IoFailure
    );

    let transaction_commit = key::Error::Transaction(TransactionError::Persist {
        path: path("target"),
        source: None,
    });
    assert_eq!(
        transaction_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let wrong_old_key = key::Error::IncorrectKey;
    assert_eq!(
        wrong_old_key.workflow_class(),
        WorkflowErrorClass::IncorrectKey
    );

    let unsupported_kdf = key::Error::UnsupportedKdf([0xDF, 0x02]);
    assert_eq!(
        unsupported_kdf.workflow_class(),
        WorkflowErrorClass::KdfFailure
    );
}

#[test]
fn key_delete_errors_classify_mutation_failures_without_display_strings() {
    let unsafe_path = key::Error::PathIdentity(IdentityError::UnsafePath(path("..")));
    assert_eq!(unsafe_path.workflow_class(), WorkflowErrorClass::UnsafePath);

    let transaction_commit = key::Error::Transaction(TransactionError::Persist {
        path: path("target"),
        source: None,
    });
    assert_eq!(
        transaction_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let final_slot = key::Error::CannotRemoveFinalV1Keyslot;
    assert_eq!(
        final_slot.workflow_class(),
        WorkflowErrorClass::UnsupportedWorkflow
    );

    let wrong_old_key = key::Error::IncorrectKey;
    assert_eq!(
        wrong_old_key.workflow_class(),
        WorkflowErrorClass::IncorrectKey
    );
}

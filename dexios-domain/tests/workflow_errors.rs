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
#[expect(
    unused_imports,
    reason = "Error trait import documents the error-source surface under test"
)]
use std::error::Error as _;
use std::io;
use std::path::PathBuf;

use core::header::common::HeaderReadError;
#[cfg(unix)]
use dexios_domain::archive::ArchivePolicy;
use dexios_domain::archive::{ArchiveLimitError, ArchiveLimitKind};
use dexios_domain::storage;
#[cfg(feature = "test-support")]
use dexios_domain::storage::cleanup::{CleanupFailure, CleanupResult, CleanupTarget};
use dexios_domain::storage::identity::IdentityError;
#[cfg(unix)]
use dexios_domain::storage::identity::OverwritePolicy;
#[cfg(feature = "test-support")]
use dexios_domain::storage::identity::PathRole;
use dexios_domain::storage::transaction::TransactionError;
#[cfg(feature = "test-support")]
use dexios_domain::storage::transaction::{CommittedArtifact, PartialCommitReceipt};
use dexios_domain::workflow_error::WorkflowErrorClass;
use dexios_domain::{decrypt, encrypt, header, key, pack, unpack};

const DOMAIN_WORKFLOW_ERROR_SOURCE: &str = include_str!("../src/workflow_error.rs");
const DOMAIN_PACK_SOURCE: &str = include_str!("../src/pack.rs");
const DOMAIN_UNPACK_SOURCE: &str = include_str!("../src/unpack.rs");
const CLI_ERROR_MAPPER_SOURCE: &str = include_str!("../../dexios/src/subcommands/errors.rs");
#[cfg(unix)]
const PASSWORD: &[u8; 8] = b"12345678";

fn path(name: &str) -> PathBuf {
    PathBuf::from(name)
}

#[cfg(feature = "test-support")]
fn partial_commit_error_with_source(source: io::Error) -> TransactionError {
    TransactionError::PartialCommit {
        receipt: PartialCommitReceipt::unchecked_new_for_test(vec![
            CommittedArtifact::unchecked_new_for_test(PathRole::Output, path("written.out")),
        ]),
        failed: CommittedArtifact::unchecked_new_for_test(
            PathRole::DetachedHeader,
            path("failed.header"),
        ),
        source: Some(source),
    }
}

#[cfg(feature = "test-support")]
fn partial_commit_error() -> TransactionError {
    partial_commit_error_with_source(io::Error::from(io::ErrorKind::AlreadyExists))
}

#[cfg(feature = "test-support")]
fn post_commit_sync_error_with_source(source: io::Error) -> TransactionError {
    TransactionError::PostCommitSync {
        receipt: PartialCommitReceipt::unchecked_new_for_test(vec![
            CommittedArtifact::unchecked_new_for_test(PathRole::Output, path("visible.out")),
        ]),
        source: Some(source),
    }
}

fn archive_limit_error() -> ArchiveLimitError {
    ArchiveLimitError {
        kind: ArchiveLimitKind::EntryCount,
        limit: 1,
        actual: 2,
    }
}

#[cfg(unix)]
fn pack_revalidation_intent(
    source_paths: Vec<PathBuf>,
    output_path: &std::path::Path,
    detached_header_path: &std::path::Path,
) -> Result<pack::PackIntent, pack::Error> {
    pack::PackIntent::new(
        source_paths,
        output_path,
        OverwritePolicy::CreateNew,
        Some(pack::DetachedHeaderTarget::new(
            detached_header_path,
            OverwritePolicy::CreateNew,
        )),
        core::protected::Protected::new(PASSWORD.to_vec()),
        core::kdf::Kdf::Argon2id,
        ArchivePolicy::default(),
        true,
        None,
    )
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

fn assert_error_chain_contains_io_kind(
    mut error: &(dyn std::error::Error + 'static),
    expected: io::ErrorKind,
    label: &str,
) {
    loop {
        if let Some(source) = error.downcast_ref::<io::Error>() {
            assert_eq!(source.kind(), expected, "{label} preserved wrong IO kind");
            return;
        }

        error = error
            .source()
            .unwrap_or_else(|| panic!("{label} must preserve IO source kind {expected:?}"));
    }
}

fn assert_replacement_path_class(class: WorkflowErrorClass, label: &str) {
    assert!(
        matches!(
            class,
            WorkflowErrorClass::UnsafePath | WorkflowErrorClass::IoFailure
        ),
        "{label} must classify replacement-path failures as unsafe path or IO failure, got {class:?}"
    );
    assert!(
        !matches!(
            class,
            WorkflowErrorClass::MalformedFormat
                | WorkflowErrorClass::KdfFailure
                | WorkflowErrorClass::AuthenticationFailure
                | WorkflowErrorClass::Other
        ),
        "{label} replacement-path failure must not be hidden as malformed archive, crypto/auth, or generic error"
    );
}

fn assert_unsafe_path_revalidation_class(class: WorkflowErrorClass, label: &str) {
    assert_eq!(
        class,
        WorkflowErrorClass::UnsafePath,
        "{label} must classify underlying unsafe-path revalidation as UnsafePath, got {class:?}"
    );
}

fn assert_encrypt_source(error: encrypt::Error, class: WorkflowErrorClass, label: &str) {
    assert_eq!(error.workflow_class(), class);
    assert_source(&error, label);
}

#[cfg(feature = "test-support")]
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
fn replacement_path_failures_keep_unsafe_or_io_classes_and_sources() {
    let pack_unsafe_source =
        pack::Error::ReadSourceWithSource(storage::Error::UnsafePath(path("source")));
    assert_replacement_path_class(
        pack_unsafe_source.workflow_class(),
        "pack source replacement",
    );
    assert_source(
        &pack_unsafe_source,
        "pack source replacement storage wrapper",
    );

    let pack_missing_source = pack::Error::ReadSourceWithSource(
        storage::Error::FileAccessWithSource(io::Error::from(io::ErrorKind::NotFound)),
    );
    assert_eq!(
        pack_missing_source.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_error_chain_contains_io_kind(
        &pack_missing_source,
        io::ErrorKind::NotFound,
        "pack missing replacement source",
    );

    let unpack_root_replaced = unpack::Error::UnsafeOutputPath(path("replacement-root"));
    assert_replacement_path_class(
        unpack_root_replaced.workflow_class(),
        "unpack root replacement",
    );

    let unpack_access_failure = unpack::Error::Storage(storage::Error::FileAccessWithSource(
        io::Error::from(io::ErrorKind::PermissionDenied),
    ));
    assert_eq!(
        unpack_access_failure.workflow_class(),
        WorkflowErrorClass::IoFailure
    );
    assert_error_chain_contains_io_kind(
        &unpack_access_failure,
        io::ErrorKind::PermissionDenied,
        "unpack replacement path access failure",
    );
}

#[cfg(unix)]
#[test]
fn pack_source_root_revalidation_failure_keeps_unsafe_path_classification() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    let original_dir = root.path().join("original-source");
    let output_path = root.path().join("archive.enc");
    let header_path = root.path().join("archive.header");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::write(source_dir.join("original-only.txt"), b"original").unwrap();

    let intent =
        pack_revalidation_intent(vec![source_dir.clone()], &output_path, &header_path).unwrap();

    std::fs::rename(&source_dir, &original_dir).unwrap();
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::write(source_dir.join("replacement-only.txt"), b"replacement").unwrap();

    let error = pack::execute_transactional(intent)
        .expect_err("replaced source root must fail before archive commit");
    assert!(
        matches!(
            &error,
            pack::Error::ReadSourceWithSource(storage::Error::UnsafePath(_))
        ),
        "replaced source root must remain a storage unsafe-path read-source failure, got {error:?}"
    );
    assert_unsafe_path_revalidation_class(error.workflow_class(), "pack source-root replacement");
    assert!(
        !matches!(
            error.workflow_class(),
            WorkflowErrorClass::MalformedFormat
                | WorkflowErrorClass::KdfFailure
                | WorkflowErrorClass::AuthenticationFailure
                | WorkflowErrorClass::TransactionCommitFailure
                | WorkflowErrorClass::Other
        ),
        "pack source-root replacement must not be hidden as malformed archive, crypto/auth, transaction-only, or generic failure"
    );
    assert!(
        !output_path.exists(),
        "archive output must not be committed after source-root replacement"
    );
    assert!(
        !header_path.exists(),
        "detached header output must not be committed after source-root replacement"
    );
}

#[cfg(all(unix, feature = "test-support"))]
#[test]
fn pack_walked_entry_revalidation_failure_keeps_unsafe_path_classification() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    let target_file = source_dir.join("target.txt");
    let original_file = root.path().join("target-original.txt");
    let output_path = root.path().join("archive.enc");
    let header_path = root.path().join("archive.header");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::write(&target_file, b"original").unwrap();

    let swapped = std::rc::Rc::new(std::cell::Cell::new(false));
    let swapped_for_observer = std::rc::Rc::clone(&swapped);
    let observed_target = target_file.clone();
    let replacement_target = target_file.clone();
    let original_target = original_file.clone();
    let intent = pack_revalidation_intent(vec![source_dir], &output_path, &header_path)
        .unwrap()
        .with_walked_entry_after_metadata_observer(Box::new(move |walked_path| {
            if walked_path == observed_target && !swapped_for_observer.replace(true) {
                std::fs::rename(&replacement_target, &original_target).unwrap();
                std::fs::write(&replacement_target, b"replacement").unwrap();
            }
        }));

    let error = pack::execute_transactional(intent)
        .expect_err("swapped walked entry must fail before archive commit");
    assert!(
        swapped.get(),
        "regression must swap the walked entry after traversal metadata is captured"
    );
    assert!(
        matches!(
            &error,
            pack::Error::ReadSourceWithSource(storage::Error::UnsafePath(_))
        ),
        "swapped walked entry must remain a storage unsafe-path read-source failure, got {error:?}"
    );
    assert_unsafe_path_revalidation_class(error.workflow_class(), "pack walked-entry replacement");
    assert!(
        !matches!(
            error.workflow_class(),
            WorkflowErrorClass::MalformedFormat
                | WorkflowErrorClass::KdfFailure
                | WorkflowErrorClass::AuthenticationFailure
                | WorkflowErrorClass::TransactionCommitFailure
                | WorkflowErrorClass::Other
        ),
        "pack walked-entry replacement must not be hidden as malformed archive, crypto/auth, transaction-only, or generic failure"
    );
    assert!(
        !output_path.exists(),
        "archive output must not be committed after walked-entry replacement"
    );
    assert!(
        !header_path.exists(),
        "detached header output must not be committed after walked-entry replacement"
    );
    assert_eq!(std::fs::read(&target_file).unwrap(), b"replacement");
    assert_eq!(std::fs::read(&original_file).unwrap(), b"original");
}

#[test]
#[cfg(feature = "test-support")]
fn resource_pressure_helpers_detect_storage_full_source_chains() {
    let storage_error = storage::Error::CreateFileWithSource(storage_full());
    assert!(storage_error.is_resource_pressure());

    let transaction_error = TransactionError::Write {
        path: path("packed.out"),
        source: Some(storage_full()),
    };
    assert!(transaction_error.is_resource_pressure());

    let partial_commit = TransactionError::PartialCommit {
        receipt: PartialCommitReceipt::unchecked_new_for_test(vec![
            CommittedArtifact::unchecked_new_for_test(PathRole::Output, path("committed.out")),
        ]),
        failed: CommittedArtifact::unchecked_new_for_test(
            PathRole::DetachedHeader,
            path("failed.header"),
        ),
        source: Some(storage_full()),
    };
    assert!(partial_commit.is_resource_pressure());
    let pack_partial_commit = pack::Error::Transaction(partial_commit);
    assert_eq!(
        pack_partial_commit.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
    assert!(pack_partial_commit.is_resource_pressure());

    let post_commit_sync = post_commit_sync_error_with_source(storage_full());
    assert!(post_commit_sync.is_resource_pressure());
    let pack_post_commit_sync = pack::Error::Transaction(post_commit_sync);
    assert_eq!(
        pack_post_commit_sync.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
    assert!(pack_post_commit_sync.is_resource_pressure());

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
#[cfg(feature = "test-support")]
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
#[cfg(feature = "test-support")]
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
    assert_eq!(receipt.committed_artifacts().len(), 1);
    assert_eq!(receipt.committed_artifacts()[0].role(), PathRole::Output);
    assert_eq!(receipt.committed_artifacts()[0].path(), path("written.out"));
    assert_eq!(failed.role(), PathRole::DetachedHeader);
    assert_eq!(failed.path(), path("failed.header"));
    assert_source(&partial, "partial commit transaction wrapper");

    let post_commit_sync = pack::Error::Transaction(post_commit_sync_error_with_source(
        io::Error::from(io::ErrorKind::Other),
    ));
    assert_eq!(
        post_commit_sync.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );
    let pack::Error::Transaction(TransactionError::PostCommitSync { receipt, .. }) =
        &post_commit_sync
    else {
        unreachable!("post-commit sync fixture must stay transaction-backed");
    };
    assert_eq!(receipt.committed_artifacts().len(), 1);
    assert_eq!(receipt.committed_artifacts()[0].path(), path("visible.out"));
    assert_source(&post_commit_sync, "post-commit sync transaction wrapper");

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

    let stale_target = key::Error::TargetChanged;
    assert_eq!(stale_target.workflow_class(), WorkflowErrorClass::IoFailure);

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

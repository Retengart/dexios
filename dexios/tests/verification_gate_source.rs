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
mod verification_gate_support;

use verification_gate_support::*;

#[test]
fn rust_production_source_gate_catches_multiline_dangerous_calls() {
    let source = r"
fn production_write(path: &std::path::Path) {
    std::fs::OpenOptions::new()
        .create(true)
        .open(path)
        .unwrap();
}

#[cfg(test)]
mod tests {
    fn fixture(path: &std::path::Path) {
        std::fs::File::create(path).unwrap();
    }
}
";
    let normalized = normalized_rust_production_source(source);

    assert!(normalized.contains("OpenOptions::new().create(true)"));
    assert!(!normalized.contains("File::create"));
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", source);
        })
        .is_err()
    );

    let reordered_open_options_source = r"
fn production_write(path: &std::path::Path) {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
}
";
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", reordered_open_options_source);
        })
        .is_err()
    );

    let file_options_source = r"
fn production_write(path: &std::path::Path) {
    std::fs::File::options()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
}
";
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", file_options_source);
        })
        .is_err()
    );

    let file_options_create_new_source = r"
fn production_write(path: &std::path::Path) {
    std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
}
";
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", file_options_create_new_source);
        })
        .is_err()
    );
}

#[test]
fn domain_path_identity_hardening_negative_fixtures_prove_gate_failures() {
    let missing_root_revalidation = normalized_rust_production_source(
        r"
fn stage_manifest_file_body(
    stor: &storage::FileStorage,
    output_root: &ResolvedTarget,
    transaction: &mut LinkedOutputTransaction,
    entity: &ExtractionEntity,
) -> Result<(), Error> {
    let output_dir = output_root.target_path().to_path_buf();
    stor.revalidate_unpack_target(&output_dir, &entity.relative_path, target)?;
    transaction.stage_in(target.clone(), &output_dir)?;
    Ok(())
}
",
    );

    assert!(
        std::panic::catch_unwind(|| {
            assert_normalized_section_order(
                "synthetic missing unpack root revalidation",
                &missing_root_revalidation,
                &[
                    ".revalidate_resolved_directory_root(output_root)",
                    ".stage_in(target.clone(), &output_dir)",
                ],
            );
        })
        .is_err()
    );

    let missing_read_identity = normalized_rust_production_source(
        r"
pub fn read_resolved_existing_no_follow(
    &self,
    target: &ResolvedTarget,
) -> Result<Entry<std_fs::File>, Error> {
    let entry = self.read_file_no_follow(target.target_path())?;
    if entry.is_dir() != target.is_dir() {
        return Err(Error::UnsafePath(target.original_path().to_path_buf()));
    }
    Ok(entry)
}
",
    );
    assert!(
        std::panic::catch_unwind(|| {
            assert_normalized_section_order(
                "synthetic missing read-side identity comparison",
                &missing_read_identity,
                &[
                    "let entry = self.read_file_no_follow(target.target_path())?",
                    "verify_entry_matches_resolved_target(&entry, target)?",
                    "Ok(entry)",
                ],
            );
        })
        .is_err()
    );
}

#[test]
fn domain_path_identity_hardening_boundaries_are_source_gated() {
    let pack_intent = normalized_rust_production_section(
        "dexios-domain/src/pack.rs",
        DEXIOS_DOMAIN_PACK_RS,
        "impl PackIntent",
        "struct HandleRequest",
    );
    assert_normalized_section_order(
        "dexios-domain/src/pack.rs::PackIntent::new",
        &pack_intent,
        &[
            "PathIdentityGraph::new",
            ".add_existing(source_path, PathRole::ProcessedSource)",
            "CleanupReceipt::from_processed_source_trees",
            ".add_output(output_path, PathRole::GeneratedOutput, output_overwrite)",
            "PathRole::GeneratedDetachedHeader",
            "graph.validate()",
        ],
    );

    let pack_materialization = normalized_rust_production_section(
        "dexios-domain/src/pack.rs",
        DEXIOS_DOMAIN_PACK_RS,
        "fn materialize_archive_entries_with_limits",
        "#[cfg(unix)]",
    );
    assert_normalized_section_order(
        "dexios-domain/src/pack.rs::materialize_archive_entries_with_limits",
        &pack_materialization,
        &[
            ".read_resolved_existing_no_follow(&source_root.target)",
            ".revalidate_resolved_directory_root(&source_root.target)",
            "walkdir::WalkDir::new(&root_path)",
            ".read_file_no_follow(source.path())",
            "verify_walked_entry_matches_opened(&source, &walked_metadata)?",
            "push_archive_entry",
        ],
    );

    let pack_execute = normalized_rust_production_section(
        "dexios-domain/src/pack.rs",
        DEXIOS_DOMAIN_PACK_RS,
        "pub fn execute_transactional_with_cleanup",
        "fn map_detached_publication_transaction_error",
    );
    assert_normalized_section_order(
        "dexios-domain/src/pack.rs::execute_transactional_with_cleanup",
        &pack_execute,
        &[
            "materialize_archive_entries",
            "validate_generated_targets_against_entries",
            "transaction.stage(output_target)?",
            "execute_streaming_archive",
            "transaction.commit_all()",
        ],
    );

    let unpack_prepare = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn prepare_manifest_extraction_entities",
        "fn stage_manifest_file_body",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::prepare_manifest_extraction_entities",
        &unpack_prepare,
        &[
            "PathIdentityGraph::new",
            ".add_existing(input_path, PathRole::Input)",
            ".add_existing(detached_header_path, PathRole::DetachedHeader)",
            ".add_unpack_root(&output_dir)",
            ".add_output(&full_path, PathRole::Output, overwrite_policy)",
            "Ok(PreparedExtraction { output_root, entities, })",
        ],
    );

    let unpack_staging = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn stage_manifest_file_body",
        "fn copy_manifest_body",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::stage_manifest_file_body",
        &unpack_staging,
        &[
            ".revalidate_resolved_directory_root(output_root)",
            "stor.revalidate_unpack_target(&output_dir, &entity.relative_path, target)",
            ".stage_in(target.clone(), &output_dir)",
            ".staged_output_mut(transaction_index)",
            "copy_manifest_body(plaintext_reader, writer, body_len)",
        ],
    );

    let unpack_final_commit = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn execute_manifest_archive",
        "#[expect(",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::execute_manifest_archive",
        &unpack_final_commit,
        &[
            "stage_manifest_extraction",
            "drain_trailing_plaintext_to_final_auth",
            "plaintext_reader.finish()",
            "revalidate_extraction_targets(&stor, &prepared.output_root, &prepared.entities)?",
            "create_selected_directories_after_final_auth",
            "transaction.commit_all()",
        ],
    );

    let unpack_directory_creation = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn create_selected_directories_after_final_auth",
        "fn revalidate_extraction_targets",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::create_selected_directories_after_final_auth",
        &unpack_directory_creation,
        &[
            ".revalidate_resolved_directory_root(output_root)",
            "stor.revalidate_unpack_directory_target(&output_dir, &entity.relative_path, target)",
            "stor.create_unpack_dir_all(&output_dir, &entity.relative_path)",
            "artifacts.push(CommittedArtifact::new",
        ],
    );

    for required in [
        "pack_rejects_source_root_replaced_after_intent_capture",
        "pack_rejects_walked_file_replaced_between_metadata_and_open",
    ] {
        assert_contains(
            "dexios-domain/tests/pack_paths.rs",
            DEXIOS_DOMAIN_PACK_PATHS_TESTS,
            required,
        );
    }
    for required in [
        "unpack_rejects_output_root_replaced_before_selected_file_staging",
        "unpack_rejects_output_root_replaced_after_final_auth_before_selected_directory_creation",
        "unpack_revalidation_failure_does_not_create_selected_directory_entries",
    ] {
        assert_corpus_contains(
            "domain path identity unpack regression evidence",
            &[
                (
                    "dexios-domain/tests/unpack_path_identity.rs",
                    DEXIOS_DOMAIN_UNPACK_PATH_IDENTITY_TESTS,
                ),
                (
                    "dexios-domain/tests/unpack_symlink_revalidation.rs",
                    DEXIOS_DOMAIN_UNPACK_SYMLINK_REVALIDATION_TESTS,
                ),
            ],
            required,
        );
    }
    for required in [
        "pack_source_root_revalidation_failure_keeps_unsafe_path_classification",
        "pack_walked_entry_revalidation_failure_keeps_unsafe_path_classification",
    ] {
        assert_contains(
            "dexios-domain/tests/workflow_errors.rs",
            DEXIOS_DOMAIN_WORKFLOW_ERROR_TESTS,
            required,
        );
    }
}
#[test]
fn phase19_public_api_authority_contract_is_source_gated() {
    let docs = [
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        ("book/src/dexios-core/Encryption.md", ENCRYPTION),
    ];

    for required in [
        "public API authority boundaries",
        "forge-resistant receipts",
        "V1FinalAuth",
        "cleanup receipts",
        "transaction receipts",
        "detached pair receipts",
        "mutation snapshots",
        "caller obligations for uncommitted stream reads",
    ] {
        assert_corpus_markdown_text_contains("Phase 19 APIF documentation corpus", &docs, required);
    }

    for (source_name, source) in docs {
        for forbidden in [
            "public API rollback guarantee",
            "public API recovery guarantee",
            "public API locking guarantee",
            "public API secure erase guarantee",
        ] {
            assert_not_contains(source_name, source, forbidden);
        }
    }

    for command in [
        "run cargo test --locked -p dexios-domain --features test-support --test workflow_public_api --test archive_public_api --test cleanup_receipts --test transactions_staged_output --test transactions_linked_publication --test transactions_failure_hooks --test workflow_errors --release",
        "run cargo test --locked -p dexios-core --test public_api_footguns --release",
        "run cargo test --locked -p dexios --test verification_gate_docs --release",
    ] {
        assert_non_comment_line_count(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            command,
            1,
        );
    }
}
#[test]
fn phase15_storage_identity_source_boundaries_are_source_gated() {
    for required in [
        "pub enum PathRole",
        "ProcessedSource",
        "CleanupTarget",
        "fs::symlink_metadata(&absolute_path)",
        "meta.file_type().is_symlink()",
        "reject_parent_components(&path)?",
        "Component::ParentDir",
        "reject_symlinked_prefix(&absolute_path)?",
        "reject_symlinked_prefix(&existing_parent)?",
        "same_file::is_same_file",
        "resolve_missing_target_parent",
    ] {
        assert_contains(
            "dexios-domain/src/storage/identity.rs",
            DEXIOS_DOMAIN_IDENTITY_RS,
            required,
        );
    }

    let unpack_intent_section = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "impl UnpackIntent",
        "struct HandleRequest",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::UnpackIntent::new",
        &unpack_intent_section,
        &[
            "PathIdentityGraph::new",
            ".add_existing(&input_path, PathRole::ProcessedSource)",
            "CleanupReceipt::from_processed_sources",
            ".add_existing(path, PathRole::DetachedHeader)",
            "graph.validate()",
            "read_resolved_existing_no_follow(&input_target)",
        ],
    );
    for required in [
        "let input_path = input_path.as_ref().to_path_buf();",
        "output_dir_path: output_dir_path.as_ref().to_path_buf()",
        "PathRole::ProcessedSource",
        "PathRole::DetachedHeader",
        "read_resolved_existing_no_follow",
    ] {
        assert_contains(
            "dexios-domain/src/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_RS,
            required,
        );
    }

    let manifest_identity_section = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn prepare_manifest_extraction_entities",
        "fn stage_manifest_file_body",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::prepare_manifest_extraction_entities",
        &manifest_identity_section,
        &[
            "PathIdentityGraph::new",
            ".add_existing(input_path, PathRole::Input)",
            ".add_existing(detached_header_path, PathRole::DetachedHeader)",
            ".add_unpack_root(&output_dir)",
            ".add_output(&full_path, PathRole::Output, overwrite_policy)",
        ],
    );

    for required in [
        "identity_rejects_existing_roles_with_final_symlink_components",
        "identity_rejects_existing_roles_with_symlinked_parent_prefixes",
        "identity_rejects_existing_output_roles_with_symlinked_parent_prefixes",
        "identity_accepts_processed_source_and_cleanup_roles_for_real_existing_files",
        "identity_rejects_hardlink_alias",
        "identity_rejects_symlinked_missing_target_prefix",
    ] {
        assert_contains(
            "dexios-domain/tests/path_identity.rs",
            DEXIOS_DOMAIN_PATH_IDENTITY_TESTS,
            required,
        );
    }

    for required in [
        "unpack_intent_rejects_final_symlink_archive_input_before_parsing",
        "unpack_intent_rejects_final_symlink_detached_header_before_parsing",
        "unpack_intent_rejects_archive_input_with_symlinked_parent_before_parsing",
        "unpack_rejects_symlinked_intermediate_output_paths",
        "unpack_rejects_symlinked_output_directory_prefix",
    ] {
        assert_contains(
            "dexios-domain/tests/unpack_symlink_revalidation.rs",
            DEXIOS_DOMAIN_UNPACK_SYMLINK_REVALIDATION_TESTS,
            required,
        );
    }
    for required in [
        "unpack_rejects_entry_that_aliases_encrypted_input_archive",
        "unpack_rejects_entry_that_aliases_detached_header",
    ] {
        assert_contains(
            "dexios-domain/tests/unpack_path_identity.rs",
            DEXIOS_DOMAIN_UNPACK_PATH_IDENTITY_TESTS,
            required,
        );
    }

    for required in [
        "unpack_cli_rejects_final_symlink_archive_input_before_parsing",
        "unpack_cli_rejects_final_symlink_detached_header_before_parsing",
        "unpack_cli_rejects_symlinked_output_component",
        "unpack_cli_rejects_symlinked_output_prefix",
        "unpack_cli_delete_input_rejects_archive_entry_that_aliases_input",
    ] {
        assert_contains(
            "dexios/tests/unpack_cli_regressions.rs",
            DEXIOS_UNPACK_CLI_REGRESSION_TESTS,
            required,
        );
    }
}
#[test]
fn phase16_processed_source_cleanup_authorization_is_source_gated() {
    let docs = [
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        ("book/src/technical-details/Secure-Erase.md", SECURE_ERASE),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
        ("SECURITY.md", SECURITY_MD),
    ];

    for required in [
        "from_processed_sources",
        "from_processed_source_trees",
        "ProcessedSourceCleanupResult",
        "cleanup target is not processed-source evidence",
        "changed cleanup target tree",
        "struct CapturedTarget",
        "let (file_content, handle) = CleanupFileStamp::capture(path)?;",
        "CleanupTargetIdentity::from_handle(handle, is_symlink)",
        "same_file::Handle::from_file(file.try_clone()?)?",
        "pub fn from_commit_and_hash",
        "HashVerification::Failed",
    ] {
        assert_contains(
            "dexios-domain/src/storage/cleanup.rs",
            DEXIOS_DOMAIN_CLEANUP_RS,
            required,
        );
    }

    for required in [
        "impl sealed::CleanupAuthorizedReceipt for CommitReceipt",
        "impl CleanupAuthorizedReceipt for CommitReceipt",
    ] {
        assert_contains(
            "dexios-domain/src/storage/transaction.rs",
            DEXIOS_DOMAIN_TRANSACTION_RS,
            required,
        );
    }
    assert_not_contains(
        "dexios-domain/src/storage/transaction.rs",
        DEXIOS_DOMAIN_TRANSACTION_RS,
        "impl CleanupAuthorizedReceipt for PartialCommitReceipt",
    );

    for (source_name, source, constructor) in [
        (
            "dexios-domain/src/encrypt.rs",
            DEXIOS_DOMAIN_ENCRYPT_RS,
            "CleanupReceipt::from_processed_sources",
        ),
        (
            "dexios-domain/src/decrypt.rs",
            DEXIOS_DOMAIN_DECRYPT_RS,
            "CleanupReceipt::from_processed_sources",
        ),
        (
            "dexios-domain/src/pack.rs",
            DEXIOS_DOMAIN_PACK_RS,
            "CleanupReceipt::from_processed_source_trees",
        ),
        (
            "dexios-domain/src/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_RS,
            "CleanupReceipt::from_processed_sources",
        ),
    ] {
        assert_contains(source_name, source, "PathRole::ProcessedSource");
        assert_contains(source_name, source, constructor);
        assert_contains(source_name, source, "ProcessedSourceCleanupResult");
    }

    assert_contains(
        "dexios-domain/src/storage/identity.rs",
        DEXIOS_DOMAIN_IDENTITY_RS,
        "matches!(input.role, PathRole::Input | PathRole::ProcessedSource)",
    );

    for (source_name, source, execute_fn) in [
        (
            "dexios/src/subcommands/encrypt.rs",
            DEXIOS_ENCRYPT_RS,
            "execute_transactional_with_cleanup",
        ),
        (
            "dexios/src/subcommands/decrypt.rs",
            DEXIOS_DECRYPT_RS,
            "execute_transactional_with_cleanup",
        ),
        (
            "dexios/src/subcommands/pack.rs",
            DEXIOS_PACK_RS,
            "execute_transactional_with_cleanup",
        ),
        (
            "dexios/src/subcommands/unpack.rs",
            DEXIOS_UNPACK_RS,
            "execute_with_cleanup",
        ),
    ] {
        assert_contains(source_name, source, execute_fn);
        assert_contains(source_name, source, "cleanup_receipt()");
        assert_not_contains(source_name, source, "CleanupReceipt::from_paths");
    }

    assert_not_contains(
        "dexios/src/subcommands.rs",
        DEXIOS_SUBCOMMANDS_RS,
        "CleanupReceipt::from_paths",
    );
    assert_contains(
        "dexios/src/subcommands.rs",
        DEXIOS_SUBCOMMANDS_RS,
        "Domain-returned processed-source cleanup evidence",
    );
    assert_contains(
        "dexios/src/subcommands.rs",
        DEXIOS_SUBCOMMANDS_RS,
        "PostCommitSuccess::from_commit_and_hash",
    );

    for required in [
        "cleanup_receipt_from_processed_source_refuses_replaced_file",
        "cleanup_receipt_from_processed_source_tree_refuses_changed_directory_tree",
        "cleanup_receipt_requires_hash_success_before_delete",
    ] {
        assert_contains(
            "dexios-domain/tests/cleanup_receipts.rs",
            DEXIOS_DOMAIN_CLEANUP_RECEIPTS_TESTS,
            required,
        );
    }

    for required in [
        "ordinary delete-after-success cleanup",
        "processed-source cleanup evidence",
        "changed source tree",
        "partial commit evidence is not cleanup authorization",
        "committed outputs are not rolled back",
        "no secure erase",
        "no physical sanitization",
    ] {
        assert_corpus_markdown_text_contains("Phase 16 documentation corpus", &docs, required);
    }

    for (source_name, source) in docs {
        for forbidden in [
            "secure erase guarantee",
            "physical sanitization guarantee",
            "cleanup runs after partial commit evidence",
            "cleanup rollback",
            "rollback committed outputs",
        ] {
            assert_not_contains(source_name, source, forbidden);
        }
    }

    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "cargo test --locked -p dexios-domain --features test-support --test cleanup_receipts --test path_identity --release",
    );
}
#[test]
fn phase17_detached_payload_header_publication_is_source_gated() {
    let docs = [
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        ("book/src/technical-details/Secure-Erase.md", SECURE_ERASE),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
        ("SECURITY.md", SECURITY_MD),
    ];

    for required in [
        "DetachedPairReceipt",
        "PartialDetachedPublication",
        "DetachedPublicationFailure",
        "detached_publication_failure",
    ] {
        assert_contains(
            "dexios-domain/src/storage/transaction.rs",
            DEXIOS_DOMAIN_TRANSACTION_RS,
            required,
        );
    }
    assert_not_contains(
        "dexios-domain/src/storage/transaction.rs",
        DEXIOS_DOMAIN_TRANSACTION_RS,
        "impl CleanupAuthorizedReceipt for PartialDetachedPublication",
    );

    for (source_name, source) in [
        ("dexios-domain/src/encrypt.rs", DEXIOS_DOMAIN_ENCRYPT_RS),
        ("dexios-domain/src/pack.rs", DEXIOS_DOMAIN_PACK_RS),
    ] {
        assert_contains(source_name, source, "DetachedPublication(TransactionError)");
        assert_contains(source_name, source, "detached_publication_failure");
        assert_contains(
            source_name,
            source,
            "map_detached_publication_transaction_error",
        );
    }
    assert_contains(
        "dexios-domain/src/pack.rs",
        DEXIOS_DOMAIN_PACK_RS,
        "has_detached_header",
    );

    for required in [
        "Detached publication incomplete",
        "source cleanup was not authorized",
        "PathRole::Output | PathRole::GeneratedOutput => \"payload\"",
        "PathRole::DetachedHeader | PathRole::GeneratedDetachedHeader => \"header\"",
    ] {
        assert_contains(
            "dexios/src/subcommands/errors.rs",
            DEXIOS_SUBCOMMAND_ERRORS_RS,
            required,
        );
    }

    for required in [
        "linked_transaction_complete_detached_pair_receipt_names_payload_and_header",
        "linked_transaction_partial_detached_publication_receipt_names_committed_and_failed_artifacts",
        "post_commit_sync_detached_publication_failure_is_not_clean_success",
    ] {
        assert_contains(
            "dexios-domain/tests/transactions_linked_publication.rs",
            DEXIOS_DOMAIN_TRANSACTIONS_LINKED_PUBLICATION_TESTS,
            required,
        );
    }
    assert_contains(
        "dexios-domain/tests/transactions_linked_publication.rs",
        DEXIOS_DOMAIN_TRANSACTIONS_LINKED_PUBLICATION_TESTS,
        "TransactionError::PostCommitSync",
    );

    for required in [
        "encrypt_detached_partial_publication_reports_committed_payload_and_failed_header",
        "pack_detached_partial_publication_reports_committed_payload_and_failed_header",
    ] {
        assert_contains(
            "dexios-domain/tests/detached_publication.rs",
            DEXIOS_DOMAIN_DETACHED_PUBLICATION_TESTS,
            required,
        );
    }

    for required in [
        "partial_detached_publication_has_no_cleanup_authorization_impl",
        "delete_source_detached_partial_publication_cleanup_denial_is_source_gated",
        "detached_encrypt_partial_publication_names_committed_and_failed_artifacts",
        "detached_pack_partial_publication_names_committed_and_failed_artifacts",
        "encrypt_detached_partial_publication_source_gate_names_artifact_state",
        "pack_detached_partial_publication_source_gate_names_generated_artifact_state",
    ] {
        assert_corpus_contains(
            "Phase 17 detached publication tests",
            &[
                (
                    "dexios-domain/tests/cleanup_receipts.rs",
                    DEXIOS_DOMAIN_CLEANUP_RECEIPTS_TESTS,
                ),
                (
                    "dexios/tests/delete_source_cli.rs",
                    DEXIOS_DELETE_SOURCE_CLI_TESTS,
                ),
                (
                    "dexios/tests/workflow_error_cli_boundary.rs",
                    DEXIOS_WORKFLOW_ERROR_CLI_BOUNDARY_TESTS,
                ),
                (
                    "dexios/tests/encrypt_cli_regressions.rs",
                    DEXIOS_ENCRYPT_CLI_REGRESSION_TESTS,
                ),
                (
                    "dexios/tests/pack_cli_regressions.rs",
                    DEXIOS_PACK_CLI_REGRESSION_TESTS,
                ),
            ],
            required,
        );
    }

    for required in [
        "pair-aware detached publication",
        "partial detached publication",
        "committed and failed artifact state",
        "source cleanup is denied after partial detached publication",
        "does not roll back committed artifacts",
        "guarantee recovery",
    ] {
        assert_corpus_markdown_text_contains("Phase 17 documentation corpus", &docs, required);
    }
    assert_contains(
        "SECURITY.md",
        SECURITY_MD,
        "detached payload/header partial publication diagnostics and cleanup denial",
    );

    for (source_name, source) in docs {
        for forbidden in [
            "provides atomic multi-file commit",
            "automatic rollback",
            "guaranteed recovery",
            "cleanup authorized after partial detached publication",
        ] {
            assert_not_contains(source_name, source, forbidden);
        }
    }

    for command in [
        "run cargo test --locked -p dexios-domain --features test-support --test transactions_staged_output --test transactions_linked_publication --test transactions_failure_hooks --test cleanup_receipts --test detached_publication --release",
        "run cargo test --locked -p dexios --test encrypt_cli_regressions --test pack_cli_regressions --test delete_source_cli --test workflow_error_cli_boundary --test workflow_error_cli_archive --test workflow_error_cli_header_key --test verification_gate_docs --release",
    ] {
        assert_non_comment_line_count(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            command,
            1,
        );
    }
}
#[test]
fn phase18_header_and_key_mutation_guards_are_source_gated() {
    let docs = [
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        ("book/src/technical-details/Keys.md", KEYS),
        ("book/src/dexios-core/Headers.md", HEADERS),
    ];

    for required in [
        "MutationSnapshot",
        "MutationFreshnessError",
        "fs::symlink_metadata",
        "metadata.dev()",
        "metadata.ino()",
        "IdentityChanged",
        "ContentChanged",
    ] {
        assert_contains(
            "dexios-domain/src/storage/mutation.rs",
            DEXIOS_DOMAIN_MUTATION_RS,
            required,
        );
    }

    for forbidden in [
        "modified()",
        "created()",
        "accessed()",
        "SystemTime",
        "mtime",
        "ctime",
    ] {
        assert_not_contains(
            "dexios-domain/src/storage/mutation.rs",
            DEXIOS_DOMAIN_MUTATION_RS,
            forbidden,
        );
    }

    for (source_name, source) in [
        (
            "dexios-domain/src/header/strip.rs",
            DEXIOS_DOMAIN_HEADER_STRIP_RS,
        ),
        (
            "dexios-domain/src/header/restore.rs",
            DEXIOS_DOMAIN_HEADER_RESTORE_RS,
        ),
    ] {
        assert_contains(source_name, source, "MutationSnapshot");
        assert_contains(source_name, source, "original_bytes()");
        assert_contains(source_name, source, "ensure_fresh()");
        assert_contains(source_name, source, "map_mutation_freshness_error");
    }
    assert_contains(
        "dexios-domain/src/header/restore.rs",
        DEXIOS_DOMAIN_HEADER_RESTORE_RS,
        "header_target.original_bytes()",
    );
    assert_contains(
        "dexios-domain/src/header/restore.rs",
        DEXIOS_DOMAIN_HEADER_RESTORE_RS,
        "target.original_bytes().to_vec()",
    );

    for required in [
        "TargetChanged",
        "DetachedHeaderChanged",
        "map_mutation_freshness_error",
    ] {
        assert_contains(
            "dexios-domain/src/header.rs",
            DEXIOS_DOMAIN_HEADER_RS,
            required,
        );
    }

    for required in [
        "crate::storage::mutation::ensure_fresh",
        "storage::mutation::{MutationFreshnessError, MutationSnapshot}",
        "read_mutation_target",
        "MutationFreshnessError::IdentityChanged",
        "MutationFreshnessError::ContentChanged",
        "Error::TargetChanged",
    ] {
        assert_contains("dexios-domain/src/key.rs", DEXIOS_DOMAIN_KEY_RS, required);
    }

    for (source_name, source) in [
        ("dexios-domain/src/key/add.rs", DEXIOS_DOMAIN_KEY_ADD_RS),
        (
            "dexios-domain/src/key/change.rs",
            DEXIOS_DOMAIN_KEY_CHANGE_RS,
        ),
        (
            "dexios-domain/src/key/delete.rs",
            DEXIOS_DOMAIN_KEY_DELETE_RS,
        ),
    ] {
        assert_contains(source_name, source, "super::read_mutation_target(target)?");
        assert_not_contains(source_name, source, "fs::read(target.target_path())");
    }

    for required in [
        "mutation_snapshot_rejects_same_inode_content_rewrite",
        "mutation_snapshot_rejects_path_replacement_with_identical_bytes",
        "header_strip_rejects_target_rewrite_after_snapshot",
        "header_strip_rejects_target_replacement_after_snapshot",
        "header_restore_rejects_target_rewrite_after_snapshot",
        "header_restore_rejects_detached_header_append_after_snapshot",
        "header_restore_rejects_detached_header_replacement_after_snapshot",
    ] {
        assert_contains(
            "dexios-domain/tests/header_restore.rs",
            DEXIOS_DOMAIN_HEADER_RESTORE_TESTS,
            required,
        );
    }
    assert_contains(
        "dexios-domain/tests/keyslots_intent_v1.rs",
        DEXIOS_DOMAIN_KEYSLOTS_INTENT_TESTS,
        "key_add_rejects_target_replacement_after_old_key_proof",
    );

    assert_contains(
        "dexios/tests/header_cli_regressions.rs",
        DEXIOS_HEADER_CLI_REGRESSION_TESTS,
        "header_stale_errors_have_role_specific_cli_mappings",
    );
    assert_contains(
        "dexios/tests/key_cli_regressions.rs",
        DEXIOS_KEY_CLI_REGRESSION_TESTS,
        "key_stale_target_error_mapping_is_sanitized",
    );

    for required in [
        "Header workflow target changed before commit",
        "Detached header changed before header restore commit",
        "Key workflow target changed before commit",
    ] {
        assert_contains(
            "dexios/src/subcommands/errors.rs",
            DEXIOS_SUBCOMMAND_ERRORS_RS,
            required,
        );
    }

    for required in [
        "mutation freshness",
        "same-inode content changes",
        "path replacement",
        "stale detached header",
        "stale key mutation",
        "does not add recovery",
        "does not use filesystem locks",
    ] {
        assert_corpus_markdown_text_contains("Phase 18 documentation corpus", &docs, required);
    }

    for (source_name, source) in docs {
        for forbidden in [
            "timestamp-only freshness",
            "automatic rollback",
            "guaranteed recovery",
            "stale mutation recovery",
            "secure erase stale mutation",
            "uses filesystem locks",
        ] {
            assert_not_contains(source_name, source, forbidden);
        }
    }

    for command in [
        "run cargo test --locked -p dexios-domain --test header_restore --test header_workflow_errors --test keyslots_intent_v1 --test keyslots_crypto_v1 --test keyslots_mutation_v1 --test workflow_errors --release",
        "run cargo test --locked -p dexios --test header_cli_regressions --test key_cli_regressions --test verification_gate_docs --release",
    ] {
        assert_non_comment_line_count(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            command,
            1,
        );
    }
}
#[test]
fn crate_roots_keep_the_no_unsafe_compiler_baseline() {
    for (source_name, source) in [
        ("dexios/src/main.rs", DEXIOS_MAIN_RS),
        ("dexios-core/src/lib.rs", DEXIOS_CORE_LIB_RS),
        ("dexios-domain/src/lib.rs", DEXIOS_DOMAIN_LIB_RS),
    ] {
        assert_contains(source_name, source, "#![forbid(unsafe_code)]");
    }
}
#[test]
fn phase9_kdf_passphrase_and_secret_contract_is_source_gated() {
    for required in [
        "argon2 = { version = \"0.5.3\", default-features = false, features = [\"alloc\", \"zeroize\"] }",
        "blake3 = \"1.8\"",
    ] {
        assert_contains("Cargo.toml", CARGO_TOML, required);
    }

    for required in [
        "PassphraseWordCount",
        "pub const DEFAULT",
        "generate_passphrase(total_words: PassphraseWordCount)",
    ] {
        assert_contains("dexios-core/src/key.rs", DEXIOS_CORE_KEY_RS, required);
    }

    for required in [
        "validate_autogenerate_words",
        "PassphraseWordCount::try_new",
        "generated passphrase word count must be a positive integer",
    ] {
        assert_contains("dexios/src/cli.rs", DEXIOS_CLI_RS, required);
    }

    for required in [
        "parse_generated_passphrase_word_count",
        "Invalid generated passphrase word count",
        "generated_passphrase_disclosure",
    ] {
        assert_contains("dexios/src/global/states.rs", DEXIOS_STATES_RS, required);
    }

    for required in [
        "case_encrypt_auto_invalid_values_do_not_disclose",
        "--auto=0",
        "--auto=-1",
        "--auto=abc",
        "Your generated passphrase is intentionally shown here",
    ] {
        assert_contains(
            "scripts/verify_cli_surface.sh",
            VERIFY_CLI_SURFACE,
            required,
        );
    }

    for required in [
        "argon2 0.5.3",
        "zeroize",
        "scripts/measure_performance_gate.sh --scenario kdf",
        "--max-kdf-seconds",
        "DEXIOS_KDF_MAX_SECONDS",
        "not a whole-process memory cleanup",
    ] {
        assert_contains(
            "book/src/dexios-core/Password-Hashing.md",
            PASSWORD_HASHING,
            required,
        );
    }

    for required in [
        "--auto` without a",
        "defaults to `7` words",
        "--auto=0",
        "--auto=-1",
        "rejected before passphrase generation",
        "terminal scrollback or logs",
        "`key add`",
        "fresh keyslot wrapping nonce",
        "preserve payload bytes",
    ] {
        assert_contains("book/src/technical-details/Keys.md", KEYS, required);
    }
    assert_not_contains(
        "book/src/technical-details/Keys.md",
        KEYS,
        "`key add` remains unsupported",
    );

    for required in [
        "redacted",
        "no blanket clone",
        "no public direct exposure API",
        "does not implement `Deref`",
        "closure-scoped",
        "OS",
        "swap",
        "crash dump",
        "physical-media",
    ] {
        assert_contains(
            "book/src/dexios-core/Protected-Wrapper.md",
            PROTECTED_WRAPPER,
            required,
        );
    }

    for required in [
        "uname=",
        "rustc=",
        "cargo=",
        "cpu_model=",
        "mem_total=",
        "--max-kdf-seconds",
        "DEXIOS_KDF_MAX_SECONDS",
    ] {
        assert_contains(
            "scripts/measure_performance_gate.sh",
            MEASURE_PERFORMANCE_GATE,
            required,
        );
    }

    for required in [
        "argon2 0.5.3",
        "invalid `--auto` word counts",
        "hardware profile",
        "narrow secret-memory claim",
    ] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }

    for required in [
        "argon2 0.5.3",
        "invalid generated passphrase counts",
        "--max-kdf-seconds",
        "narrow secret-memory claim",
    ] {
        assert_contains("CHANGELOG.md", CHANGELOG, required);
    }

    for forbidden in [
        "guaranteed unrecoverable",
        "securely erased from all memory",
        "physical media sanitization guarantee",
    ] {
        assert_not_contains(
            "book/src/dexios-core/Protected-Wrapper.md",
            PROTECTED_WRAPPER,
            forbidden,
        );
        assert_not_contains(
            "dexios-core/src/protected.rs",
            DEXIOS_CORE_PROTECTED_RS,
            forbidden,
        );
    }
}
#[test]
fn phase10_domain_api_and_error_cleanup_is_source_gated() {
    for required in [
        "UnpackIntent",
        "test-support",
        "diagnostic source chains",
        "class-based and terse",
    ] {
        assert_contains("CHANGELOG.md", CHANGELOG, required);
    }

    for required in [
        "API-001",
        "checked `UnpackIntent`",
        "test-support",
        "WorkflowErrorClass",
        "diagnostic `source()` chains",
        "source-chain",
        "not printed by default CLI errors",
    ] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }

    for required in [
        "checked `UnpackIntent` state",
        "manifest-first archive payload",
        "no longer creates a full plaintext archive temporary file",
        "selected staged file bodies",
        "they do not prove that the host has enough free memory or disk space",
    ] {
        assert_contains(
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
            required,
        );
    }

    for forbidden in [
        "crash-consistency guarantee",
        "crash consistency guarantee",
        "unpack-side plaintext temporary ZIP exposure eliminated",
        "eliminates unpack-side plaintext temporary ZIP exposure",
        "secure erase guarantee",
        "physical sanitization guarantee",
        "provides forensic recovery resistance",
    ] {
        assert_not_contains("CHANGELOG.md", CHANGELOG, forbidden);
        assert_not_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, forbidden);
        assert_not_contains(
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
            forbidden,
        );
    }

    for required in [
        "pub struct UnpackIntent",
        "impl UnpackIntent",
        "input.try_reader().map_err(Error::Storage)?",
        "pub fn execute(intent: UnpackIntent)",
        "fn source(&self) -> Option<&(dyn std::error::Error + 'static)>",
    ] {
        assert_contains(
            "dexios-domain/src/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_RS,
            required,
        );
    }
    for forbidden in ["pub struct Request", "pub(crate) struct Request"] {
        assert_not_contains(
            "dexios-domain/src/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_RS,
            forbidden,
        );
    }

    assert_contains(
        "dexios/src/subcommands/unpack.rs",
        DEXIOS_UNPACK_RS,
        "domain::unpack::UnpackIntent::new",
    );
    assert_not_contains(
        "dexios/src/subcommands/unpack.rs",
        DEXIOS_UNPACK_RS,
        "domain::unpack::Request",
    );

    for required in ["default = []", "test-support = []"] {
        assert_contains(
            "dexios-domain/Cargo.toml",
            DEXIOS_DOMAIN_CARGO_TOML,
            required,
        );
    }
    for required in [
        "#[cfg(any(test, feature = \"test-support\"))]",
        "pub mod test_support;",
        "#[cfg(not(any(test, feature = \"test-support\")))]",
        "mod test_support;",
    ] {
        assert_contains(
            "dexios-domain/src/storage/mod.rs",
            DEXIOS_DOMAIN_STORAGE_RS,
            required,
        );
    }
    for required in [
        "#[cfg(any(test, feature = \"test-support\"))]",
        "pub fn with_failure_hooks",
    ] {
        assert_contains(
            "dexios-domain/src/storage/transaction.rs",
            DEXIOS_DOMAIN_TRANSACTION_RS,
            required,
        );
        assert_contains(
            "dexios-domain/src/storage/temp.rs",
            DEXIOS_DOMAIN_TEMP_RS,
            required,
        );
    }
    for required in [
        "source: Option<io::Error>",
        "fn source(&self) -> Option<&(dyn std::error::Error + 'static)>",
        "source: Some(source)",
    ] {
        assert_contains(
            "dexios-domain/src/storage/transaction.rs",
            DEXIOS_DOMAIN_TRANSACTION_RS,
            required,
        );
    }

    for required in [
        "WorkflowErrorClass::IoFailure",
        "WorkflowErrorClass::TransactionCommitFailure",
        "map_unpack_error",
    ] {
        assert_contains(
            "dexios/src/subcommands/errors.rs",
            DEXIOS_SUBCOMMAND_ERRORS_RS,
            required,
        );
    }
    for forbidden in [".chain()", ".source()", "source chain"] {
        assert_not_contains(
            "dexios/src/subcommands/errors.rs",
            DEXIOS_SUBCOMMAND_ERRORS_RS,
            forbidden,
        );
    }

    for required in [
        "error.source().is_some()",
        "storage_errors_preserve_io_sources",
        "transaction_errors_preserve_io_sources",
        "domain_errors_classify_transactions_without_display_strings",
    ] {
        assert_contains(
            "dexios-domain/tests/workflow_errors.rs",
            DEXIOS_DOMAIN_WORKFLOW_ERROR_TESTS,
            required,
        );
    }
    for required in [
        "assert_no_default_source_chain",
        "Authentication failed",
        "master key",
        "keyslot",
    ] {
        assert_contains(
            "dexios/tests/workflow_error_cli_boundary.rs",
            DEXIOS_WORKFLOW_ERROR_CLI_BOUNDARY_TESTS,
            required,
        );
    }
}
#[test]
fn phase04_failure_hook_and_workflow_boundary_gates_are_source_gated() {
    for required in [
        "WorkflowErrorClass::CleanupFailure",
        "WorkflowErrorClass::ResourcePressure",
        "classify_cleanup_failure",
        "classify_cleanup_result",
    ] {
        assert_contains(
            "dexios-domain/src/workflow_error.rs",
            DEXIOS_DOMAIN_WORKFLOW_ERROR_RS,
            required,
        );
    }

    for required in [
        "source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>",
        "FailureHooks::none()",
        "#[cfg(any(test, feature = \"test-support\"))]",
        "pub fn run_with_failure_hooks",
        "pub enum HashVerification",
        "pub struct PostCommitSuccess",
    ] {
        assert_contains(
            "dexios-domain/src/storage/cleanup.rs",
            DEXIOS_DOMAIN_CLEANUP_RS,
            required,
        );
    }

    for required in [
        "WorkflowErrorClass::CleanupFailure",
        "WorkflowErrorClass::ResourcePressure",
        "eprintln!(\"{error}\")",
        "CleanupAfterCommitError",
        "PostCommitSuccess::from_commit_and_hash",
        "HashVerification::Failed",
    ] {
        assert_corpus_contains(
            "Phase 4 CLI workflow boundary corpus",
            &[
                ("dexios/src/main.rs", DEXIOS_MAIN_RS),
                ("dexios/src/subcommands.rs", DEXIOS_SUBCOMMANDS_RS),
                (
                    "dexios/src/subcommands/errors.rs",
                    DEXIOS_SUBCOMMAND_ERRORS_RS,
                ),
            ],
            required,
        );
    }

    for required in [
        "phase04_source_gates_cover_all_migration_boundary_sources",
        "DEXIOS_FAIL_POINT",
        "fail-on",
        "formatted_error_control_flow_rejects_string_inspection",
    ] {
        assert_contains(
            "dexios-domain/tests/workflow_public_api.rs",
            DEXIOS_DOMAIN_WORKFLOW_PUBLIC_API_TESTS,
            required,
        );
    }

    for command in [
        "run cargo test --locked -p dexios-domain --test workflow_public_api --all-features --release",
        "run cargo test --locked -p dexios --test verification_gate_docs --release",
    ] {
        assert_non_comment_line_count(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            command,
            1,
        );
    }
}
#[test]
fn phase04_archive_boundary_gates_are_source_gated() {
    for required in [
        "phase4_archive_boundary_rejects_phase5_dxar_extraction_surface",
        "payload_kind_and_framing_bytes_stay_core_owned_not_cli_duplicated",
        "phase5_archive_surface_violations",
        "payload_contract_duplication_violations",
        "public_line_exposes_zip_type",
        "public_line_exposes_zip_metadata_knob",
        "d03_public_archive_policy_has_no_compression_selector",
    ] {
        assert_contains(
            "dexios-domain/tests/archive_public_api.rs",
            DEXIOS_DOMAIN_ARCHIVE_PUBLIC_API_TESTS,
            required,
        );
    }

    assert_contains(
        "dexios-domain/src/archive.rs",
        DEXIOS_DOMAIN_ARCHIVE_RS,
        "pub struct ArchivePolicy",
    );

    for forbidden in [
        "pub enum ArchiveCompression",
        "ArchiveCompression::Zstd",
        "pub const fn zstd",
        "pub const fn compression",
    ] {
        assert_not_contains(
            "dexios-domain/src/archive.rs",
            DEXIOS_DOMAIN_ARCHIVE_RS,
            forbidden,
        );
    }

    for forbidden in [
        "pub fn extract_dxar",
        "pub struct DxarExtractor",
        "Arg::new(\"dxar\")",
        ".long(\"dxar\")",
        "PayloadKind::ManifestArchive",
        "PayloadFramingProfile::ManifestFirst",
    ] {
        assert_not_contains("dexios/src/cli.rs", DEXIOS_CLI_RS, forbidden);
        assert_not_contains("dexios/src/subcommands/pack.rs", DEXIOS_PACK_RS, forbidden);
        assert_not_contains(
            "dexios/src/subcommands/unpack.rs",
            DEXIOS_UNPACK_RS,
            forbidden,
        );
    }

    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo test --locked -p dexios-domain --test archive_public_api --release",
        1,
    );
}
#[test]
fn phase11_filesystem_transaction_and_cleanup_contract_is_source_gated() {
    let docs = [
        ("README.md", README),
        ("CHANGELOG.md", CHANGELOG),
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        ("book/src/technical-details/Secure-Erase.md", SECURE_ERASE),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
    ];
    let sources = [
        (
            "dexios-domain/src/storage/cleanup.rs",
            DEXIOS_DOMAIN_CLEANUP_RS,
        ),
        (
            "dexios-domain/src/storage/transaction.rs",
            DEXIOS_DOMAIN_TRANSACTION_RS,
        ),
        ("dexios-domain/src/storage/temp.rs", DEXIOS_DOMAIN_TEMP_RS),
    ];
    for (source_name, source) in docs {
        for forbidden in [
            "secure erase guarantee",
            "physical sanitization guarantee",
            "forensic recovery resistance",
            "full crash-consistency guarantee",
            "provides power-failure proof",
            "rollback committed outputs",
            "unpack-side plaintext temporary ZIP exposure eliminated",
            "eliminates unpack-side plaintext temporary ZIP exposure",
        ] {
            assert_not_contains(source_name, source, forbidden);
        }
    }

    for required in [
        "ordinary delete-after-success cleanup",
        "changed cleanup identity",
        "partial commit evidence",
        "linked commit evidence",
        "committed outputs are not rolled back",
        "staged flush/sync/fd-relative final placement",
        "same-directory temporary files",
        "linkat",
        "renameat",
        "File::sync_all",
        "does not claim portable parent-directory durability",
        "remove_file does not guarantee immediate physical deletion",
        "no secure erase",
        "no physical sanitization",
        "no full power-failure proof",
        "manifest-first archive payload",
        "no full plaintext archive temporary file",
        "selected staged file bodies",
    ] {
        assert_corpus_contains("Phase 11 documentation corpus", &docs, required);
    }

    for required in [
        "Phase 11 filesystem transaction and cleanup",
        "linked commit evidence",
        "changed cleanup identity",
        "delete-after-success proof",
        "committed outputs are not rolled back",
        "no secure erase",
        "no physical sanitization",
        "no full power-failure proof",
        "manifest-first archive payload",
        "no full plaintext archive temporary file",
    ] {
        assert_contains("CHANGELOG.md", CHANGELOG, required);
    }

    for required in [
        "CleanupTarget",
        "target identity snapshot",
        "changed cleanup identity",
        "PostCommitSuccess",
        "HashVerification::Failed",
    ] {
        assert_corpus_contains("Phase 11 cleanup source corpus", &sources, required);
    }

    for required in [
        "TransactionError::PartialCommit",
        "CommittedArtifact",
        "receipt",
        "failed",
    ] {
        assert_contains(
            "dexios-domain/src/storage/transaction.rs",
            DEXIOS_DOMAIN_TRANSACTION_RS,
            required,
        );
    }

    for required in [
        "NamedTempFile::new_in",
        "target.target_parent()",
        "self.wrote = true",
        "if !self.wrote",
        "NamedStagedOutput::prepare_for_persist",
        "prepare_for_persist()?",
        "flush()",
        "sync_all()",
        "persist_prepared",
        "openat(",
        "OFlags::NOFOLLOW",
        "mkdirat(",
        "linkat(",
        "renameat(",
    ] {
        assert_contains(
            "dexios-domain/src/storage/temp.rs",
            DEXIOS_DOMAIN_TEMP_RS,
            required,
        );
    }

    assert_occurs_before(
        "dexios-domain/src/storage/temp.rs",
        DEXIOS_DOMAIN_TEMP_RS,
        "self.flush()?;",
        "self.sync_all()",
    );
    assert_occurs_before(
        "dexios-domain/src/storage/temp.rs",
        DEXIOS_DOMAIN_TEMP_RS,
        "if !self.flushed",
        "if !self.synced",
    );
    assert_occurs_before(
        "dexios-domain/src/storage/temp.rs",
        DEXIOS_DOMAIN_TEMP_RS,
        "self.prepare_for_persist()?",
        "self.persist_prepared()",
    );
    assert_occurs_before(
        "dexios-domain/src/storage/transaction.rs",
        DEXIOS_DOMAIN_TRANSACTION_RS,
        "staged.prepare_for_persist()?",
        "staged.persist_prepared()",
    );
}
#[test]
fn phase12_unpack_directory_rollback_contract_is_source_gated() {
    for required in [
        "execute_with_failure_hooks",
        "create_selected_directories_after_final_auth",
        "rollback_empty_directories_best_effort",
        "TransactionError::PartialCommit",
        "commit_all",
    ] {
        assert_contains(
            "dexios-domain/src/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_RS,
            required,
        );
    }

    for required in [
        "pub(crate) fn rollback_empty_directories_best_effort",
        "created_dirs.iter().rev()",
        "delete_empty_directory_target",
        "fs::remove_dir(&target.path)",
    ] {
        assert_contains(
            "dexios-domain/src/storage/cleanup.rs",
            DEXIOS_DOMAIN_CLEANUP_RS,
            required,
        );
    }

    let rollback_section = normalized_rust_production_section(
        "dexios-domain/src/storage/cleanup.rs",
        DEXIOS_DOMAIN_CLEANUP_RS,
        "pub(crate) fn rollback_empty_directories_best_effort",
        "#[derive(Clone, Debug, Eq, PartialEq)]",
    );
    assert_normalized_section_order(
        "dexios-domain/src/storage/cleanup.rs::rollback_empty_directories_best_effort",
        &rollback_section,
        &[
            "created_dirs.iter().rev()",
            "CleanupTarget::from_path(path)",
            "delete_empty_directory_target(&target)",
        ],
    );

    let empty_directory_delete_section = normalized_rust_production_section(
        "dexios-domain/src/storage/cleanup.rs",
        DEXIOS_DOMAIN_CLEANUP_RS,
        "fn delete_empty_directory_target",
        "fn revalidate_target",
    );
    assert!(
        empty_directory_delete_section.contains(&normalized_token("fs::remove_dir(&target.path)")),
        "rollback empty-directory delete must use non-recursive remove_dir"
    );
    assert!(
        !empty_directory_delete_section.contains(&normalized_token("remove_dir_all")),
        "rollback empty-directory delete must not recursively remove directories"
    );

    let unpack_commit_section = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn execute_manifest_archive",
        "fn stage_manifest_extraction",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::execute_manifest_archive",
        &unpack_commit_section,
        &[
            ".finish()",
            "revalidate_extraction_targets",
            "create_selected_directories_after_final_auth",
            "commit_all",
        ],
    );

    let create_selected_directories_section = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn create_selected_directories_after_final_auth",
        "fn revalidate_extraction_targets",
    );
    assert!(
        create_selected_directories_section
            .matches(&normalized_token(
                "rollback_empty_directories_best_effort(&rollback_dirs)"
            ))
            .count()
            >= 2,
        "selected-directory creation must roll back prior created directories on revalidation and mkdir failures"
    );

    for required in [
        "unpack_commit_failure_removes_created_selected_directories",
        "unpack_commit_failure_preserves_preexisting_selected_directories",
        "unpack_commit_failure_removes_nested_intermediates_in_reverse_order",
        "FailurePoint::Persist",
    ] {
        assert_contains(
            "dexios-domain/tests/unpack_commit_rollback.rs",
            DEXIOS_DOMAIN_UNPACK_COMMIT_ROLLBACK_TESTS,
            required,
        );
    }

    for required in [
        "best-effort removes directories created by the current post-final-auth directory pass before first selected file commit",
        "Pre-existing directories are preserved",
        "`TransactionError::PartialCommit`",
        "committed file artifacts are not rolled back",
    ] {
        assert_contains(
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
            required,
        );
    }

    for required in [
        "Phase 12 manifest-unpack directory rollback boundaries",
        "pre-existing directories are preserved",
        "`TransactionError::PartialCommit`",
    ] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }

    for forbidden in [
        "full unpack atomicity",
        "rollback committed outputs",
        "secure erase guarantee",
    ] {
        assert_not_contains(
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
            forbidden,
        );
        assert_not_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, forbidden);
    }
}
#[test]
fn phase7_decision_groups_are_source_gated() {
    // D-01 through D-05: minimum gate authority lives in the safety contract.
    for required in ["VERI-04", "Maintainer Verification Gate"] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }

    // D-06 through D-10: local scripts and CI keep audit/docs checks fresh.
    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "cargo audit --deny warnings",
    );
    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "cargo deny check",
    );
    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "bash scripts/verify_cli_surface.sh",
    );
    assert_contains(
        ".github/workflows/docs.yml",
        DOCS_WORKFLOW,
        "mdbook build --dest-dir target/mdbook",
    );
    assert_contains(
        ".github/workflows/docs.yml",
        DOCS_WORKFLOW,
        "cargo install mdbook --locked --version 0.5.3",
    );

    // D-11 through D-15: resource-sensitive defaults require measured evidence.
    assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, "VERI-05");
    assert_contains(
        "scripts/measure_performance_gate.sh",
        MEASURE_PERFORMANCE_GATE,
        "target/phase7-measurements",
    );

    // D-16 through D-20: breaking safety changes require release notes.
    assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, "VERI-06");
    assert_contains("CHANGELOG.md", CHANGELOG, "## Unreleased");
    assert_contains("dexios/src/cli/args.rs", DEXIOS_CLI_ARGS_RS, "env_key_arg");
    assert_contains("dexios/src/cli.rs", DEXIOS_CLI_RS, "args::env_key_arg()");
    assert_contains(
        "dexios/src/global/states.rs",
        DEXIOS_STATES_RS,
        "env_key_requested",
    );
    assert_contains(
        "book/src/Environment-Variables.md",
        include_str!("../../book/src/Environment-Variables.md"),
        "--env-key",
    );

    assert_contains(".gitignore", GITIGNORE, "/local-notes/");
    assert_contains(
        "scripts/verify_repo_hygiene.sh",
        VERIFY_REPO_HYGIENE,
        "local scratch path is tracked by git",
    );
    assert_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        "Local-only working notes",
    );
    assert_not_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        "committed maintainer project state",
    );
}

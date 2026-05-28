mod verification_gate_support;

use verification_gate_support::*;

#[test]
fn manifest_archive_gate_is_zip_dependency_free() {
    for (source_name, source) in [
        ("Cargo.toml", CARGO_TOML),
        ("dexios-domain/Cargo.toml", DEXIOS_DOMAIN_CARGO_TOML),
        ("dexios/Cargo.toml", DEXIOS_CARGO_TOML),
    ] {
        assert_manifest_has_no_dependency_package(source_name, source, "zip");
    }
    assert_lockfile_has_no_package("Cargo.lock", CARGO_LOCK, "zip");

    for (source_name, bad_manifest) in [
        (
            "synthetic/dependency-table.toml",
            "[dependencies.zip]\nversion = \"8.6.0\"\n",
        ),
        (
            "synthetic/workspace-dependency-table.toml",
            "[workspace.dependencies.zip]\nversion = \"8.6.0\"\n",
        ),
        (
            "synthetic/aliased-package.toml",
            "[dependencies]\narchive_zip = { package = \"zip\", version = \"8.6.0\" }\n",
        ),
    ] {
        assert!(
            std::panic::catch_unwind(|| {
                assert_manifest_has_no_dependency_package(source_name, bad_manifest, "zip");
            })
            .is_err(),
            "manifest zip gate must reject {source_name}"
        );
    }

    assert!(
        std::panic::catch_unwind(|| {
            assert_lockfile_has_no_package(
                "synthetic/Cargo.lock",
                "[[package]]\nname = \"zip\"\nversion = \"8.6.0\"\n",
                "zip",
            );
        })
        .is_err(),
        "lockfile zip gate must reject stale zip package rows"
    );

    for required in [
        "pack_writes_relative_archive_paths",
        "PayloadKind::ManifestArchive",
        "PayloadFramingProfile::ManifestFirst",
        "ManifestFirstPayload::parse",
    ] {
        assert_contains(
            "dexios-domain/tests/pack_paths.rs",
            DEXIOS_DOMAIN_PACK_PATHS_TESTS,
            required,
        );
    }

    for (source_name, source) in [
        ("dexios-domain/src/pack.rs", DEXIOS_DOMAIN_PACK_RS),
        ("dexios-domain/src/unpack.rs", DEXIOS_DOMAIN_UNPACK_RS),
    ] {
        assert_rust_production_source_excludes(
            source_name,
            source,
            &["zip::", "ZipWriter", "ZipArchive", "CompressionMethod"],
        );
    }

    for (source_name, source) in [
        ("dexios-domain/src/unpack.rs", DEXIOS_DOMAIN_UNPACK_RS),
        (
            "dexios-domain/src/storage/transaction.rs",
            DEXIOS_DOMAIN_TRANSACTION_RS,
        ),
        ("dexios-domain/src/storage/temp.rs", DEXIOS_DOMAIN_TEMP_RS),
    ] {
        assert_rust_production_source_excludes(
            source_name,
            source,
            &[
                ".extract(",
                "File::create",
                "std::fs::write",
                "OpenOptions::new().create(true)",
                "OpenOptions::new().create_new(true)",
            ],
        );
        assert_no_direct_final_create_builders(source_name, source);
    }

    for required in [
        "V1PayloadDecryptingReader::new",
        "ArchiveManifest::read_from",
        "ArchiveBodyFrameHeader::read_from",
        "LinkedOutputTransaction::new",
        "stage_in",
        ".with_writer_result(",
        "drain_trailing_plaintext_to_final_auth",
        ".finish()",
        "revalidate_extraction_targets",
        "revalidate_unpack_directory_target",
        "create_unpack_dir_all",
        "create_selected_directories_after_final_auth",
        "commit_all",
        "revalidate_unpack_target",
    ] {
        assert_contains(
            "dexios-domain/src/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_RS,
            required,
        );
    }
    let commit_section = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn execute_manifest_archive",
        "fn stage_manifest_extraction",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::execute_manifest_archive",
        &commit_section,
        &[
            "V1PayloadDecryptingReader::new",
            "stage_manifest_extraction",
            "drain_trailing_plaintext_to_final_auth",
            ".finish()",
            "revalidate_extraction_targets",
            "create_selected_directories_after_final_auth",
            "commit_all",
        ],
    );
    assert_no_normalized_tokens_before(
        "dexios-domain/src/unpack.rs::execute_manifest_archive",
        &commit_section,
        &["commit_all"],
        normalized_section_order_indices(
            "dexios-domain/src/unpack.rs::execute_manifest_archive",
            &commit_section,
            &[".finish()"],
        )[0],
        "final authentication",
    );

    let stage_section = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn stage_manifest_file_body",
        "fn copy_manifest_body",
    );
    let stage_order = [
        "revalidate_unpack_target",
        "stage_in",
        "staged_output_mut",
        ".with_writer_result(",
    ];
    let stage_order_indices = normalized_section_order_indices(
        "dexios-domain/src/unpack.rs::stage_extracted_file",
        &stage_section,
        &stage_order,
    );
    assert_no_normalized_tokens_before(
        "dexios-domain/src/unpack.rs::stage_manifest_file_body",
        &stage_section,
        &["stage_in", "staged_output_mut", ".with_writer_result("],
        stage_order_indices[0],
        "target revalidation",
    );

    for required in [
        "NamedStagedOutput::with_hooks",
        "staged_output_mut",
        "prepare_for_persist",
        "persist_replace_at_commit",
        "persist_noclobber",
    ] {
        assert_corpus_contains(
            "archive staging source",
            &[
                (
                    "dexios-domain/src/storage/transaction.rs",
                    DEXIOS_DOMAIN_TRANSACTION_RS,
                ),
                ("dexios-domain/src/storage/temp.rs", DEXIOS_DOMAIN_TEMP_RS),
            ],
            required,
        );
    }
}
#[test]
fn phase01_assurance_manifests_link_requirements() {
    for (source_name, source, rows) in [
        (
            "dexios-core/tests/testdata/fixture_manifest.toml",
            DEXIOS_CORE_FIXTURE_MANIFEST,
            &[
                ("phase01-stream-payload-boundary-matrix", "STRM-01"),
                ("phase01-stream-duplicated-chunk", "STRM-02"),
                ("phase01-header-malformed-evidence", "ASSR-02"),
                ("phase01-keyslot-corruption-evidence", "ASSR-02"),
                ("phase01-core-generated-stream-cases-promoted", "ASSR-03"),
            ][..],
        ),
        (
            "dexios-domain/tests/fixture_manifest.toml",
            DEXIOS_DOMAIN_FIXTURE_MANIFEST,
            &[
                ("phase01-domain-corrupted-stream", "STRM-02"),
                ("phase01-domain-corrupted-archive-stream", "STRM-02"),
                ("phase01-domain-keyslot-corruption", "ASSR-02"),
                ("phase01-domain-archive-path", "ASSR-02"),
                ("phase01-domain-generated-corruption-promoted", "ASSR-03"),
            ][..],
        ),
        (
            "dexios/tests/fixture_manifest.toml",
            DEXIOS_CLI_FIXTURE_MANIFEST,
            &[
                ("phase01-cli-corrupted-stream", "STRM-02"),
                ("phase01-cli-corrupted-archive-stream", "STRM-02"),
                ("phase01-cli-archive-path-symlink-component", "ASSR-02"),
                (
                    "phase01-cli-archive-path-duplicate-normalized-targets",
                    "ASSR-02",
                ),
                ("phase01-cli-generated-corruption-promoted", "ASSR-03"),
            ][..],
        ),
    ] {
        let manifest_rows = parsed_fixture_rows(source_name, source);
        for (row_id, requirement) in rows {
            assert_manifest_row(source_name, &manifest_rows, row_id, requirement);
        }
    }
}
#[test]
fn cargo_deny_policy_is_source_gated() {
    for required in [
        "[advisories]",
        "unsound = \"all\"",
        "[bans]",
        "multiple-versions = \"deny\"",
        "wildcards = \"deny\"",
        "[sources]",
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
        "allow-registry = [\"https://github.com/rust-lang/crates.io-index\"]",
        "[licenses]",
        "confidence-threshold = 0.93",
    ] {
        assert_contains("deny.toml", DENY_TOML, required);
    }
    assert_not_contains("deny.toml", DENY_TOML, "getrandom@0.3.4");
}
#[test]
fn canonical_v1_assurance_replay_includes_phase3_evidence() {
    for command in [
        "cargo test --locked --offline -p dexios-core --test v1_header --release",
        "cargo test --locked --offline -p dexios-core --test stream_v1 --release",
        "cargo test --locked --offline -p dexios-core --test key_derivation --release",
        "cargo test --locked --offline -p dexios-domain --test keyslots_intent_v1 --test keyslots_crypto_v1 --test keyslots_mutation_v1 --release",
        "cargo test --locked --offline -p dexios-domain --test decrypt_workflow_errors --release",
        "cargo test --locked --offline -p dexios-domain --features test-support --test unpack_manifest_v1 --test unpack_path_identity --test unpack_commit_rollback --test unpack_symlink_revalidation --release",
    ] {
        assert_non_comment_line_count(
            "scripts/verify_assurance_replay.sh",
            VERIFY_ASSURANCE_REPLAY,
            &format!("run {command}"),
            1,
        );
    }

    assert_non_comment_line_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo test --locked --workspace --all-features --release --verbose",
        "run bash scripts/verify_assurance_replay.sh",
    );
}
#[test]
fn phase05_manifest_archive_and_cli_gate_is_source_gated() {
    let focused_commands = [
        "run cargo test --locked -p dexios-core --test stream_v1 --release",
        "run cargo test --locked -p dexios-core --test v1_header --release",
        "run cargo test --locked -p dexios-domain --test pack_paths --release",
        "run cargo test --locked -p dexios-domain --features test-support --test unpack_manifest_v1 --test unpack_path_identity --test unpack_commit_rollback --test unpack_symlink_revalidation --release",
        "run cargo test --locked -p dexios-domain --test archive_public_api --release",
        "run cargo test --locked -p dexios-domain --test workflow_errors --all-features --release",
        "run cargo test --locked -p dexios --test pack_cli_regressions --release",
        "run cargo test --locked -p dexios --test unpack_cli_regressions --release",
        "run cargo test --locked -p dexios --test delete_source_cli --release",
        "run cargo test --locked -p dexios --test workflow_error_cli_boundary --test workflow_error_cli_archive --test workflow_error_cli_header_key --release",
        "run cargo test --locked -p dexios --test verification_gate_docs --release",
    ];
    for command in focused_commands {
        assert_non_comment_line_count(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            command,
            1,
        );
        assert_non_comment_line_occurs_before(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            command,
            "run cargo test --locked --workspace --all-features --release --verbose",
        );
    }

    for (source_name, source, required) in [
        (
            "dexios-core/tests/stream_v1.rs",
            DEXIOS_CORE_STREAM_V1_TESTS,
            "ManifestFirst",
        ),
        (
            "dexios-core/tests/v1_header.rs",
            DEXIOS_CORE_V1_HEADER_TESTS,
            "ManifestArchive",
        ),
        (
            "dexios-domain/tests/pack_paths.rs",
            DEXIOS_DOMAIN_PACK_PATHS_TESTS,
            "ManifestFirstPayload::parse",
        ),
        (
            "dexios-domain/tests/support/unpack_v1.rs",
            DEXIOS_DOMAIN_UNPACK_SUPPORT,
            "write_manifest_archive_with_entries",
        ),
        (
            "dexios-domain/tests/archive_public_api.rs",
            DEXIOS_DOMAIN_ARCHIVE_PUBLIC_API_TESTS,
            "phase05_manifest_archive_normal_path_stays_private_and_zip_free",
        ),
        (
            "dexios/tests/pack_cli_regressions.rs",
            DEXIOS_PACK_CLI_REGRESSION_TESTS,
            "ManifestFirstPayload::parse",
        ),
        (
            "dexios/tests/unpack_cli_regressions.rs",
            DEXIOS_UNPACK_CLI_REGRESSION_TESTS,
            "write_manifest_archive_with_entries",
        ),
        (
            "dexios/tests/delete_source_cli.rs",
            DEXIOS_DELETE_SOURCE_CLI_TESTS,
            "write_manifest_archive_with_entries",
        ),
        (
            "dexios/tests/support/workflow_error_cli.rs",
            DEXIOS_WORKFLOW_ERROR_CLI_SUPPORT,
            "write_manifest_archive_with_entries",
        ),
    ] {
        assert_contains(source_name, source, required);
    }
    assert_contains(
        "dexios/tests/workflow_error_cli_archive.rs",
        DEXIOS_WORKFLOW_ERROR_CLI_ARCHIVE_TESTS,
        "legacy raw archive payload must fail as a terse archive class",
    );
    assert_contains(
        "dexios/tests/support/workflow_error_cli.rs",
        DEXIOS_WORKFLOW_ERROR_CLI_SUPPORT,
        "PayloadError",
    );

    for (source_name, source) in [
        (
            "dexios/tests/pack_cli_regressions.rs",
            DEXIOS_PACK_CLI_REGRESSION_TESTS,
        ),
        (
            "dexios/tests/unpack_cli_regressions.rs",
            DEXIOS_UNPACK_CLI_REGRESSION_TESTS,
        ),
        (
            "dexios/tests/delete_source_cli.rs",
            DEXIOS_DELETE_SOURCE_CLI_TESTS,
        ),
        (
            "dexios/tests/workflow_error_cli_archive.rs",
            DEXIOS_WORKFLOW_ERROR_CLI_ARCHIVE_TESTS,
        ),
        (
            "dexios/tests/support/workflow_error_cli.rs",
            DEXIOS_WORKFLOW_ERROR_CLI_SUPPORT,
        ),
    ] {
        assert_not_contains(source_name, source, "write_zip_with_entries");
        assert_not_contains(source_name, source, "ZipArchive::new");
        assert_not_contains(source_name, source, "ZipWriter::new");
    }

    let normal_unpack = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "fn execute_manifest_archive",
        "fn stage_manifest_extraction",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::execute_manifest_archive",
        &normal_unpack,
        &[
            "V1PayloadDecryptingReader::new",
            "stage_manifest_extraction",
            "drain_trailing_plaintext_to_final_auth",
            ".finish()",
            "revalidate_extraction_targets",
            "create_selected_directories_after_final_auth",
            "commit_all",
        ],
    );
    for forbidden in ["ZipArchive", "OpenArchiveWithSource", "_temp_factory()"] {
        assert!(
            !normal_unpack.contains(&normalized_token(forbidden)),
            "normal manifest unpack path must not contain {forbidden:?}"
        );
    }
}

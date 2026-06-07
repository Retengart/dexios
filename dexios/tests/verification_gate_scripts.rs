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

use std::process::Command;

use verification_gate_support::*;

#[test]
fn phase06_release_evidence_script_and_claims_are_source_gated() {
    for required in [
        "git rev-parse HEAD",
        "refs/tags/$tag",
        "git show-ref --verify --quiet",
        "git rev-parse -q --verify",
        "Cargo.lock",
        "sha256",
        "rustc --version",
        "cargo --version",
        "rustc -vV",
        "target platform",
        "cargo metadata --format-version=1",
        "bash scripts/verify_phase_gate.sh",
        "--allow-dirty",
        "--asset",
        "--tag",
    ] {
        assert_contains(
            "scripts/generate_release_manifest.sh",
            GENERATE_RELEASE_MANIFEST,
            required,
        );
    }
    assert_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        "local-notes/*",
    );

    for required in [
        "manifest-first archive payload",
        "DXAR",
        "DXBF",
        "no full plaintext archive temporary file",
        "selected staged file bodies",
        "asset SHA256",
        "does not claim bit-for-bit reproducibility",
        "SBOM completeness, SBOM protection, supply-chain prevention",
        "completed verification",
        "verification command contract",
    ] {
        assert_corpus_contains(
            "Phase 06 documentation and changelog corpus",
            &[
                ("CHANGELOG.md", CHANGELOG),
                ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
                (
                    "scripts/generate_release_manifest.sh",
                    GENERATE_RELEASE_MANIFEST,
                ),
                (
                    "book/src/technical-details/Directory-Packing.md",
                    DIRECTORY_PACKING,
                ),
                ("book/src/technical-details/Secure-Erase.md", SECURE_ERASE),
            ],
            required,
        );
    }
    assert_corpus_markdown_text_contains(
        "Phase 06 documentation and changelog corpus",
        &[
            ("CHANGELOG.md", CHANGELOG),
            ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
            (
                "scripts/generate_release_manifest.sh",
                GENERATE_RELEASE_MANIFEST,
            ),
        ],
        "Cargo.lock SHA256",
    );

    let release_evidence_corpus = format!(
        "{GENERATE_RELEASE_MANIFEST}\n{SAFETY_CONTRACT}\n{INSTALLING_AND_BUILDING}\n{CHANGELOG}"
    );
    assert_not_contains(
        "Phase 06 release evidence corpus",
        &release_evidence_corpus,
        "git rev-list -n 1 \"$tag\"",
    );
    assert_no_release_overclaim_patterns(
        "Phase 06 release evidence corpus",
        &release_evidence_corpus,
    );
}

#[test]
fn local_working_notes_are_ignored() {
    for required in ["/local-notes/", "/local-plans/", "/.local-tools/"] {
        assert_contains(".gitignore", GITIGNORE, required);
    }

    assert_contains(
        "scripts/verify_repo_hygiene.sh",
        VERIFY_REPO_HYGIENE,
        "local scratch path is tracked by git",
    );
    assert_contains(
        "scripts/verify_repo_hygiene.sh",
        VERIFY_REPO_HYGIENE,
        "local scratch path must be ignored",
    );
}

#[test]
fn release_hygiene_repository_policy_is_source_gated() {
    assert_contains(".gitattributes", GITATTRIBUTES, "*.pdf binary");

    assert_all_contains(
        "scripts/verify_repo_hygiene.sh",
        VERIFY_REPO_HYGIENE,
        &[
            "git ls-files --error-unmatch .gitattributes",
            ".gitattributes must be tracked",
            "*.pdf binary",
            "git status --porcelain --untracked-files=all",
            "release-sensitive untracked path",
            "track or remove it before release-equivalent evidence",
            ".github/workflows/*",
            "book/src/*",
            "dexios*/src/*",
            "dexios*/tests/*",
            "scripts/*",
            "spec/*",
            "release-evidence/*",
        ],
    );
}

#[test]
fn local_scripts_expose_the_full_maintainer_gate() {
    assert_all_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        REPAIRED_GATE_COMMANDS,
    );
    assert_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run git diff --check",
        "run bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --asset target/release-lto/dexios",
    );
    assert_non_comment_lines_exclude(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        &["--allow-dirty"],
    );

    for required in [
        "require_tool_version cargo-audit cargo-audit 0.22.1 \"cargo install cargo-audit --locked --version 0.22.1\" cargo audit --version",
        "require_tool_version cargo-deny cargo-deny 0.19.6 \"cargo install cargo-deny --locked --version 0.19.6\" cargo deny --version",
        "require_tool_version mdbook mdbook 0.5.3 \"cargo install mdbook --locked --version 0.5.3\" mdbook --version",
        "require_tool_version typst typst 0.14.2 \"install Typst from https://typst.app/docs/install/ or your OS package manager\" typst --version",
        "verify_no_unsafe_crate_roots",
        "grep -Fxq '#![forbid(unsafe_code)]'",
        "dexios/src/main.rs",
        "dexios-core/src/lib.rs",
        "dexios-domain/src/lib.rs",
        "run verify_no_unsafe_crate_roots",
    ] {
        assert_contains("scripts/verify_phase_gate.sh", VERIFY_PHASE_GATE, required);
    }

    for (line_number, line) in VERIFY_PHASE_GATE.lines().enumerate() {
        if is_non_comment_line(line) {
            assert!(
                !line.contains("measure_performance_gate.sh"),
                "scripts/verify_phase_gate.sh:{} must not call the focused performance gate by default",
                line_number + 1
            );
        }
    }

    for required in ["git ls-files", "git check-ignore -q"] {
        assert_contains(
            "scripts/verify_repo_hygiene.sh",
            VERIFY_REPO_HYGIENE,
            required,
        );
    }
}

#[test]
fn phase_gate_tool_version_equivalence_is_source_gated() {
    assert_all_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        &[
            "require_tool_version()",
            "expected=$3",
            "observed=",
            "observed_version=",
            "observed_tool_version_token()",
            "BASH_REMATCH[1]",
            "for word in $observed",
            "[[ \"$observed_version\" != \"$expected\" ]]",
            "Required $label version mismatch: expected $expected, observed $observed",
            "require_tool_version cargo-audit cargo-audit 0.22.1",
            "require_tool_version cargo-deny cargo-deny 0.19.6",
            "require_tool_version mdbook mdbook 0.5.3",
            "require_tool_version typst typst 0.14.2",
        ],
    );

    for forbidden in [
        "require_tool cargo-audit",
        "require_tool cargo-deny",
        "require_tool mdbook",
        "typst_version=\"$(typst --version",
    ] {
        assert_non_comment_lines_exclude(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            &[forbidden],
        );
    }

    assert_non_comment_line_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "require_tool_version cargo-audit cargo-audit 0.22.1 \"cargo install cargo-audit --locked --version 0.22.1\" cargo audit --version",
        "run cargo metadata --format-version=1 --locked --no-deps > /dev/null",
    );

    assert!(
        !VERIFY_PHASE_GATE.contains("[[ \"$observed\" != *\"$expected\"* ]]"),
        "scripts/verify_phase_gate.sh must reject adjacent-prefix versions exactly, not by substring"
    );
}

fn shell_function(source_name: &str, source: &str, function_name: &str) -> String {
    let start = source
        .find(&format!("{function_name}() {{"))
        .unwrap_or_else(|| panic!("{source_name} must define shell function {function_name}"));
    let relative_end = source[start..]
        .find("\n}")
        .unwrap_or_else(|| panic!("{source_name} shell function {function_name} must close"));
    source[start..start + relative_end + 3].to_owned()
}

fn observed_tool_version_token_from_source(
    source_name: &str,
    source: &str,
    observed: &str,
) -> String {
    let function = shell_function(source_name, source, "observed_tool_version_token");
    let script = format!("{function}\nobserved_tool_version_token \"$1\"\n");
    let output = Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("observed_tool_version_token")
        .arg(observed)
        .output()
        .unwrap_or_else(|error| panic!("{source_name} parser probe must run bash: {error}"));

    assert!(
        output.status.success(),
        "{source_name} parser probe failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("{source_name} parser probe stdout must be utf8: {error}"))
}

#[test]
fn release_tool_version_parser_rejects_suffix_and_extra_component_canaries() {
    for (source_name, source) in [
        ("scripts/verify_phase_gate.sh", VERIFY_PHASE_GATE),
        (
            "scripts/generate_release_manifest.sh",
            GENERATE_RELEASE_MANIFEST,
        ),
    ] {
        for (observed, expected_token) in [
            ("cargo-audit-audit 0.22.10", "0.22.10"),
            ("cargo-audit-audit 0.22.1-beta", "0.22.1-beta"),
            ("cargo-audit-audit 0.22.1.1", "0.22.1.1"),
            ("mdbook v0.5.3", "0.5.3"),
            ("typst 0.14.2 (b33de9de)", "0.14.2"),
        ] {
            let token = observed_tool_version_token_from_source(source_name, source, observed);
            assert_eq!(
                token, expected_token,
                "{source_name} must parse the full version token from {observed:?}"
            );
        }
    }
}

#[test]
fn release_manifest_dirty_policy_is_split_between_local_dry_run_and_release_gate() {
    for required in [
        "bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --asset target/release-lto/dexios",
        "tracked working tree changes fail closed",
        "--allow-dirty` is only for local dry runs",
    ] {
        assert_contains(
            "book/src/Installing-and-Building.md",
            INSTALLING_AND_BUILDING,
            required,
        );
    }

    assert_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        "bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --asset target/release-lto/dexios",
    );
    assert_not_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        "verify_phase_gate.sh` may pass `--allow-dirty`",
    );
}

#[test]
fn release_manifest_equivalence_policy_is_source_gated() {
    assert_all_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        &[
            "release_sensitive_untracked_state",
            "release_sensitive_untracked_paths",
            "Release-sensitive untracked files are present",
            "track or remove them before release-equivalent evidence",
            "local_dry_run=yes",
            "release_equivalent=no",
            "release_equivalent=yes",
            "release-sensitive untracked state: `%s`",
            "local dry run: `%s`",
            "release-equivalent: `%s`",
            "This manifest is a local dry run and is not release-equivalent.",
        ],
    );

    let release_evidence_corpus = format!("{GENERATE_RELEASE_MANIFEST}\n{INSTALLING_AND_BUILDING}");
    for stale_claim in [
        "Untracked files\nare ignored by the dirty check",
        "Untracked local files are ignored by the dirty check",
    ] {
        assert_not_contains(
            "release evidence corpus",
            &release_evidence_corpus,
            stale_claim,
        );
    }
}

#[test]
fn release_manifest_rc_evidence_wording_is_version_neutral() {
    assert_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        "release candidate closeout evidence artifact is recorded at",
    );
    assert_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        "release candidate.",
    );
    assert_not_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        "v3.0 release candidate",
    );
    assert_not_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        "performance gate status for v3.0",
    );
}

#[test]
fn release_manifest_tool_equivalence_policy_is_source_gated() {
    assert_all_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        &[
            "EXPECTED_CARGO_AUDIT_VERSION=0.22.1",
            "EXPECTED_CARGO_DENY_VERSION=0.19.6",
            "EXPECTED_MDBOOK_VERSION=0.5.3",
            "EXPECTED_TYPST_VERSION=0.14.2",
            "release_tool_equivalence_state",
            "observed_tool_version_token()",
            "[[ \"$observed_version\" == \"$expected\" ]]",
            "Release-equivalent tool version mismatch",
            "release-equivalent tool versions: `%s`",
            "expected `cargo-audit`: `%s`",
            "observed `cargo audit --version`: `%s`",
            "expected `cargo-deny`: `%s`",
            "observed `cargo deny --version`: `%s`",
            "expected `mdbook`: `%s`",
            "observed `mdbook --version`: `%s`",
            "expected `typst`: `%s`",
            "observed `typst --version`: `%s`",
        ],
    );
}

#[test]
fn assurance_replay_runs_once_after_workspace_tests_before_audit() {
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run bash scripts/verify_assurance_replay.sh",
        1,
    );
    assert_non_comment_line_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo test --locked --workspace --all-features --release --verbose",
        "run bash scripts/verify_assurance_replay.sh",
    );
    assert_non_comment_line_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run bash scripts/verify_assurance_replay.sh",
        "run cargo audit --deny warnings",
    );
}

#[test]
fn phase_gate_stays_independent_of_local_planning_state() {
    assert_not_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "local-notes",
    );
    assert_non_comment_lines_exclude(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        &["local-notes"],
    );
}

#[test]
fn phase_gate_uses_split_regression_targets_and_single_verification_gate_glob() {
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo test --locked -p dexios --test 'verification_gate_*' --release",
        1,
    );

    for target in [
        "keyslots_intent_v1",
        "keyslots_crypto_v1",
        "keyslots_mutation_v1",
        "unpack_manifest_v1",
        "unpack_path_identity",
        "unpack_commit_rollback",
        "unpack_symlink_revalidation",
        "transactions_staged_output",
        "transactions_linked_publication",
        "transactions_failure_hooks",
        "workflow_error_cli_boundary",
        "workflow_error_cli_archive",
        "workflow_error_cli_header_key",
    ] {
        assert_contains(
            "scripts/verify_phase_gate.sh",
            VERIFY_PHASE_GATE,
            &format!("--test {target}"),
        );
    }

    assert_non_comment_lines_exclude(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        &[
            "--test keyslots_v1",
            "--test unpack --release",
            "--test transactions --",
            "--test workflow_error_cli --",
        ],
    );
}

#[test]
fn assurance_replay_script_is_bounded_offline_and_crate_owned() {
    assert_contains(
        "scripts/verify_assurance_replay.sh",
        VERIFY_ASSURANCE_REPLAY,
        "CARGO_NET_OFFLINE=true",
    );
    for command in ASSURANCE_REPLAY_COMMANDS {
        assert_non_comment_line_count(
            "scripts/verify_assurance_replay.sh",
            VERIFY_ASSURANCE_REPLAY,
            &format!("run {command}"),
            1,
        );
    }
    for pair in ASSURANCE_REPLAY_COMMANDS.windows(2) {
        let earlier = format!("run {}", pair[0]);
        let later = format!("run {}", pair[1]);
        assert_non_comment_line_occurs_before(
            "scripts/verify_assurance_replay.sh",
            VERIFY_ASSURANCE_REPLAY,
            &earlier,
            &later,
        );
    }
    assert_not_contains(
        "scripts/verify_assurance_replay.sh",
        VERIFY_ASSURANCE_REPLAY,
        "local-notes",
    );
    assert_non_comment_lines_exclude(
        "scripts/verify_assurance_replay.sh",
        VERIFY_ASSURANCE_REPLAY,
        ASSURANCE_REPLAY_FORBIDDEN_NON_COMMENT_TOKENS,
    );

    for (source_name, source, symbols) in [
        (
            "dexios-core/tests/stream_v1.rs",
            DEXIOS_CORE_STREAM_V1_TESTS,
            &[
                "stream_payload_boundary_matrix_roundtrips_with_file_api",
                "stream_file_api_handles_short_output_writes_at_boundaries",
                "decrypt_rejects_duplicated_chunk",
                "decrypt_rejects_each_truncated_stream_chunk",
            ][..],
        ),
        (
            "dexios-domain/tests/decrypt_workflow_errors.rs",
            DEXIOS_DOMAIN_DECRYPT_WORKFLOW_ERROR_TESTS,
            &["decrypt_corrupted_stream_variants_never_commit_final_output"][..],
        ),
        (
            "dexios-domain/tests/unpack_commit_rollback.rs",
            DEXIOS_DOMAIN_UNPACK_COMMIT_ROLLBACK_TESTS,
            &["unpack_corrupted_stream_never_extracts_outputs"][..],
        ),
        (
            "dexios/tests/decrypt_cli_regressions.rs",
            DEXIOS_DECRYPT_CLI_REGRESSION_TESTS,
            &["decrypt_cli_corrupted_stream_variants_preserve_existing_output"][..],
        ),
        (
            "dexios/tests/unpack_cli_regressions.rs",
            DEXIOS_UNPACK_CLI_REGRESSION_TESTS,
            &["unpack_cli_corrupted_archive_never_extracts_outputs"][..],
        ),
    ] {
        assert_all_contains(source_name, source, symbols);
    }
}

#[test]
fn exploratory_assurance_tools_stay_out_of_default_gates() {
    for (source_name, source) in [
        (
            "scripts/verify_assurance_replay.sh",
            VERIFY_ASSURANCE_REPLAY,
        ),
        ("scripts/verify_phase_gate.sh", VERIFY_PHASE_GATE),
    ] {
        assert_non_comment_lines_exclude(source_name, source, EXPLORATORY_TOOL_TOKENS);
    }
}

#[test]
fn measurement_policy_is_source_gated() {
    for required in [
        "--scenario",
        "kdf",
        "stream",
        "pack-unpack",
        "temp-space",
        "target/phase7-measurements",
        "--dry-run",
        "--max-stream-encrypt-seconds",
        "--max-stream-decrypt-seconds",
        "--max-pack-seconds",
        "--max-unpack-seconds",
        "--max-temp-space-kib",
        "DEXIOS_STREAM_ENCRYPT_MAX_SECONDS",
        "DEXIOS_STREAM_DECRYPT_MAX_SECONDS",
        "DEXIOS_PACK_MAX_SECONDS",
        "DEXIOS_UNPACK_MAX_SECONDS",
        "DEXIOS_TEMP_SPACE_MAX_KIB",
        "threshold failure",
        "operation=",
        "measured_seconds=",
        "threshold_seconds=",
        "measured_kib=",
        "threshold_kib=",
        "measured_path=",
        "log_path=$LOG_PATH",
        "work_root=",
    ] {
        assert_contains(
            "scripts/measure_performance_gate.sh",
            MEASURE_PERFORMANCE_GATE,
            required,
        );
    }

    for required in [
        "measure_performance_gate.sh",
        "KDF cost",
        "stream throughput",
        "pack/unpack memory",
        "temp-space",
    ] {
        assert_contains(
            "book/src/technical-details/Performance-Notes.md",
            PERFORMANCE_NOTES,
            required,
        );
    }

    for required in ["VERI-05", "measure_performance_gate.sh", "not applicable"] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }
}

#[test]
fn phase12_performance_and_temp_exposure_contract_is_source_gated() {
    for required in [
        "--max-stream-encrypt-seconds",
        "--max-stream-decrypt-seconds",
        "--max-pack-seconds",
        "--max-unpack-seconds",
        "--max-temp-space-kib",
        "DEXIOS_STREAM_ENCRYPT_MAX_SECONDS",
        "DEXIOS_STREAM_DECRYPT_MAX_SECONDS",
        "DEXIOS_PACK_MAX_SECONDS",
        "DEXIOS_UNPACK_MAX_SECONDS",
        "DEXIOS_TEMP_SPACE_MAX_KIB",
        "threshold failure",
        "operation=",
        "measured_seconds=",
        "threshold_seconds=",
        "measured_kib=",
        "threshold_kib=",
        "log_path=$LOG_PATH",
        "work_root=",
    ] {
        assert_contains(
            "scripts/measure_performance_gate.sh",
            MEASURE_PERFORMANCE_GATE,
            required,
        );
    }

    for (line_number, line) in VERIFY_PHASE_GATE.lines().enumerate() {
        if is_non_comment_line(line) {
            assert!(
                !line.contains("measure_performance_gate.sh"),
                "scripts/verify_phase_gate.sh:{} must keep the focused performance gate out of the default maintainer gate",
                line_number + 1
            );
        }
    }

    for required in [
        "focused release gate",
        "stream encrypt threshold",
        "stream decrypt threshold",
        "pack threshold",
        "unpack threshold",
        "temp-space threshold",
        "DEXIOS_STREAM_ENCRYPT_MAX_SECONDS",
        "DEXIOS_TEMP_SPACE_MAX_KIB",
        "target/phase7-measurements",
        "hardware profile",
        "advisory",
    ] {
        assert_contains(
            "book/src/technical-details/Performance-Notes.md",
            PERFORMANCE_NOTES,
            required,
        );
    }

    for required in [
        "Phase 12 measured stream/archive/temp-space thresholds",
        "focused release gate",
        "manifest-first archive payload",
        "DXAR",
        "DXBF",
        "no longer creates a full plaintext archive temporary file",
        "selected staged file bodies",
        "capacity pressure",
        "best-effort",
        "does not prove portable free space",
    ] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }

    for required in [
        "manifest-first archive payload",
        "DXAR",
        "DXBF",
        "no longer creates a full plaintext archive temporary file",
        "selected staged file bodies",
        "ordinary filesystem cleanup",
        "capacity pressure",
        "does not prove portable free space",
    ] {
        assert_contains(
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
            required,
        );
    }

    for required in [
        "Not enough temporary or output storage while packing archive",
        "Not enough temporary or output storage while unpacking archive",
        "is_resource_pressure",
    ] {
        assert_contains(
            "dexios/src/subcommands/errors.rs",
            DEXIOS_SUBCOMMAND_ERRORS_RS,
            required,
        );
    }

    assert_contains(
        "dexios-domain/src/pack.rs",
        DEXIOS_DOMAIN_PACK_RS,
        "manifest-first archive streamed directly through V1 encryption",
    );
    assert_contains(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "unpack-side plaintext exposure is scoped to selected staged file bodies",
    );

    for required in [
        "performance thresholds",
        "capacity-pressure reporting",
        "manifest-first archive payload",
        "no full plaintext archive temporary file",
        "selected staged file bodies",
    ] {
        assert_contains("CHANGELOG.md", CHANGELOG, required);
    }

    for (source_name, source) in [
        ("CHANGELOG.md", CHANGELOG),
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
        ("book/src/technical-details/Secure-Erase.md", SECURE_ERASE),
    ] {
        for forbidden in [
            "secure erase guarantee",
            "physical sanitization guarantee",
            "provides portable free-space proof",
            "guarantees portable free-space proof",
            "provides recovery protection",
            "guarantees recovery protection",
            "unpack streaming extraction is atomic",
        ] {
            assert_not_contains(source_name, source, forbidden);
        }
    }
}

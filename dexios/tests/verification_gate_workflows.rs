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

// --- Phase 21 gate tests ---

#[test]
fn cargo_build_workflow_lints_production_default_feature_build() {
    // Audit-closure regression guard (quality-3): the `--all-features` clippy job
    // exempts feature-gated-private items as *exported* API (`unreachable_pub`,
    // `trivially_copy_pass_by_ref`), masking warnings that only surface in the
    // production (default-feature) build — e.g. the storage failure-injection seam
    // in dexios-domain/src/storage/test_support.rs. CI must therefore also lint the
    // default-feature lib+bins under `-D warnings`. No `--all-targets` here: that
    // would pull in the `test-support`-gated integration tests, which do not compile
    // without the feature.
    assert_contains(
        ".github/workflows/cargo-build.yml",
        CARGO_BUILD_WORKFLOW,
        "cargo clippy --locked --workspace --no-deps -- -D warnings",
    );
}

#[test]
fn ci_workflows_keep_audit_and_docs_fresh() {
    for required in [
        "pull_request",
        "push:",
        "schedule:",
        "cargo audit --deny warnings",
        "cargo deny check",
    ] {
        assert_contains(".github/workflows/audit.yml", AUDIT_WORKFLOW, required);
    }

    for required in [
        "mdbook build --dest-dir target/mdbook",
        "verify_repo_hygiene.sh",
        "workflow_dispatch",
    ] {
        assert_contains(".github/workflows/docs.yml", DOCS_WORKFLOW, required);
    }

    for (source_name, source) in [
        (".github/workflows/audit.yml", AUDIT_WORKFLOW),
        (".github/workflows/build_nix.yml", BUILD_NIX_WORKFLOW),
        (".github/workflows/cargo-build.yml", CARGO_BUILD_WORKFLOW),
        (".github/workflows/cli-surface.yml", CLI_SURFACE_WORKFLOW),
        (".github/workflows/dexios-tests.yml", DEXIOS_TESTS_WORKFLOW),
        (".github/workflows/docs.yml", DOCS_WORKFLOW),
        (".github/workflows/unit_tests.yml", UNIT_TESTS_WORKFLOW),
    ] {
        assert_workflow_default_read_permissions(source_name, source);
        assert_external_actions_are_full_sha_pinned(source_name, source);
        assert_checkout_steps_disable_persist_credentials(source_name, source);
    }
}

#[test]
fn release_workflow_actions_are_sha_pinned_with_verified_tag_comments() {
    for forbidden in [
        "actions/checkout@v",
        "actions/upload-artifact@v",
        "actions/download-artifact@v",
    ] {
        assert_not_contains(".github/workflows/release.yml", RELEASE_WORKFLOW, forbidden);
    }

    for required in [
        "# actions/checkout v6.0.2",
        "# actions/upload-artifact v7.0.0",
        "# actions/download-artifact v8.0.0",
    ] {
        assert_contains(".github/workflows/release.yml", RELEASE_WORKFLOW, required);
    }

    assert_workflow_default_read_permissions(".github/workflows/release.yml", RELEASE_WORKFLOW);
    assert_external_actions_are_full_sha_pinned(".github/workflows/release.yml", RELEASE_WORKFLOW);
    assert_checkout_steps_disable_persist_credentials(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
    );
    assert_action_pin(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "actions/checkout",
        "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    );
    assert_action_pin(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "actions/upload-artifact",
        "bbbca2ddaa5d8feaa63e36b76fdaad77386f024f",
    );
    assert_action_pin(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "actions/download-artifact",
        "70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3",
    );
    assert_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "environment: release",
    );
    assert_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "permissions:\n      contents: write",
    );
    assert_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "duplicate_assets=()",
    );
    assert_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "already contains asset names from this run",
    );
}

#[test]
fn nix_gate_tracks_current_workspace_msrv() {
    assert_not_contains(
        "flake.lock",
        FLAKE_LOCK,
        "0e304ff0d9db453a4b230e9386418fd974d5804a",
    );

    for required in [
        "nix-build . -A defaultPackage.x86_64-linux --dry-run",
        "Rust `1.88`",
        "edition `2024`",
    ] {
        assert_contains(
            "book/src/Installing-and-Building.md",
            INSTALLING_AND_BUILDING,
            required,
        );
    }
}

#[test]
fn dexios_tests_workflow_does_not_reintroduce_removed_positive_cli_surface() {
    for forbidden in ["--aes", "--argon", "--zstd", "--erase"] {
        assert_not_contains(
            ".github/workflows/dexios-tests.yml",
            DEXIOS_TESTS_WORKFLOW,
            forbidden,
        );
    }

    for (line_number, line) in DEXIOS_TESTS_WORKFLOW.lines().enumerate() {
        assert!(
            !(line.contains("\"$DEXIOS_BIN\" erase") || line.contains("dexios erase")),
            ".github/workflows/dexios-tests.yml:{} must not positively invoke top-level erase: {}",
            line_number + 1,
            line
        );
    }
}

#[test]
fn ci_workflow_determinism_contract_is_source_gated() {
    assert_all_contains(
        ".github/workflows/dexios-tests.yml",
        DEXIOS_TESTS_WORKFLOW,
        &[
            "name: Dexios Tests",
            "on:\n  push:\n    branches: [ main ]\n  pull_request:\n    branches: [ main ]\n  workflow_dispatch:",
            "run: cargo build --locked --release -p dexios",
            "path: target/release/dexios",
        ],
    );

    assert_all_contains(
        ".github/workflows/cli-surface.yml",
        CLI_SURFACE_WORKFLOW,
        &[
            "name: CLI Surface",
            "DEXIOS_BIN: ${{ github.workspace }}/target/release/dexios",
            "run: cargo build --locked -p dexios --profile release",
            "bash scripts/verify_cli_surface.sh 2>&1 | tee target/cli-surface-artifacts/cli-surface.log",
        ],
    );

    for (source_name, source) in [
        (".github/workflows/dexios-tests.yml", DEXIOS_TESTS_WORKFLOW),
        (".github/workflows/cli-surface.yml", CLI_SURFACE_WORKFLOW),
    ] {
        assert_not_contains(source_name, source, "workflow_dispatch:\n    branches:");
    }

    assert_cli_surface_harness_invocation_has_no_positional_args();
}

#[test]
fn dexios_tests_workflow_tracks_current_mutating_cli_contracts() {
    for required in [
        "header strip -f --header 100MB.enc.header 100MB.enc",
        "key change -f -k keyfile -n keyfile-new 100MB.enc",
    ] {
        assert_contains(
            ".github/workflows/dexios-tests.yml",
            DEXIOS_TESTS_WORKFLOW,
            required,
        );
    }
}

#[test]
fn phase21_release_workflow_tool_pins_and_locked_build_are_source_gated() {
    // CIGR-01, CIGR-03, D-01, D-07: release.yml build uses --locked; mdbook and
    // typst-cli are version-pinned in the maintainer_gate job.

    assert_all_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        &[
            // rel-1: built with cargo-auditable to embed the dependency list; still
            // --locked --profile release -p dexios.
            "cargo auditable build --locked --profile release -p dexios",
            "cargo install mdbook --locked --version 0.5.3",
            "cargo install typst-cli --locked --version 0.14.2",
        ],
    );
}

#[test]
fn phase21_locked_flag_and_lockfile_gate_are_source_gated() {
    // CIGR-01 / D-01 / D-02: cargo --locked usage is structurally asserted on
    // verify_phase_gate.sh (as established by Plan 02). No release.yml assertion
    // here — those belong to Plan 04.

    // Lockfile consistency: metadata --locked runs exactly once, before clippy
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo metadata --format-version=1 --locked --no-deps > /dev/null",
        1,
    );
    assert_non_comment_line_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo metadata --format-version=1 --locked --no-deps > /dev/null",
        "run cargo clippy --workspace --all-targets --all-features --no-deps --locked",
    );

    // Release LTO build uses --locked
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo build --locked -p dexios --profile release",
        1,
    );

    // Workspace test suite uses --locked
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run cargo test --locked --workspace --all-features --release --verbose",
        1,
    );
}

#[test]
fn phase21_tool_version_pins_are_source_gated() {
    // CIGR-03 / D-07 / D-08: tool version pins are structurally asserted on the
    // gate script only. release.yml tool-version assertions belong to Plan 04.

    // mdbook version pin: active require_tool_version call with version 0.5.3
    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "require_tool_version mdbook mdbook 0.5.3 \"cargo install mdbook --locked --version 0.5.3\" mdbook --version",
    );

    // Old unversioned mdbook hint must be gone
    assert_not_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "require_tool_version mdbook mdbook 0.5.3 \"cargo install mdbook --locked\"",
    );

    for required in [
        "require_tool_version cargo-audit cargo-audit 0.22.1",
        "require_tool_version cargo-deny cargo-deny 0.19.6",
        "require_tool_version typst typst 0.14.2",
    ] {
        assert_contains("scripts/verify_phase_gate.sh", VERIFY_PHASE_GATE, required);
    }

    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "Required $label version mismatch: expected $expected, observed $observed",
    );

    // D-08: action-pin coverage — unit_tests workflow already has full SHA pins
    assert_external_actions_are_full_sha_pinned(
        ".github/workflows/unit_tests.yml",
        UNIT_TESTS_WORKFLOW,
    );
}

#[test]
fn phase21_permissions_and_job_ordering_are_source_gated() {
    // CIGR-02 / D-09 / D-10: least-privilege permissions on all 8 workflows +
    // release.yml job ordering. Closes Blocker 6. Config is already correct so
    // this test is green immediately within Wave 3.

    // (a) Least-privilege: every workflow must declare permissions: contents: read
    for (source_name, source) in [
        (".github/workflows/audit.yml", AUDIT_WORKFLOW),
        (".github/workflows/build_nix.yml", BUILD_NIX_WORKFLOW),
        (".github/workflows/cargo-build.yml", CARGO_BUILD_WORKFLOW),
        (".github/workflows/cli-surface.yml", CLI_SURFACE_WORKFLOW),
        (".github/workflows/dexios-tests.yml", DEXIOS_TESTS_WORKFLOW),
        (".github/workflows/docs.yml", DOCS_WORKFLOW),
        (".github/workflows/unit_tests.yml", UNIT_TESTS_WORKFLOW),
        (".github/workflows/release.yml", RELEASE_WORKFLOW),
    ] {
        assert_workflow_default_read_permissions(source_name, source);
    }

    // (b) release.yml job ordering: validate_tag -> maintainer_gate -> build -> publish
    // Each needs: line appears exactly once
    assert_non_comment_line_count(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "needs: validate_tag",
        1,
    );
    assert_non_comment_line_count(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "needs: maintainer_gate",
        1,
    );
    assert_non_comment_line_count(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "needs: build",
        1,
    );

    // Ordering is enforced: validate_tag < maintainer_gate < build
    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "needs: validate_tag",
        "needs: maintainer_gate",
    );
    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "needs: maintainer_gate",
        "needs: build",
    );
}

#[test]
fn release_attestations_are_created_before_public_release_assets() {
    assert_all_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        &[
            "artifact-metadata: write",
            "Validate release assets",
            "Attest build provenance",
            "Attest Linux SBOM",
            "Attest macOS SBOM",
            "Attest Windows SBOM",
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
            "sbom-path:",
        ],
    );

    assert_not_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "actions/attest-build-provenance@",
    );
    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "- name: Validate release assets",
        "- name: Attest build provenance",
    );
    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "- name: Attest build provenance",
        "- name: Create GitHub Release",
    );
    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "- name: Attest Windows SBOM",
        "- name: Create GitHub Release",
    );
}

#[test]
fn phase21_rc_closeout_artifact_is_present_and_source_gated() {
    // RCEV-01 / RCEV-05: RC-CLOSEOUT.md stub (from Plan 01) contains all required
    // structural headings and key content strings. Green from Wave 3.

    // Required section headings
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "# Dexios v3.0 Release Candidate Closeout Evidence",
    );
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "## Blocker-to-Check Traceability Matrix",
    );
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "## Accepted Residual Risks",
    );
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "## Platform Limits",
    );
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "## Non-Goals",
    );
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "## Property and Fuzz Coverage Decision (RCEV-03)",
    );
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "## Performance Gate Evidence (RCEV-04)",
    );

    // Blocker ID prefix coverage
    assert_contains("release-evidence/RC-CLOSEOUT.md", RC_CLOSEOUT, "PATH-");
    assert_contains("release-evidence/RC-CLOSEOUT.md", RC_CLOSEOUT, "CIGR-");
    assert_contains("release-evidence/RC-CLOSEOUT.md", RC_CLOSEOUT, "RCEV-");

    // Key residual risk strings
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "ordinary (non-secure-erase) deletion",
    );
    assert_contains(
        "release-evidence/RC-CLOSEOUT.md",
        RC_CLOSEOUT,
        "Windows filesystem identity",
    );

    // Deferred fuzz/property milestone reference
    assert_contains("release-evidence/RC-CLOSEOUT.md", RC_CLOSEOUT, "ASR-01");

    // No overclaim patterns on any active line
    assert_no_release_overclaim_patterns("release-evidence/RC-CLOSEOUT.md", RC_CLOSEOUT);
}

#[test]
fn phase21_release_workflow_asset_set_contract_is_source_gated() {
    // CIGR-04, D-04, D-05, Blocker 4: publish job enumerates all 6 expected
    // asset basenames; old sole partial-set check is gone; find for list-building
    // appears only after the explicit enumeration.

    assert_all_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        &[
            "dexios-${GITHUB_REF_NAME}-linux-amd64",
            "dexios-${GITHUB_REF_NAME}-linux-amd64.cdx.json",
            "dexios-${GITHUB_REF_NAME}-macos-amd64",
            "dexios-${GITHUB_REF_NAME}-macos-amd64.cdx.json",
            "dexios-${GITHUB_REF_NAME}-windows-amd64.exe",
            "dexios-${GITHUB_REF_NAME}-windows-amd64.exe.cdx.json",
        ],
    );

    // FAIL-CLOSED NEGATIVE (Blocker 4): the bare non-empty check must not be an
    // active (non-comment) line.
    assert_non_comment_lines_exclude(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        &["test \"${#files[@]}\" -gt 0"],
    );

    // Ordering: explicit expected-name enumeration must precede any find for
    // list-building.
    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "\"dexios-${GITHUB_REF_NAME}-linux-amd64\"",
        "mapfile -t files < <(find release-assets -type f | sort)",
    );
}

#[test]
fn phase21_windows_ci_coverage_is_source_gated() {
    // CIGR-05, D-11: unit_tests.yml has windows-latest active; dexios-tests.yml
    // stays Linux/macOS-only per Pattern 5.

    assert_non_comment_line_count(
        ".github/workflows/unit_tests.yml",
        UNIT_TESTS_WORKFLOW,
        "- windows-latest",
        1,
    );

    assert_non_comment_lines_exclude(
        ".github/workflows/dexios-tests.yml",
        DEXIOS_TESTS_WORKFLOW,
        &["windows-latest"],
    );
}

fn assert_cli_surface_harness_invocation_has_no_positional_args() {
    let script = "bash scripts/verify_cli_surface.sh";
    let mut found = false;

    for (line_number, line) in CLI_SURFACE_WORKFLOW.lines().enumerate() {
        let trimmed = line.trim();
        let Some(after_script) = trimmed.strip_prefix(script) else {
            continue;
        };
        found = true;

        let after_script = after_script.trim_start();
        if after_script.is_empty() {
            continue;
        }

        let first_token = after_script
            .split_whitespace()
            .next()
            .expect("non-empty script suffix has a first token");
        assert!(
            first_token.starts_with('|')
                || first_token.starts_with('<')
                || first_token.starts_with('>')
                || first_token.contains(">&"),
            ".github/workflows/cli-surface.yml:{} must invoke {script} without positional arguments: {}",
            line_number + 1,
            line
        );
    }

    assert!(
        found,
        ".github/workflows/cli-surface.yml must invoke {script}"
    );
}

// --- Phase 22 gate tests ---

#[test]
fn cosign_composite_action_exists_and_is_sha_pinned() {
    assert_contains(
        ".github/actions/sign-and-attest/action.yml",
        SIGN_AND_ATTEST_ACTION,
        "using: 'composite'",
    );

    assert_action_pin(
        ".github/actions/sign-and-attest/action.yml",
        SIGN_AND_ATTEST_ACTION,
        "sigstore/cosign-installer",
        "6f9f17788090df1f26f669e9d70d6ae9567deba6",
    );

    assert_action_pin(
        ".github/actions/sign-and-attest/action.yml",
        SIGN_AND_ATTEST_ACTION,
        "actions/attest-build-provenance",
        "a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32",
    );

    assert_external_actions_are_full_sha_pinned(
        ".github/actions/sign-and-attest/action.yml",
        SIGN_AND_ATTEST_ACTION,
    );
}

#[test]
fn release_workflow_invokes_sign_and_attest_action() {
    assert_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "uses: ./.github/actions/sign-and-attest",
    );

    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "- name: Attest Windows SBOM",
        "- name: Sign and attest artifacts",
    );
    assert_non_comment_line_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "- name: Sign and attest artifacts",
        "- name: Create GitHub Release",
    );
}

#[test]
fn release_workflow_expects_sigstore_bundles_for_all_platforms() {
    for suffix in [
        "linux-amd64.sigstore.json",
        "linux-amd64.cdx.json.sigstore.json",
        "macos-amd64.sigstore.json",
        "macos-amd64.cdx.json.sigstore.json",
        "windows-amd64.exe.sigstore.json",
        "windows-amd64.exe.cdx.json.sigstore.json",
    ] {
        assert_contains(
            ".github/workflows/release.yml",
            RELEASE_WORKFLOW,
            suffix,
        );
    }
}

#[test]
fn signing_documentation_exists_and_covers_cosign() {
    assert_contains("SIGNING.md", SIGNING_MD, "# Verifying Dexios Releases");
    assert_contains(
        "SIGNING.md",
        SIGNING_MD,
        "cosign verify-blob",
    );
    assert_contains(
        "SIGNING.md",
        SIGNING_MD,
        "certificate-identity",
    );
    assert_contains(
        "SIGNING.md",
        SIGNING_MD,
        "certificate-oidc-issuer",
    );
    assert_contains(
        "SIGNING.md",
        SIGNING_MD,
        "gh attestation verify",
    );
    assert_contains(
        "SIGNING.md",
        SIGNING_MD,
        ".sigstore.json",
    );
}

#[test]
fn release_body_generator_has_correct_structure() {
    assert_contains(
        "scripts/gen-release-body.sh",
        GEN_RELEASE_BODY,
        "## Downloads",
    );
    assert_contains(
        "scripts/gen-release-body.sh",
        GEN_RELEASE_BODY,
        "## Verifying your download",
    );
    assert_contains(
        "scripts/gen-release-body.sh",
        GEN_RELEASE_BODY,
        "cosign verify-blob",
    );
    assert_contains(
        "scripts/gen-release-body.sh",
        GEN_RELEASE_BODY,
        "gh attestation verify",
    );
    assert_contains(
        "scripts/gen-release-body.sh",
        GEN_RELEASE_BODY,
        ".sigstore.json",
    );

    assert_not_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "--generate-notes",
    );
    assert_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "gen-release-body.sh",
    );
}

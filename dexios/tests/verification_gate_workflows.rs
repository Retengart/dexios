mod verification_gate_support;

use verification_gate_support::*;

// --- Phase 21 gate tests ---

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
        "mdbook build",
        "git diff --exit-code -- docs",
        "git status --porcelain --untracked-files=all -- docs",
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
fn phase21_release_workflow_tool_pins_and_locked_build_are_source_gated() {
    // CIGR-01, CIGR-03, D-01, D-07: release.yml build uses --locked; mdbook and
    // typst-cli are version-pinned in the maintainer_gate job.

    assert_all_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        &[
            "cargo build --locked --profile release-lto -p dexios",
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
        "run cargo build --locked -p dexios --profile release-lto",
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

    // mdbook version pin: active require_tool call with version 0.5.3
    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "require_tool mdbook \"cargo install mdbook --locked --version 0.5.3\"",
    );

    // Old unversioned mdbook hint must be gone
    assert_not_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "require_tool mdbook \"cargo install mdbook --locked\"",
    );

    // typst version pin: 0.14.2 appears in a non-comment active check
    assert_contains(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "typst version 0.14.2",
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
            "dexios-${GITHUB_REF_NAME}-linux-amd64.sha256",
            "dexios-${GITHUB_REF_NAME}-macos-amd64",
            "dexios-${GITHUB_REF_NAME}-macos-amd64.sha256",
            "dexios-${GITHUB_REF_NAME}-windows-amd64.exe",
            "dexios-${GITHUB_REF_NAME}-windows-amd64.exe.sha256",
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

// --- Phase 22 gate tests ---

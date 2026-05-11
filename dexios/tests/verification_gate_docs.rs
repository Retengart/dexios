const SAFETY_CONTRACT: &str = include_str!("../../docs/safety-contract.md");
const CONTRIBUTING: &str = include_str!("../../CONTRIBUTING.md");
const README: &str = include_str!("../../README.md");
const INSTALLING_AND_BUILDING: &str = include_str!("../../book/src/Installing-and-Building.md");
const AUDITING: &str = include_str!("../../book/src/dexios-core/Auditing.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
const GITIGNORE: &str = include_str!("../../.gitignore");
const VERIFY_PHASE_GATE: &str = include_str!("../../scripts/verify_phase_gate.sh");
const VERIFY_REPO_HYGIENE: &str = include_str!("../../scripts/verify_repo_hygiene.sh");
const MEASURE_PERFORMANCE_GATE: &str = include_str!("../../scripts/measure_performance_gate.sh");
const AUDIT_WORKFLOW: &str = include_str!("../../.github/workflows/audit.yml");
const DOCS_WORKFLOW: &str = include_str!("../../.github/workflows/docs.yml");
const PERFORMANCE_NOTES: &str =
    include_str!("../../book/src/technical-details/Performance-Notes.md");

fn assert_contains(source_name: &str, source: &str, needle: &str) {
    assert!(
        source.contains(needle),
        "{source_name} must contain {needle:?}"
    );
}

#[test]
fn tracked_docs_define_the_minimum_maintainer_gate() {
    for required in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --all-features --no-deps",
        "cargo test --workspace --all-features --release --verbose",
        "cargo audit",
        "mdbook build",
        "CHANGELOG.md",
        "local-notes/",
    ] {
        assert_contains("docs/safety-contract.md", SAFETY_CONTRACT, required);
    }

    for (source_name, source) in [
        ("CONTRIBUTING.md", CONTRIBUTING),
        ("README.md", README),
        (
            "book/src/Installing-and-Building.md",
            INSTALLING_AND_BUILDING,
        ),
        ("book/src/dexios-core/Auditing.md", AUDITING),
    ] {
        assert_contains(source_name, source, "Maintainer Verification Gate");
    }
}

#[test]
fn release_notes_track_breaking_security_verification_and_docs_changes() {
    for required in [
        "## Unreleased",
        "### Breaking Changes",
        "### Security",
        "### Verification",
        "### Documentation",
    ] {
        assert_contains("CHANGELOG.md", CHANGELOG, required);
    }
}

#[test]
fn planning_artifacts_remain_local_only() {
    assert_contains(".gitignore", GITIGNORE, "local-notes/");
}

#[test]
fn local_scripts_expose_the_full_maintainer_gate() {
    for required in [
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --all-features --no-deps",
        "cargo test --workspace --all-features --release --verbose",
        "cargo audit",
        "bash scripts/verify_repo_hygiene.sh",
        "mdbook build",
    ] {
        assert_contains("scripts/verify_phase_gate.sh", VERIFY_PHASE_GATE, required);
    }

    for required in ["git ls-files local-notes", "git check-ignore"] {
        assert_contains("scripts/verify_repo_hygiene.sh", VERIFY_REPO_HYGIENE, required);
    }
}

#[test]
fn ci_workflows_keep_audit_and_docs_fresh() {
    for required in ["pull_request", "push:", "schedule:", "cargo audit"] {
        assert_contains(".github/workflows/audit.yml", AUDIT_WORKFLOW, required);
    }

    for required in [
        "mdbook build",
        "git diff --exit-code -- docs",
        "verify_repo_hygiene.sh",
        "workflow_dispatch",
    ] {
        assert_contains(".github/workflows/docs.yml", DOCS_WORKFLOW, required);
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
        assert_contains("docs/safety-contract.md", SAFETY_CONTRACT, required);
    }
}

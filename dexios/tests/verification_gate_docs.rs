const SAFETY_CONTRACT: &str = include_str!("../../docs/safety-contract.md");
const CONTRIBUTING: &str = include_str!("../../CONTRIBUTING.md");
const README: &str = include_str!("../../README.md");
const INSTALLING_AND_BUILDING: &str = include_str!("../../book/src/Installing-and-Building.md");
const AUDITING: &str = include_str!("../../book/src/dexios-core/Auditing.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
const GITIGNORE: &str = include_str!("../../.gitignore");

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

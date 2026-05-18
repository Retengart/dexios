const SAFETY_CONTRACT: &str = include_str!("../../book/src/Safety-Contract.md");
const CONTRIBUTING: &str = include_str!("../../CONTRIBUTING.md");
const README: &str = include_str!("../../README.md");
const CLI_README: &str = include_str!("../../dexios/README.md");
const USAGE_EXAMPLES: &str = include_str!("../../book/src/Usage-Examples.md");
const DIRECTORY_PACKING: &str =
    include_str!("../../book/src/technical-details/Directory-Packing.md");
const SECURE_ERASE: &str = include_str!("../../book/src/technical-details/Secure-Erase.md");
const GENERATED_SAFETY_CONTRACT: &str = include_str!("../../docs/Safety-Contract.html");
const GENERATED_DIRECTORY_PACKING: &str =
    include_str!("../../docs/technical-details/Directory-Packing.html");
const GENERATED_SECURE_ERASE: &str = include_str!("../../docs/technical-details/Secure-Erase.html");
const INSTALLING_AND_BUILDING: &str = include_str!("../../book/src/Installing-and-Building.md");
const AUDITING: &str = include_str!("../../book/src/dexios-core/Auditing.md");
const HEADERS: &str = include_str!("../../book/src/dexios-core/Headers.md");
const ENCRYPTION: &str = include_str!("../../book/src/dexios-core/Encryption.md");
const PASSWORD_HASHING: &str = include_str!("../../book/src/dexios-core/Password-Hashing.md");
const PROTECTED_WRAPPER: &str = include_str!("../../book/src/dexios-core/Protected-Wrapper.md");
const KEYS: &str = include_str!("../../book/src/technical-details/Keys.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");
const DEXIOS_DOMAIN_CARGO_TOML: &str = include_str!("../../dexios-domain/Cargo.toml");
const GITIGNORE: &str = include_str!("../../.gitignore");
const DENY_TOML: &str = include_str!("../../deny.toml");
const VERIFY_PHASE_GATE: &str = include_str!("../../scripts/verify_phase_gate.sh");
const VERIFY_ASSURANCE_REPLAY: &str = include_str!("../../scripts/verify_assurance_replay.sh");
const VERIFY_CLI_SURFACE: &str = include_str!("../../scripts/verify_cli_surface.sh");
const VERIFY_REPO_HYGIENE: &str = include_str!("../../scripts/verify_repo_hygiene.sh");
const MEASURE_PERFORMANCE_GATE: &str = include_str!("../../scripts/measure_performance_gate.sh");
const GENERATE_RELEASE_MANIFEST: &str = include_str!("../../scripts/generate_release_manifest.sh");
const DEXIOS_CORE_STREAM_V1_TESTS: &str = include_str!("../../dexios-core/tests/stream_v1.rs");
const DEXIOS_CORE_V1_HEADER_TESTS: &str = include_str!("../../dexios-core/tests/v1_header.rs");
const DEXIOS_DOMAIN_DECRYPT_WORKFLOW_ERROR_TESTS: &str =
    include_str!("../../dexios-domain/tests/decrypt_workflow_errors.rs");
const DEXIOS_DOMAIN_PACK_PATHS_TESTS: &str =
    include_str!("../../dexios-domain/tests/pack_paths.rs");
const DEXIOS_DOMAIN_UNPACK_TESTS: &str = include_str!("../../dexios-domain/tests/unpack.rs");
const ARCHIVE_STREAMING_FEASIBILITY: &str =
    include_str!("../../dexios-domain/tests/archive_streaming_feasibility.rs");
const DEXIOS_PACK_CLI_REGRESSION_TESTS: &str = include_str!("pack_cli_regressions.rs");
const DEXIOS_DECRYPT_CLI_REGRESSION_TESTS: &str = include_str!("decrypt_cli_regressions.rs");
const DEXIOS_UNPACK_CLI_REGRESSION_TESTS: &str = include_str!("unpack_cli_regressions.rs");
const DEXIOS_DELETE_SOURCE_CLI_TESTS: &str = include_str!("delete_source_cli.rs");
const DEXIOS_CORE_FIXTURE_MANIFEST: &str =
    include_str!("../../dexios-core/tests/testdata/fixture_manifest.toml");
const DEXIOS_DOMAIN_FIXTURE_MANIFEST: &str =
    include_str!("../../dexios-domain/tests/fixture_manifest.toml");
const DEXIOS_CLI_FIXTURE_MANIFEST: &str = include_str!("fixture_manifest.toml");
const DEXIOS_MAIN_RS: &str = include_str!("../src/main.rs");
const DEXIOS_CLI_RS: &str = include_str!("../src/cli.rs");
const DEXIOS_STATES_RS: &str = include_str!("../src/global/states.rs");
const DEXIOS_UNPACK_RS: &str = include_str!("../src/subcommands/unpack.rs");
const DEXIOS_SUBCOMMAND_ERRORS_RS: &str = include_str!("../src/subcommands/errors.rs");
const DEXIOS_CORE_LIB_RS: &str = include_str!("../../dexios-core/src/lib.rs");
const DEXIOS_CORE_KEY_RS: &str = include_str!("../../dexios-core/src/key.rs");
const DEXIOS_CORE_PROTECTED_RS: &str = include_str!("../../dexios-core/src/protected.rs");
const DEXIOS_DOMAIN_LIB_RS: &str = include_str!("../../dexios-domain/src/lib.rs");
const DEXIOS_DOMAIN_WORKFLOW_ERROR_RS: &str =
    include_str!("../../dexios-domain/src/workflow_error.rs");
const DEXIOS_DOMAIN_ARCHIVE_RS: &str = include_str!("../../dexios-domain/src/archive.rs");
const DEXIOS_DOMAIN_PACK_RS: &str = include_str!("../../dexios-domain/src/pack.rs");
const DEXIOS_DOMAIN_UNPACK_RS: &str = include_str!("../../dexios-domain/src/unpack.rs");
const DEXIOS_DOMAIN_STORAGE_RS: &str = include_str!("../../dexios-domain/src/storage/mod.rs");
const DEXIOS_DOMAIN_CLEANUP_RS: &str = include_str!("../../dexios-domain/src/storage/cleanup.rs");
const DEXIOS_DOMAIN_TRANSACTION_RS: &str =
    include_str!("../../dexios-domain/src/storage/transaction.rs");
const DEXIOS_DOMAIN_TEMP_RS: &str = include_str!("../../dexios-domain/src/storage/temp.rs");
const DEXIOS_DOMAIN_WORKFLOW_ERROR_TESTS: &str =
    include_str!("../../dexios-domain/tests/workflow_errors.rs");
const DEXIOS_DOMAIN_WORKFLOW_PUBLIC_API_TESTS: &str =
    include_str!("../../dexios-domain/tests/workflow_public_api.rs");
const DEXIOS_DOMAIN_ARCHIVE_PUBLIC_API_TESTS: &str =
    include_str!("../../dexios-domain/tests/archive_public_api.rs");
const DEXIOS_WORKFLOW_ERROR_CLI_TESTS: &str = include_str!("workflow_error_cli.rs");
const DEXIOS_SUBCOMMANDS_RS: &str = include_str!("../src/subcommands.rs");
const DEXIOS_PACK_RS: &str = include_str!("../src/subcommands/pack.rs");
const AUDIT_WORKFLOW: &str = include_str!("../../.github/workflows/audit.yml");
const DOCS_WORKFLOW: &str = include_str!("../../.github/workflows/docs.yml");
const DEXIOS_TESTS_WORKFLOW: &str = include_str!("../../.github/workflows/dexios-tests.yml");
const PERFORMANCE_NOTES: &str =
    include_str!("../../book/src/technical-details/Performance-Notes.md");

const REPAIRED_GATE_COMMANDS: &[&str] = &[
    "cargo fmt --all --check",
    "cargo clippy --workspace --all-targets --all-features --no-deps",
    "cargo test --workspace --all-features --release --verbose",
    "cargo audit --deny warnings",
    "cargo deny check",
    "cargo build -p dexios --profile release-lto",
    "bash scripts/verify_cli_surface.sh",
    "mdbook build",
    "git diff --exit-code -- docs",
    "bash scripts/verify_repo_hygiene.sh",
    "git diff --check",
    "bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --allow-dirty --asset target/release-lto/dexios",
];

const ASSURANCE_REPLAY_COMMANDS: &[&str] = &[
    "cargo test --locked --offline -p dexios-core --test v1_header --release",
    "cargo test --locked --offline -p dexios-core --test stream_v1 --release",
    "cargo test --locked --offline -p dexios-core --test key_derivation --release",
    "cargo test --locked --offline -p dexios-domain --test keyslots_v1 --release",
    "cargo test --locked --offline -p dexios-domain --test decrypt_workflow_errors --release",
    "cargo test --locked --offline -p dexios-domain --test unpack --release",
    "cargo test --locked --offline -p dexios --test decrypt_cli_regressions --release",
    "cargo test --locked --offline -p dexios --test unpack_cli_regressions --release",
];

const ASSURANCE_REPLAY_FORBIDDEN_NON_COMMENT_TOKENS: &[&str] = &[
    "cargo install",
    "rustup",
    "curl",
    "wget",
    "npx",
    "cargo fuzz",
    "miri",
    "kani",
    "tarpaulin",
    "grcov",
];

const EXPLORATORY_TOOL_TOKENS: &[&str] =
    &["cargo fuzz", "miri", "kani", "tarpaulin", "grcov", "stress"];

fn assert_contains(source_name: &str, source: &str, needle: &str) {
    assert!(
        source.contains(needle),
        "{source_name} must contain {needle:?}"
    );
}

fn assert_not_contains(source_name: &str, source: &str, needle: &str) {
    assert!(
        !source.contains(needle),
        "{source_name} must not contain {needle:?}"
    );
}

fn assert_no_release_overclaim_patterns(source_name: &str, source: &str) {
    let normalized = source.to_ascii_lowercase();
    for forbidden in [
        "guarantees bit-for-bit reproducibility",
        "guarantees reproducible builds",
        "guarantees sbom",
        "guarantees sbom coverage",
        "guarantees sbom protection",
        "provides sbom coverage",
        "provides sbom protection",
        "sbom protects",
        "prevents supply-chain attacks",
        "prevents supply-chain compromise",
        "prevents supply-chain tampering",
        "proves completed verification",
        "proves supply-chain integrity",
        "signed artifacts are trusted",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "{source_name} must not contain release overclaim pattern: {forbidden}"
        );
    }
}

fn assert_all_contains(source_name: &str, source: &str, needles: &[&str]) {
    for needle in needles {
        assert_contains(source_name, source, needle);
    }
}

fn assert_non_comment_lines_exclude(source_name: &str, source: &str, forbidden: &[&str]) {
    for (line_number, line) in source.lines().enumerate() {
        if !is_non_comment_line(line) {
            continue;
        }

        for needle in forbidden {
            assert!(
                !line.contains(needle),
                "{source_name}:{} must not contain {needle:?} in default gate code: {}",
                line_number + 1,
                line
            );
        }
    }
}

fn normalized_rust_production_source(source: &str) -> String {
    let mut next_module_is_test_only = false;
    let mut in_trailing_test_module = false;
    let mut normalized = String::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            next_module_is_test_only = true;
            continue;
        }
        if next_module_is_test_only && trimmed.starts_with("mod tests") {
            in_trailing_test_module = true;
            continue;
        }
        if in_trailing_test_module {
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        normalized.extend(line.chars().filter(|character| !character.is_whitespace()));

        next_module_is_test_only = false;
    }

    normalized
}

fn normalized_rust_production_section(
    source_name: &str,
    source: &str,
    start: &str,
    end: &str,
) -> String {
    let start_index = source
        .find(start)
        .unwrap_or_else(|| panic!("{source_name} must contain section start {start:?}"));
    let end_index = source[start_index..]
        .find(end)
        .map(|index| start_index + index)
        .unwrap_or_else(|| panic!("{source_name} must contain section end {end:?}"));
    normalized_rust_production_source(&source[start_index..end_index])
}

fn assert_rust_production_source_excludes(source_name: &str, source: &str, forbidden: &[&str]) {
    let normalized = normalized_rust_production_source(source);

    for needle in forbidden {
        let compact_needle = needle
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(
            !normalized.contains(&compact_needle),
            "{source_name} must not contain {needle:?} in production Rust code"
        );
    }
}

fn assert_no_direct_final_create_builders(source_name: &str, source: &str) {
    let normalized = normalized_rust_production_source(source);

    for builder in ["OpenOptions::new()", "File::options()"] {
        let mut search_from = 0;
        while let Some(relative_start) = normalized[search_from..].find(builder) {
            let start = search_from + relative_start;
            let end = normalized[start..]
                .find(';')
                .map(|relative_end| start + relative_end)
                .unwrap_or(normalized.len());
            let statement = &normalized[start..end];
            for forbidden in [".create(true)", ".create_new(true)"] {
                assert!(
                    !statement.contains(forbidden),
                    "{source_name} must not build direct final output files with {builder}{forbidden}"
                );
            }
            search_from = start + builder.len();
        }
    }
}

fn normalized_token(token: &str) -> String {
    token
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn normalized_token_positions(normalized: &str, token: &str) -> Vec<usize> {
    let token = normalized_token(token);
    let mut positions = Vec::new();
    let mut search_from = 0;

    while let Some(relative_index) = normalized[search_from..].find(&token) {
        let index = search_from + relative_index;
        positions.push(index);
        search_from = index + token.len();
    }

    positions
}

fn normalized_section_order_indices(
    source_name: &str,
    normalized: &str,
    expected_order: &[&str],
) -> Vec<usize> {
    let mut search_from = 0;
    let mut indices = Vec::with_capacity(expected_order.len());

    for token in expected_order {
        let compact_token = normalized_token(token);
        let relative_index = normalized[search_from..]
            .find(&compact_token)
            .unwrap_or_else(|| panic!("{source_name} must contain production token {token:?}"));
        let index = search_from + relative_index;
        indices.push(index);
        search_from = index + compact_token.len();
    }

    indices
}

fn assert_normalized_section_order(source_name: &str, normalized: &str, expected_order: &[&str]) {
    normalized_section_order_indices(source_name, normalized, expected_order);
}

fn assert_no_normalized_tokens_before(
    source_name: &str,
    normalized: &str,
    forbidden_tokens: &[&str],
    boundary_index: usize,
    boundary_name: &str,
) {
    for token in forbidden_tokens {
        for index in normalized_token_positions(normalized, token) {
            assert!(
                index >= boundary_index,
                "{source_name} must not contain production token {token:?} before {boundary_name}"
            );
        }
    }
}

fn assert_corpus_contains(corpus_name: &str, sources: &[(&str, &str)], needle: &str) {
    assert!(
        sources.iter().any(|(_, source)| source.contains(needle)),
        "{corpus_name} must contain {needle:?} in one of: {}",
        sources
            .iter()
            .map(|(source_name, _)| *source_name)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn assert_corpus_markdown_text_contains(corpus_name: &str, sources: &[(&str, &str)], needle: &str) {
    assert!(
        sources
            .iter()
            .any(|(_, source)| source.replace('`', "").contains(needle)),
        "{corpus_name} must contain markdown text {needle:?} in one of: {}",
        sources
            .iter()
            .map(|(source_name, _)| *source_name)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn assert_occurs_before(source_name: &str, source: &str, earlier: &str, later: &str) {
    let earlier_index = source
        .find(earlier)
        .unwrap_or_else(|| panic!("{source_name} must contain {earlier:?}"));
    let later_index = source
        .find(later)
        .unwrap_or_else(|| panic!("{source_name} must contain {later:?}"));
    assert!(
        earlier_index < later_index,
        "{source_name} must place {earlier:?} before {later:?}"
    );
}

fn assert_non_comment_line_count(source_name: &str, source: &str, needle: &str, expected: usize) {
    let count = source
        .lines()
        .filter(|line| is_non_comment_line(line) && line.trim() == needle)
        .count();
    assert_eq!(
        count, expected,
        "{source_name} must contain exactly {expected} non-comment line(s) matching {needle:?}"
    );
}

fn non_comment_line_index(source_name: &str, source: &str, needle: &str) -> usize {
    source
        .lines()
        .enumerate()
        .find_map(|(index, line)| {
            (is_non_comment_line(line) && line.trim() == needle).then_some(index)
        })
        .unwrap_or_else(|| panic!("{source_name} must contain executable line {needle:?}"))
}

fn assert_non_comment_line_occurs_before(
    source_name: &str,
    source: &str,
    earlier: &str,
    later: &str,
) {
    let earlier_index = non_comment_line_index(source_name, source, earlier);
    let later_index = non_comment_line_index(source_name, source, later);
    assert!(
        earlier_index < later_index,
        "{source_name} must execute {earlier:?} before {later:?}"
    );
}

fn parsed_fixture_rows(source_name: &str, source: &str) -> Vec<toml::Value> {
    let manifest: toml::Value =
        toml::from_str(source).unwrap_or_else(|error| panic!("{source_name} must parse: {error}"));
    manifest
        .get("fixture")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_else(|| panic!("{source_name} must expose [[fixture]] rows"))
}

fn required_manifest_field<'a>(
    source_name: &str,
    row_id: &str,
    row: &'a toml::Value,
    field: &str,
) -> &'a str {
    let value = row
        .get(field)
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("{source_name}:{row_id} must contain string field {field}"));
    assert!(
        !value.trim().is_empty(),
        "{source_name}:{row_id} field {field} must not be empty"
    );
    value
}

fn assert_manifest_row(source_name: &str, rows: &[toml::Value], row_id: &str, requirement: &str) {
    let matches = rows
        .iter()
        .filter(|row| row.get("id").and_then(|value| value.as_str()) == Some(row_id))
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "{source_name} must contain exactly one manifest row {row_id:?}"
    );
    let row = matches[0];

    for field in [
        "id",
        "group",
        "path",
        "purpose",
        "invariant",
        "requirement",
        "source",
        "expected",
        "owner_phase",
    ] {
        required_manifest_field(source_name, row_id, row, field);
    }

    assert_eq!(
        required_manifest_field(source_name, row_id, row, "id"),
        row_id,
        "{source_name}:{row_id} id must match the expected row"
    );
    assert!(
        required_manifest_field(source_name, row_id, row, "group").starts_with("phase01-"),
        "{source_name}:{row_id} group must remain in the Phase 01 namespace"
    );
    assert!(
        required_manifest_field(source_name, row_id, row, "invariant").starts_with("D-"),
        "{source_name}:{row_id} invariant must link to a Phase 01 decision"
    );
    assert_eq!(
        required_manifest_field(source_name, row_id, row, "requirement"),
        requirement,
        "{source_name}:{row_id} requirement must link to {requirement}"
    );
    assert_eq!(
        required_manifest_field(source_name, row_id, row, "owner_phase"),
        "Phase 1",
        "{source_name}:{row_id} owner phase must remain Phase 1"
    );
}

fn is_non_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

#[test]
fn tracked_docs_define_the_minimum_maintainer_gate() {
    for (source_name, source) in [
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        (
            "book/src/Installing-and-Building.md",
            INSTALLING_AND_BUILDING,
        ),
    ] {
        assert_all_contains(source_name, source, REPAIRED_GATE_COMMANDS);
    }

    for required in [
        "cargo install cargo-audit --locked --version 0.22.1",
        "cargo install cargo-deny --locked --version 0.19.6",
        "cargo install mdbook --locked",
        "no-unsafe crate-root",
        "dexios/src/main.rs",
        "dexios-core/src/lib.rs",
        "dexios-domain/src/lib.rs",
        "does not auto-install tools",
        "scripts/measure_performance_gate.sh",
        "not part of the default",
        "CHANGELOG.md",
        "local-notes/",
    ] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
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
        "RUSTSEC-2026-0097",
        "blake3 = \"=1.8.3\"",
        "traits-preview",
        "deny.toml",
        "cargo audit --deny warnings",
        "cargo deny check",
        "release-lto CLI smoke",
        "removed `--aes`, `--argon`",
        "top-level `erase`",
    ] {
        assert_contains("CHANGELOG.md", CHANGELOG, required);
    }
}

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
    assert_not_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        "local-notes",
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
fn release_claim_gate_rejects_common_positive_overclaim_phrases() {
    let result = std::panic::catch_unwind(|| {
        assert_no_release_overclaim_patterns(
            "synthetic release claim",
            "Dexios guarantees SBOM coverage for release assets.",
        );
    });
    assert!(
        result.is_err(),
        "release claim source gate must reject positive SBOM overclaims"
    );
}

#[test]
fn planning_artifacts_remain_local_only() {
    assert_contains(".gitignore", GITIGNORE, "local-notes/");
}

#[test]
fn rust_production_source_gate_catches_multiline_dangerous_calls() {
    let source = r#"
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
"#;
    let normalized = normalized_rust_production_source(source);

    assert!(normalized.contains("OpenOptions::new().create(true)"));
    assert!(!normalized.contains("File::create"));
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", source);
        })
        .is_err()
    );

    let reordered_open_options_source = r#"
fn production_write(path: &std::path::Path) {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
}
"#;
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", reordered_open_options_source);
        })
        .is_err()
    );

    let file_options_source = r#"
fn production_write(path: &std::path::Path) {
    std::fs::File::options()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
}
"#;
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", file_options_source);
        })
        .is_err()
    );

    let file_options_create_new_source = r#"
fn production_write(path: &std::path::Path) {
    std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
}
"#;
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_direct_final_create_builders("synthetic.rs", file_options_create_new_source);
        })
        .is_err()
    );
}

#[test]
fn archive_streaming_feasibility_rejects_direct_zip_extract() {
    for required in [
        "ZipStreamReader",
        "ProofVisitor",
        "finalize_after_auth",
        "zip_streaming_proof_stages_without_committing_before_finalize",
    ] {
        assert_contains(
            "dexios-domain/tests/archive_streaming_feasibility.rs",
            ARCHIVE_STREAMING_FEASIBILITY,
            required,
        );
    }

    for (source_name, source) in [
        (
            "dexios-domain/tests/archive_streaming_feasibility.rs",
            ARCHIVE_STREAMING_FEASIBILITY,
        ),
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
        "run bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --allow-dirty --asset target/release-lto/dexios",
    );

    for required in [
        "require_tool cargo-audit \"cargo install cargo-audit --locked --version 0.22.1\"",
        "require_tool cargo-deny \"cargo install cargo-deny --locked --version 0.19.6\"",
        "require_tool mdbook \"cargo install mdbook --locked\"",
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

    for required in ["git ls-files local-notes", "git check-ignore"] {
        assert_contains(
            "scripts/verify_repo_hygiene.sh",
            VERIFY_REPO_HYGIENE,
            required,
        );
    }
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
        "run cargo test --workspace --all-features --release --verbose",
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
            "dexios-domain/tests/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_TESTS,
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
fn canonical_v1_docs_source_gate_catches_format_claims() {
    for required in [
        "canonical V1",
        "512 bytes",
        "DXIO 00 01 CV1\\0",
        "retired 416-byte",
        "obsolete retired layout",
        "exact 512-byte canonical V1 header bytes",
        "PayloadKind",
        "PayloadFramingProfile",
        "payload AAD",
        "excludes mutable keyslot table state",
        "slot-scoped AAD",
        "payload nonce",
        "keyslot nonce",
        "fixed physical slots",
        "do not compact or reorder",
        "fresh keyslot wrapping nonce",
        "unsupported keyslot metadata does not count",
    ] {
        assert_contains("book/src/dexios-core/Headers.md", HEADERS, required);
    }

    for forbidden in [
        "416-byte V1 layout is supported",
        "first **32 bytes** are the static header region",
        "key add remains unsupported",
    ] {
        assert_not_contains("book/src/dexios-core/Headers.md", HEADERS, forbidden);
    }
}

#[test]
fn canonical_v1_docs_source_gate_catches_stream_and_payload_claims() {
    for required in [
        "canonical V1",
        "payload nonce",
        "keyslot nonce",
        "immutable canonical V1 static header",
        "Payload AAD excludes mutable keyslot table state",
        "slot-scoped AAD",
        "V1FinalAuth",
        "final authentication",
        "final output",
        "PayloadKind",
        "PayloadFramingProfile",
        "manifest-first archive framing",
        "ordered `DXBF` body frames",
        "not ZIP crate surface",
        "ZIP implementation bytes",
        "not canonical V1 format surface",
    ] {
        assert_contains("book/src/dexios-core/Encryption.md", ENCRYPTION, required);
    }

    for forbidden in [
        "returns `Ok(())`",
        "first 32 bytes of the header",
        "ZIP crate types are canonical V1 surface",
    ] {
        assert_not_contains("book/src/dexios-core/Encryption.md", ENCRYPTION, forbidden);
    }
}

#[test]
fn canonical_v1_docs_source_gate_catches_manifest_and_error_claims() {
    for required in [
        "manifest-first archive payloads",
        "DXAR",
        "ordered `DXBF` body frames",
        "structural limit checks",
        "body-frame length mismatch",
        "ordered body-frame rules",
        "ZIP bytes",
        "ZIP crate types",
        "not canonical V1 surface",
    ] {
        assert_contains(
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
            required,
        );
    }

    for required in [
        "RetiredV1Layout",
        "InvalidCanonicalDiscriminator",
        "InvalidPayloadKind",
        "InvalidPayloadFraming",
        "InvalidKdfProfile",
        "InvalidKdfParamProfile",
        "InvalidSlotState",
        "InvalidPhysicalSlotIndex",
        "TruncatedHeader",
        "FinalBlockAuthentication",
    ] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }

    assert_not_contains(
        "book/src/technical-details/Directory-Packing.md",
        DIRECTORY_PACKING,
        "ZIP implementation types are canonical format surface",
    );
}

#[test]
fn canonical_v1_assurance_replay_includes_phase3_evidence() {
    for command in [
        "cargo test --locked --offline -p dexios-core --test v1_header --release",
        "cargo test --locked --offline -p dexios-core --test stream_v1 --release",
        "cargo test --locked --offline -p dexios-core --test key_derivation --release",
        "cargo test --locked --offline -p dexios-domain --test keyslots_v1 --release",
        "cargo test --locked --offline -p dexios-domain --test decrypt_workflow_errors --release",
        "cargo test --locked --offline -p dexios-domain --test unpack --release",
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
        "run cargo test --workspace --all-features --release --verbose",
        "run bash scripts/verify_assurance_replay.sh",
    );
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
        "mdbook build",
        "git diff --exit-code -- docs",
        "verify_repo_hygiene.sh",
        "workflow_dispatch",
    ] {
        assert_contains(".github/workflows/docs.yml", DOCS_WORKFLOW, required);
    }
}

#[test]
fn repaired_cli_surface_is_rejection_only_for_removed_behavior() {
    for (line_number, line) in VERIFY_CLI_SURFACE.lines().enumerate() {
        if !is_non_comment_line(line) {
            continue;
        }

        let has_removed_flag = line.contains("--aes")
            || line.contains("--argon")
            || line.contains("--zstd")
            || line.contains("--erase");
        let has_removed_subcommand = line.contains("\"$BIN\" erase");

        if has_removed_flag || has_removed_subcommand {
            assert!(
                line.contains("expect_rejected"),
                "scripts/verify_cli_surface.sh:{} removed CLI token must stay in an expect_rejected context: {}",
                line_number + 1,
                line
            );
        }
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

#[test]
fn phase9_kdf_passphrase_and_secret_contract_is_source_gated() {
    for required in [
        "balloon-hash = { version = \"0.4.0\", features = [\"zeroize\"] }",
        "blake3 = \"=1.8.3\"",
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
        "balloon-hash 0.4.0",
        "zeroize",
        "blake3 = \"=1.8.3\"",
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
    ] {
        assert_contains("book/src/technical-details/Keys.md", KEYS, required);
    }

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
        "balloon-hash 0.4.0",
        "invalid `--auto` word counts",
        "hardware profile",
        "narrow secret-memory claim",
    ] {
        assert_contains("book/src/Safety-Contract.md", SAFETY_CONTRACT, required);
    }

    for required in [
        "balloon-hash 0.4.0",
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
            "dexios/tests/workflow_error_cli.rs",
            DEXIOS_WORKFLOW_ERROR_CLI_TESTS,
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
        "run cargo test -p dexios-domain --test workflow_public_api --all-features --release",
        "run cargo test -p dexios --test verification_gate_docs --release",
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
    ] {
        assert_contains(
            "dexios-domain/tests/archive_public_api.rs",
            DEXIOS_DOMAIN_ARCHIVE_PUBLIC_API_TESTS,
            required,
        );
    }

    for required in [
        "pub enum ArchiveCompression",
        "pub struct ArchivePolicy",
        "Self::Zstd",
    ] {
        assert_contains(
            "dexios-domain/src/archive.rs",
            DEXIOS_DOMAIN_ARCHIVE_RS,
            required,
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
        "run cargo test -p dexios-domain --test archive_public_api --release",
        1,
    );
}

#[test]
fn phase05_manifest_archive_and_cli_gate_is_source_gated() {
    let focused_commands = [
        "run cargo test -p dexios-core --test stream_v1 --release",
        "run cargo test -p dexios-core --test v1_header --release",
        "run cargo test -p dexios-domain --test pack_paths --release",
        "run cargo test -p dexios-domain --test unpack --release",
        "run cargo test -p dexios-domain --test archive_public_api --release",
        "run cargo test -p dexios-domain --test workflow_errors --all-features --release",
        "run cargo test -p dexios --test pack_cli_regressions --release",
        "run cargo test -p dexios --test unpack_cli_regressions --release",
        "run cargo test -p dexios --test delete_source_cli --release",
        "run cargo test -p dexios --test workflow_error_cli --release",
        "run cargo test -p dexios --test verification_gate_docs --release",
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
            "run cargo test --workspace --all-features --release --verbose",
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
            "dexios-domain/tests/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_TESTS,
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
            "dexios/tests/workflow_error_cli.rs",
            DEXIOS_WORKFLOW_ERROR_CLI_TESTS,
            "write_manifest_archive_with_entries",
        ),
    ] {
        assert_contains(source_name, source, required);
    }
    assert_contains(
        "dexios/tests/workflow_error_cli.rs",
        DEXIOS_WORKFLOW_ERROR_CLI_TESTS,
        "legacy raw archive payload must fail as a terse archive class",
    );
    assert_contains(
        "dexios/tests/workflow_error_cli.rs",
        DEXIOS_WORKFLOW_ERROR_CLI_TESTS,
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
            "dexios/tests/workflow_error_cli.rs",
            DEXIOS_WORKFLOW_ERROR_CLI_TESTS,
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
    let generated_docs = [
        ("docs/Safety-Contract.html", GENERATED_SAFETY_CONTRACT),
        (
            "docs/technical-details/Secure-Erase.html",
            GENERATED_SECURE_ERASE,
        ),
        (
            "docs/technical-details/Directory-Packing.html",
            GENERATED_DIRECTORY_PACKING,
        ),
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
        "staged flush/sync/persist",
        "same-directory temporary files",
        "tempfile::NamedTempFile::persist",
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
        "ordinary delete-after-success cleanup",
        "changed cleanup identity",
        "partial commit evidence",
        "committed outputs are not rolled back",
        "no secure erase",
        "no physical sanitization",
        "no full power-failure proof",
        "manifest-first archive payload",
        "no full plaintext archive temporary file",
        "selected staged file bodies",
    ] {
        assert_corpus_contains("generated Phase 11 docs", &generated_docs, required);
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
        "persist_noclobber",
        "persist(&path)",
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
fn archive_docs_do_not_reintroduce_removed_compression_selector() {
    for (source_name, source) in [
        ("README.md", README),
        ("dexios/README.md", CLI_README),
        ("book/src/Usage-Examples.md", USAGE_EXAMPLES),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
    ] {
        assert_not_contains(source_name, source, "--zstd");
        assert_not_contains(source_name, source, "Compression is optional");
    }
    let archive_docs = [
        ("README.md", README),
        ("dexios/README.md", CLI_README),
        ("book/src/Usage-Examples.md", USAGE_EXAMPLES),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
    ];
    assert_corpus_contains(
        "archive documentation corpus",
        &archive_docs,
        "default Dexios archive",
    );
    assert_corpus_contains(
        "archive documentation corpus",
        &archive_docs,
        "compression policy",
    );
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
    assert_contains(".github/workflows/docs.yml", DOCS_WORKFLOW, "mdbook build");

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

    // D-21 through D-23: planning context stays local and outside CI inputs.
    assert_contains(".gitignore", GITIGNORE, "local-notes/");
    assert_contains(
        "scripts/verify_repo_hygiene.sh",
        VERIFY_REPO_HYGIENE,
        "local-notes/",
    );
}

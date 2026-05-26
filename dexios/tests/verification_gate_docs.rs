const SAFETY_CONTRACT: &str = include_str!("../../book/src/Safety-Contract.md");
const CONTRIBUTING: &str = include_str!("../../CONTRIBUTING.md");
const README: &str = include_str!("../../README.md");
const CLI_README: &str = include_str!("../../dexios/README.md");
const SPEC_FORMAT_REFERENCE: &str = include_str!("../../spec/dexios-paper.typ");
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
const SECURITY_MD: &str = include_str!("../../SECURITY.md");
const SECURITY_POLICY: &str = include_str!("../../book/src/Security-Policy.md");
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");
const CARGO_LOCK: &str = include_str!("../../Cargo.lock");
const FLAKE_LOCK: &str = include_str!("../../flake.lock");
const DEXIOS_DOMAIN_CARGO_TOML: &str = include_str!("../../dexios-domain/Cargo.toml");
const DEXIOS_CARGO_TOML: &str = include_str!("../../dexios/Cargo.toml");
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
const DEXIOS_ENCRYPT_CLI_REGRESSION_TESTS: &str = include_str!("encrypt_cli_regressions.rs");
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
const DEXIOS_GLOBAL_RS: &str = include_str!("../src/global.rs");
const DEXIOS_STATES_RS: &str = include_str!("../src/global/states.rs");
const DEXIOS_ENCRYPT_RS: &str = include_str!("../src/subcommands/encrypt.rs");
const DEXIOS_DECRYPT_RS: &str = include_str!("../src/subcommands/decrypt.rs");
const DEXIOS_UNPACK_RS: &str = include_str!("../src/subcommands/unpack.rs");
const DEXIOS_SUBCOMMAND_ERRORS_RS: &str = include_str!("../src/subcommands/errors.rs");
const DEXIOS_CORE_LIB_RS: &str = include_str!("../../dexios-core/src/lib.rs");
const DEXIOS_CORE_KEY_RS: &str = include_str!("../../dexios-core/src/key.rs");
const DEXIOS_CORE_PROTECTED_RS: &str = include_str!("../../dexios-core/src/protected.rs");
const DEXIOS_CORE_STREAM_RS: &str = include_str!("../../dexios-core/src/stream.rs");
const DEXIOS_DOMAIN_LIB_RS: &str = include_str!("../../dexios-domain/src/lib.rs");
const DEXIOS_DOMAIN_WORKFLOW_ERROR_RS: &str =
    include_str!("../../dexios-domain/src/workflow_error.rs");
const DEXIOS_DOMAIN_ARCHIVE_RS: &str = include_str!("../../dexios-domain/src/archive.rs");
const DEXIOS_DOMAIN_ENCRYPT_RS: &str = include_str!("../../dexios-domain/src/encrypt.rs");
const DEXIOS_DOMAIN_PACK_RS: &str = include_str!("../../dexios-domain/src/pack.rs");
const DEXIOS_DOMAIN_DECRYPT_RS: &str = include_str!("../../dexios-domain/src/decrypt.rs");
const DEXIOS_DOMAIN_UNPACK_RS: &str = include_str!("../../dexios-domain/src/unpack.rs");
const DEXIOS_DOMAIN_IDENTITY_RS: &str = include_str!("../../dexios-domain/src/storage/identity.rs");
const DEXIOS_DOMAIN_STORAGE_RS: &str = include_str!("../../dexios-domain/src/storage/mod.rs");
const DEXIOS_DOMAIN_MUTATION_RS: &str = include_str!("../../dexios-domain/src/storage/mutation.rs");
const DEXIOS_DOMAIN_CLEANUP_RS: &str = include_str!("../../dexios-domain/src/storage/cleanup.rs");
const DEXIOS_DOMAIN_TRANSACTION_RS: &str =
    include_str!("../../dexios-domain/src/storage/transaction.rs");
const DEXIOS_DOMAIN_TEMP_RS: &str = include_str!("../../dexios-domain/src/storage/temp.rs");
const DEXIOS_DOMAIN_HEADER_RS: &str = include_str!("../../dexios-domain/src/header.rs");
const DEXIOS_DOMAIN_HEADER_STRIP_RS: &str = include_str!("../../dexios-domain/src/header/strip.rs");
const DEXIOS_DOMAIN_HEADER_RESTORE_RS: &str =
    include_str!("../../dexios-domain/src/header/restore.rs");
const DEXIOS_DOMAIN_KEY_RS: &str = include_str!("../../dexios-domain/src/key.rs");
const DEXIOS_DOMAIN_PATH_IDENTITY_TESTS: &str =
    include_str!("../../dexios-domain/tests/path_identity.rs");
const DEXIOS_DOMAIN_TRANSACTION_TESTS: &str =
    include_str!("../../dexios-domain/tests/transactions.rs");
const DEXIOS_DOMAIN_HEADER_RESTORE_TESTS: &str =
    include_str!("../../dexios-domain/tests/header_restore.rs");
const DEXIOS_DOMAIN_KEYSLOTS_TESTS: &str = include_str!("../../dexios-domain/tests/keyslots_v1.rs");
const DEXIOS_DOMAIN_CLEANUP_RECEIPTS_TESTS: &str =
    include_str!("../../dexios-domain/tests/cleanup_receipts.rs");
const DEXIOS_DOMAIN_DETACHED_PUBLICATION_TESTS: &str =
    include_str!("../../dexios-domain/tests/detached_publication.rs");
const DEXIOS_DOMAIN_WORKFLOW_ERROR_TESTS: &str =
    include_str!("../../dexios-domain/tests/workflow_errors.rs");
const DEXIOS_DOMAIN_WORKFLOW_PUBLIC_API_TESTS: &str =
    include_str!("../../dexios-domain/tests/workflow_public_api.rs");
const DEXIOS_DOMAIN_ARCHIVE_PUBLIC_API_TESTS: &str =
    include_str!("../../dexios-domain/tests/archive_public_api.rs");
const DEXIOS_WORKFLOW_ERROR_CLI_TESTS: &str = include_str!("workflow_error_cli.rs");
const DEXIOS_HEADER_CLI_REGRESSION_TESTS: &str = include_str!("header_cli_regressions.rs");
const DEXIOS_KEY_CLI_REGRESSION_TESTS: &str = include_str!("key_cli_regressions.rs");
const DEXIOS_SUBCOMMANDS_RS: &str = include_str!("../src/subcommands.rs");
const DEXIOS_PACK_RS: &str = include_str!("../src/subcommands/pack.rs");
const AUDIT_WORKFLOW: &str = include_str!("../../.github/workflows/audit.yml");
const BUILD_NIX_WORKFLOW: &str = include_str!("../../.github/workflows/build_nix.yml");
const CARGO_BUILD_WORKFLOW: &str = include_str!("../../.github/workflows/cargo-build.yml");
const CLI_SURFACE_WORKFLOW: &str = include_str!("../../.github/workflows/cli-surface.yml");
const DOCS_WORKFLOW: &str = include_str!("../../.github/workflows/docs.yml");
const DEXIOS_TESTS_WORKFLOW: &str = include_str!("../../.github/workflows/dexios-tests.yml");
const RELEASE_WORKFLOW: &str = include_str!("../../.github/workflows/release.yml");
const UNIT_TESTS_WORKFLOW: &str = include_str!("../../.github/workflows/unit_tests.yml");
const PERFORMANCE_NOTES: &str =
    include_str!("../../book/src/technical-details/Performance-Notes.md");
const RC_CLOSEOUT: &str = include_str!("../../release-evidence/RC-CLOSEOUT.md");

const REPAIRED_GATE_COMMANDS: &[&str] = &[
    "cargo metadata --format-version=1 --locked --no-deps",
    "cargo fmt --all --check",
    "cargo clippy --workspace --all-targets --all-features --no-deps --locked",
    "cargo test --locked --workspace --all-features --release --verbose",
    "cargo audit --deny warnings",
    "cargo deny check",
    "cargo build --locked -p dexios --profile release-lto",
    "bash scripts/verify_cli_surface.sh",
    "mdbook build",
    "git diff --exit-code -- docs",
    "git status --porcelain --untracked-files=all -- docs",
    "typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
    "git diff --exit-code -- spec/dexios-paper.pdf",
    "bash scripts/verify_repo_hygiene.sh",
    "git diff --check",
    "bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --asset target/release-lto/dexios",
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

fn assert_action_pin(source_name: &str, source: &str, action: &str, sha: &str) {
    assert_eq!(sha.len(), 40, "expected full SHA for {action}");
    assert!(
        sha.chars().all(|ch| ch.is_ascii_hexdigit()),
        "expected lowercase/uppercase hex SHA for {action}: {sha}"
    );
    assert_contains(source_name, source, &format!("uses: {action}@{sha}"));
}

fn assert_external_actions_are_full_sha_pinned(source_name: &str, source: &str) {
    for (line_number, line) in source.lines().enumerate() {
        let line = line.trim();
        let Some(uses_ref) = line
            .strip_prefix("- uses: ")
            .or_else(|| line.strip_prefix("uses: "))
        else {
            continue;
        };
        if uses_ref.starts_with("./") {
            continue;
        }
        let Some((_action, reference)) = uses_ref.rsplit_once('@') else {
            panic!(
                "{source_name}:{} action use must include an @ ref",
                line_number + 1
            );
        };
        assert!(
            reference.len() == 40 && reference.chars().all(|ch| ch.is_ascii_hexdigit()),
            "{source_name}:{} action ref must be a full 40-char SHA: {uses_ref}",
            line_number + 1
        );
    }
}

fn assert_checkout_steps_disable_persist_credentials(source_name: &str, source: &str) {
    let lines: Vec<_> = source.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("uses: actions/checkout@") {
            continue;
        }
        let window_end = (index + 4).min(lines.len());
        assert!(
            lines[index..window_end]
                .iter()
                .any(|line| line.trim() == "persist-credentials: false"),
            "{source_name}:{} checkout step must set persist-credentials: false",
            index + 1
        );
    }
}

fn assert_workflow_default_read_permissions(source_name: &str, source: &str) {
    assert_contains(source_name, source, "\npermissions:\n  contents: read\n");
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

fn spec_format_reference_alignment_issues(source: &str) -> Vec<&'static str> {
    let mut issues = Vec::new();

    for (required, issue) in [
        (
            "512-byte canonical V1 header",
            "missing canonical 512-byte V1 header claim",
        ),
        (
            "DXIO 00 01 CV1\\0",
            "missing canonical V1 discriminator claim",
        ),
        (
            "64-byte immutable static header",
            "missing 64-byte static header claim",
        ),
        (
            "payload AAD covers the 64-byte immutable static header",
            "missing current payload AAD boundary",
        ),
        (
            "112-byte physical keyslot",
            "missing current physical keyslot size",
        ),
        (
            "BLAKE3-Balloon",
            "missing current BLAKE3-Balloon write policy",
        ),
        (
            "historical Argon2id tag",
            "missing unsupported historical Argon2id metadata boundary",
        ),
        (
            "manifest-first archive payload",
            "missing manifest-first archive payload claim",
        ),
        ("DXAR", "missing DXAR manifest magic"),
        ("DXBF", "missing DXBF body-frame magic"),
        (
            "no full plaintext archive temporary file",
            "missing pack/unpack temporary-file exposure boundary",
        ),
    ] {
        if !source.contains(required) {
            issues.push(issue);
        }
    }

    for (forbidden, issue) in [
        ("416", "stale 416-byte header claim"),
        ("first 32 bytes", "stale 32-byte payload AAD claim"),
        ("96 bytes", "stale 96-byte keyslot claim"),
        ("--argon", "stale Argon2id CLI selector claim"),
        ("ZSTD", "stale archive compression selector claim"),
        (
            "encrypted `zip` archive",
            "stale encrypted zip archive format claim",
        ),
        (
            "temporary `zip` archive",
            "stale plaintext zip temporary-file claim",
        ),
    ] {
        if source.contains(forbidden) {
            issues.push(issue);
        }
    }

    issues
}

fn phase15_safety_contract_issues(source: &str) -> Vec<&'static str> {
    let mut issues = Vec::new();

    for (required, issue) in [
        (
            "dexios-domain/src/storage/identity.rs",
            "missing storage identity source authority",
        ),
        (
            "dexios-domain/tests/path_identity.rs",
            "missing path identity test authority",
        ),
        (
            "dexios-domain/tests/unpack.rs",
            "missing unpack identity regression authority",
        ),
        (
            "dexios/tests/unpack_cli_regressions.rs",
            "missing unpack CLI identity regression authority",
        ),
        (
            "dexios/tests/delete_source_cli.rs",
            "missing delete-source cleanup identity regression authority",
        ),
        ("PathRole::Input", "missing input path identity role"),
        (
            "PathRole::DetachedHeader",
            "missing detached-header path identity role",
        ),
        (
            "PathRole::ProcessedSource",
            "missing processed-source cleanup role",
        ),
        (
            "PathRole::CleanupTarget",
            "missing cleanup-target identity role",
        ),
        (
            "parent-directory components before normalization",
            "missing parent-component pre-normalization boundary",
        ),
        (
            "FileStorage::read_resolved_existing_no_follow",
            "missing identity-bound no-follow reopen boundary",
        ),
    ] {
        if !source.contains(required) {
            issues.push(issue);
        }
    }

    issues
}

fn phase15_public_docs_issues(sources: &[(&str, &str)]) -> Vec<&'static str> {
    let mut issues = Vec::new();

    for (required, issue) in [
        ("symlinked parent", "missing symlinked parent rejection"),
        (
            "parent-directory components",
            "missing parent-component rejection wording",
        ),
        ("final symlink", "missing final symlink rejection"),
        (
            "alias-aware identity",
            "missing alias-aware identity wording",
        ),
        ("same-file", "missing same-file alias wording"),
        (
            "ordinary delete-after-success cleanup",
            "missing ordinary cleanup boundary",
        ),
        ("no secure erase", "missing no-secure-erase boundary"),
        (
            "no physical sanitization",
            "missing no-physical-sanitization boundary",
        ),
    ] {
        if !sources
            .iter()
            .any(|(_, source)| source.replace('`', "").contains(required))
        {
            issues.push(issue);
        }
    }

    for (source_name, source) in sources {
        issues.extend(phase15_platform_parity_issues(
            source_name,
            source,
            &[DEXIOS_DOMAIN_IDENTITY_RS, DEXIOS_DOMAIN_PATH_IDENTITY_TESTS],
        ));
        issues.extend(phase15_cleanup_authorization_issues(source_name, source));
    }

    issues
}

fn phase15_platform_parity_issues(
    _source_name: &str,
    source: &str,
    proof_sources: &[&str],
) -> Vec<&'static str> {
    let has_explicit_unqualified_proof = proof_sources.iter().any(|proof_source| {
        proof_source.contains("explicit Windows/non-Unix path identity parity proof")
            || proof_source.contains("explicit Windows and non-Unix path identity parity proof")
    });
    if has_explicit_unqualified_proof {
        return Vec::new();
    }

    let normalized = source.to_ascii_lowercase();
    let mut issues = Vec::new();

    for forbidden in [
        "windows/non-unix parity",
        "windows and non-unix parity",
        "identical path identity behavior on windows and non-unix",
        "same path identity guarantees on windows and non-unix",
        "full path identity parity across windows and non-unix",
        "symlink rejection parity on every platform",
    ] {
        if normalized.contains(forbidden) {
            issues.push("unqualified Windows/non-Unix parity claim without source proof");
        }
    }

    issues
}

fn phase15_cleanup_authorization_issues(_source_name: &str, source: &str) -> Vec<&'static str> {
    let normalized = source.to_ascii_lowercase();
    let mut issues = Vec::new();

    for forbidden in [
        "phase 16 cleanup authorization",
        "phase16 cleanup authorization",
        "partial commit evidence is cleanup authorization",
        "partial commit evidence authorizes cleanup",
        "cleanup may run after partial commit",
        "cleanup runs after partial commit evidence",
        "secure erase guarantee",
        "physical sanitization guarantee",
    ] {
        if normalized.contains(forbidden) {
            issues.push("cleanup or secure-erase overclaim");
        }
    }

    issues
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

fn assert_manifest_has_no_dependency_package(source_name: &str, source: &str, package: &str) {
    let manifest: toml::Value =
        toml::from_str(source).unwrap_or_else(|error| panic!("{source_name} must parse: {error}"));
    inspect_manifest_tables_for_package(source_name, &manifest, package);
}

fn inspect_manifest_tables_for_package(source_name: &str, value: &toml::Value, package: &str) {
    let Some(table) = value.as_table() else {
        return;
    };

    for (key, child) in table {
        if matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            inspect_dependency_table_for_package(source_name, child, package);
        }

        inspect_manifest_tables_for_package(source_name, child, package);
    }
}

fn inspect_dependency_table_for_package(source_name: &str, value: &toml::Value, package: &str) {
    let Some(table) = value.as_table() else {
        return;
    };

    for (dependency_name, spec) in table {
        assert_ne!(
            dependency_name, package,
            "{source_name} must not declare direct dependency {package:?}"
        );
        let package_override = spec
            .as_table()
            .and_then(|dependency| dependency.get("package"))
            .and_then(toml::Value::as_str);
        assert_ne!(
            package_override,
            Some(package),
            "{source_name} must not alias direct dependency package {package:?}"
        );
    }
}

fn assert_lockfile_has_no_package(source_name: &str, source: &str, package: &str) {
    let lockfile: toml::Value =
        toml::from_str(source).unwrap_or_else(|error| panic!("{source_name} must parse: {error}"));
    let packages = lockfile
        .get("package")
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{source_name} must contain package rows"));

    for row in packages {
        let name = row.get("name").and_then(toml::Value::as_str);
        assert_ne!(
            name,
            Some(package),
            "{source_name} must not lock package {package:?}"
        );
    }
}

fn is_non_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

#[test]
fn tracked_docs_define_the_minimum_maintainer_gate() {
    assert_all_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        REPAIRED_GATE_COMMANDS,
    );

    let installing_gate_commands: Vec<_> = REPAIRED_GATE_COMMANDS
        .iter()
        .copied()
        .filter(|command| !command.starts_with("typst compile "))
        .collect();
    assert_all_contains(
        "book/src/Installing-and-Building.md",
        INSTALLING_AND_BUILDING,
        &installing_gate_commands,
    );

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
        "require_tool cargo-audit \"cargo install cargo-audit --locked --version 0.22.1\"",
        "require_tool cargo-deny \"cargo install cargo-deny --locked --version 0.19.6\"",
        "require_tool mdbook \"cargo install mdbook --locked --version 0.5.3\"",
        "require_tool typst \"install Typst from https://typst.app/docs/install/ or your OS package manager\"",
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
        "run cargo test --locked -p dexios-domain --features test-support --test workflow_public_api --test archive_public_api --test cleanup_receipts --test transactions --test workflow_errors --release",
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
fn phase14_spec_alignment_and_release_gate_are_source_gated() {
    let spec_issues = spec_format_reference_alignment_issues(SPEC_FORMAT_REFERENCE);
    assert!(
        spec_issues.is_empty(),
        "spec/dexios-paper.typ must stay aligned to current source/docs; issues: {spec_issues:?}"
    );

    for stale_claim in [
        "The current V1 header length is `416` bytes.",
        "`--argon` selects `Argon2id` for new files.",
        "ZSTD compression is available but must be explicitly enabled.",
        "The packed payload is still just an encrypted `zip` archive.",
    ] {
        assert!(
            !spec_format_reference_alignment_issues(stale_claim).is_empty(),
            "spec source gate must reject stale claim: {stale_claim}"
        );
    }

    assert_all_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        &[
            "maintainer_gate:",
            "cargo install cargo-audit --locked --version 0.22.1",
            "cargo install cargo-deny --locked --version 0.19.6",
            "cargo install mdbook --locked",
            "bash scripts/verify_phase_gate.sh",
            "needs: maintainer_gate",
            "needs: build",
        ],
    );
    assert_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "validate_tag:",
        "maintainer_gate:",
    );
    assert_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "maintainer_gate:",
        "build:",
    );
    assert_occurs_before(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        "build:",
        "publish:",
    );
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
        "unpack_rejects_entry_that_aliases_encrypted_input_archive",
        "unpack_rejects_entry_that_aliases_detached_header",
    ] {
        assert_contains(
            "dexios-domain/tests/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_TESTS,
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
            "dexios-domain/tests/transactions.rs",
            DEXIOS_DOMAIN_TRANSACTION_TESTS,
            required,
        );
    }
    assert_contains(
        "dexios-domain/tests/transactions.rs",
        DEXIOS_DOMAIN_TRANSACTION_TESTS,
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
                    "dexios/tests/workflow_error_cli.rs",
                    DEXIOS_WORKFLOW_ERROR_CLI_TESTS,
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
        "run cargo test --locked -p dexios-domain --features test-support --test transactions --test cleanup_receipts --test detached_publication --release",
        "run cargo test --locked -p dexios --test encrypt_cli_regressions --test pack_cli_regressions --test delete_source_cli --test workflow_error_cli --test verification_gate_docs --release",
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
        "MutationFreshnessError::IdentityChanged",
        "MutationFreshnessError::ContentChanged",
        "Error::TargetChanged",
    ] {
        assert_contains("dexios-domain/src/key.rs", DEXIOS_DOMAIN_KEY_RS, required);
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
        "dexios-domain/tests/keyslots_v1.rs",
        DEXIOS_DOMAIN_KEYSLOTS_TESTS,
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
        "run cargo test --locked -p dexios-domain --test header_restore --test header_workflow_errors --test keyslots_v1 --test workflow_errors --release",
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
fn phase15_storage_identity_public_docs_are_source_gated() {
    let mut issues = phase15_safety_contract_issues(SAFETY_CONTRACT);
    issues.extend(phase15_public_docs_issues(&[
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
        ("book/src/technical-details/Secure-Erase.md", SECURE_ERASE),
    ]));

    assert!(
        issues.is_empty(),
        "Phase 15 storage identity docs must stay aligned to current source/tests; issues: {issues:?}"
    );
}

#[test]
fn phase15_docs_gate_rejects_stale_identity_and_cleanup_overclaims() {
    let stale_safety = "Path identity is implemented somewhere and cleanup is safe.";
    assert!(
        !phase15_safety_contract_issues(stale_safety).is_empty(),
        "Phase 15 Safety Contract gate must reject vague source evidence"
    );

    let overclaim = "Dexios has Windows/non-Unix parity for every path identity check. \
        Phase 16 cleanup authorization lets cleanup run after partial commit evidence. \
        This is a secure erase guarantee.";
    assert!(
        !phase15_platform_parity_issues(
            "synthetic Phase 15 overclaim",
            overclaim,
            &[DEXIOS_DOMAIN_IDENTITY_RS, DEXIOS_DOMAIN_PATH_IDENTITY_TESTS],
        )
        .is_empty(),
        "Phase 15 docs gate must reject unqualified platform parity claims"
    );
    assert!(
        !phase15_cleanup_authorization_issues("synthetic Phase 15 overclaim", overclaim).is_empty(),
        "Phase 15 docs gate must reject cleanup authorization and secure-erase overclaims"
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
        "run cargo test --locked --workspace --all-features --release --verbose",
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
    assert_not_contains("deny.toml", DENY_TOML, "getrandom@0.3.4");
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
fn security_policy_prefers_private_reporting_for_unpatched_vulnerabilities() {
    for (source_name, source) in [
        ("SECURITY.md", SECURITY_MD),
        ("book/src/Security-Policy.md", SECURITY_POLICY),
    ] {
        for required in [
            "private GitHub security advisory",
            "brxken128@tutanota.com",
            "Do not open a public issue for an unpatched vulnerability",
        ] {
            assert_contains(source_name, source, required);
        }
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
fn phase05_manifest_archive_and_cli_gate_is_source_gated() {
    let focused_commands = [
        "run cargo test --locked -p dexios-core --test stream_v1 --release",
        "run cargo test --locked -p dexios-core --test v1_header --release",
        "run cargo test --locked -p dexios-domain --test pack_paths --release",
        "run cargo test --locked -p dexios-domain --test unpack --release",
        "run cargo test --locked -p dexios-domain --test archive_public_api --release",
        "run cargo test --locked -p dexios-domain --test workflow_errors --all-features --release",
        "run cargo test --locked -p dexios --test pack_cli_regressions --release",
        "run cargo test --locked -p dexios --test unpack_cli_regressions --release",
        "run cargo test --locked -p dexios --test delete_source_cli --release",
        "run cargo test --locked -p dexios --test workflow_error_cli --release",
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
            "dexios-domain/tests/unpack.rs",
            DEXIOS_DOMAIN_UNPACK_TESTS,
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
        assert_contains(
            "docs/technical-details/Directory-Packing.html",
            GENERATED_DIRECTORY_PACKING,
            required.trim_matches('`'),
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
fn phase13_cli_output_and_decrypt_contract_is_source_gated() {
    assert_contains(
        "dexios/src/global.rs",
        DEXIOS_GLOBAL_RS,
        "eprintln!(\"[-] {}\", format!($($arg)*))",
    );
    assert_non_comment_line_count(
        "dexios/src/global.rs",
        DEXIOS_GLOBAL_RS,
        "println!(\"[-] {}\", format!($($arg)*))",
        0,
    );

    for required in [
        "generated_passphrase_secret(*i, |message| warn!(\"{message}\"))",
        "Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: ",
    ] {
        assert_contains("dexios/src/global/states.rs", DEXIOS_STATES_RS, required);
    }

    for required in [
        "encrypt_auto_generated_passphrase_disclosure_uses_stderr_not_stdout",
        "--auto=4",
        "output.stderr",
        "output.stdout",
        "Your generated passphrase is intentionally shown here",
    ] {
        assert_contains(
            "dexios/tests/encrypt_cli_regressions.rs",
            DEXIOS_ENCRYPT_CLI_REGRESSION_TESTS,
            required,
        );
    }

    for required in [
        "auto.stderr",
        "auto.stdout",
        "2> \"$dir/auto.stderr\"",
        "\"$dir/auto.stderr\"",
    ] {
        assert_contains(
            "scripts/verify_cli_surface.sh",
            VERIFY_CLI_SURFACE,
            required,
        );
    }
    assert_not_contains(
        "scripts/verify_cli_surface.sh",
        VERIFY_CLI_SURFACE,
        "auto_key=\"$(sed -n 's/^\\[-\\] Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: //p' \"$dir/auto.stdout\"",
    );

    for required in [
        "#[cfg(test)]\npub(crate) struct HandleRequest",
        "#[cfg(test)]\npub(crate) fn execute_handles",
        "_final_auth: V1FinalAuth",
    ] {
        assert_contains(
            "dexios-domain/src/decrypt.rs",
            DEXIOS_DOMAIN_DECRYPT_RS,
            required,
        );
    }

    let decrypt_section = normalized_rust_production_section(
        "dexios-domain/src/decrypt.rs",
        DEXIOS_DOMAIN_DECRYPT_RS,
        "fn execute_transactional_target",
        "pub(crate) fn read_v1_payload",
    );
    assert_normalized_section_order(
        "dexios-domain/src/decrypt.rs::execute_transactional_target",
        &decrypt_section,
        &[
            "StagedOutputTransaction::new",
            ".with_writer_result(",
            "decrypt_payload_with_master_key",
            "commit_after_final_auth(transaction, final_auth)",
        ],
    );

    for required in [
        "pub struct V1FinalAuth",
        "_private: ()",
        "Result<V1FinalAuth, StreamError>",
        "uncommitted scratch",
        "Ok(V1FinalAuth)",
    ] {
        assert_contains("dexios-core/src/stream.rs", DEXIOS_CORE_STREAM_RS, required);
    }
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
        "Dexios-owned manifest-first archive",
    );
    assert_corpus_contains(
        "archive documentation corpus",
        &archive_docs,
        "fixed archive policy",
    );
    for (source_name, source) in archive_docs {
        assert_not_contains(source_name, source, "archive compression policy");
        assert_not_contains(source_name, source, "current archive compression policy");
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

fn phase20_stale_current_product_claim_issues(source: &str) -> Vec<&'static str> {
    let normalized = source.replace('`', "").to_ascii_lowercase();
    let mut issues = Vec::new();

    for (needle, issue) in [
        (
            "416-byte canonical v1 header",
            "stale 416-byte header claim",
        ),
        (
            "current v1 header is 416",
            "stale current 416-byte header claim",
        ),
        ("first 32 bytes", "stale 32-byte payload AAD claim"),
        ("--argon", "stale Argon2id CLI selector claim"),
        (
            "argon2id is supported",
            "stale normal Argon2id support claim",
        ),
        (
            "normal argon2id support",
            "stale normal Argon2id support claim",
        ),
        (
            "encrypted zip archive",
            "stale encrypted ZIP archive format claim",
        ),
        (
            "temporary zip archive",
            "stale plaintext ZIP temporary-file claim",
        ),
        ("zstd", "stale archive compression claim"),
        (
            "compression selector",
            "stale archive compression selector claim",
        ),
    ] {
        if normalized.contains(needle) {
            issues.push(issue);
        }
    }

    issues
}

fn phase20_safety_limit_overclaim_issues(source: &str) -> Vec<&'static str> {
    let normalized = source.replace('`', "").to_ascii_lowercase();
    let mut issues = Vec::new();

    for (needle, issue) in [
        ("secure erase guarantee", "secure erase overclaim"),
        ("guarantees secure erase", "secure erase overclaim"),
        (
            "physical sanitization guarantee",
            "physical sanitization overclaim",
        ),
        (
            "guarantees physical sanitization",
            "physical sanitization overclaim",
        ),
        (
            "forensic recovery resistance",
            "forensic recovery overclaim",
        ),
        ("automatic rollback", "automatic rollback overclaim"),
        (
            "rollback committed outputs",
            "committed-output rollback overclaim",
        ),
        ("guaranteed recovery", "guaranteed recovery overclaim"),
        ("guarantee recovery", "guaranteed recovery overclaim"),
        (
            "cleanup authorized after partial detached publication",
            "partial detached cleanup overclaim",
        ),
        (
            "windows/non-unix parity",
            "unqualified Windows/non-Unix parity overclaim",
        ),
        ("non-unix parity", "unqualified non-Unix parity overclaim"),
        (
            "timestamp-only freshness",
            "timestamp-only freshness overclaim",
        ),
        ("mtime-only freshness", "timestamp-only freshness overclaim"),
        (
            "fully eliminated plaintext exposure",
            "unpack plaintext exposure overclaim",
        ),
        (
            "no plaintext exposure during unpack",
            "unpack plaintext exposure overclaim",
        ),
    ] {
        if normalized.contains(needle) {
            issues.push(issue);
        }
    }

    issues
}

fn phase20_release_metadata_overclaim_issues(source: &str) -> Vec<&'static str> {
    let normalized = source.replace('`', "").to_ascii_lowercase();
    let mut issues = Vec::new();

    for (needle, issue) in [
        (
            "guarantees bit-for-bit reproducibility",
            "reproducibility overclaim",
        ),
        ("guarantee signing trust", "signing-trust overclaim"),
        ("guarantees signing trust", "signing-trust overclaim"),
        (
            "guarantees sbom completeness",
            "SBOM completeness overclaim",
        ),
        ("guarantees sbom protection", "SBOM protection overclaim"),
        (
            "prevents supply-chain attacks",
            "supply-chain prevention overclaim",
        ),
        (
            "proves completed verification",
            "completed-verification overclaim",
        ),
        ("proves runtime safety", "runtime-safety overclaim"),
        (
            "complete platform asset set is enforced",
            "platform asset-set overclaim",
        ),
        (
            "full platform asset set is enforced",
            "platform asset-set overclaim",
        ),
        (
            "all release assets are present",
            "release asset-set overclaim",
        ),
        (
            "phase 20 enforces platform assets",
            "Phase 21 asset-enforcement overclaim",
        ),
    ] {
        if normalized.contains(needle) {
            issues.push(issue);
        }
    }

    issues
}

fn phase20_pdf_policy_overclaim_issues(source: &str) -> Vec<&'static str> {
    let normalized = source.replace('`', "").to_ascii_lowercase();
    let mut issues = Vec::new();

    for (needle, issue) in [
        (
            "spec/specification-v1.pdf is current release-critical authority",
            "binary-only historical PDF treated as current authority",
        ),
        (
            "specification-v1.pdf is source-backed current spec",
            "binary-only historical PDF treated as source-backed current spec",
        ),
        (
            "generated pdf text is hand-edited truth",
            "generated PDF text treated as hand-edited truth",
        ),
        (
            "manual edits to spec/dexios-paper.pdf are release evidence",
            "manual PDF edits treated as release evidence",
        ),
    ] {
        if normalized.contains(needle) {
            issues.push(issue);
        }
    }

    issues
}

#[test]
fn phase20_canonical_public_facts_are_source_gated() {
    let required_by_source: &[(&str, &str, &[&str])] = &[
        (
            "README.md",
            README,
            &[
                "512-byte canonical V1 header",
                "BLAKE3-Balloon",
                "historical Argon2id tag",
                "not canonical V1 archive format surface",
            ],
        ),
        (
            "book/src/dexios-core/Headers.md",
            HEADERS,
            &[
                "512-byte canonical V1 header",
                "64-byte immutable static header",
                "payload AAD covers the 64-byte immutable static header",
                "112-byte physical keyslot",
                "BLAKE3-Balloon",
                "historical Argon2id tag",
            ],
        ),
        (
            "book/src/dexios-core/Encryption.md",
            ENCRYPTION,
            &[
                "payload AAD covers the 64-byte immutable static header",
                "slot-scoped AAD",
                "manifest-first archive framing",
                "ordered `DXBF` body frames",
                "not canonical V1 archive format surface",
            ],
        ),
        (
            "book/src/dexios-core/Password-Hashing.md",
            PASSWORD_HASHING,
            &[
                "BLAKE3-Balloon",
                "historical Argon2id tag",
                "unsupported metadata",
                "not a normal write policy",
            ],
        ),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
            &[
                "DXAR",
                "DXBF",
                "not canonical V1 archive format surface",
                "Compression is not user-configurable",
                "no full plaintext archive temporary file",
            ],
        ),
        (
            "spec/dexios-paper.typ",
            SPEC_FORMAT_REFERENCE,
            &[
                "512-byte canonical V1 header",
                "64-byte immutable static header",
                "payload AAD covers the 64-byte immutable static header",
                "112-byte physical keyslot",
                "BLAKE3-Balloon",
                "historical Argon2id tag",
                "DXAR",
                "DXBF",
                "not canonical V1 archive format surface",
                "source tree and mdBook safety contract remain the authority",
            ],
        ),
    ];

    for (source_name, source, required) in required_by_source {
        assert_all_contains(source_name, source, required);
    }

    for (source_name, source, _) in required_by_source {
        for forbidden in [
            "416-byte canonical V1 header",
            "current V1 header is 416",
            "first 32 bytes",
            "--argon",
            "Argon2id is supported",
            "normal Argon2id support",
            "encrypted `zip` archive",
            "temporary `zip` archive",
            "ZSTD",
        ] {
            assert_not_contains(source_name, source, forbidden);
        }
    }
}

#[test]
fn phase20_docs_gate_rejects_stale_current_product_claims() {
    for stale_claim in [
        "Current V1 uses a 416-byte canonical V1 header.",
        "Payload AAD covers the first 32 bytes of the header.",
        "`--argon` selects Argon2id for normal encryption.",
        "Argon2id is supported as a normal KDF.",
        "Dexios stores an encrypted ZIP archive as its canonical archive format.",
        "ZSTD compression selector controls archive compression.",
        "Pack creates a temporary ZIP archive before encryption.",
    ] {
        assert!(
            !phase20_stale_current_product_claim_issues(stale_claim).is_empty(),
            "Phase 20 stale-claim gate must reject: {stale_claim}"
        );
    }
}

#[test]
fn phase20_safety_limit_docs_are_source_gated() {
    for (source_name, source) in [
        ("SECURITY.md", SECURITY_MD),
        ("book/src/Security-Policy.md", SECURITY_POLICY),
    ] {
        for required in [
            "detached payload/header partial publication diagnostics and cleanup denial",
            "delete-after-success cleanup authority",
            "source replacement or changed source tree refusal",
            "temporary artifact lifecycle behavior",
        ] {
            assert_contains(source_name, source, required);
        }
    }

    assert_all_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        &[
            "delete-after-success and secure erase wording",
            "ordinary delete-after-success only",
            "complete commit and requested hash success",
            "no secure erase",
            "no physical sanitization",
            "pair-aware detached publication",
            "source cleanup is denied after partial detached publication",
            "non-Unix behavior is limited by platform identity APIs and available tests",
        ],
    );

    assert_all_contains(
        "book/src/technical-details/Secure-Erase.md",
        SECURE_ERASE,
        &[
            "ordinary delete-after-success cleanup",
            "processed-source cleanup evidence",
            "complete commit",
            "requested hash",
            "final-auth evidence",
            "cleanup-refusal conditions",
            "changed source tree",
            "source data is preserved",
            "committed outputs are not rolled back",
            "no secure erase",
            "no physical sanitization",
            "Partial detached publication reports the committed and failed artifact state",
            "source cleanup is denied after partial detached publication",
            "does not roll back committed artifacts",
            "guarantee recovery",
        ],
    );

    assert_all_contains(
        "book/src/technical-details/Directory-Packing.md",
        DIRECTORY_PACKING,
        &[
            "reject final symlinks",
            "symlinked parent prefixes",
            "aliases",
            "non-Unix behavior is limited by platform identity APIs and available tests",
            "not a sandbox",
            "selected staged file bodies",
            "ordinary filesystem temporary/staged files",
            "committed file artifacts are not rolled back",
        ],
    );

    assert_all_contains(
        "book/src/technical-details/Keys.md",
        KEYS,
        &[
            "does not use filesystem locks",
            "does not add recovery",
            "rollback",
            "secure erase",
        ],
    );

    assert_all_contains(
        "book/src/technical-details/Performance-Notes.md",
        PERFORMANCE_NOTES,
        &[
            "Structural archive limits are not proof that the host has enough free memory or disk space",
            "Capacity and temp-space measurements are best-effort release evidence",
            "do not prove that unpack plaintext exposure is eliminated",
        ],
    );
}

#[test]
fn phase20_safety_limit_gate_rejects_stale_overclaims() {
    for stale_claim in [
        "Dexios gives a secure erase guarantee for deleted inputs.",
        "Delete-after-success guarantees physical sanitization.",
        "Temporary cleanup provides forensic recovery resistance.",
        "Detached mode performs automatic rollback after partial publication.",
        "Dexios will rollback committed outputs when cleanup fails.",
        "Partial detached publication has guaranteed recovery.",
        "Cleanup authorized after partial detached publication.",
        "The path identity policy has Windows/non-Unix parity.",
        "Mutation freshness can rely on timestamp-only freshness.",
        "Unpack has fully eliminated plaintext exposure.",
        "There is no plaintext exposure during unpack.",
    ] {
        assert!(
            !phase20_safety_limit_overclaim_issues(stale_claim).is_empty(),
            "Phase 20 safety-limit gate must reject: {stale_claim}"
        );
    }
}

#[test]
fn phase20_release_metadata_boundaries_are_source_gated() {
    assert_all_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        &[
            "## Verification Command Contract",
            "does not prove that the commands completed successfully",
            "## Assets",
            "- name: `%s`",
            "- SHA256: `%s`",
            "Asset entries record only files passed with `--asset` by basename and SHA256.",
            "This manifest does not claim a complete platform asset set; Phase 21 owns full expected asset-set enforcement and publishing gates.",
            "## Claim Limits",
            "does not claim bit-for-bit reproducibility, signing trust, SBOM completeness, SBOM protection, supply-chain prevention, completed verification, or runtime safety beyond separately completed gate results",
        ],
    );

    assert_all_contains(
        "README.md",
        README,
        &[
            "release manifest wording lives in `scripts/generate_release_manifest.sh`",
            "source-backed docs/spec locations",
            "does not claim a complete platform asset set",
        ],
    );

    assert_all_contains(
        "CHANGELOG.md",
        CHANGELOG,
        &[
            "Docs, Spec, and Generated Artifact Fidelity",
            "canonical V1 fact reconciliation",
            "PDF/generated artifact policy",
            "source gates",
            "ordinary delete-after-success cleanup",
            "no secure erase",
            "no physical sanitization",
            "does not claim a complete platform asset set",
        ],
    );

    assert_all_contains(
        ".github/workflows/release.yml",
        RELEASE_WORKFLOW,
        &[
            "asset_name=\"dexios-${GITHUB_REF_NAME}-${{ matrix.asset_suffix }}${{ matrix.asset_ext }}\"",
            "asset_suffix: linux-amd64",
            "asset_suffix: macos-amd64",
            "asset_suffix: windows-amd64",
            "asset_ext: \".exe\"",
        ],
    );

    for (source_name, source) in [
        ("README.md", README),
        ("CHANGELOG.md", CHANGELOG),
        (
            "scripts/generate_release_manifest.sh",
            GENERATE_RELEASE_MANIFEST,
        ),
    ] {
        assert_no_release_overclaim_patterns(source_name, source);
        let issues = phase20_release_metadata_overclaim_issues(source);
        assert!(
            issues.is_empty(),
            "{source_name} must not overclaim release metadata boundaries; issues: {issues:?}"
        );
    }
}

#[test]
fn phase20_pdf_authority_policy_is_source_gated() {
    assert_all_contains(
        "README.md",
        README,
        &[
            "the whitepaper-style format source lives in `spec/dexios-paper.typ`",
            "the current PDF `spec/dexios-paper.pdf` is generated from that Typst source",
            "typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
            "`spec/specification-v1.pdf` is historical comparison input only, not current release-critical authority",
        ],
    );

    assert_all_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        &[
            "spec source and PDF artifacts",
            "`spec/dexios-paper.typ` is the current source-backed whitepaper source",
            "`spec/dexios-paper.pdf` is generated output from that Typst source",
            "`spec/specification-v1.pdf` is historical comparison input only, not current release-critical authority",
            "typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
            "git diff --exit-code -- spec/dexios-paper.pdf",
            "Generated PDF text is not hand-edited truth",
            "manual edits to `spec/dexios-paper.pdf` are not release evidence",
        ],
    );

    for (source_name, source) in [
        ("README.md", README),
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
    ] {
        let issues = phase20_pdf_policy_overclaim_issues(source);
        assert!(
            issues.is_empty(),
            "{source_name} must not overclaim PDF artifact policy; issues: {issues:?}"
        );
    }
}

#[test]
fn phase20_pdf_freshness_commands_are_source_gated() {
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
        1,
    );
    assert_non_comment_line_count(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run git diff --exit-code -- spec/dexios-paper.pdf",
        1,
    );
    assert_non_comment_line_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
        "run git diff --exit-code -- spec/dexios-paper.pdf",
    );
    assert_non_comment_line_occurs_before(
        "scripts/verify_phase_gate.sh",
        VERIFY_PHASE_GATE,
        "run git diff --exit-code -- docs",
        "run typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
    );

    assert_all_contains(
        "scripts/generate_release_manifest.sh",
        GENERATE_RELEASE_MANIFEST,
        &[
            "typst --version",
            "typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
            "git diff --exit-code -- spec/dexios-paper.pdf",
            "The verification command section records the required command contract. It is\nnot a pass/fail log for those commands.",
        ],
    );

    {
        let (source_name, source) = (
            "scripts/generate_release_manifest.sh",
            GENERATE_RELEASE_MANIFEST,
        );
        let issues = phase20_pdf_policy_overclaim_issues(source);
        assert!(
            issues.is_empty(),
            "{source_name} must not overclaim PDF artifact policy; issues: {issues:?}"
        );
    }
}

#[test]
fn phase20_pdf_policy_gate_rejects_stale_authority_claims() {
    for stale_claim in [
        "spec/specification-v1.pdf is current release-critical authority.",
        "specification-v1.pdf is source-backed current spec.",
        "Generated PDF text is hand-edited truth.",
        "Manual edits to spec/dexios-paper.pdf are release evidence.",
    ] {
        assert!(
            !phase20_pdf_policy_overclaim_issues(stale_claim).is_empty(),
            "Phase 20 PDF policy gate must reject: {stale_claim}"
        );
    }
}

#[test]
fn phase20_release_metadata_gate_rejects_positive_overclaims() {
    for stale_claim in [
        "Dexios guarantees bit-for-bit reproducibility for release assets.",
        "Release artifacts guarantee signing trust.",
        "Dexios guarantees SBOM completeness.",
        "The manifest guarantees SBOM protection.",
        "The release process prevents supply-chain attacks.",
        "The manifest proves completed verification.",
        "The manifest proves runtime safety.",
        "The complete platform asset set is enforced in Phase 20.",
        "All release assets are present.",
    ] {
        assert!(
            !phase20_release_metadata_overclaim_issues(stale_claim).is_empty(),
            "Phase 20 release metadata gate must reject: {stale_claim}"
        );
    }
}

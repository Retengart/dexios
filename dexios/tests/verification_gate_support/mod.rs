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
        clippy::allow_attributes,
        clippy::redundant_pub_crate,
        reason = "shared gate helpers assert exact behavior and may panic on failure"
    )
)]
#![allow(
    dead_code,
    reason = "shared gate helpers are used selectively across gate modules"
)]

use std::borrow::Cow;
use std::process::Command;

pub(crate) const SAFETY_CONTRACT: &str = include_str!("../../../book/src/Safety-Contract.md");
pub(crate) const CONTRIBUTING: &str = include_str!("../../../CONTRIBUTING.md");
pub(crate) const README: &str = include_str!("../../../README.md");
pub(crate) const CLI_README: &str = include_str!("../../../dexios/README.md");
pub(crate) const SPEC_FORMAT_REFERENCE: &str = include_str!("../../../spec/dexios-paper.typ");
pub(crate) const USAGE_EXAMPLES: &str = include_str!("../../../book/src/Usage-Examples.md");
pub(crate) const DIRECTORY_PACKING: &str =
    include_str!("../../../book/src/technical-details/Directory-Packing.md");
pub(crate) const SECURE_ERASE: &str =
    include_str!("../../../book/src/technical-details/Secure-Erase.md");
pub(crate) const INSTALLING_AND_BUILDING: &str =
    include_str!("../../../book/src/Installing-and-Building.md");
pub(crate) const AUDITING: &str = include_str!("../../../book/src/dexios-core/Auditing.md");
pub(crate) const HEADERS: &str = include_str!("../../../book/src/dexios-core/Headers.md");
pub(crate) const ENCRYPTION: &str = include_str!("../../../book/src/dexios-core/Encryption.md");
pub(crate) const PASSWORD_HASHING: &str =
    include_str!("../../../book/src/dexios-core/Password-Hashing.md");
pub(crate) const PROTECTED_WRAPPER: &str =
    include_str!("../../../book/src/dexios-core/Protected-Wrapper.md");
pub(crate) const KEYS: &str = include_str!("../../../book/src/technical-details/Keys.md");
pub(crate) const SECURITY_MD: &str = include_str!("../../../SECURITY.md");
pub(crate) const SECURITY_POLICY: &str = include_str!("../../../book/src/Security-Policy.md");
pub(crate) const CHANGELOG: &str = include_str!("../../../CHANGELOG.md");
pub(crate) const CARGO_TOML: &str = include_str!("../../../Cargo.toml");
pub(crate) const CARGO_LOCK: &str = include_str!("../../../Cargo.lock");
pub(crate) const FLAKE_LOCK: &str = include_str!("../../../flake.lock");
pub(crate) const DEXIOS_DOMAIN_CARGO_TOML: &str = include_str!("../../../dexios-domain/Cargo.toml");
pub(crate) const DEXIOS_CARGO_TOML: &str = include_str!("../../../dexios/Cargo.toml");
pub(crate) const GITIGNORE: &str = include_str!("../../../.gitignore");
pub(crate) const GITATTRIBUTES: &str = include_str!("../../../.gitattributes");
pub(crate) const DENY_TOML: &str = include_str!("../../../deny.toml");
pub(crate) const VERIFY_PHASE_GATE: &str = include_str!("../../../scripts/verify_phase_gate.sh");
pub(crate) const VERIFY_ASSURANCE_REPLAY: &str =
    include_str!("../../../scripts/verify_assurance_replay.sh");
pub(crate) const VERIFY_CLI_SURFACE: &str = include_str!("../../../scripts/verify_cli_surface.sh");
pub(crate) const VERIFY_REPO_HYGIENE: &str =
    include_str!("../../../scripts/verify_repo_hygiene.sh");
pub(crate) const MEASURE_PERFORMANCE_GATE: &str =
    include_str!("../../../scripts/measure_performance_gate.sh");
pub(crate) const GENERATE_RELEASE_MANIFEST: &str =
    include_str!("../../../scripts/generate_release_manifest.sh");
pub(crate) const DEXIOS_CORE_STREAM_V1_TESTS: &str =
    include_str!("../../../dexios-core/tests/stream_v1.rs");
pub(crate) const DEXIOS_CORE_V1_HEADER_TESTS: &str =
    include_str!("../../../dexios-core/tests/v1_header.rs");
pub(crate) const DEXIOS_DOMAIN_DECRYPT_WORKFLOW_ERROR_TESTS: &str =
    include_str!("../../../dexios-domain/tests/decrypt_workflow_errors.rs");
pub(crate) const DEXIOS_DOMAIN_PACK_PATHS_TESTS: &str =
    include_str!("../../../dexios-domain/tests/pack_paths.rs");
pub(crate) const DEXIOS_DOMAIN_UNPACK_MANIFEST_TESTS: &str =
    include_str!("../../../dexios-domain/tests/unpack_manifest_v1.rs");
pub(crate) const DEXIOS_DOMAIN_UNPACK_PATH_IDENTITY_TESTS: &str =
    include_str!("../../../dexios-domain/tests/unpack_path_identity.rs");
pub(crate) const DEXIOS_DOMAIN_UNPACK_COMMIT_ROLLBACK_TESTS: &str =
    include_str!("../../../dexios-domain/tests/unpack_commit_rollback.rs");
pub(crate) const DEXIOS_DOMAIN_UNPACK_SYMLINK_REVALIDATION_TESTS: &str =
    include_str!("../../../dexios-domain/tests/unpack_symlink_revalidation.rs");
pub(crate) const DEXIOS_DOMAIN_UNPACK_SUPPORT: &str =
    include_str!("../../../dexios-domain/tests/support/unpack_v1.rs");
pub(crate) const DEXIOS_ENCRYPT_CLI_REGRESSION_TESTS: &str =
    include_str!("../encrypt_cli_regressions.rs");
pub(crate) const DEXIOS_PACK_CLI_REGRESSION_TESTS: &str =
    include_str!("../pack_cli_regressions.rs");
pub(crate) const DEXIOS_DECRYPT_CLI_REGRESSION_TESTS: &str =
    include_str!("../decrypt_cli_regressions.rs");
pub(crate) const DEXIOS_UNPACK_CLI_REGRESSION_TESTS: &str =
    include_str!("../unpack_cli_regressions.rs");
pub(crate) const DEXIOS_DELETE_SOURCE_CLI_TESTS: &str = include_str!("../delete_source_cli.rs");
pub(crate) const DEXIOS_CORE_FIXTURE_MANIFEST: &str =
    include_str!("../../../dexios-core/tests/testdata/fixture_manifest.toml");
pub(crate) const DEXIOS_DOMAIN_FIXTURE_MANIFEST: &str =
    include_str!("../../../dexios-domain/tests/fixture_manifest.toml");
pub(crate) const DEXIOS_CLI_FIXTURE_MANIFEST: &str = include_str!("../fixture_manifest.toml");
pub(crate) const DEXIOS_MAIN_RS: &str = include_str!("../../src/main.rs");
pub(crate) const DEXIOS_CLI_RS: &str = include_str!("../../src/cli.rs");
pub(crate) const DEXIOS_CLI_ARGS_RS: &str = include_str!("../../src/cli/args.rs");
pub(crate) const DEXIOS_CLI_TESTS_RS: &str = include_str!("../../src/cli/tests.rs");
pub(crate) const DEXIOS_CLI_COMMANDS_STREAM_RS: &str =
    include_str!("../../src/cli/commands/stream.rs");
pub(crate) const DEXIOS_CLI_COMMANDS_ARCHIVE_RS: &str =
    include_str!("../../src/cli/commands/archive.rs");
pub(crate) const DEXIOS_CLI_COMMANDS_HASH_RS: &str = include_str!("../../src/cli/commands/hash.rs");
pub(crate) const DEXIOS_CLI_COMMANDS_KEY_RS: &str = include_str!("../../src/cli/commands/key.rs");
pub(crate) const DEXIOS_CLI_COMMANDS_HEADER_RS: &str =
    include_str!("../../src/cli/commands/header.rs");
pub(crate) const DEXIOS_GLOBAL_RS: &str = include_str!("../../src/global.rs");
pub(crate) const DEXIOS_PARAMETERS_RS: &str = include_str!("../../src/global/parameters.rs");
pub(crate) const DEXIOS_STATES_RS: &str = include_str!("../../src/global/states.rs");
pub(crate) const DEXIOS_ENCRYPT_RS: &str = include_str!("../../src/subcommands/encrypt.rs");
pub(crate) const DEXIOS_DECRYPT_RS: &str = include_str!("../../src/subcommands/decrypt.rs");
pub(crate) const DEXIOS_UNPACK_RS: &str = include_str!("../../src/subcommands/unpack.rs");
pub(crate) const DEXIOS_SUBCOMMAND_ERRORS_RS: &str =
    include_str!("../../src/subcommands/errors.rs");
pub(crate) const DEXIOS_CORE_LIB_RS: &str = include_str!("../../../dexios-core/src/lib.rs");
pub(crate) const DEXIOS_CORE_KEY_RS: &str = include_str!("../../../dexios-core/src/key.rs");
pub(crate) const DEXIOS_CORE_PROTECTED_RS: &str =
    include_str!("../../../dexios-core/src/protected.rs");
pub(crate) const DEXIOS_CORE_STREAM_RS: &str = include_str!("../../../dexios-core/src/stream.rs");
pub(crate) const DEXIOS_DOMAIN_LIB_RS: &str = include_str!("../../../dexios-domain/src/lib.rs");
pub(crate) const DEXIOS_DOMAIN_WORKFLOW_ERROR_RS: &str =
    include_str!("../../../dexios-domain/src/workflow_error.rs");
pub(crate) const DEXIOS_DOMAIN_ARCHIVE_RS: &str =
    include_str!("../../../dexios-domain/src/archive.rs");
pub(crate) const DEXIOS_DOMAIN_ENCRYPT_RS: &str =
    include_str!("../../../dexios-domain/src/encrypt.rs");
pub(crate) const DEXIOS_DOMAIN_PACK_RS: &str = include_str!("../../../dexios-domain/src/pack.rs");
pub(crate) const DEXIOS_DOMAIN_DECRYPT_RS: &str =
    include_str!("../../../dexios-domain/src/decrypt.rs");
pub(crate) const DEXIOS_DOMAIN_UNPACK_RS: &str =
    include_str!("../../../dexios-domain/src/unpack.rs");
pub(crate) const DEXIOS_DOMAIN_IDENTITY_RS: &str =
    include_str!("../../../dexios-domain/src/storage/identity.rs");
pub(crate) const DEXIOS_DOMAIN_STORAGE_RS: &str =
    include_str!("../../../dexios-domain/src/storage/mod.rs");
pub(crate) const DEXIOS_DOMAIN_STORAGE_FS_RS: &str =
    include_str!("../../../dexios-domain/src/storage/fs.rs");
pub(crate) const DEXIOS_DOMAIN_MUTATION_RS: &str =
    include_str!("../../../dexios-domain/src/storage/mutation.rs");
pub(crate) const DEXIOS_DOMAIN_CLEANUP_RS: &str =
    include_str!("../../../dexios-domain/src/storage/cleanup.rs");
pub(crate) const DEXIOS_DOMAIN_TRANSACTION_RS: &str =
    include_str!("../../../dexios-domain/src/storage/transaction.rs");
pub(crate) const DEXIOS_DOMAIN_TEMP_RS: &str =
    include_str!("../../../dexios-domain/src/storage/temp.rs");
pub(crate) const DEXIOS_DOMAIN_HEADER_RS: &str =
    include_str!("../../../dexios-domain/src/header.rs");
pub(crate) const DEXIOS_DOMAIN_HEADER_DUMP_RS: &str =
    include_str!("../../../dexios-domain/src/header/dump.rs");
pub(crate) const DEXIOS_DOMAIN_HEADER_STRIP_RS: &str =
    include_str!("../../../dexios-domain/src/header/strip.rs");
pub(crate) const DEXIOS_DOMAIN_HEADER_RESTORE_RS: &str =
    include_str!("../../../dexios-domain/src/header/restore.rs");
pub(crate) const DEXIOS_DOMAIN_KEY_RS: &str = include_str!("../../../dexios-domain/src/key.rs");
pub(crate) const DEXIOS_DOMAIN_KEY_ADD_RS: &str =
    include_str!("../../../dexios-domain/src/key/add.rs");
pub(crate) const DEXIOS_DOMAIN_KEY_CHANGE_RS: &str =
    include_str!("../../../dexios-domain/src/key/change.rs");
pub(crate) const DEXIOS_DOMAIN_KEY_DELETE_RS: &str =
    include_str!("../../../dexios-domain/src/key/delete.rs");
pub(crate) const DEXIOS_DOMAIN_PATH_IDENTITY_TESTS: &str =
    include_str!("../../../dexios-domain/tests/path_identity.rs");
pub(crate) const DEXIOS_DOMAIN_TRANSACTIONS_STAGED_OUTPUT_TESTS: &str =
    include_str!("../../../dexios-domain/tests/transactions_staged_output.rs");
pub(crate) const DEXIOS_DOMAIN_TRANSACTIONS_LINKED_PUBLICATION_TESTS: &str =
    include_str!("../../../dexios-domain/tests/transactions_linked_publication.rs");
pub(crate) const DEXIOS_DOMAIN_TRANSACTIONS_FAILURE_HOOKS_TESTS: &str =
    include_str!("../../../dexios-domain/tests/transactions_failure_hooks.rs");
pub(crate) const DEXIOS_DOMAIN_HEADER_RESTORE_TESTS: &str =
    include_str!("../../../dexios-domain/tests/header_restore.rs");
pub(crate) const DEXIOS_DOMAIN_KEYSLOTS_INTENT_TESTS: &str =
    include_str!("../../../dexios-domain/tests/keyslots_intent_v1.rs");
pub(crate) const DEXIOS_DOMAIN_KEYSLOTS_CRYPTO_TESTS: &str =
    include_str!("../../../dexios-domain/tests/keyslots_crypto_v1.rs");
pub(crate) const DEXIOS_DOMAIN_KEYSLOTS_MUTATION_TESTS: &str =
    include_str!("../../../dexios-domain/tests/keyslots_mutation_v1.rs");
pub(crate) const DEXIOS_DOMAIN_KEYSLOTS_SUPPORT: &str =
    include_str!("../../../dexios-domain/tests/support/keyslots_v1.rs");
pub(crate) const DEXIOS_DOMAIN_CLEANUP_RECEIPTS_TESTS: &str =
    include_str!("../../../dexios-domain/tests/cleanup_receipts.rs");
pub(crate) const DEXIOS_DOMAIN_DETACHED_PUBLICATION_TESTS: &str =
    include_str!("../../../dexios-domain/tests/detached_publication.rs");
pub(crate) const DEXIOS_DOMAIN_WORKFLOW_ERROR_TESTS: &str =
    include_str!("../../../dexios-domain/tests/workflow_errors.rs");
pub(crate) const DEXIOS_DOMAIN_WORKFLOW_PUBLIC_API_TESTS: &str =
    include_str!("../../../dexios-domain/tests/workflow_public_api.rs");
pub(crate) const DEXIOS_DOMAIN_ARCHIVE_PUBLIC_API_TESTS: &str =
    include_str!("../../../dexios-domain/tests/archive_public_api.rs");
pub(crate) const DEXIOS_WORKFLOW_ERROR_CLI_BOUNDARY_TESTS: &str =
    include_str!("../workflow_error_cli_boundary.rs");
pub(crate) const DEXIOS_WORKFLOW_ERROR_CLI_ARCHIVE_TESTS: &str =
    include_str!("../workflow_error_cli_archive.rs");
pub(crate) const DEXIOS_WORKFLOW_ERROR_CLI_HEADER_KEY_TESTS: &str =
    include_str!("../workflow_error_cli_header_key.rs");
pub(crate) const DEXIOS_WORKFLOW_ERROR_CLI_SUPPORT: &str =
    include_str!("../support/workflow_error_cli.rs");
pub(crate) const DEXIOS_HEADER_CLI_REGRESSION_TESTS: &str =
    include_str!("../header_cli_regressions.rs");
pub(crate) const DEXIOS_KEY_CLI_REGRESSION_TESTS: &str = include_str!("../key_cli_regressions.rs");
pub(crate) const DEXIOS_SUBCOMMANDS_RS: &str = include_str!("../../src/subcommands.rs");
pub(crate) const DEXIOS_PACK_RS: &str = include_str!("../../src/subcommands/pack.rs");
pub(crate) const AUDIT_WORKFLOW: &str = include_str!("../../../.github/workflows/audit.yml");
pub(crate) const BUILD_NIX_WORKFLOW: &str =
    include_str!("../../../.github/workflows/build_nix.yml");
pub(crate) const CARGO_BUILD_WORKFLOW: &str =
    include_str!("../../../.github/workflows/cargo-build.yml");
pub(crate) const CLI_SURFACE_WORKFLOW: &str =
    include_str!("../../../.github/workflows/cli-surface.yml");
pub(crate) const DOCS_WORKFLOW: &str = include_str!("../../../.github/workflows/docs.yml");
pub(crate) const DEXIOS_TESTS_WORKFLOW: &str =
    include_str!("../../../.github/workflows/dexios-tests.yml");
pub(crate) const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
pub(crate) const UNIT_TESTS_WORKFLOW: &str =
    include_str!("../../../.github/workflows/unit_tests.yml");
pub(crate) const PERFORMANCE_NOTES: &str =
    include_str!("../../../book/src/technical-details/Performance-Notes.md");
pub(crate) const RC_CLOSEOUT: &str = include_str!("../../../release-evidence/RC-CLOSEOUT.md");
pub(crate) const SIGN_AND_ATTEST_ACTION: &str =
    include_str!("../../../.github/actions/sign-and-attest/action.yml");
pub(crate) const SIGNING_MD: &str = include_str!("../../../SIGNING.md");

pub(crate) const REPAIRED_GATE_COMMANDS: &[&str] = &[
    "cargo metadata --format-version=1 --locked --no-deps",
    "cargo fmt --all --check",
    "cargo clippy --workspace --all-targets --all-features --no-deps --locked",
    "cargo test --locked --workspace --all-features --release --verbose",
    "cargo audit --deny warnings",
    "cargo deny check",
    "cargo build --locked -p dexios --profile release",
    "bash scripts/verify_cli_surface.sh",
    "mdbook build --dest-dir target/mdbook",
    "typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf",
    "git diff --exit-code -- spec/dexios-paper.pdf",
    "bash scripts/verify_repo_hygiene.sh",
    "git diff --check",
    "bash scripts/generate_release_manifest.sh --output target/release-evidence/release-manifest.md --asset target/release/dexios",
];

pub(crate) const ASSURANCE_REPLAY_COMMANDS: &[&str] = &[
    "cargo test --locked --offline -p dexios-core --test v1_header --release",
    "cargo test --locked --offline -p dexios-core --test stream_v1 --release",
    "cargo test --locked --offline -p dexios-core --test key_derivation --release",
    "cargo test --locked --offline -p dexios-domain --test keyslots_intent_v1 --test keyslots_crypto_v1 --test keyslots_mutation_v1 --release",
    "cargo test --locked --offline -p dexios-domain --test decrypt_workflow_errors --release",
    "cargo test --locked --offline -p dexios-domain --features test-support --test unpack_manifest_v1 --test unpack_path_identity --test unpack_commit_rollback --test unpack_symlink_revalidation --release",
    "cargo test --locked --offline -p dexios --test decrypt_cli_regressions --release",
    "cargo test --locked --offline -p dexios --test unpack_cli_regressions --release",
];

pub(crate) const ASSURANCE_REPLAY_FORBIDDEN_NON_COMMENT_TOKENS: &[&str] = &[
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

pub(crate) const EXPLORATORY_TOOL_TOKENS: &[&str] =
    &["cargo fuzz", "miri", "kani", "tarpaulin", "grcov", "stress"];

pub(crate) fn assert_contains(source_name: &str, source: &str, needle: &str) {
    let source = normalized_line_endings(source);
    assert!(
        source.contains(needle),
        "{source_name} must contain {needle:?}"
    );
}

pub(crate) fn assert_not_contains(source_name: &str, source: &str, needle: &str) {
    let source = normalized_line_endings(source);
    assert!(
        !source.contains(needle),
        "{source_name} must not contain {needle:?}"
    );
}

pub(crate) fn normalized_line_endings(source: &str) -> Cow<'_, str> {
    if source.contains('\r') {
        Cow::Owned(source.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(source)
    }
}

pub(crate) fn bash_command() -> Command {
    #[cfg(windows)]
    {
        let git_bash = r"C:\Program Files\Git\bin\bash.exe";
        if std::path::Path::new(git_bash).exists() {
            return Command::new(git_bash);
        }
    }

    Command::new("bash")
}

pub(crate) fn assert_action_pin(source_name: &str, source: &str, action: &str, sha: &str) {
    assert_eq!(sha.len(), 40, "expected full SHA for {action}");
    assert!(
        sha.chars().all(|ch| ch.is_ascii_hexdigit()),
        "expected lowercase/uppercase hex SHA for {action}: {sha}"
    );
    assert_contains(source_name, source, &format!("uses: {action}@{sha}"));
}

pub(crate) fn assert_external_actions_are_full_sha_pinned(source_name: &str, source: &str) {
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

pub(crate) fn assert_checkout_steps_disable_persist_credentials(source_name: &str, source: &str) {
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

pub(crate) fn assert_workflow_default_read_permissions(source_name: &str, source: &str) {
    assert_contains(source_name, source, "\npermissions:\n  contents: read\n");
}

pub(crate) fn assert_no_release_overclaim_patterns(source_name: &str, source: &str) {
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

pub(crate) fn spec_format_reference_alignment_issues(source: &str) -> Vec<&'static str> {
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
        ("Argon2id", "missing current Argon2id write policy"),
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

pub(crate) fn phase15_safety_contract_issues(source: &str) -> Vec<&'static str> {
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
            "dexios-domain/tests/unpack_path_identity.rs",
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

pub(crate) fn phase15_public_docs_issues(sources: &[(&str, &str)]) -> Vec<&'static str> {
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

pub(crate) fn phase15_platform_parity_issues(
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

pub(crate) fn phase15_cleanup_authorization_issues(
    _source_name: &str,
    source: &str,
) -> Vec<&'static str> {
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

pub(crate) fn assert_all_contains(source_name: &str, source: &str, needles: &[&str]) {
    for needle in needles {
        assert_contains(source_name, source, needle);
    }
}

pub(crate) fn assert_non_comment_lines_exclude(
    source_name: &str,
    source: &str,
    forbidden: &[&str],
) {
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

pub(crate) fn normalized_rust_production_source(source: &str) -> String {
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

pub(crate) fn normalized_rust_production_section(
    source_name: &str,
    source: &str,
    start: &str,
    end: &str,
) -> String {
    let start_index = source
        .find(start)
        .unwrap_or_else(|| panic!("{source_name} must contain section start {start:?}"));
    let end_index = source[start_index..].find(end).map_or_else(
        || panic!("{source_name} must contain section end {end:?}"),
        |index| start_index + index,
    );
    normalized_rust_production_source(&source[start_index..end_index])
}

pub(crate) fn assert_rust_production_source_excludes(
    source_name: &str,
    source: &str,
    forbidden: &[&str],
) {
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

pub(crate) fn assert_no_direct_final_create_builders(source_name: &str, source: &str) {
    let normalized = normalized_rust_production_source(source);

    for builder in ["OpenOptions::new()", "File::options()"] {
        let mut search_from = 0;
        while let Some(relative_start) = normalized[search_from..].find(builder) {
            let start = search_from + relative_start;
            let end = normalized[start..]
                .find(';')
                .map_or(normalized.len(), |relative_end| start + relative_end);
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

pub(crate) fn normalized_token(token: &str) -> String {
    token
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

pub(crate) fn normalized_token_positions(normalized: &str, token: &str) -> Vec<usize> {
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

pub(crate) fn normalized_section_order_indices(
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

pub(crate) fn assert_normalized_section_order(
    source_name: &str,
    normalized: &str,
    expected_order: &[&str],
) {
    normalized_section_order_indices(source_name, normalized, expected_order);
}

pub(crate) fn assert_no_normalized_tokens_before(
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

pub(crate) fn assert_corpus_contains(corpus_name: &str, sources: &[(&str, &str)], needle: &str) {
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

pub(crate) fn assert_corpus_markdown_text_contains(
    corpus_name: &str,
    sources: &[(&str, &str)],
    needle: &str,
) {
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

pub(crate) fn assert_occurs_before(source_name: &str, source: &str, earlier: &str, later: &str) {
    let source = normalized_line_endings(source);
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

pub(crate) fn assert_non_comment_line_count(
    source_name: &str,
    source: &str,
    needle: &str,
    expected: usize,
) {
    let count = source
        .lines()
        .filter(|line| is_non_comment_line(line) && line.trim() == needle)
        .count();
    assert_eq!(
        count, expected,
        "{source_name} must contain exactly {expected} non-comment line(s) matching {needle:?}"
    );
}

pub(crate) fn non_comment_line_index(source_name: &str, source: &str, needle: &str) -> usize {
    source
        .lines()
        .enumerate()
        .find_map(|(index, line)| {
            (is_non_comment_line(line) && line.trim() == needle).then_some(index)
        })
        .unwrap_or_else(|| panic!("{source_name} must contain executable line {needle:?}"))
}

pub(crate) fn assert_non_comment_line_occurs_before(
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

pub(crate) fn parsed_fixture_rows(source_name: &str, source: &str) -> Vec<toml::Value> {
    let manifest: toml::Value =
        toml::from_str(source).unwrap_or_else(|error| panic!("{source_name} must parse: {error}"));
    manifest
        .get("fixture")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_else(|| panic!("{source_name} must expose [[fixture]] rows"))
}

pub(crate) fn required_manifest_field<'a>(
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

pub(crate) fn assert_manifest_row(
    source_name: &str,
    rows: &[toml::Value],
    row_id: &str,
    requirement: &str,
) {
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

pub(crate) fn assert_manifest_has_no_dependency_package(
    source_name: &str,
    source: &str,
    package: &str,
) {
    let manifest: toml::Value =
        toml::from_str(source).unwrap_or_else(|error| panic!("{source_name} must parse: {error}"));
    inspect_manifest_tables_for_package(source_name, &manifest, package);
}

pub(crate) fn inspect_manifest_tables_for_package(
    source_name: &str,
    value: &toml::Value,
    package: &str,
) {
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

pub(crate) fn inspect_dependency_table_for_package(
    source_name: &str,
    value: &toml::Value,
    package: &str,
) {
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

pub(crate) fn assert_lockfile_has_no_package(source_name: &str, source: &str, package: &str) {
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

pub(crate) fn is_non_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

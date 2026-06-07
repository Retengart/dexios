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
        "Local-only working notes",
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
        "blake3 = \"1.8\"",
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

fn domain_path_identity_doc_overclaim_issues(source: &str) -> Vec<&'static str> {
    let normalized = source.replace('`', "").to_ascii_lowercase();
    let mut issues = Vec::new();

    for (needle, issue) in [
        ("secure erase guarantee", "secure erase overclaim"),
        ("guarantees secure erase", "secure erase overclaim"),
        (
            "non-unix behavior is unix-equivalent",
            "Unix-equivalent non-Unix identity overclaim",
        ),
        (
            "non-unix behavior has unix-equivalent",
            "Unix-equivalent non-Unix identity overclaim",
        ),
        (
            "same identity guarantees on non-unix",
            "same-guarantee non-Unix identity overclaim",
        ),
        (
            "full non-unix path identity parity",
            "full non-Unix identity parity overclaim",
        ),
        (
            "full platform identity parity",
            "full platform identity parity overclaim",
        ),
        (
            "fully eliminated plaintext exposure",
            "unpack plaintext exposure overclaim",
        ),
        (
            "no plaintext exposure during unpack",
            "unpack plaintext exposure overclaim",
        ),
        (
            "no plaintext ever touches disk during unpack",
            "unpack plaintext exposure overclaim",
        ),
        (
            "plaintext staging is eliminated",
            "unpack plaintext staging overclaim",
        ),
    ] {
        if normalized.contains(needle) {
            issues.push(issue);
        }
    }

    issues
}

/// Canonical v3.0 support window: Dexios majors 8 and 7 are supported; 6 and below
/// are unsupported. Closes DOCS-02 support-window gate coverage (audit v3.0).
const SUPPORT_WINDOW_SUPPORTED: &[&str] = &["8.x.x", "7.x.x"];
const SUPPORT_WINDOW_UNSUPPORTED: &[&str] = &["6.x.x", "5.0.x", "4.0.x"];

/// Reads the support marker for a version row from a markdown support table.
/// Maps both glyph styles (`✅`/`:x:` in SECURITY.md, `Yes`/`No` in Security-Policy.md)
/// to a boolean. Returns `None` when there is no matching row or the marker is ambiguous.
fn support_window_status(source: &str, version: &str) -> Option<bool> {
    for line in source.lines() {
        if !line.trim_start().starts_with('|') || !line.contains(version) {
            continue;
        }
        let lowered = line.to_ascii_lowercase();
        let supported = line.contains('✅') || lowered.contains("yes");
        let unsupported = line.contains(":x:") || lowered.contains("no");
        return match (supported, unsupported) {
            (true, false) => Some(true),
            (false, true) => Some(false),
            _ => None,
        };
    }
    None
}

fn phase20_stale_support_window_issues(source: &str) -> Vec<&'static str> {
    let normalized = source.replace('`', "").to_ascii_lowercase();
    let mut issues = Vec::new();

    for (needle, issue) in [
        (
            "versions 6 and above",
            "stale support-window floor claim (6 and above)",
        ),
        (
            "versions 5 and above",
            "stale support-window floor claim (5 and above)",
        ),
        ("6.x.x is supported", "stale 6.x supported claim"),
        ("6.x is supported", "stale 6.x supported claim"),
        (
            "all versions of dexios are supported",
            "stale all-versions-supported claim",
        ),
        (
            "every version is supported",
            "stale all-versions-supported claim",
        ),
        ("no version reaches end of life", "stale never-EOL claim"),
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
                "Argon2id",
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
                "Argon2id",
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
                "Argon2id",
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
                "Argon2id",
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
fn domain_path_identity_hardening_docs_are_source_gated() {
    assert_all_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        &[
            "Unix-backed guarantee uses no-follow opens and dev/inode identity evidence",
            "non-Unix behavior is limited by platform identity APIs and available tests",
            "Existing V1 archive compatibility remains manifest-first",
            "Unpack-side plaintext exposure is scoped to selected staged file bodies and ordinary filesystem temporary/staged files",
            "not secure erase",
        ],
    );

    assert_all_contains(
        "book/src/technical-details/Directory-Packing.md",
        DIRECTORY_PACKING,
        &[
            "On Unix, checked source reads use `O_NOFOLLOW` plus dev/inode identity revalidation",
            "Non-Unix behavior is a weaker boundary limited by platform identity APIs and available tests",
            "Existing V1 archive compatibility remains based on manifest-first `DXAR`/`DXBF` framing",
            "During unpack, staged plaintext is limited to selected file bodies in ordinary filesystem temporary/staged files",
            "does not claim secure erase",
        ],
    );

    for (source_name, source) in [
        ("book/src/Safety-Contract.md", SAFETY_CONTRACT),
        (
            "book/src/technical-details/Directory-Packing.md",
            DIRECTORY_PACKING,
        ),
    ] {
        let issues = domain_path_identity_doc_overclaim_issues(source);
        assert!(
            issues.is_empty(),
            "{source_name} must not overclaim platform parity or plaintext exposure; issues: {issues:?}"
        );
    }
}

#[test]
fn domain_path_identity_hardening_gate_rejects_stale_overclaims() {
    for stale_claim in [
        "Non-Unix behavior is Unix-equivalent to the Unix no-follow identity checks.",
        "The docs prove the same identity guarantees on non-Unix platforms.",
        "Dexios has full non-Unix path identity parity.",
        "Unpack has fully eliminated plaintext exposure.",
        "No plaintext ever touches disk during unpack.",
        "Plaintext staging is eliminated.",
        "Staged plaintext has a secure erase guarantee.",
    ] {
        assert!(
            !domain_path_identity_doc_overclaim_issues(stale_claim).is_empty(),
            "domain path identity docs gate must reject: {stale_claim}"
        );
    }
}

#[test]
fn phase20_support_window_docs_are_source_gated() {
    for (source_name, source) in [
        ("SECURITY.md", SECURITY_MD),
        ("book/src/Security-Policy.md", SECURITY_POLICY),
    ] {
        for version in SUPPORT_WINDOW_SUPPORTED {
            assert_eq!(
                support_window_status(source, version),
                Some(true),
                "{source_name} must mark {version} as a supported version"
            );
        }
        for version in SUPPORT_WINDOW_UNSUPPORTED {
            assert_eq!(
                support_window_status(source, version),
                Some(false),
                "{source_name} must mark {version} as an unsupported version"
            );
        }
        let stale = phase20_stale_support_window_issues(source);
        assert!(
            stale.is_empty(),
            "{source_name} has stale support-window claims: {stale:?}"
        );
    }

    // Keep the two support-policy mirrors in sync: both docs must agree per version.
    for version in SUPPORT_WINDOW_SUPPORTED
        .iter()
        .chain(SUPPORT_WINDOW_UNSUPPORTED)
    {
        assert_eq!(
            support_window_status(SECURITY_MD, version),
            support_window_status(SECURITY_POLICY, version),
            "SECURITY.md and book/src/Security-Policy.md disagree on support status for {version}"
        );
    }

    // dexios-core support statement must remain present and consistent on both surfaces.
    assert_contains(
        "SECURITY.md",
        SECURITY_MD,
        "all versions of `dexios-core` are supported",
    );
    assert_contains(
        "book/src/Security-Policy.md",
        SECURITY_POLICY,
        "`dexios-core` versions are currently listed as supported",
    );
}

#[test]
fn phase20_support_window_gate_rejects_stale_claims() {
    for stale_claim in [
        "Versions 6 and above will receive security updates.",
        "Versions 5 and above are supported.",
        "Dexios 6.x.x is supported.",
        "All versions of Dexios are supported.",
        "Every version is supported and no version reaches end of life.",
    ] {
        assert!(
            !phase20_stale_support_window_issues(stale_claim).is_empty(),
            "Phase 20 support-window gate must reject: {stale_claim}"
        );
    }

    // A drifted mirror that flips 6.x.x to supported must be detectable, so the
    // cross-mirror sync assertion above would fail on real drift.
    let drifted = "| Version | Supported |\n| 6.x.x | Yes |\n";
    assert_eq!(support_window_status(drifted, "6.x.x"), Some(true));
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
            "gh attestation verify dexios-vX.Y.Z-linux-amd64",
            "--repo brxken128/dexios",
            "--signer-workflow brxken128/dexios/.github/workflows/release.yml",
            "--source-ref refs/tags/vX.Y.Z",
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
fn release_hygiene_evidence_wording_is_source_gated() {
    assert_all_contains(
        "book/src/Installing-and-Building.md",
        INSTALLING_AND_BUILDING,
        &[
            "clean release-equivalent working tree",
            "release-sensitive untracked files fail closed",
            "non-release-equivalent dirty state",
            "release-sensitive untracked state",
            "release-equivalence status",
            "release-equivalent tool-version state",
        ],
    );

    assert_all_contains(
        "book/src/Safety-Contract.md",
        SAFETY_CONTRACT,
        &[
            "release-sensitive untracked state",
            "release-equivalence status",
            "release-equivalent tool versions",
            "non-release-equivalent local dry runs",
            ".gitattributes",
            "*.pdf binary",
        ],
    );

    let release_evidence_corpus = format!("{SAFETY_CONTRACT}\n{INSTALLING_AND_BUILDING}");
    for stale_claim in [
        "Untracked local files are ignored by the dirty check",
        "Untracked files\nare ignored by the dirty check",
    ] {
        assert_not_contains(
            "release evidence docs corpus",
            &release_evidence_corpus,
            stale_claim,
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
        "run mdbook build --dest-dir target/mdbook",
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

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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use verification_gate_support::*;

const PRODUCTION_RUST_CAP: usize = 700;
const REGULAR_TEST_CAP: usize = 800;
const SHELL_SCRIPT_CAP: usize = 500;
const VERIFICATION_GATE_CAP: usize = 600;
const SECURITY_EVIDENCE_CAP: usize = 2000;

const SCAN_ROOTS: &[&str] = &[
    "dexios/src",
    "dexios/tests",
    "dexios-domain/src",
    "dexios-domain/tests",
    "dexios-core/src",
    "dexios-core/tests",
    "scripts",
];

#[derive(Clone, Copy, Debug)]
struct FileSizeException {
    path: &'static str,
    category: &'static str,
    rationale: &'static str,
    current_lines: usize,
    cap: usize,
}

const FILE_SIZE_EXCEPTIONS: &[FileSizeException] = &[
    FileSizeException {
        path: "dexios-domain/tests/workflow_public_api.rs",
        category: "domain workflow public API evidence",
        rationale: "Phase 25 carry-forward source/API authority evidence per D-12.",
        current_lines: 1844,
        cap: 1844,
    },
    FileSizeException {
        path: "dexios/tests/verification_gate_source.rs",
        category: "Phase 25 source-gate evidence",
        rationale: "Phase 25 fail-closed source/API safety evidence per D-11.",
        current_lines: 1582,
        cap: 1582,
    },
    FileSizeException {
        path: "dexios-core/tests/stream_v1.rs",
        category: "core stream security matrix",
        rationale: "Core stream final-auth and tamper matrix kept explicit per D-03.",
        current_lines: 1314,
        cap: 1314,
    },
    FileSizeException {
        path: "dexios-domain/src/pack.rs",
        category: "D-05 production authority cap",
        rationale: "Archive pack authority file is deferred from production splitting per D-05.",
        current_lines: 1194,
        cap: 1194,
    },
    FileSizeException {
        path: "dexios/tests/verification_gate_docs.rs",
        category: "Phase 25 docs-gate evidence",
        rationale: "Public docs/spec/generated-artifact evidence remains explicit per D-11.",
        current_lines: 1103,
        cap: 1103,
    },
    FileSizeException {
        path: "dexios/tests/verification_gate_support/mod.rs",
        category: "Phase 25 source-gate support evidence",
        rationale: "Shared include_str and normalization authority stays centralized per D-11.",
        current_lines: 987,
        cap: 987,
    },
    FileSizeException {
        path: "dexios-core/tests/v1_header.rs",
        category: "core header security matrix",
        rationale: "Core V1 header compatibility and tamper matrix kept explicit per D-03.",
        current_lines: 1091,
        cap: 1091,
    },
    FileSizeException {
        path: "dexios-domain/tests/archive_public_api.rs",
        category: "domain archive public API evidence",
        rationale: "Phase 25 carry-forward source/API authority evidence per D-12.",
        current_lines: 961,
        cap: 961,
    },
    FileSizeException {
        path: "dexios/src/cli/tests.rs",
        category: "parser compatibility matrix",
        rationale: "CLI parser compatibility matrix remains source-local evidence per D-03.",
        current_lines: 976,
        cap: 976,
    },
    FileSizeException {
        path: "dexios-domain/src/unpack.rs",
        category: "D-05 production authority cap",
        rationale: "Archive unpack authority file is deferred from production splitting per D-05.",
        current_lines: 874,
        cap: 874,
    },
    FileSizeException {
        path: "dexios/tests/key_cli_regressions.rs",
        category: "key CLI security regression matrix",
        rationale: "Key-source prompting and stderr regression matrix remains explicit per D-03.",
        current_lines: 812,
        cap: 812,
    },
    FileSizeException {
        path: "dexios-core/src/payload.rs",
        category: "D-05 production authority cap",
        rationale: "Payload framing authority file is deferred from production splitting per D-05.",
        current_lines: 765,
        cap: 765,
    },
    FileSizeException {
        path: "dexios-domain/src/storage/temp.rs",
        category: "fd-relative storage security evidence",
        rationale: "fd-relative persist + TOCTOU-safe directory creation (fs-1/fs-2) kept centralized.",
        current_lines: 709,
        cap: 709,
    },
    FileSizeException {
        path: "dexios-domain/src/storage/cleanup.rs",
        category: "cleanup digest security evidence",
        rationale: "No-follow content digest + identity revalidation (fs-3) kept centralized.",
        current_lines: 708,
        cap: 708,
    },
];

#[derive(Debug)]
struct SizeViolation {
    path: String,
    lines: usize,
    cap: usize,
    category: &'static str,
}

#[test]
fn file_size_caps_are_enforced_with_structured_allowlist() {
    let violations = oversized_files(FILE_SIZE_EXCEPTIONS);
    assert!(
        violations.is_empty(),
        "unreviewed oversized files or grown exceptions:\n{}",
        format_violations(&violations)
    );

    let first_exception = FILE_SIZE_EXCEPTIONS
        .first()
        .expect("maintainability gate must have live oversized exceptions");
    let without_first_exception = FILE_SIZE_EXCEPTIONS
        .iter()
        .copied()
        .filter(|entry| entry.path != first_exception.path)
        .collect::<Vec<_>>();
    let violations = oversized_files(&without_first_exception);

    assert!(
        violations
            .iter()
            .any(|violation| violation.path == first_exception.path),
        "removing an oversized exception must fail closed; got:\n{}",
        format_violations(&violations)
    );
}

#[test]
fn allowlist_entries_have_rationales_current_counts_and_caps() {
    let mut seen_paths = BTreeSet::new();

    for entry in FILE_SIZE_EXCEPTIONS {
        assert!(
            !entry.path.trim().is_empty(),
            "allowlist path must not be blank"
        );
        assert!(
            seen_paths.insert(entry.path),
            "duplicate allowlist path: {}",
            entry.path
        );
        assert!(
            !entry.category.trim().is_empty(),
            "{} must have a category",
            entry.path
        );
        assert!(
            !entry.rationale.trim().is_empty(),
            "{} must have a rationale",
            entry.path
        );

        let live_lines = line_count(entry.path);
        assert_eq!(
            live_lines, entry.current_lines,
            "{} current_lines must match the live physical line count",
            entry.path
        );
        assert!(
            entry.cap >= entry.current_lines,
            "{} cap {} must cover current_lines {}",
            entry.path,
            entry.cap,
            entry.current_lines
        );

        let (_, default_cap) = default_category_and_cap(entry.path);
        assert!(
            entry.current_lines > default_cap,
            "{} no longer needs an oversized-file exception",
            entry.path
        );
    }
}

#[test]
fn security_evidence_allowlists_stay_below_category_caps() {
    for entry in FILE_SIZE_EXCEPTIONS {
        let is_evidence_or_authority = entry.category.contains("evidence")
            || entry.category.contains("security")
            || entry.category.contains("authority")
            || entry.category.contains("compatibility");

        assert!(
            is_evidence_or_authority,
            "{} category must explain why the exception is security or evidence sensitive",
            entry.path
        );
        assert!(
            entry.cap <= SECURITY_EVIDENCE_CAP,
            "{} cap {} exceeds security evidence cap {}",
            entry.path,
            entry.cap,
            SECURITY_EVIDENCE_CAP
        );
        assert!(
            entry.current_lines <= entry.cap,
            "{} current_lines {} must not exceed cap {}",
            entry.path,
            entry.current_lines,
            entry.cap
        );
    }
}

#[test]
fn cli_dispatch_stays_fallible_and_no_silent_fallback_patterns() {
    assert_all_contains(
        "dexios/src/main.rs",
        DEXIOS_MAIN_RS,
        &[
            "CliRoute::from_matches(&matches)?.dispatch()",
            "enum CliRoute<'a>",
            "HeaderRoute::from_matches(sub_matches)?",
            "KeyRoute::from_matches(sub_matches)?",
        ],
    );

    assert_rust_production_source_excludes(
        "dexios/src/main.rs",
        DEXIOS_MAIN_RS,
        &["subcommand_matches(", "_ => (),"],
    );
    assert_rust_production_source_excludes(
        "dexios/src/subcommands.rs",
        DEXIOS_SUBCOMMANDS_RS,
        &["subcommand_matches(", "_ => (),"],
    );
    assert_rust_production_source_excludes(
        "dexios/src/global/states.rs",
        DEXIOS_STATES_RS,
        &[".ok().flatten()"],
    );
}

#[test]
fn phase_gate_runs_all_verification_gate_targets() {
    let active_glob_lines = VERIFY_PHASE_GATE
        .lines()
        .filter(|line| is_non_comment_line(line))
        .filter(|line| {
            line.trim()
                == "run cargo test --locked -p dexios --test 'verification_gate_*' --release"
        })
        .collect::<Vec<_>>();

    assert_eq!(
        active_glob_lines.len(),
        1,
        "scripts/verify_phase_gate.sh must have exactly one active quoted verification_gate_* Cargo line"
    );
    assert!(
        VERIFY_PHASE_GATE
            .lines()
            .filter(|line| is_non_comment_line(line))
            .filter(|line| line.contains("verification_gate_maintainability"))
            .count()
            == 0,
        "maintainability gate must run through the existing quoted verification_gate_* glob, not a duplicate explicit line"
    );
}

fn oversized_files(exceptions: &[FileSizeException]) -> Vec<SizeViolation> {
    let exception_map = exceptions
        .iter()
        .map(|entry| (entry.path, *entry))
        .collect::<BTreeMap<_, _>>();
    let mut violations = Vec::new();

    for path in scanned_source_files() {
        let relative_path = relative_workspace_path(&path);
        let (category, default_cap) = default_category_and_cap(&relative_path);
        let lines = physical_line_count(&path);
        let cap = exception_map
            .get(relative_path.as_str())
            .map_or(default_cap, |entry| entry.cap);

        if lines > cap
            || (lines > default_cap && !exception_map.contains_key(relative_path.as_str()))
        {
            violations.push(SizeViolation {
                path: relative_path,
                lines,
                cap,
                category,
            });
        }
    }

    violations
}

fn format_violations(violations: &[SizeViolation]) -> String {
    violations
        .iter()
        .map(|violation| {
            format!(
                "{} has {} lines over cap {} ({})",
                violation.path, violation.lines, violation.cap, violation.category
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn scanned_source_files() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut files = Vec::new();

    for scan_root in SCAN_ROOTS {
        collect_source_files(&root.join(scan_root), &mut files);
    }

    files.sort();
    files
}

fn collect_source_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in
        fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
    {
        let path = entry
            .unwrap_or_else(|error| panic!("read entry under {}: {error}", root.display()))
            .path();
        if path.is_dir() {
            collect_source_files(&path, files);
        } else if is_scanned_source_file(&path) {
            files.push(path);
        }
    }
}

fn is_scanned_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("rs" | "sh")
    )
}

fn line_count(relative_path: &str) -> usize {
    let path = workspace_root().join(relative_path);
    physical_line_count(&path)
}

fn physical_line_count(path: &Path) -> usize {
    fs::read(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .into_iter()
        .filter(|byte| *byte == b'\n')
        .count()
}

fn default_category_and_cap(relative_path: &str) -> (&'static str, usize) {
    if relative_path.ends_with(".sh") {
        return ("shell script", SHELL_SCRIPT_CAP);
    }
    if relative_path.starts_with("dexios/tests/verification_gate_")
        || relative_path == "dexios/tests/verification_gate_support/mod.rs"
    {
        return ("verification gate module", VERIFICATION_GATE_CAP);
    }
    if relative_path.contains("/tests/") || relative_path == "dexios/src/cli/tests.rs" {
        return ("regular test", REGULAR_TEST_CAP);
    }

    ("production Rust source", PRODUCTION_RUST_CAP)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dexios crate must live under workspace root")
        .to_path_buf()
}

fn relative_workspace_path(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or_else(|error| panic!("{} must be under workspace root: {error}", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
}

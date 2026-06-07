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
use std::fs;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use dexios_domain::storage::FileStorage;
use dexios_domain::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole,
};

const STORAGE_FS_RS: &str = include_str!("../src/storage/fs.rs");
const DOMAIN_PACK_RS: &str = include_str!("../src/pack.rs");
const NON_UNIX_PLATFORM_LIMITATION_WORDING: &str =
    "non-Unix fallback is limited by platform identity APIs";
const NON_UNIX_NO_PARITY_WORDING: &str = "does not provide Unix-equivalent identity evidence";

struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Self { _dir: dir, path }
    }

    fn new_under_workdir(prefix: &str) -> Self {
        let root = Path::new("target").join("path-identity-tests");
        fs::create_dir_all(&root).unwrap();
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir_in(root)
            .unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Self { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[test]
fn path_identity_harness_creates_disposable_real_fs_dir() {
    let test_dir = TestDir::new("path-identity");
    let input = test_dir.path().join("input.txt");

    fs::write(&input, b"path identity fixture").unwrap();

    // D-17 requires real filesystem evidence for aliasing and identity edges.
    let temp_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(test_dir.path().starts_with(&temp_root));
    assert_eq!(fs::read(&input).unwrap(), b"path identity fixture");
}

fn assert_alias(result: Result<impl std::fmt::Debug, IdentityError>) {
    assert!(
        matches!(result, Err(IdentityError::AliasedPath { .. })),
        "expected AliasedPath, got {result:?}"
    );
}

fn assert_unsafe_path(result: Result<impl std::fmt::Debug, IdentityError>) {
    assert!(
        matches!(result, Err(IdentityError::UnsafePath(_))),
        "expected UnsafePath, got {result:?}"
    );
}

fn existing_roles_requiring_no_follow_policy() -> [PathRole; 5] {
    [
        PathRole::Input,
        PathRole::DetachedHeader,
        PathRole::MutationTarget,
        PathRole::ProcessedSource,
        PathRole::CleanupTarget,
    ]
}

fn existing_output_roles_requiring_no_follow_policy() -> [PathRole; 5] {
    [
        PathRole::Output,
        PathRole::DetachedHeader,
        PathRole::GeneratedOutput,
        PathRole::GeneratedDetachedHeader,
        PathRole::MutationTarget,
    ]
}

fn assert_identity_source_kind(error: &IdentityError, expected: ErrorKind) {
    let source = std::error::Error::source(error)
        .expect("identity IO error must preserve an io::Error source");
    let source = source
        .downcast_ref::<std::io::Error>()
        .expect("identity error source must be std::io::Error");
    assert_eq!(source.kind(), expected);
}

fn source_section(source_name: &str, source: &str, start: &str, end: &str) -> String {
    let source = source.replace("\r\n", "\n");
    let (_, rest) = source
        .split_once(start)
        .unwrap_or_else(|| panic!("{source_name} missing source anchor {start:?}"));
    let (section, _) = rest
        .split_once(end)
        .unwrap_or_else(|| panic!("{source_name} missing source anchor {end:?} after {start:?}"));
    section.to_owned()
}

fn assert_unix_strong_identity_wording(source_name: &str, section: &str) {
    assert!(
        section.contains("no-follow opened entry") && section.contains("identity evidence"),
        "{source_name} must describe Unix strong identity as no-follow open plus identity evidence"
    );
}

fn assert_non_unix_limited_identity_wording(source_name: &str, section: &str) {
    let normalized = section.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized.contains(NON_UNIX_PLATFORM_LIMITATION_WORDING),
        "{source_name} must label non-Unix identity fallback as limited by platform APIs"
    );
    assert!(
        normalized.contains(NON_UNIX_NO_PARITY_WORDING),
        "{source_name} must not imply Unix-equivalent non-Unix identity evidence"
    );

    for overclaim in [
        "Unix-equivalent parity",
        "Windows/non-Unix parity",
        "non-Unix parity",
        "same guarantees as Unix",
    ] {
        assert!(
            !normalized.contains(overclaim),
            "{source_name} must not claim unsupported platform parity via {overclaim:?}"
        );
    }
}

#[test]
fn platform_identity_contract_distinguishes_unix_revalidation_from_non_unix_fallback() {
    let unix_read_reopen = source_section(
        "dexios-domain/src/storage/fs.rs",
        STORAGE_FS_RS,
        "#[cfg(unix)]\nfn verify_entry_matches_resolved_target",
        "#[cfg(unix)]\nfn open_no_follow",
    );
    assert!(
        unix_read_reopen.contains("existing_target_identity()"),
        "Unix read-side reopen must be bound to captured identity evidence"
    );
    assert_unix_strong_identity_wording(
        "dexios-domain/src/storage/fs.rs::verify_entry_matches_resolved_target",
        &unix_read_reopen,
    );
    assert!(
        unix_read_reopen.contains("actual.dev() != expected_identity.dev")
            && unix_read_reopen.contains("actual.ino() != expected_identity.ino"),
        "Unix read-side reopen must compare dev/inode identity"
    );

    let non_unix_open = source_section(
        "dexios-domain/src/storage/fs.rs",
        STORAGE_FS_RS,
        "#[cfg(not(unix))]\nfn open_no_follow",
        "fn reject_mutated_root",
    );
    assert!(
        non_unix_open.contains("std_fs::File::open(path)"),
        "non-Unix fallback must remain visibly weaker than Unix no-follow reopen"
    );
    assert_non_unix_limited_identity_wording(
        "dexios-domain/src/storage/fs.rs::open_no_follow non-Unix fallback",
        &non_unix_open,
    );
    assert!(
        !non_unix_open.contains(".dev()") && !non_unix_open.contains(".ino()"),
        "non-Unix fallback must not pretend to perform Unix dev/inode revalidation"
    );

    let unix_walk_entry = source_section(
        "dexios-domain/src/pack.rs",
        DOMAIN_PACK_RS,
        "#[cfg(unix)]\nfn verify_walked_entry_matches_opened",
        "#[cfg(not(unix))]\nfn verify_walked_entry_matches_opened",
    );
    assert!(
        unix_walk_entry.contains("opened_metadata.dev() != walked_metadata.dev()")
            && unix_walk_entry.contains("opened_metadata.ino() != walked_metadata.ino()"),
        "Unix pack entry materialization must compare walked and opened identities"
    );
    assert_unix_strong_identity_wording(
        "dexios-domain/src/pack.rs::verify_walked_entry_matches_opened Unix",
        &unix_walk_entry,
    );

    let non_unix_walk_entry = source_section(
        "dexios-domain/src/pack.rs",
        DOMAIN_PACK_RS,
        "#[cfg(not(unix))]\nfn verify_walked_entry_matches_opened",
        "fn push_archive_entry",
    );
    assert!(
        non_unix_walk_entry.contains("Ok(())"),
        "non-Unix pack entry identity fallback is intentionally limited"
    );
    assert_non_unix_limited_identity_wording(
        "dexios-domain/src/pack.rs::verify_walked_entry_matches_opened non-Unix fallback",
        &non_unix_walk_entry,
    );
    assert!(
        !non_unix_walk_entry.contains(".dev()") && !non_unix_walk_entry.contains(".ino()"),
        "non-Unix pack fallback must not claim Unix-equivalent identity evidence"
    );
}

#[test]
fn identity_io_failures_preserve_sources_for_missing_existing_paths() {
    let test_dir = TestDir::new("path-identity-source");
    let missing = test_dir.path().join("missing-input.txt");

    let mut graph = PathIdentityGraph::new();
    let error = graph
        .add_existing(&missing, PathRole::Input)
        .expect_err("missing existing input must fail");

    assert_identity_source_kind(&error, ErrorKind::NotFound);
}

#[test]
fn identity_rejects_relative_alias() {
    let test_dir = TestDir::new_under_workdir("path-identity-relative");
    let input = test_dir.path().join("input.txt");
    fs::write(&input, b"path identity fixture").unwrap();

    let current_dir = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
    let relative = input.strip_prefix(&current_dir).unwrap();

    let mut graph = PathIdentityGraph::new();
    graph.add_existing(&input, PathRole::Input).unwrap();

    assert_alias(graph.add_output(relative, PathRole::Output, OverwritePolicy::ReplaceAtCommit));
}

#[test]
fn identity_rejects_canonical_alias() {
    let test_dir = TestDir::new("path-identity-canonical");
    let input = test_dir.path().join("input.txt");
    let alias = test_dir.path().join(".").join("input.txt");
    fs::write(&input, b"path identity fixture").unwrap();

    let mut graph = PathIdentityGraph::new();
    graph
        .add_existing(fs::canonicalize(&input).unwrap(), PathRole::Input)
        .unwrap();

    assert_alias(graph.add_output(alias, PathRole::Output, OverwritePolicy::ReplaceAtCommit));
}

#[cfg(unix)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping symlink identity check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_file(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping symlink identity check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_file_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping symlink identity check: symlink helper unsupported on this platform");
    false
}

#[test]
fn identity_rejects_symlink_alias() {
    let test_dir = TestDir::new("path-identity-symlink");
    let input = test_dir.path().join("input.txt");
    let alias = test_dir.path().join("input-link.txt");
    fs::write(&input, b"path identity fixture").unwrap();

    if !symlink_file_or_skip(&input, &alias) {
        return;
    }

    let mut graph = PathIdentityGraph::new();
    graph.add_existing(&input, PathRole::Input).unwrap();

    assert_unsafe_path(graph.add_output(alias, PathRole::Output, OverwritePolicy::ReplaceAtCommit));
}

#[test]
fn identity_rejects_existing_roles_with_final_symlink_components() {
    let test_dir = TestDir::new("path-identity-existing-final-symlink");
    let target = test_dir.path().join("target.txt");
    let link = test_dir.path().join("target-link.txt");
    fs::write(&target, b"path identity fixture").unwrap();

    if !symlink_file_or_skip(&target, &link) {
        return;
    }

    for role in existing_roles_requiring_no_follow_policy() {
        let mut graph = PathIdentityGraph::new();
        assert_unsafe_path(graph.add_existing(&link, role));
    }
}

#[test]
fn identity_rejects_existing_roles_with_symlinked_parent_prefixes() {
    let test_dir = TestDir::new("path-identity-existing-parent-symlink");
    let outside = test_dir.path().join("outside");
    let link = test_dir.path().join("link");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("target.txt"), b"path identity fixture").unwrap();

    if !symlink_dir_or_skip(&outside, &link) {
        return;
    }

    for role in existing_roles_requiring_no_follow_policy() {
        let mut graph = PathIdentityGraph::new();
        assert_unsafe_path(graph.add_existing(link.join("target.txt"), role));
    }
}

#[cfg(unix)]
#[test]
fn identity_rejects_existing_roles_with_symlinked_parent_hidden_by_parent_component() {
    let test_dir = TestDir::new("path-identity-existing-parent-dotdot");
    let outside = test_dir.path().join("outside");
    let link = test_dir.path().join("link");
    let safe = test_dir.path().join("safe");
    fs::create_dir(&outside).unwrap();
    fs::create_dir(&safe).unwrap();
    fs::write(safe.join("target.txt"), b"path identity fixture").unwrap();

    if !symlink_dir_or_skip(&outside, &link) {
        return;
    }

    for role in existing_roles_requiring_no_follow_policy() {
        let mut graph = PathIdentityGraph::new();
        assert_unsafe_path(graph.add_existing(link.join("../safe/target.txt"), role));
    }
}

#[test]
fn identity_rejects_existing_output_roles_with_symlinked_parent_prefixes() {
    let test_dir = TestDir::new("path-identity-output-parent-symlink");
    let outside = test_dir.path().join("outside");
    let link = test_dir.path().join("link");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("output.dexios"), b"path identity fixture").unwrap();

    if !symlink_dir_or_skip(&outside, &link) {
        return;
    }

    for role in existing_output_roles_requiring_no_follow_policy() {
        let mut graph = PathIdentityGraph::new();
        assert_unsafe_path(graph.add_output(
            link.join("output.dexios"),
            role,
            OverwritePolicy::ReplaceAtCommit,
        ));
    }
}

#[cfg(unix)]
#[test]
fn identity_rejects_output_roles_with_symlinked_parent_hidden_by_parent_component() {
    let test_dir = TestDir::new("path-identity-output-parent-dotdot");
    let outside = test_dir.path().join("outside");
    let link = test_dir.path().join("link");
    let safe = test_dir.path().join("safe");
    fs::create_dir(&outside).unwrap();
    fs::create_dir(&safe).unwrap();
    fs::write(safe.join("output.dexios"), b"path identity fixture").unwrap();

    if !symlink_dir_or_skip(&outside, &link) {
        return;
    }

    for role in existing_output_roles_requiring_no_follow_policy() {
        let mut graph = PathIdentityGraph::new();
        assert_unsafe_path(graph.add_output(
            link.join("../safe/output.dexios"),
            role,
            OverwritePolicy::ReplaceAtCommit,
        ));
    }
}

#[cfg(unix)]
#[test]
fn identity_rejects_missing_output_with_symlinked_parent_hidden_by_parent_component() {
    let test_dir = TestDir::new("path-identity-missing-output-dotdot");
    let outside = test_dir.path().join("outside");
    let link = test_dir.path().join("link");
    let safe = test_dir.path().join("safe");
    fs::create_dir(&outside).unwrap();
    fs::create_dir(&safe).unwrap();

    if !symlink_dir_or_skip(&outside, &link) {
        return;
    }

    let mut graph = PathIdentityGraph::new();
    assert_unsafe_path(graph.add_output(
        link.join("../safe/new-output.dexios"),
        PathRole::Output,
        OverwritePolicy::CreateNew,
    ));
}

#[cfg(unix)]
#[test]
fn resolved_existing_no_follow_rejects_file_replaced_after_identity_capture() {
    let test_dir = TestDir::new("path-identity-open-replaced");
    let input = test_dir.path().join("archive.dexios");
    let replacement = test_dir.path().join("replacement.dexios");
    fs::write(&input, b"original archive").unwrap();
    fs::write(&replacement, b"replacement archive").unwrap();
    let original_metadata = fs::metadata(&input).unwrap();
    let replacement_metadata = fs::metadata(&replacement).unwrap();
    assert!(
        original_metadata.dev() != replacement_metadata.dev()
            || original_metadata.ino() != replacement_metadata.ino(),
        "replacement fixture must have a distinct identity"
    );

    let mut graph = PathIdentityGraph::new();
    let target = graph.add_existing(&input, PathRole::Input).unwrap();
    fs::rename(&replacement, &input).unwrap();

    let stor = FileStorage;
    let result = stor.read_resolved_existing_no_follow(&target);

    match result {
        Err(dexios_domain::storage::Error::UnsafePath(_)) => {}
        Err(err) => {
            panic!("expected resolved no-follow read to reject changed identity, got {err}")
        }
        Ok(_) => panic!("expected resolved no-follow read to reject changed identity"),
    }
}

#[test]
fn identity_accepts_processed_source_and_cleanup_roles_for_real_existing_files() {
    let test_dir = TestDir::new("path-identity-cleanup-roles");
    let source = test_dir.path().join("source.txt");
    let cleanup = test_dir.path().join("cleanup.txt");
    fs::write(&source, b"path identity fixture").unwrap();
    fs::write(&cleanup, b"path identity fixture").unwrap();

    let mut graph = PathIdentityGraph::new();
    let processed = graph
        .add_existing(&source, PathRole::ProcessedSource)
        .unwrap();
    let cleanup = graph
        .add_existing(&cleanup, PathRole::CleanupTarget)
        .unwrap();

    assert_eq!(processed.role(), PathRole::ProcessedSource);
    assert_eq!(cleanup.role(), PathRole::CleanupTarget);
    graph.validate().unwrap();
}

#[test]
fn identity_rejects_hardlink_alias() {
    let test_dir = TestDir::new("path-identity-hardlink");
    let input = test_dir.path().join("input.txt");
    let alias = test_dir.path().join("alias.txt");
    fs::write(&input, b"path identity fixture").unwrap();

    if let Err(err) = fs::hard_link(&input, &alias) {
        eprintln!("skipping hardlink identity check: hard links unsupported here: {err}");
        return;
    }

    let mut graph = PathIdentityGraph::new();
    graph.add_existing(&input, PathRole::Input).unwrap();

    assert_alias(graph.add_output(&alias, PathRole::Output, OverwritePolicy::ReplaceAtCommit));
}

#[test]
fn identity_rejects_detached_header_conflict() {
    let test_dir = TestDir::new("path-identity-detached-header");
    let output = test_dir.path().join("cipher.dexios");

    let mut graph = PathIdentityGraph::new();
    graph
        .add_output(&output, PathRole::Output, OverwritePolicy::CreateNew)
        .unwrap();

    assert_alias(graph.add_output(
        &output,
        PathRole::DetachedHeader,
        OverwritePolicy::CreateNew,
    ));
}

#[test]
fn identity_rejects_generated_output_conflict() {
    let test_dir = TestDir::new("path-identity-generated-output");
    let source_dir = test_dir.path().join("source");
    fs::create_dir(&source_dir).unwrap();

    let mut graph = PathIdentityGraph::new();
    graph.add_existing(&source_dir, PathRole::Input).unwrap();

    assert_alias(graph.add_generated(source_dir.join("cipher.dexios"), PathRole::GeneratedOutput));
}

#[test]
fn identity_rejects_output_vs_input_conflict() {
    let test_dir = TestDir::new("path-identity-output-input");
    let input = test_dir.path().join("input.txt");
    fs::write(&input, b"path identity fixture").unwrap();

    let mut graph = PathIdentityGraph::new();
    graph.add_existing(&input, PathRole::Input).unwrap();

    assert_alias(graph.add_output(&input, PathRole::Output, OverwritePolicy::ReplaceAtCommit));
}

#[test]
fn identity_resolves_missing_target_parent_without_canonicalizing_final_path() {
    let test_dir = TestDir::new("path-identity-missing-target");
    let target = test_dir.path().join("missing-parent").join("output.dexios");

    let mut graph = PathIdentityGraph::new();
    let resolved = graph
        .add_output(&target, PathRole::Output, OverwritePolicy::CreateNew)
        .unwrap();

    assert_eq!(resolved.target_parent(), test_dir.path());
    assert_eq!(resolved.target_path(), target);
    assert_eq!(
        resolved.missing_components(),
        &[
            std::ffi::OsString::from("missing-parent"),
            std::ffi::OsString::from("output.dexios")
        ]
    );
    assert!(resolved.target_parent().is_dir());
    assert!(!resolved.target_path().exists());
    graph.validate().unwrap();
}

#[cfg(unix)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping symlink identity check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_dir(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping symlink identity check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_dir_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping symlink identity check: symlink helper unsupported on this platform");
    false
}

#[test]
fn identity_rejects_symlinked_missing_target_prefix() {
    let test_dir = TestDir::new("path-identity-symlink-prefix");
    let outside = test_dir.path().join("outside");
    let link = test_dir.path().join("link");
    fs::create_dir(&outside).unwrap();

    if !symlink_dir_or_skip(&outside, &link) {
        return;
    }

    let mut graph = PathIdentityGraph::new();
    let result = graph.add_output(
        link.join("output.dexios"),
        PathRole::Output,
        OverwritePolicy::CreateNew,
    );

    assert!(
        matches!(result, Err(IdentityError::UnsafePath(_))),
        "expected UnsafePath for symlinked prefix, got {result:?}"
    );
}

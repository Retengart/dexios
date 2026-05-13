use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use dexios_domain::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole,
};

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

fn assert_identity_source_kind(error: &IdentityError, expected: ErrorKind) {
    let source = std::error::Error::source(error)
        .expect("identity IO error must preserve an io::Error source");
    let source = source
        .downcast_ref::<std::io::Error>()
        .expect("identity error source must be std::io::Error");
    assert_eq!(source.kind(), expected);
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

    assert_alias(graph.add_output(alias, PathRole::Output, OverwritePolicy::ReplaceAtCommit));
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

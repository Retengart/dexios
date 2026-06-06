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
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::payload::{ManifestEntryKind, ManifestFirstPayload};
use core::protected::Protected;
use domain::decrypt;
use domain::storage::identity::OverwritePolicy;

const PASSWORD: &str = "12345678";
const DOMAIN_PACK_SOURCE: &str = include_str!("../../dexios-domain/src/pack.rs");
const CLI_ERROR_MAPPER_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let seq = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dexios-{prefix}-{}-{seq}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_pack(
    current_dir: &Path,
    extra_args: &[&str],
    inputs: &[&str],
    output_name: &str,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", PASSWORD)
        .arg("--env-key")
        .arg("pack")
        .arg("-f");

    for arg in extra_args {
        command.arg(arg);
    }

    for input in inputs {
        command.arg(input);
    }

    command.arg(output_name).output().unwrap()
}

fn run_cli_with_stdin(current_dir: &Path, args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dexios"))
        .current_dir(current_dir)
        .env_remove("DEXIOS_KEY")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let write_result = child.stdin.as_mut().unwrap().write_all(stdin);
    if let Err(error) = write_result {
        assert_eq!(
            error.kind(),
            ErrorKind::BrokenPipe,
            "unexpected stdin write error: {error}"
        );
    }
    child.wait_with_output().unwrap()
}

fn decrypt_manifest_entry_names(archive_path: &Path, header_path: Option<&Path>) -> Vec<String> {
    let seq = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
    let decrypted_path = archive_path
        .parent()
        .unwrap()
        .join(format!("decrypted-{seq}.dxar"));
    let intent = decrypt::DecryptIntent::new(
        archive_path,
        &decrypted_path,
        OverwritePolicy::CreateNew,
        header_path,
        Protected::new(PASSWORD.as_bytes().to_vec()),
        None,
    )
    .unwrap();
    decrypt::execute(intent).unwrap();

    let bytes = fs::read(decrypted_path).unwrap();
    let payload = ManifestFirstPayload::parse(&bytes).unwrap();
    let mut names = payload
        .manifest()
        .entries()
        .iter()
        .map(|entry| {
            let mut name = std::str::from_utf8(entry.normalized_path())
                .unwrap()
                .to_string();
            if entry.kind() == ManifestEntryKind::Directory {
                name.push('/');
            }
            name
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn pack_keyfile_stdin_fails_before_interactive_overwrite_prompt() {
    let test_dir = TestDir::new("pack-keyfile-stdin-overwrite");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("plain.txt"), b"plain").unwrap();
    fs::write(test_dir.path().join("archive.enc"), b"existing archive").unwrap();
    fs::write(test_dir.path().join("archive.hdr"), b"existing header").unwrap();

    let output = run_cli_with_stdin(
        test_dir.path(),
        &[
            "pack",
            "--keyfile",
            "-",
            "--header",
            "archive.hdr",
            "source",
            "archive.enc",
        ],
        b"secret-from-stdin\n",
    );

    assert!(
        !output.status.success(),
        "pack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--keyfile - cannot be combined with interactive overwrite prompts"),
        "stderr did not explain stdin/prompt conflict: {stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("archive.enc")).unwrap(),
        b"existing archive"
    );
    assert_eq!(
        fs::read(test_dir.path().join("archive.hdr")).unwrap(),
        b"existing header"
    );
}

fn create_deep_source_file(root: &Path, depth: usize) -> PathBuf {
    let source_dir = root.join("source");
    let mut nested_dir = source_dir;
    for index in 0..depth {
        nested_dir.push(format!("dir{index}"));
    }
    fs::create_dir_all(&nested_dir).unwrap();
    let file_path = nested_dir.join("deep.txt");
    fs::write(&file_path, b"deep").unwrap();
    file_path
}

fn assert_alias_rejected(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "pack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Path aliases detected"),
        "stderr did not mention path alias conflict: {stderr}"
    );
}

fn assert_unsafe_path_rejected(output: &std::process::Output, path_hint: &str) {
    assert!(
        !output.status.success(),
        "pack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unsafe path"),
        "stderr did not mention unsafe path: {stderr}"
    );
    assert!(
        stderr.contains(path_hint),
        "stderr did not mention rejected path {path_hint}: {stderr}"
    );
}

#[cfg(unix)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlink alias check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_file(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlink alias check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_file_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping pack symlink alias check: symlink helper unsupported on this platform");
    false
}

#[cfg(unix)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlink parent check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_dir(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlink parent check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_dir_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping pack symlink parent check: symlink helper unsupported on this platform");
    false
}

#[test]
fn pack_dot_input_uses_current_directory_name() {
    let test_dir = TestDir::new("pack-dot");
    let source_dir = test_dir.path().join("source");
    let archive_path = test_dir.path().join("archive.enc");
    let header_path = test_dir.path().join("header.bin");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();

    let output = run_pack(
        &source_dir,
        &["--header", header_path.to_str().unwrap()],
        &["."],
        archive_path.to_str().unwrap(),
    );

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let names = decrypt_manifest_entry_names(&archive_path, Some(&header_path));

    assert_eq!(
        names,
        vec![
            "source/",
            "source/hello.txt",
            "source/nested/",
            "source/nested/world.txt",
        ]
    );
}

#[test]
fn pack_rejects_generated_output_inside_source_and_keeps_source() {
    let test_dir = TestDir::new("pack-generated-output-inside-source");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    let output_path = source_dir.join("archive.enc");

    let output = run_pack(
        test_dir.path(),
        &[],
        &["source"],
        output_path.to_str().unwrap(),
    );

    assert_alias_rejected(&output);
    assert_eq!(fs::read(source_dir.join("hello.txt")).unwrap(), b"hello");
    assert!(!output_path.exists());
}

#[test]
fn pack_rejects_generated_detached_header_inside_source_and_keeps_source() {
    let test_dir = TestDir::new("pack-generated-header-inside-source");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    let header_path = source_dir.join("header.bin");
    let archive_path = test_dir.path().join("archive.enc");

    let output = run_pack(
        test_dir.path(),
        &["--header", header_path.to_str().unwrap()],
        &["source"],
        archive_path.to_str().unwrap(),
    );

    assert_alias_rejected(&output);
    assert_eq!(fs::read(source_dir.join("hello.txt")).unwrap(), b"hello");
    assert!(!header_path.exists());
    assert!(!archive_path.exists());
}

#[test]
fn pack_rejects_hardlink_generated_output_alias_and_preserves_source() {
    let test_dir = TestDir::new("pack-hardlink-generated-output");
    let source_dir = test_dir.path().join("source");
    let source_file = source_dir.join("hello.txt");
    let output_path = test_dir.path().join("archive.enc");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(&source_file, b"hello").unwrap();

    if let Err(err) = fs::hard_link(&source_file, &output_path) {
        eprintln!("skipping pack hardlink alias check: hard links unsupported here: {err}");
        return;
    }

    let output = run_pack(
        test_dir.path(),
        &[],
        &["source"],
        output_path.to_str().unwrap(),
    );

    assert_alias_rejected(&output);
    assert_eq!(fs::read(&source_file).unwrap(), b"hello");
    assert_eq!(fs::read(&output_path).unwrap(), b"hello");
}

#[test]
fn pack_rejects_symlink_generated_output_alias_and_preserves_source() {
    let test_dir = TestDir::new("pack-symlink-generated-output");
    let source_dir = test_dir.path().join("source");
    let source_file = source_dir.join("hello.txt");
    let output_path = test_dir.path().join("archive.enc");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(&source_file, b"hello").unwrap();

    if !symlink_file_or_skip(&source_file, &output_path) {
        return;
    }

    let output = run_pack(
        test_dir.path(),
        &[],
        &["source"],
        output_path.to_str().unwrap(),
    );

    assert_unsafe_path_rejected(&output, "archive.enc");
    assert_eq!(fs::read(&source_file).unwrap(), b"hello");
    assert_eq!(fs::read(&output_path).unwrap(), b"hello");
}

#[test]
fn pack_rejects_symlinked_file_source() {
    let test_dir = TestDir::new("pack-symlinked-file-source");
    let source_dir = test_dir.path().join("source");
    let source_file = source_dir.join("real.txt");
    let symlink_path = source_dir.join("link.txt");
    let archive_path = test_dir.path().join("archive.enc");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(&source_file, b"real").unwrap();

    if !symlink_file_or_skip(&source_file, &symlink_path) {
        return;
    }

    let output = run_pack(test_dir.path(), &[], &["source"], "archive.enc");

    assert!(
        !output.status.success(),
        "pack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unsafe path"),
        "stderr did not mention unsafe path: {stderr}"
    );
    assert!(
        stderr.contains("link.txt"),
        "stderr did not mention rejected symlink path: {stderr}"
    );
    assert_eq!(fs::read(&source_file).unwrap(), b"real");
    assert!(!archive_path.exists());
}

#[test]
fn pack_rejects_source_root_with_symlinked_parent_prefix() {
    let test_dir = TestDir::new("pack-source-parent-symlink");
    let outside = test_dir.path().join("outside");
    let source_dir = outside.join("source");
    let parent_link = test_dir.path().join("link");
    let archive_path = test_dir.path().join("archive.enc");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("real.txt"), b"real").unwrap();

    if !symlink_dir_or_skip(&outside, &parent_link) {
        return;
    }

    let output = run_pack(test_dir.path(), &[], &["link/source"], "archive.enc");

    assert_unsafe_path_rejected(&output, "link");
    assert_eq!(fs::read(source_dir.join("real.txt")).unwrap(), b"real");
    assert!(!archive_path.exists());
}

#[test]
fn pack_rejects_generated_output_with_symlinked_parent_prefix() {
    let test_dir = TestDir::new("pack-output-parent-symlink");
    let source_dir = test_dir.path().join("source");
    let outside = test_dir.path().join("outside");
    let parent_link = test_dir.path().join("link");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("real.txt"), b"real").unwrap();
    fs::create_dir_all(&outside).unwrap();

    if !symlink_dir_or_skip(&outside, &parent_link) {
        return;
    }

    let output = run_pack(test_dir.path(), &[], &["source"], "link/archive.enc");

    assert_unsafe_path_rejected(&output, "link");
    assert_eq!(fs::read(source_dir.join("real.txt")).unwrap(), b"real");
    assert!(!outside.join("archive.enc").exists());
}

#[test]
fn pack_rejects_generated_detached_header_with_symlinked_parent_prefix() {
    let test_dir = TestDir::new("pack-header-parent-symlink");
    let source_dir = test_dir.path().join("source");
    let outside = test_dir.path().join("outside");
    let parent_link = test_dir.path().join("link");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("real.txt"), b"real").unwrap();
    fs::create_dir_all(&outside).unwrap();

    if !symlink_dir_or_skip(&outside, &parent_link) {
        return;
    }

    let output = run_pack(
        test_dir.path(),
        &["--header", "link/archive.hdr"],
        &["source"],
        "archive.enc",
    );

    assert_unsafe_path_rejected(&output, "link");
    assert_eq!(fs::read(source_dir.join("real.txt")).unwrap(), b"real");
    assert!(!outside.join("archive.hdr").exists());
    assert!(!test_dir.path().join("archive.enc").exists());
}

#[test]
fn pack_duplicate_basenames_uses_unique_archive_roots() {
    let test_dir = TestDir::new("pack-duplicate-basenames");
    let parent1 = test_dir.path().join("parent1/foo/sub");
    let parent2 = test_dir.path().join("parent2/foo/sub");
    fs::create_dir_all(&parent1).unwrap();
    fs::create_dir_all(&parent2).unwrap();
    fs::write(parent1.join("one.txt"), b"one").unwrap();
    fs::write(parent2.join("two.txt"), b"two").unwrap();

    let output = run_pack(
        test_dir.path(),
        &[],
        &["parent1/foo", "parent2/foo"],
        "archive.enc",
    );

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let names = decrypt_manifest_entry_names(&test_dir.path().join("archive.enc"), None);

    assert_eq!(
        names,
        vec![
            "parent1/foo/",
            "parent1/foo/sub/",
            "parent1/foo/sub/one.txt",
            "parent2/foo/",
            "parent2/foo/sub/",
            "parent2/foo/sub/two.txt",
        ]
    );
}

#[test]
fn pack_mixed_nested_roots_do_not_leak_current_directory_name() {
    let test_dir = TestDir::new("pack-mixed-nested-roots");
    let foo_dir = test_dir.path().join("foo");
    let nested_dir = test_dir.path().join("bar/foo");
    fs::create_dir_all(&foo_dir).unwrap();
    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(foo_dir.join("one.txt"), b"one").unwrap();
    fs::write(nested_dir.join("two.txt"), b"two").unwrap();

    let output = run_pack(test_dir.path(), &[], &["foo", "bar/foo"], "archive.enc");

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let names = decrypt_manifest_entry_names(&test_dir.path().join("archive.enc"), None);

    assert_eq!(
        names,
        vec!["bar/foo/", "bar/foo/two.txt", "foo/", "foo/one.txt",]
    );
}

#[test]
fn pack_verbose_reports_archived_entries() {
    let test_dir = TestDir::new("pack-verbose");
    let source_dir = test_dir.path().join("source");
    let archive_path = test_dir.path().join("archive.enc");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();

    let output = run_pack(&source_dir, &["-v"], &["."], archive_path.to_str().unwrap());

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[i] Packing source/hello.txt"));
    assert!(stdout.contains("[i] Packing source/nested/world.txt"));
}

#[test]
fn pack_recursive_flag_matches_default_recursive_behavior() {
    let test_dir = TestDir::new("pack-recursive-alias");
    let default_dir = test_dir.path().join("default/source");
    let recursive_dir = test_dir.path().join("recursive/source");
    let default_archive = test_dir.path().join("default.enc");
    let recursive_archive = test_dir.path().join("recursive.enc");
    fs::create_dir_all(default_dir.join("nested/deeper")).unwrap();
    fs::create_dir_all(recursive_dir.join("nested/deeper")).unwrap();
    fs::write(default_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(default_dir.join("nested/deeper/world.txt"), b"world").unwrap();
    fs::write(recursive_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(recursive_dir.join("nested/deeper/world.txt"), b"world").unwrap();

    let default_output = run_pack(&default_dir, &[], &["."], default_archive.to_str().unwrap());
    let recursive_output = run_pack(
        &recursive_dir,
        &["-r"],
        &["."],
        recursive_archive.to_str().unwrap(),
    );

    assert!(
        default_output.status.success(),
        "default pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&default_output.stdout),
        String::from_utf8_lossy(&default_output.stderr)
    );
    assert!(
        recursive_output.status.success(),
        "recursive pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&recursive_output.stdout),
        String::from_utf8_lossy(&recursive_output.stderr)
    );

    let default_names = decrypt_manifest_entry_names(&default_archive, None);
    let recursive_names = decrypt_manifest_entry_names(&recursive_archive, None);

    assert_eq!(default_names, recursive_names);
    assert!(default_names.contains(&"source/nested/deeper/world.txt".to_string()));
}

#[test]
fn pack_delete_source_removes_source_directory_after_success() {
    let test_dir = TestDir::new("pack-delete-source");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();

    let output = run_pack(
        test_dir.path(),
        &["--delete-source"],
        &["source"],
        "archive.enc",
    );

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!source_dir.exists());
    assert!(test_dir.path().join("archive.enc").exists());
}

#[test]
fn pack_delete_source_rejects_output_inside_source_and_keeps_source() {
    let test_dir = TestDir::new("pack-delete-source-output-inside-source");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();
    let output_path = source_dir.join("archive.enc");

    let output = run_pack(
        test_dir.path(),
        &["--delete-source"],
        &["source"],
        output_path.to_str().unwrap(),
    );

    assert_alias_rejected(&output);
    assert!(source_dir.exists());
    assert!(source_dir.join("hello.txt").exists());
    assert!(!output_path.exists());
}

#[test]
fn pack_delete_source_rejects_detached_header_inside_source_and_keeps_source() {
    let test_dir = TestDir::new("pack-delete-source-header-inside-source");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();
    let header_path = source_dir.join("header.bin");
    let archive_path = test_dir.path().join("archive.enc");

    let output = run_pack(
        test_dir.path(),
        &["--delete-source", "--header", header_path.to_str().unwrap()],
        &["source"],
        archive_path.to_str().unwrap(),
    );

    assert_alias_rejected(&output);
    assert!(source_dir.exists());
    assert!(source_dir.join("hello.txt").exists());
    assert!(!header_path.exists());
    assert!(!archive_path.exists());
}

#[test]
fn pack_delete_source_rejects_archive_limit_failure_and_keeps_source() {
    let test_dir = TestDir::new("pack-delete-source-archive-limit");
    let deep_file = create_deep_source_file(test_dir.path(), 65);

    let output = run_pack(
        test_dir.path(),
        &["--delete-source"],
        &["source"],
        "archive.enc",
    );

    assert!(
        !output.status.success(),
        "pack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Archive limit error"),
        "stderr did not mention archive limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&deep_file).unwrap(), b"deep");
    assert!(!test_dir.path().join("archive.enc").exists());
}

#[test]
fn pack_detached_partial_publication_source_gate_names_generated_artifact_state() {
    assert!(
        DOMAIN_PACK_SOURCE.contains("DetachedPublication(TransactionError)"),
        "pack domain errors must preserve a detached-publication error variant"
    );
    assert!(
        DOMAIN_PACK_SOURCE.contains("has_detached_header")
            && DOMAIN_PACK_SOURCE.contains("map_detached_publication_transaction_error"),
        "pack must only map linked commit partials as detached publication when a header target exists"
    );
    assert!(
        DOMAIN_PACK_SOURCE.contains("PathRole::GeneratedOutput")
            && DOMAIN_PACK_SOURCE.contains("PathRole::GeneratedDetachedHeader"),
        "pack detached publication must preserve generated payload/header roles"
    );
    assert!(
        CLI_ERROR_MAPPER_SOURCE.contains("Detached publication incomplete")
            && CLI_ERROR_MAPPER_SOURCE.contains("payload")
            && CLI_ERROR_MAPPER_SOURCE.contains("header")
            && CLI_ERROR_MAPPER_SOURCE.contains("source cleanup was not authorized"),
        "CLI detached pack diagnostics must name artifact state and cleanup denial"
    );
}

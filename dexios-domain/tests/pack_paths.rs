#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use core::header::{ParsedHeader, read_header};
use core::kdf::Kdf;
use core::payload::{ManifestEntryKind, ManifestFirstPayload, PayloadFramingProfile, PayloadKind};
use core::protected::Protected;
use dexios_domain::archive::{ArchiveLimitKind, ArchivePolicy};
use dexios_domain::decrypt;
use dexios_domain::pack::{self, DetachedHeaderTarget, PackIntent};
use dexios_domain::storage::identity::OverwritePolicy;
#[cfg(unix)]
use dexios_domain::workflow_error::WorkflowErrorClass;

const PASSWORD: &[u8; 8] = b"12345678";
const DOMAIN_PACK_RS: &str = include_str!("../src/pack.rs");

fn create_source_dir(root: &Path) -> PathBuf {
    let source_dir = root.join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();
    source_dir
}

#[test]
fn pack_streaming_source_gate_removes_plaintext_temp_zip_creation() {
    assert!(
        DOMAIN_PACK_RS.contains("begin_v1_manifest_archive_writer"),
        "ARCH-01 pack must use the manifest archive encrypted writer"
    );
    assert!(
        DOMAIN_PACK_RS.contains("ArchiveManifest")
            && DOMAIN_PACK_RS.contains("ArchiveBodyFrameHeader"),
        "ARCH-01 pack must write Dexios manifest-first payload framing"
    );
    assert!(
        !DOMAIN_PACK_RS.contains("zip::ZipWriter::new_stream"),
        "ARCH-01 pack must not write canonical archives through a normal ZIP writer"
    );
    assert!(
        !DOMAIN_PACK_RS.contains("create_temp_artifact"),
        "ARCH-01 pack execution must not create a plaintext temporary archive artifact"
    );
}

fn create_deep_source_file(root: &Path, depth: usize) -> (PathBuf, PathBuf) {
    let source_dir = root.join("source");
    let mut nested_dir = source_dir.clone();
    for index in 0..depth {
        nested_dir.push(format!("dir{index}"));
    }
    fs::create_dir_all(&nested_dir).unwrap();
    let file_path = nested_dir.join("deep.txt");
    fs::write(&file_path, b"deep").unwrap();
    (source_dir, file_path)
}

fn pack_intent(
    source_paths: Vec<PathBuf>,
    output_path: &Path,
    detached_header_path: Option<&Path>,
) -> Result<PackIntent, pack::Error> {
    PackIntent::new(
        source_paths,
        output_path,
        OverwritePolicy::CreateNew,
        detached_header_path
            .map(|path| DetachedHeaderTarget::new(path, OverwritePolicy::CreateNew)),
        Protected::new(PASSWORD.to_vec()),
        Kdf::Argon2id,
        ArchivePolicy::default(),
        true,
        None,
    )
}

fn decrypted_manifest_archive(
    archive_path: &Path,
    header_path: Option<&Path>,
) -> ManifestFirstPayload {
    let decrypted_path = archive_path.with_extension("dxar");
    let decrypt_intent = decrypt::DecryptIntent::new(
        archive_path,
        &decrypted_path,
        OverwritePolicy::CreateNew,
        header_path,
        Protected::new(PASSWORD.to_vec()),
        None,
    )
    .unwrap();
    decrypt::execute(decrypt_intent).unwrap();

    let bytes = fs::read(decrypted_path).unwrap();
    ManifestFirstPayload::parse(&bytes).unwrap()
}

fn decrypted_archive_entry_names(archive_path: &Path, header_path: Option<&Path>) -> Vec<String> {
    let payload = decrypted_manifest_archive(archive_path, header_path);
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

#[cfg(unix)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlinked file check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_file_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_file(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlinked file check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_file_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!("skipping pack symlinked file check: symlink helper unsupported on this platform");
    false
}

#[cfg(unix)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlinked directory check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_dir(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping pack symlinked directory check: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_dir_or_skip(_src: &Path, _dst: &Path) -> bool {
    eprintln!(
        "skipping pack symlinked directory check: symlink helper unsupported on this platform"
    );
    false
}

#[test]
fn pack_rejects_source_root_symlink() {
    let root = tempfile::tempdir().unwrap();
    let target_dir = root.path().join("target");
    let source_link = root.path().join("source_link");
    let output_path = root.path().join("archive.enc");
    fs::create_dir_all(&target_dir).unwrap();
    fs::write(target_dir.join("hello.txt"), b"hello").unwrap();

    if !symlink_dir_or_skip(&target_dir, &source_link) {
        return;
    }

    let result = pack_intent(vec![source_link.clone()], &output_path, None)
        .and_then(pack::execute_transactional);

    assert!(
        matches!(result, Err(pack::Error::SymlinkSource(ref path)) if path == &source_link),
        "expected source root symlink rejection for {}, got {result:?}",
        source_link.display()
    );
    assert!(!output_path.exists());
}

#[cfg(unix)]
#[test]
fn pack_rejects_source_root_replaced_after_intent_capture() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    let original_dir = root.path().join("original-source");
    let output_path = root.path().join("archive.enc");
    let header_path = root.path().join("archive.header");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("original-only.txt"), b"original").unwrap();

    let intent = pack_intent(vec![source_dir.clone()], &output_path, Some(&header_path)).unwrap();

    fs::rename(&source_dir, &original_dir).unwrap();
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("replacement-only.txt"), b"replacement").unwrap();

    let result = pack::execute_transactional(intent);

    if output_path.exists() && header_path.exists() {
        let names = decrypted_archive_entry_names(&output_path, Some(&header_path));
        assert!(
            !names.contains(&"source/replacement-only.txt".to_string()),
            "replaced source-root content must never be committed to the archive"
        );
    }

    let error = result.expect_err("replaced source root must fail before commit");
    assert!(
        matches!(
            error.workflow_class(),
            WorkflowErrorClass::UnsafePath | WorkflowErrorClass::IoFailure
        ),
        "replaced source root must fail as unsafe path or read-source failure, got {error:?}"
    );
    assert!(
        !output_path.exists(),
        "generated archive output must not be committed after source-root replacement"
    );
    assert!(
        !header_path.exists(),
        "detached header output must not be committed after source-root replacement"
    );
}

#[test]
fn pack_rejects_symlinked_file_entry() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    let outside_file = root.path().join("outside.txt");
    let symlink_path = source_dir.join("link.txt");
    let output_path = root.path().join("archive.enc");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("real.txt"), b"real").unwrap();
    fs::write(&outside_file, b"outside").unwrap();

    if !symlink_file_or_skip(&outside_file, &symlink_path) {
        return;
    }

    let result =
        pack_intent(vec![source_dir], &output_path, None).and_then(pack::execute_transactional);

    assert!(
        matches!(result, Err(pack::Error::SymlinkSource(ref path)) if path == &symlink_path),
        "expected symlinked file rejection for {}, got {result:?}",
        symlink_path.display()
    );
    assert!(!output_path.exists());
}

#[test]
fn pack_rejects_symlinked_directory_entry() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    let outside_dir = root.path().join("outside");
    let symlink_path = source_dir.join("linkdir");
    let output_path = root.path().join("archive.enc");
    fs::create_dir_all(&source_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();
    fs::write(source_dir.join("real.txt"), b"real").unwrap();
    fs::write(outside_dir.join("secret.txt"), b"secret").unwrap();

    if !symlink_dir_or_skip(&outside_dir, &symlink_path) {
        return;
    }

    let result =
        pack_intent(vec![source_dir], &output_path, None).and_then(pack::execute_transactional);

    assert!(
        matches!(result, Err(pack::Error::SymlinkSource(ref path)) if path == &symlink_path),
        "expected symlinked directory rejection for {}, got {result:?}",
        symlink_path.display()
    );
    assert!(!output_path.exists());
}

#[test]
fn pack_recursive_real_tree_still_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = create_source_dir(root.path());
    let output_path = root.path().join("archive.enc");

    let intent = pack_intent(vec![source_dir], &output_path, None).unwrap();
    pack::execute_transactional(intent).unwrap();

    let names = decrypted_archive_entry_names(&output_path, None);

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
fn pack_intent_rejects_generated_output_inside_source_before_creating_output() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = create_source_dir(root.path());
    let output_path = source_dir.join("archive.dexios");

    let result = pack_intent(vec![source_dir.clone()], &output_path, None);

    assert!(
        matches!(result, Err(pack::Error::PathIdentity(_))),
        "D-06 generated output inside a source tree must fail at the validated pack intent boundary"
    );
    assert!(!output_path.exists());
    assert_eq!(fs::read(source_dir.join("hello.txt")).unwrap(), b"hello");
}

#[test]
fn pack_intent_rejects_generated_detached_header_inside_source_before_creating_outputs() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = create_source_dir(root.path());
    let output_path = root.path().join("archive.dexios");
    let header_path = source_dir.join("archive.header");

    let result = pack_intent(vec![source_dir.clone()], &output_path, Some(&header_path));

    assert!(
        matches!(result, Err(pack::Error::PathIdentity(_))),
        "D-07 generated detached header inside a source tree must fail at the validated pack intent boundary"
    );
    assert!(!output_path.exists());
    assert!(!header_path.exists());
    assert_eq!(fs::read(source_dir.join("hello.txt")).unwrap(), b"hello");
}

#[test]
fn pack_intent_preserves_existing_dexios_looking_files_as_user_data() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = create_source_dir(root.path());
    fs::write(source_dir.join("old.dexios"), b"old encrypted archive").unwrap();
    fs::write(source_dir.join("archive.header"), b"old detached header").unwrap();
    fs::write(source_dir.join("archive.sig"), b"old signature").unwrap();
    let output_path = root.path().join("archive.dexios");

    let intent = pack_intent(vec![source_dir], &output_path, None).unwrap();
    pack::execute_transactional(intent).unwrap();

    let names = decrypted_archive_entry_names(&output_path, None);
    assert!(
        names.contains(&"source/old.dexios".to_string()),
        "D-08 old .dexios files are ordinary source data"
    );
    assert!(
        names.contains(&"source/archive.header".to_string()),
        "D-08 detached-header-looking files are ordinary source data"
    );
    assert!(
        names.contains(&"source/archive.sig".to_string()),
        "D-08 signature-looking files are ordinary source data"
    );
}

#[test]
fn pack_writes_relative_archive_paths() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = create_source_dir(root.path());
    let output_path = root.path().join("archive.enc");

    let intent = pack_intent(vec![source_dir], &output_path, None).unwrap();
    pack::execute_transactional(intent).unwrap();

    let output_bytes = fs::read(&output_path).unwrap();
    let parsed = read_header(&mut Cursor::new(&output_bytes)).unwrap();
    let ParsedHeader::V1(payload) = parsed;
    assert_eq!(payload.header().keyslots().len(), 1);
    assert_eq!(
        payload.header().payload_kind(),
        PayloadKind::ManifestArchive
    );
    assert_eq!(
        payload.header().payload_framing(),
        PayloadFramingProfile::ManifestFirst
    );

    let names = decrypted_archive_entry_names(&output_path, None);

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
fn pack_does_not_delete_source_directory_or_files() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = create_source_dir(root.path());
    let output_path = root.path().join("archive.enc");

    let intent = pack_intent(vec![source_dir.clone()], &output_path, None).unwrap();
    pack::execute_transactional(intent).unwrap();

    assert!(source_dir.exists());
    assert!(source_dir.join("hello.txt").exists());
    assert!(source_dir.join("nested/world.txt").exists());
}

#[test]
fn pack_rejects_path_deeper_than_archive_limit_and_preserves_source() {
    let root = tempfile::tempdir().unwrap();
    let (source_dir, deep_file) = create_deep_source_file(root.path(), 65);
    let output_path = root.path().join("archive.enc");

    let result = pack_intent(vec![source_dir], &output_path, None)
        .and_then(pack::execute_transactional);

    assert!(
        matches!(
            result,
            Err(pack::Error::ArchiveLimit(ref err))
                if err.kind == ArchiveLimitKind::NormalizedPathDepth
        ),
        "expected normalized path depth archive limit, got {result:?}"
    );
    assert_eq!(fs::read(&deep_file).unwrap(), b"deep");
    assert!(!output_path.exists());
}

#[test]
fn pack_arch_04_d16_temp_cleanup_on_limit_failure_keeps_source_and_output_absent() {
    let root = tempfile::tempdir().unwrap();
    let (source_dir, deep_file) = create_deep_source_file(root.path(), 65);
    let output_path = root.path().join("archive.enc");

    let result =
        pack_intent(vec![source_dir], &output_path, None).and_then(pack::execute_transactional);

    assert!(matches!(result, Err(pack::Error::ArchiveLimit(_))));
    assert_eq!(fs::read(&deep_file).unwrap(), b"deep");
    assert!(!output_path.exists());
}

#[test]
fn pack_d21_representative_large_tree_materializes_expected_entries() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    for dir_index in 0..6 {
        let nested = source_dir.join(format!("dir{dir_index}"));
        fs::create_dir_all(&nested).unwrap();
        for file_index in 0..3 {
            fs::write(
                nested.join(format!("file{file_index}.txt")),
                format!("{dir_index}:{file_index}"),
            )
            .unwrap();
        }
    }
    fs::write(source_dir.join("root.txt"), b"root").unwrap();
    let output_path = root.path().join("archive.enc");

    let intent = pack_intent(vec![source_dir], &output_path, None).unwrap();
    pack::execute_transactional(intent).unwrap();

    let names = decrypted_archive_entry_names(&output_path, None);

    assert_eq!(names.len(), 26, "D-21 representative tree entry count");
    assert!(names.contains(&"source/".to_string()));
    assert!(names.contains(&"source/root.txt".to_string()));
    assert!(names.contains(&"source/dir0/".to_string()));
    assert!(names.contains(&"source/dir0/file0.txt".to_string()));
    assert!(names.contains(&"source/dir5/file2.txt".to_string()));
}

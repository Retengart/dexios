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
#[path = "support/tempdir.rs"]
mod tempdir;

#[cfg(unix)]
use std::error::Error as _;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use core::header::{read_header, ParsedHeader};
use core::kdf::Kdf;
use core::payload::{ManifestEntryKind, ManifestFirstPayload, PayloadFramingProfile, PayloadKind};
use core::protected::Protected;
use dexios_domain::archive::{ArchiveLimitKind, ArchivePolicy};
use dexios_domain::decrypt;
use dexios_domain::pack::{self, DetachedHeaderTarget, PackIntent};
use dexios_domain::storage::identity::OverwritePolicy;
#[cfg(unix)]
use dexios_domain::workflow_error::WorkflowErrorClass;
use tempdir::canonical_tempdir;

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

#[cfg(unix)]
fn assert_replacement_path_error_class_and_source(error: &pack::Error, label: &str) {
    let class = error.workflow_class();
    assert!(
        matches!(
            class,
            WorkflowErrorClass::UnsafePath | WorkflowErrorClass::IoFailure
        ),
        "{label} must fail as unsafe path or IO failure, not malformed archive, crypto, or callback-adjacent classification; got {class:?} from {error:?}"
    );
    assert!(
        !matches!(
            class,
            WorkflowErrorClass::MalformedFormat
                | WorkflowErrorClass::KdfFailure
                | WorkflowErrorClass::AuthenticationFailure
                | WorkflowErrorClass::Other
        ),
        "{label} replacement-path failure must not be hidden as unrelated workflow class {class:?}"
    );
    if matches!(class, WorkflowErrorClass::IoFailure) {
        assert!(
            error.source().is_some(),
            "{label} IO-class replacement failure must preserve its storage/source error"
        );
    }
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

fn manifest_entry_names(payload: &ManifestFirstPayload) -> Vec<String> {
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

fn decrypted_archive_entry_names(archive_path: &Path, header_path: Option<&Path>) -> Vec<String> {
    let payload = decrypted_manifest_archive(archive_path, header_path);
    manifest_entry_names(&payload)
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

fn observed_leaf_path_matches(actual: &Path, expected: &Path) -> bool {
    if actual == expected {
        return true;
    }
    let Some(parent) = expected.parent() else {
        return false;
    };
    let Some(file_name) = expected.file_name() else {
        return false;
    };
    fs::canonicalize(parent)
        .is_ok_and(|canonical_parent| actual == canonical_parent.join(file_name))
}

#[test]
fn pack_rejects_source_root_symlink() {
    let (_root_dir, root) = canonical_tempdir();
    let target_dir = root.join("target");
    let source_link = root.join("source_link");
    let output_path = root.join("archive.enc");
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
fn pack_rejects_filename_containing_windows_separator_byte() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = root.join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("dir\\file.txt"), b"ambiguous").unwrap();
    let output_path = root.join("archive.enc");

    let result = PackIntent::new(
        vec![&source_dir],
        &output_path,
        OverwritePolicy::CreateNew,
        None,
        Protected::new(PASSWORD.to_vec()),
        Kdf::Argon2id,
        ArchivePolicy::default(),
        true,
        None,
    );

    assert!(
        result.is_err(),
        "pack must reject archive names containing a Windows separator byte"
    );
}

#[cfg(unix)]
#[test]
fn pack_rejects_source_root_replaced_after_intent_capture() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = root.join("source");
    let original_dir = root.join("original-source");
    let output_path = root.join("archive.enc");
    let header_path = root.join("archive.header");
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
    assert_replacement_path_error_class_and_source(&error, "replaced source root");
    assert!(
        !output_path.exists(),
        "generated archive output must not be committed after source-root replacement"
    );
    assert!(
        !header_path.exists(),
        "detached header output must not be committed after source-root replacement"
    );
}

#[cfg(all(unix, feature = "test-support"))]
#[test]
fn pack_rejects_walked_file_replaced_between_metadata_and_open() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = root.join("source");
    let target_file = source_dir.join("target.txt");
    let original_file = root.join("target-original.txt");
    let output_path = root.join("archive.enc");
    let header_path = root.join("archive.header");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(&target_file, b"original").unwrap();

    let swapped = std::rc::Rc::new(std::cell::Cell::new(false));
    let swapped_for_observer = std::rc::Rc::clone(&swapped);
    let observed_target = target_file.clone();
    let replacement_target = target_file.clone();
    let original_target = original_file.clone();
    let intent = pack_intent(vec![source_dir], &output_path, Some(&header_path))
        .unwrap()
        .with_walked_entry_after_metadata_observer(Box::new(move |walked_path| {
            if walked_path == observed_target && !swapped_for_observer.replace(true) {
                fs::rename(&replacement_target, &original_target).unwrap();
                fs::write(&replacement_target, b"replacement").unwrap();
            }
        }));

    let result = pack::execute_transactional(intent);

    assert!(
        swapped.get(),
        "regression must replace the walked file after traversal metadata is captured"
    );
    if output_path.exists() && header_path.exists() {
        let names = decrypted_archive_entry_names(&output_path, Some(&header_path));
        assert!(
            !names.contains(&"source/target.txt".to_string()),
            "replacement content must never be accepted as the walked archive entry"
        );
    }
    let error = result.expect_err("swapped walked pack entry must be rejected before commit");
    assert_replacement_path_error_class_and_source(&error, "swapped walked pack entry");
    assert!(
        !output_path.exists(),
        "generated archive output must not be committed after walked entry replacement"
    );
    assert!(
        !header_path.exists(),
        "detached header output must not be committed after walked entry replacement"
    );
    assert_eq!(fs::read(&target_file).unwrap(), b"replacement");
    assert_eq!(fs::read(&original_file).unwrap(), b"original");
}

#[test]
fn pack_rejects_symlinked_file_entry() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = root.join("source");
    let outside_file = root.join("outside.txt");
    let symlink_path = source_dir.join("link.txt");
    let output_path = root.join("archive.enc");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("real.txt"), b"real").unwrap();
    fs::write(&outside_file, b"outside").unwrap();

    if !symlink_file_or_skip(&outside_file, &symlink_path) {
        return;
    }

    let result =
        pack_intent(vec![source_dir], &output_path, None).and_then(pack::execute_transactional);

    assert!(
        matches!(result, Err(pack::Error::SymlinkSource(ref path)) if observed_leaf_path_matches(path, &symlink_path)),
        "expected symlinked file rejection for {}, got {result:?}",
        symlink_path.display()
    );
    assert!(!output_path.exists());
}

#[test]
fn pack_rejects_symlinked_directory_entry() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = root.join("source");
    let outside_dir = root.join("outside");
    let symlink_path = source_dir.join("linkdir");
    let output_path = root.join("archive.enc");
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
        matches!(result, Err(pack::Error::SymlinkSource(ref path)) if observed_leaf_path_matches(path, &symlink_path)),
        "expected symlinked directory rejection for {}, got {result:?}",
        symlink_path.display()
    );
    assert!(!output_path.exists());
}

#[test]
fn pack_recursive_real_tree_still_succeeds() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = create_source_dir(&root);
    let output_path = root.join("archive.enc");

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
fn pack_recursive_detached_header_preserves_v1_manifest_first_payload() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = create_source_dir(&root);
    let output_path = root.join("archive.enc");
    let header_path = root.join("archive.header");

    let intent = pack_intent(vec![source_dir.clone()], &output_path, Some(&header_path)).unwrap();
    pack::execute_transactional(intent).unwrap();

    let header_bytes = fs::read(&header_path).unwrap();
    let ParsedHeader::V1(parsed_header) = read_header(&mut Cursor::new(&header_bytes)).unwrap();
    assert_eq!(
        parsed_header.header().payload_kind(),
        PayloadKind::ManifestArchive
    );
    assert_eq!(
        parsed_header.header().payload_framing(),
        PayloadFramingProfile::ManifestFirst
    );

    let payload = decrypted_manifest_archive(&output_path, Some(&header_path));
    assert_eq!(
        manifest_entry_names(&payload),
        vec![
            "source/",
            "source/hello.txt",
            "source/nested/",
            "source/nested/world.txt",
        ]
    );
    assert_eq!(
        payload.body_frames().len(),
        2,
        "manifest-first payload must keep body frames only for file entries"
    );

    for (entry_name, expected_body) in [
        ("source/hello.txt", b"hello".as_slice()),
        ("source/nested/world.txt", b"world".as_slice()),
    ] {
        let entry_index = payload
            .manifest()
            .entries()
            .iter()
            .position(|entry| entry.normalized_path() == entry_name.as_bytes())
            .unwrap_or_else(|| panic!("missing manifest entry {entry_name}"));
        let frame = payload
            .body_frames()
            .iter()
            .find(|frame| frame.entry_index() == u32::try_from(entry_index).unwrap())
            .unwrap_or_else(|| panic!("missing body frame for {entry_name}"));
        assert_eq!(frame.body(), expected_body);
        assert_eq!(
            payload.manifest().entries()[entry_index].body_len(),
            Some(u64::try_from(expected_body.len()).unwrap())
        );
    }

    assert_eq!(fs::read(source_dir.join("hello.txt")).unwrap(), b"hello");
    assert_eq!(
        fs::read(source_dir.join("nested/world.txt")).unwrap(),
        b"world"
    );
}

#[test]
fn pack_intent_rejects_generated_output_inside_source_before_creating_output() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = create_source_dir(&root);
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
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = create_source_dir(&root);
    let output_path = root.join("archive.dexios");
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
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = create_source_dir(&root);
    fs::write(source_dir.join("old.dexios"), b"old encrypted archive").unwrap();
    fs::write(source_dir.join("archive.header"), b"old detached header").unwrap();
    fs::write(source_dir.join("archive.sig"), b"old signature").unwrap();
    let output_path = root.join("archive.dexios");

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
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = create_source_dir(&root);
    let output_path = root.join("archive.enc");

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
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = create_source_dir(&root);
    let output_path = root.join("archive.enc");

    let intent = pack_intent(vec![source_dir.clone()], &output_path, None).unwrap();
    pack::execute_transactional(intent).unwrap();

    assert!(source_dir.exists());
    assert!(source_dir.join("hello.txt").exists());
    assert!(source_dir.join("nested/world.txt").exists());
}

#[test]
fn pack_rejects_path_deeper_than_archive_limit_and_preserves_source() {
    let (_root_dir, root) = canonical_tempdir();
    let (source_dir, deep_file) = create_deep_source_file(&root, 65);
    let output_path = root.join("archive.enc");

    let result =
        pack_intent(vec![source_dir], &output_path, None).and_then(pack::execute_transactional);

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
fn pack_limit_failure_keeps_source_and_removes_output() {
    let (_root_dir, root) = canonical_tempdir();
    let (source_dir, deep_file) = create_deep_source_file(&root, 65);
    let output_path = root.join("archive.enc");

    let result =
        pack_intent(vec![source_dir], &output_path, None).and_then(pack::execute_transactional);

    assert!(matches!(result, Err(pack::Error::ArchiveLimit(_))));
    assert_eq!(fs::read(&deep_file).unwrap(), b"deep");
    assert!(!output_path.exists());
}

#[test]
fn pack_representative_large_tree_materializes_expected_entries() {
    let (_root_dir, root) = canonical_tempdir();
    let source_dir = root.join("source");
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
    let output_path = root.join("archive.enc");

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

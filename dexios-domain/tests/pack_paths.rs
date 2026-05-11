use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use core::header::{ParsedHeader, read_header};
use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::archive::ArchivePolicy;
use dexios_domain::decrypt;
use dexios_domain::pack::{self, ArchiveSourceEntry, DetachedHeaderTarget, PackIntent};
use dexios_domain::storage::identity::OverwritePolicy;
use dexios_domain::storage::{FileStorage, Storage};

const PASSWORD: &[u8; 8] = b"12345678";

fn create_source_dir(root: &Path) -> PathBuf {
    let source_dir = root.join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();
    source_dir
}

fn build_archive_entries(
    stor: &Arc<FileStorage>,
    source_dir: &Path,
) -> Vec<ArchiveSourceEntry<fs::File>> {
    let root = stor.read_file(source_dir).unwrap();
    let mut entries = stor.read_dir(&root).unwrap();
    entries.sort_by(|a, b| a.path().cmp(b.path()));

    let root_name = PathBuf::from(source_dir.file_name().unwrap());

    entries
        .into_iter()
        .map(|source| {
            let relative = source.path().strip_prefix(source_dir).unwrap();
            let archive_path = if relative.as_os_str().is_empty() {
                root_name.clone()
            } else {
                root_name.join(relative)
            };

            ArchiveSourceEntry {
                source,
                archive_path,
            }
        })
        .collect()
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
        Kdf::Blake3Balloon,
        ArchivePolicy::default(),
        true,
        None,
    )
}

fn decrypted_archive_entry_names(archive_path: &Path, header_path: Option<&Path>) -> Vec<String> {
    let decrypted_path = archive_path.with_extension("zip");
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
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut names = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect::<Vec<_>>();
    names.sort();
    names
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

    let stor = Arc::new(FileStorage);
    let entries = build_archive_entries(&stor, &source_dir);
    let output_file = stor.create_file(&output_path).unwrap();

    let req = pack::Request {
        entries,
        archive_policy: ArchivePolicy::default(),
        writer: output_file.try_writer().unwrap(),
        header_writer: None,
        raw_key: Protected::new(PASSWORD.to_vec()),
        kdf: Kdf::Blake3Balloon,
    };

    pack::execute(stor.clone(), req).unwrap();
    stor.flush_file(&output_file).unwrap();

    let output_bytes = fs::read(&output_path).unwrap();
    let parsed = read_header(&mut Cursor::new(&output_bytes)).unwrap();
    let ParsedHeader::V1(payload) = parsed;
    assert_eq!(payload.header().keyslots().len(), 1);

    let decrypted_path = root.path().join("archive.zip");
    let decrypt_intent = decrypt::DecryptIntent::new(
        &output_path,
        &decrypted_path,
        OverwritePolicy::CreateNew,
        None::<&Path>,
        Protected::new(PASSWORD.to_vec()),
        None,
    )
    .unwrap();
    decrypt::execute(decrypt_intent).unwrap();

    let bytes = fs::read(decrypted_path).unwrap();
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut names = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect::<Vec<_>>();
    names.sort();

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

    let stor = Arc::new(FileStorage);
    let entries = build_archive_entries(&stor, &source_dir);
    let output_file = stor.create_file(&output_path).unwrap();

    let req = pack::Request {
        entries,
        archive_policy: ArchivePolicy::default(),
        writer: output_file.try_writer().unwrap(),
        header_writer: None,
        raw_key: Protected::new(PASSWORD.to_vec()),
        kdf: Kdf::Blake3Balloon,
    };

    pack::execute(stor, req).unwrap();

    assert!(source_dir.exists());
    assert!(source_dir.join("hello.txt").exists());
    assert!(source_dir.join("nested/world.txt").exists());
}

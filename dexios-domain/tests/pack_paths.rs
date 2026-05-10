use std::cell::RefCell;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use core::header::{ParsedHeader, read_header};
use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::decrypt;
use dexios_domain::pack::{self, ArchiveSourceEntry};
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
        compression_method: zip::CompressionMethod::Stored,
        writer: output_file.try_writer().unwrap(),
        header_writer: None,
        raw_key: Protected::new(PASSWORD.to_vec()),
        kdf: Kdf::Blake3Balloon,
    };

    pack::execute(stor.clone(), req).unwrap();
    stor.flush_file(&output_file).unwrap();

    let output_bytes = fs::read(&output_path).unwrap();
    let (parsed, _aad) = read_header(&mut Cursor::new(&output_bytes)).unwrap();
    let ParsedHeader::V1(header) = parsed;
    assert_eq!(header.keyslots().len(), 1);

    let archive = stor.read_file(&output_path).unwrap();
    let decrypted = RefCell::new(Cursor::new(Vec::new()));
    let decrypt_req = decrypt::Request {
        header_reader: None,
        reader: archive.try_reader().unwrap(),
        writer: &decrypted,
        raw_key: Protected::new(PASSWORD.to_vec()),
        on_decrypted_header: None,
    };
    decrypt::execute(decrypt_req).unwrap();

    let bytes = decrypted.into_inner().into_inner();
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
        compression_method: zip::CompressionMethod::Stored,
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

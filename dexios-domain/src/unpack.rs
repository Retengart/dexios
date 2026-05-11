//! This contains the logic for decrypting a packed zip archive and extracting
//! each file to the target directory.
//!
//! This is known as "unpacking" within Dexios.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::decrypt;
use crate::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
use crate::storage::transaction::{CommitReceipt, LinkedOutputTransaction, TransactionError};
use crate::storage::{self, Storage};
use core::protected::Protected;

trait TempArtifactLike {
    fn with_reader<T, E>(&self, f: impl FnOnce(&mut dyn ReadSeek) -> Result<T, E>) -> Result<T, E>;
    fn with_writer<T, E>(&self, f: impl FnOnce(&mut dyn WriteSeek) -> Result<T, E>)
    -> Result<T, E>;
}

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

trait WriteSeek: Write + Seek {}
impl<T: Write + Seek + ?Sized> WriteSeek for T {}

impl TempArtifactLike for storage::TempArtifact {
    fn with_reader<T, E>(&self, f: impl FnOnce(&mut dyn ReadSeek) -> Result<T, E>) -> Result<T, E> {
        storage::TempArtifact::with_reader(self, |file| f(file))
    }

    fn with_writer<T, E>(
        &self,
        f: impl FnOnce(&mut dyn WriteSeek) -> Result<T, E>,
    ) -> Result<T, E> {
        storage::TempArtifact::with_writer(self, |file| f(file))
    }
}

#[derive(Debug)]
pub enum Error {
    WriteData,
    OpenArchive,
    OpenArchivedFile,
    ResetCursorPosition,
    UnsafeOutputPath(PathBuf),
    DuplicateOutputPath(PathBuf),
    Storage(storage::Error),
    PathIdentity(IdentityError),
    Transaction(TransactionError),
    Decrypt(decrypt::Error),
    OnZipFile(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WriteData => f.write_str("Unable to write data"),
            Error::OpenArchive => f.write_str("Unable to open archive"),
            Error::OpenArchivedFile => f.write_str("Unable to open archived file"),
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::UnsafeOutputPath(path) => {
                write!(f, "Unsafe output path: {}", path.display())
            }
            Error::DuplicateOutputPath(path) => {
                write!(
                    f,
                    "Duplicate output path after normalization: {}",
                    path.display()
                )
            }
            Error::Storage(inner) => write!(f, "Storage error: {inner}"),
            Error::PathIdentity(inner) => write!(f, "Path identity error: {inner}"),
            Error::Transaction(inner) => write!(f, "Transaction error: {inner}"),
            Error::Decrypt(inner) => write!(f, "Decrypt error: {inner}"),
            Error::OnZipFile(inner) => write!(f, "Zip file callback error: {inner}"),
        }
    }
}

impl std::error::Error for Error {}

type OnArchiveInfo = Box<dyn FnOnce(usize)>;
type OnZipFileFn = Box<dyn Fn(PathBuf) -> Result<bool, String>>;

pub struct Request<'a, R>
where
    R: Read,
{
    pub reader: &'a RefCell<R>,
    pub header_reader: Option<&'a RefCell<R>>,
    pub raw_key: Protected<Vec<u8>>,
    pub output_dir_path: PathBuf,
    pub on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
    pub on_archive_info: Option<OnArchiveInfo>,
    pub on_zip_file: Option<OnZipFileFn>,
}

struct ExtractionEntity {
    full_path: PathBuf,
    archive_index: usize,
    kind: ExtractionKind,
}

enum ExtractionKind {
    Directory,
    File(ResolvedTarget),
}

pub fn execute(
    stor: Arc<storage::FileStorage>,
    req: Request<'_, fs::File>,
) -> Result<CommitReceipt, Error> {
    execute_with_temp_artifact(stor, req, || {
        storage::FileStorage
            .create_temp_artifact()
            .map_err(Error::Storage)
    })
}

fn execute_with_temp_artifact<T, F>(
    stor: Arc<storage::FileStorage>,
    req: Request<'_, fs::File>,
    temp_factory: F,
) -> Result<CommitReceipt, Error>
where
    T: TempArtifactLike,
    F: FnOnce() -> Result<T, Error>,
{
    // 1. Create temp zip archive.
    let tmp_file = temp_factory()?;

    // 2. Decrypt input file to temp zip archive.
    tmp_file.with_writer(|tmp_writer| {
        tmp_writer
            .rewind()
            .map_err(|_| Error::Storage(storage::Error::OpenFile(storage::FileMode::Write)))?;
        let writer = RefCell::new(tmp_writer);
        decrypt::execute(decrypt::Request {
            header_reader: req.header_reader,
            reader: req.reader,
            writer: &writer,
            raw_key: req.raw_key,
            on_decrypted_header: req.on_decrypted_header,
        })
        .map_err(Error::Decrypt)
    })?;

    // 3. Recover files from temp archive.
    let receipt = tmp_file.with_reader(|tmp_reader| {
        tmp_reader
            .rewind()
            .map_err(|_| Error::ResetCursorPosition)?;
        let mut archive = zip::ZipArchive::new(tmp_reader).map_err(|_| Error::OpenArchive)?;

        let (output_dir, entities) = prepare_extraction_entities(
            &stor,
            &mut archive,
            &req.output_dir_path,
            req.on_zip_file.as_ref(),
        )?;
        if let Some(on_archive_info) = req.on_archive_info {
            on_archive_info(entities.len());
        }

        stage_and_commit_extraction(&stor, &mut archive, &output_dir, &entities)
    })?;

    drop(tmp_file);

    Ok(receipt)
}

fn prepare_extraction_entities<R: Read + Seek>(
    stor: &storage::FileStorage,
    archive: &mut zip::ZipArchive<R>,
    output_dir_path: &Path,
    on_zip_file: Option<&OnZipFileFn>,
) -> Result<(PathBuf, Vec<ExtractionEntity>), Error> {
    let output_dir = stor
        .prepare_unpack_root(output_dir_path)
        .map_err(map_storage_path_error)?;
    let mut identity_graph = PathIdentityGraph::new();
    identity_graph
        .add_unpack_root(&output_dir)
        .map_err(map_identity_error)?;

    let mut entities = Vec::new();
    let mut seen_paths = HashSet::new();
    for i in 0..archive.len() {
        let zip_file = archive.by_index(i).map_err(|_| Error::OpenArchive)?;
        let Some(path) = zip_file.enclosed_name() else {
            continue;
        };
        let path = normalize_archive_path(&path)?;
        if !seen_paths.insert(path.clone()) {
            return Err(Error::DuplicateOutputPath(path));
        }

        let full_path = stor
            .resolve_unpack_path(&output_dir, &path)
            .map_err(map_storage_path_error)?;

        if let Some(on_zip_file) = on_zip_file {
            let should_unpack = on_zip_file(full_path.clone()).map_err(Error::OnZipFile)?;
            if !should_unpack {
                continue;
            }
        }

        let kind = if zip_file.is_dir() {
            ExtractionKind::Directory
        } else {
            let overwrite_policy = overwrite_policy_for_extracted_file(&full_path)?;
            let target = identity_graph
                .add_output(&full_path, PathRole::Output, overwrite_policy)
                .map_err(map_identity_error)?;
            ExtractionKind::File(target)
        };

        entities.push(ExtractionEntity {
            full_path,
            archive_index: i,
            kind,
        });
    }

    Ok((output_dir, entities))
}

fn stage_and_commit_extraction<R: Read + Seek>(
    stor: &storage::FileStorage,
    archive: &mut zip::ZipArchive<R>,
    output_dir: &Path,
    entities: &[ExtractionEntity],
) -> Result<CommitReceipt, Error> {
    entities
        .iter()
        .filter(|entity| matches!(entity.kind, ExtractionKind::Directory))
        .map(|entity| entity.full_path.as_path())
        .chain(std::iter::once(output_dir))
        .try_for_each(|full_path| stor.create_dir_all(full_path).map_err(Error::Storage))?;

    let mut transaction = LinkedOutputTransaction::new();
    for entity in entities
        .iter()
        .filter(|entity| matches!(entity.kind, ExtractionKind::File(_)))
    {
        stage_extracted_file(stor, archive, &mut transaction, entity)?;
    }

    transaction.commit_all().map_err(Error::Transaction)
}

fn stage_extracted_file<R: Read + Seek>(
    stor: &storage::FileStorage,
    archive: &mut zip::ZipArchive<R>,
    transaction: &mut LinkedOutputTransaction,
    entity: &ExtractionEntity,
) -> Result<(), Error> {
    let ExtractionKind::File(target) = &entity.kind else {
        unreachable!();
    };

    if let Some(parent_dir) = entity.full_path.parent() {
        stor.create_dir_all(parent_dir).map_err(Error::Storage)?;
    }

    let transaction_index = transaction
        .stage(target.clone())
        .map_err(Error::Transaction)?;
    let staged = transaction
        .staged_output_mut(transaction_index)
        .ok_or_else(|| {
            Error::Transaction(TransactionError::Write {
                path: entity.full_path.clone(),
            })
        })?;
    let mut zip_file = archive
        .by_index(entity.archive_index)
        .map_err(|_| Error::OpenArchivedFile)?;
    staged
        .with_writer(|writer| io::copy(&mut zip_file, writer).map(|_| ()))
        .map_err(Error::Transaction)
}

fn overwrite_policy_for_extracted_file(path: &Path) -> Result<OverwritePolicy, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(Error::UnsafeOutputPath(path.to_path_buf())),
        Ok(_) => Ok(OverwritePolicy::ReplaceAtCommit),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(OverwritePolicy::CreateNew),
        Err(_) => Err(Error::Storage(storage::Error::FileAccess)),
    }
}

fn normalize_archive_path(path: &Path) -> Result<PathBuf, Error> {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(Error::UnsafeOutputPath(path.to_path_buf()));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::UnsafeOutputPath(path.to_path_buf()));
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(Error::UnsafeOutputPath(path.to_path_buf()));
    }

    Ok(normalized)
}

fn map_storage_path_error(err: storage::Error) -> Error {
    match err {
        storage::Error::UnsafePath(path) => Error::UnsafeOutputPath(path),
        other => Error::Storage(other),
    }
}

fn map_identity_error(err: IdentityError) -> Error {
    match err {
        IdentityError::UnsafePath(path) => Error::UnsafeOutputPath(path),
        other => Error::PathIdentity(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::sync::Arc;

    use core::kdf::Kdf;
    use core::protected::Protected;
    use zip::write::SimpleFileOptions;

    use crate::encrypt;
    use crate::encrypt::tests::PASSWORD;
    use crate::storage::{FileStorage, Storage};

    struct TestDir {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let dir = tempfile::Builder::new()
                .prefix(&format!("dexios-unpack-{prefix}-"))
                .tempdir()
                .unwrap();
            let path = fs::canonicalize(dir.path()).unwrap();
            Self { _dir: dir, path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    fn write_zip_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(true)
            .unix_permissions(0o755);

        for (name, body) in entries {
            zip_writer.start_file(*name, options).unwrap();
            zip_writer.write_all(body).unwrap();
        }

        zip_writer.finish().unwrap();
    }

    fn write_bar_zip(path: &Path) {
        write_zip_with_entries(
            path,
            &[
                ("bar/.hello.txt", b"hello"),
                ("bar/world.txt", b"world"),
                ("bar/.foo/world.txt", b"world"),
            ],
        );
    }

    fn encrypt_zip(input_path: &Path, output_path: &Path, header_path: Option<&Path>) {
        let input = RefCell::new(File::open(input_path).unwrap());
        let output = RefCell::new(File::create(output_path).unwrap());
        let header = header_path.map(|path| RefCell::new(File::create(path).unwrap()));

        encrypt::execute_handles(encrypt::HandleRequest {
            reader: &input,
            writer: &output,
            header_writer: header.as_ref(),
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .unwrap();

        output.borrow_mut().flush().unwrap();
        if let Some(header) = header {
            header.borrow_mut().flush().unwrap();
        }
    }

    fn assert_text(path: &Path, expected: &str) {
        assert_eq!(fs::read_to_string(path).unwrap(), expected);
    }

    #[test]
    fn should_unpack_encrypted_archive_with_embedded_header() {
        let test_dir = TestDir::new("embedded");
        let plain_zip = test_dir.path().join("plain.zip");
        let encrypted_archive = test_dir.path().join("archive.enc");
        let output_dir = test_dir.path().join("out");

        write_bar_zip(&plain_zip);
        encrypt_zip(&plain_zip, &encrypted_archive, None);

        let stor = Arc::new(FileStorage);
        let archive = stor.read_file(&encrypted_archive).unwrap();
        let req = Request {
            reader: archive.try_reader().unwrap(),
            header_reader: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: output_dir.clone(),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        let receipt = execute(stor.clone(), req).unwrap();

        assert_eq!(receipt.artifacts.len(), 3);
        assert_text(&output_dir.join("bar/.hello.txt"), "hello");
        assert_text(&output_dir.join("bar/world.txt"), "world");
        assert_text(&output_dir.join("bar/.foo/world.txt"), "world");
    }

    #[test]
    fn should_unpack_encrypted_archive_with_detached_header() {
        let test_dir = TestDir::new("detached");
        let plain_zip = test_dir.path().join("plain.zip");
        let encrypted_archive = test_dir.path().join("archive-detached.enc");
        let detached_header = test_dir.path().join("archive.hdr");
        let output_dir = test_dir.path().join("out-detached");

        write_bar_zip(&plain_zip);
        encrypt_zip(&plain_zip, &encrypted_archive, Some(&detached_header));

        let stor = Arc::new(FileStorage);
        let archive = stor.read_file(&encrypted_archive).unwrap();
        let header = stor.read_file(&detached_header).unwrap();
        let req = Request {
            reader: archive.try_reader().unwrap(),
            header_reader: Some(header.try_reader().unwrap()),
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: output_dir.clone(),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        let receipt = execute(stor.clone(), req).unwrap();

        assert_eq!(receipt.artifacts.len(), 3);
        assert_text(&output_dir.join("bar/.hello.txt"), "hello");
        assert_text(&output_dir.join("bar/world.txt"), "world");
        assert_text(&output_dir.join("bar/.foo/world.txt"), "world");
    }

    #[test]
    fn should_unpack_current_generated_archive_fixture() {
        let test_dir = TestDir::new("current-fixture");
        let plain_zip = test_dir.path().join("plain.zip");
        let encrypted_archive = test_dir.path().join("archive.enc");
        let output_dir = test_dir.path().join("archive-out");

        write_bar_zip(&plain_zip);
        encrypt_zip(&plain_zip, &encrypted_archive, None);

        let stor = Arc::new(FileStorage);
        let archive = stor.read_file(&encrypted_archive).unwrap();
        let req = Request {
            reader: archive.try_reader().unwrap(),
            header_reader: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: output_dir.clone(),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        let receipt = execute(stor.clone(), req).unwrap();

        assert_eq!(receipt.artifacts.len(), 3);
        assert_text(&output_dir.join("bar/.hello.txt"), "hello");
        assert_text(&output_dir.join("bar/world.txt"), "world");
        assert_text(&output_dir.join("bar/.foo/world.txt"), "world");
    }
}

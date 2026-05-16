//! This contains the logic for decrypting a packed zip archive and extracting
//! each file to the target directory.
//!
//! This is known as "unpacking" within Dexios.
//!
//! unpack-side plaintext temporary ZIP exposure remains: unpack keeps the
//! seekable temp ZIP so metadata validation, duplicate detection, selection,
//! path revalidation, and staged commits all happen before final outputs commit.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::archive::{ArchiveLimitError, ArchiveLimits};
use crate::decrypt;
use crate::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
use crate::storage::transaction::{CommitReceipt, LinkedOutputTransaction, TransactionError};
use crate::storage::{self, Storage};
use crate::workflow_error::{
    WorkflowErrorClass, classify_identity_error, classify_storage_error, classify_transaction_error,
};
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

struct ResourcePressureTrackingWriter<'a> {
    inner: &'a mut dyn WriteSeek,
    resource_pressure: &'a Cell<Option<io::ErrorKind>>,
}

impl<'a> ResourcePressureTrackingWriter<'a> {
    fn new(
        inner: &'a mut dyn WriteSeek,
        resource_pressure: &'a Cell<Option<io::ErrorKind>>,
    ) -> Self {
        Self {
            inner,
            resource_pressure,
        }
    }

    fn record(&self, error: &io::Error) {
        if let Some(kind) = storage::resource_pressure_kind_in_error_chain(error) {
            self.resource_pressure.set(Some(kind));
        }
    }
}

impl Write for ResourcePressureTrackingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = self.inner.write(buf);
        if let Err(error) = &result {
            self.record(error);
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        let result = self.inner.flush();
        if let Err(error) = &result {
            self.record(error);
        }
        result
    }
}

impl Seek for ResourcePressureTrackingWriter<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let result = self.inner.seek(pos);
        if let Err(error) = &result {
            self.record(error);
        }
        result
    }
}

#[derive(Debug)]
pub enum Error {
    WriteData,
    WriteDataWithSource(io::Error),
    OpenArchive,
    OpenArchiveWithSource(zip::result::ZipError),
    OpenArchivedFile,
    OpenArchivedFileWithSource(zip::result::ZipError),
    ResetCursorPosition,
    ResetCursorPositionWithSource(io::Error),
    UnsafeOutputPath(PathBuf),
    DuplicateOutputPath(PathBuf),
    ArchiveLimit(ArchiveLimitError),
    Storage(storage::Error),
    PathIdentity(IdentityError),
    Transaction(TransactionError),
    Decrypt(decrypt::Error),
    OnZipFile(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WriteData | Error::WriteDataWithSource(_) => f.write_str("Unable to write data"),
            Error::OpenArchive | Error::OpenArchiveWithSource(_) => {
                f.write_str("Unable to open archive")
            }
            Error::OpenArchivedFile | Error::OpenArchivedFileWithSource(_) => {
                f.write_str("Unable to open archived file")
            }
            Error::ResetCursorPosition | Error::ResetCursorPositionWithSource(_) => {
                f.write_str("Unable to reset cursor position")
            }
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
            Error::ArchiveLimit(inner) => write!(f, "Archive limit error: {inner}"),
            Error::Storage(inner) => write!(f, "Storage error: {inner}"),
            Error::PathIdentity(inner) => write!(f, "Path identity error: {inner}"),
            Error::Transaction(inner) => write!(f, "Transaction error: {inner}"),
            Error::Decrypt(inner) => write!(f, "Decrypt error: {inner}"),
            Error::OnZipFile(inner) => write!(f, "Zip file callback error: {inner}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WriteDataWithSource(error) | Self::ResetCursorPositionWithSource(error) => {
                Some(error)
            }
            Self::OpenArchiveWithSource(error) | Self::OpenArchivedFileWithSource(error) => {
                Some(error)
            }
            Self::ArchiveLimit(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::PathIdentity(error) => Some(error),
            Self::Transaction(error) => Some(error),
            Self::Decrypt(error) => Some(error),
            _ => None,
        }
    }
}

impl Error {
    #[must_use]
    pub fn workflow_class(&self) -> WorkflowErrorClass {
        if self.is_resource_pressure() {
            return WorkflowErrorClass::ResourcePressure;
        }

        match self {
            Self::UnsafeOutputPath(_) | Self::DuplicateOutputPath(_) | Self::ArchiveLimit(_) => {
                WorkflowErrorClass::UnsafePath
            }
            Self::OpenArchive
            | Self::OpenArchiveWithSource(_)
            | Self::OpenArchivedFile
            | Self::OpenArchivedFileWithSource(_) => WorkflowErrorClass::MalformedFormat,
            Self::Decrypt(error) => error.workflow_class(),
            Self::Storage(error) => classify_storage_error(error),
            Self::PathIdentity(error) => classify_identity_error(error),
            Self::Transaction(error) => classify_transaction_error(error),
            Self::WriteData
            | Self::WriteDataWithSource(_)
            | Self::ResetCursorPosition
            | Self::ResetCursorPositionWithSource(_) => WorkflowErrorClass::IoFailure,
            Self::OnZipFile(_) => WorkflowErrorClass::Other,
        }
    }

    #[must_use]
    pub fn is_resource_pressure(&self) -> bool {
        storage::error_chain_contains_resource_pressure(self)
    }
}

type OnArchiveInfo = Box<dyn FnOnce(usize)>;
type OnZipFileFn = Box<dyn Fn(PathBuf) -> Result<bool, String>>;

pub struct UnpackIntent {
    input: storage::Entry<fs::File>,
    detached_header: Option<storage::Entry<fs::File>>,
    raw_key: Protected<Vec<u8>>,
    output_dir_path: PathBuf,
    on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
    on_archive_info: Option<OnArchiveInfo>,
    on_zip_file: Option<OnZipFileFn>,
}

impl UnpackIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new<P>(
        input: storage::Entry<fs::File>,
        detached_header: Option<storage::Entry<fs::File>>,
        output_dir_path: P,
        raw_key: Protected<Vec<u8>>,
        on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
        on_archive_info: Option<OnArchiveInfo>,
        on_zip_file: Option<OnZipFileFn>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        input.try_reader().map_err(Error::Storage)?;
        if let Some(header) = &detached_header {
            header.try_reader().map_err(Error::Storage)?;
        }

        Ok(Self {
            input,
            detached_header,
            raw_key,
            output_dir_path: output_dir_path.as_ref().to_path_buf(),
            on_decrypted_header,
            on_archive_info,
            on_zip_file,
        })
    }
}

struct HandleRequest<'a, R>
where
    R: Read + Seek,
{
    reader: &'a RefCell<R>,
    header_reader: Option<&'a RefCell<R>>,
    input_path: PathBuf,
    detached_header_path: Option<PathBuf>,
    raw_key: Protected<Vec<u8>>,
    output_dir_path: PathBuf,
    on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
    on_archive_info: Option<OnArchiveInfo>,
    on_zip_file: Option<OnZipFileFn>,
}

struct ExtractionEntity {
    full_path: PathBuf,
    relative_path: PathBuf,
    archive_index: usize,
    kind: ExtractionKind,
}

enum ExtractionKind {
    Directory,
    File(ResolvedTarget),
}

struct ScannedEntry {
    full_path: PathBuf,
    relative_path: PathBuf,
    archive_index: usize,
    kind: ExtractionKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchiveEntryKind {
    Directory,
    File,
}

#[derive(Default)]
struct ArchivePathTree {
    root: ArchivePathNode,
}

#[derive(Default)]
struct ArchivePathNode {
    kind: Option<ArchiveEntryKind>,
    children: BTreeMap<OsString, ArchivePathNode>,
}

impl ArchivePathTree {
    fn insert(&mut self, path: &Path, kind: ArchiveEntryKind) -> Result<(), Error> {
        let mut node = &mut self.root;

        for component in path.components() {
            let Component::Normal(part) = component else {
                return Err(Error::UnsafeOutputPath(path.to_path_buf()));
            };

            if matches!(node.kind, Some(ArchiveEntryKind::File)) {
                return Err(Error::DuplicateOutputPath(path.to_path_buf()));
            }

            node = node.children.entry(part.to_os_string()).or_default();
        }

        if node.kind.is_some() || (kind == ArchiveEntryKind::File && !node.children.is_empty()) {
            return Err(Error::DuplicateOutputPath(path.to_path_buf()));
        }

        node.kind = Some(kind);
        Ok(())
    }
}

pub fn execute(intent: UnpackIntent) -> Result<CommitReceipt, Error> {
    let UnpackIntent {
        input,
        detached_header,
        raw_key,
        output_dir_path,
        on_decrypted_header,
        on_archive_info,
        on_zip_file,
    } = intent;

    let input_path = input.path().to_path_buf();
    let detached_header_path = detached_header
        .as_ref()
        .map(|header| header.path().to_path_buf());
    let reader = input.try_reader().map_err(Error::Storage)?;
    let header_reader = detached_header
        .as_ref()
        .map(|header| header.try_reader())
        .transpose()
        .map_err(Error::Storage)?;
    let req = HandleRequest {
        reader,
        header_reader,
        input_path,
        detached_header_path,
        raw_key,
        output_dir_path,
        on_decrypted_header,
        on_archive_info,
        on_zip_file,
    };

    let stor = Arc::new(storage::FileStorage);
    execute_with_temp_artifact(stor, req, || {
        storage::FileStorage
            .create_temp_artifact()
            .map_err(Error::Storage)
    })
}

fn execute_with_temp_artifact<R, T, F>(
    stor: Arc<storage::FileStorage>,
    req: HandleRequest<'_, R>,
    temp_factory: F,
) -> Result<CommitReceipt, Error>
where
    R: Read + Seek,
    T: TempArtifactLike,
    F: FnOnce() -> Result<T, Error>,
{
    // 1. Create temp zip archive.
    let tmp_file = temp_factory()?;

    // 2. Decrypt input file to temp zip archive.
    tmp_file.with_writer(|tmp_writer| {
        tmp_writer.rewind().map_err(|source| {
            Error::Storage(storage::Error::OpenFileWithSource {
                mode: storage::FileMode::Write,
                source,
            })
        })?;
        let resource_pressure = Cell::new(None);
        let writer = RefCell::new(ResourcePressureTrackingWriter::new(
            tmp_writer,
            &resource_pressure,
        ));
        let result = decrypt::execute_handles(decrypt::HandleRequest {
            header_reader: req.header_reader,
            reader: req.reader,
            writer: &writer,
            raw_key: req.raw_key,
            on_decrypted_header: req.on_decrypted_header,
        });
        match (result, resource_pressure.get()) {
            (Ok(()), _) => Ok(()),
            (Err(decrypt::Error::WriteData), Some(kind)) => {
                Err(Error::WriteDataWithSource(io::Error::from(kind)))
            }
            (Err(error), _) => Err(Error::Decrypt(error)),
        }
    })?;

    // 3. Recover files from temp archive.
    let receipt = tmp_file.with_reader(|tmp_reader| {
        tmp_reader
            .rewind()
            .map_err(Error::ResetCursorPositionWithSource)?;
        let mut archive = zip::ZipArchive::new(tmp_reader).map_err(Error::OpenArchiveWithSource)?;

        let (output_dir, entities) = prepare_extraction_entities(
            &stor,
            &mut archive,
            &req.output_dir_path,
            &req.input_path,
            req.detached_header_path.as_deref(),
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
    input_path: &Path,
    detached_header_path: Option<&Path>,
    on_zip_file: Option<&OnZipFileFn>,
) -> Result<(PathBuf, Vec<ExtractionEntity>), Error> {
    let output_dir = stor
        .prepare_unpack_root(output_dir_path)
        .map_err(map_storage_path_error)?;
    let limits = ArchiveLimits::default();
    limits
        .check_entry_count(archive.len())
        .map_err(Error::ArchiveLimit)?;
    let mut identity_graph = PathIdentityGraph::new();
    identity_graph
        .add_existing(input_path, PathRole::Input)
        .map_err(map_identity_error)?;
    if let Some(detached_header_path) = detached_header_path {
        identity_graph
            .add_existing(detached_header_path, PathRole::DetachedHeader)
            .map_err(map_identity_error)?;
    }
    identity_graph
        .add_unpack_root(&output_dir)
        .map_err(map_identity_error)?;

    let mut scanned_entries = Vec::new();
    let mut archive_paths = ArchivePathTree::default();
    for i in 0..archive.len() {
        let zip_file = archive.by_index(i).map_err(Error::OpenArchiveWithSource)?;
        let Some(path) = zip_file.enclosed_name() else {
            return Err(Error::UnsafeOutputPath(PathBuf::from(zip_file.name())));
        };
        let path = normalize_archive_path(&path)?;
        limits
            .check_normalized_path(&path)
            .map_err(Error::ArchiveLimit)?;
        let archive_entry_kind = if zip_file.is_dir() {
            ArchiveEntryKind::Directory
        } else {
            ArchiveEntryKind::File
        };
        archive_paths.insert(&path, archive_entry_kind)?;

        let full_path = stor
            .resolve_unpack_path(&output_dir, &path)
            .map_err(map_storage_path_error)?;

        let kind = if archive_entry_kind == ArchiveEntryKind::Directory {
            ExtractionKind::Directory
        } else {
            let overwrite_policy = overwrite_policy_for_extracted_file(&full_path)?;
            let target = identity_graph
                .add_output(&full_path, PathRole::Output, overwrite_policy)
                .map_err(map_identity_error)?;
            ExtractionKind::File(target)
        };

        scanned_entries.push(ScannedEntry {
            full_path,
            relative_path: path,
            archive_index: i,
            kind,
        });
    }

    let mut entities = Vec::new();
    for entry in scanned_entries {
        if let Some(on_zip_file) = on_zip_file {
            let should_unpack = on_zip_file(entry.full_path.clone()).map_err(Error::OnZipFile)?;
            if !should_unpack {
                continue;
            }
        }

        entities.push(ExtractionEntity {
            full_path: entry.full_path,
            relative_path: entry.relative_path,
            archive_index: entry.archive_index,
            kind: entry.kind,
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
        stage_extracted_file(stor, archive, output_dir, &mut transaction, entity)?;
    }

    transaction.commit_all().map_err(Error::Transaction)
}

fn stage_extracted_file<R: Read + Seek>(
    stor: &storage::FileStorage,
    archive: &mut zip::ZipArchive<R>,
    output_dir: &Path,
    transaction: &mut LinkedOutputTransaction,
    entity: &ExtractionEntity,
) -> Result<(), Error> {
    let ExtractionKind::File(target) = &entity.kind else {
        unreachable!();
    };

    stor.revalidate_unpack_target(output_dir, &entity.relative_path, target)
        .map_err(map_storage_path_error)?;

    if let Some(parent_dir) = entity.full_path.parent() {
        stor.create_dir_all(parent_dir).map_err(Error::Storage)?;
    }

    stor.revalidate_unpack_target(output_dir, &entity.relative_path, target)
        .map_err(map_storage_path_error)?;

    let transaction_index = transaction
        .stage(target.clone())
        .map_err(Error::Transaction)?;
    let staged = transaction
        .staged_output_mut(transaction_index)
        .ok_or_else(|| {
            Error::Transaction(TransactionError::Write {
                path: entity.full_path.clone(),
                source: None,
            })
        })?;
    let mut zip_file = archive
        .by_index(entity.archive_index)
        .map_err(Error::OpenArchivedFileWithSource)?;
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
    use std::cell::Cell;
    use std::fs::File;
    use std::io::{Cursor, Write};
    use std::rc::Rc;
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

    struct DropTrackingTempArtifact {
        cursor: RefCell<Cursor<Vec<u8>>>,
        dropped: Rc<Cell<bool>>,
    }

    impl DropTrackingTempArtifact {
        fn new(dropped: Rc<Cell<bool>>) -> Self {
            Self {
                cursor: RefCell::new(Cursor::new(Vec::new())),
                dropped,
            }
        }
    }

    impl Drop for DropTrackingTempArtifact {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    impl TempArtifactLike for DropTrackingTempArtifact {
        fn with_reader<T, E>(
            &self,
            f: impl FnOnce(&mut dyn ReadSeek) -> Result<T, E>,
        ) -> Result<T, E> {
            f(&mut *self.cursor.borrow_mut())
        }

        fn with_writer<T, E>(
            &self,
            f: impl FnOnce(&mut dyn WriteSeek) -> Result<T, E>,
        ) -> Result<T, E> {
            f(&mut *self.cursor.borrow_mut())
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
    fn unpack_arch_04_d16_temp_cleanup_on_validation_failure_drops_plaintext_temp_artifact() {
        let test_dir = TestDir::new("temp-cleanup-validation");
        let plain_zip = test_dir.path().join("plain.zip");
        let encrypted_archive = test_dir.path().join("archive.enc");
        let output_dir = test_dir.path().join("out");
        let dropped = Rc::new(Cell::new(false));
        let dropped_for_factory = Rc::clone(&dropped);

        write_zip_with_entries(
            &plain_zip,
            &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
        );
        encrypt_zip(&plain_zip, &encrypted_archive, None);

        let stor = Arc::new(FileStorage);
        let archive = stor.read_file(&encrypted_archive).unwrap();
        let req = HandleRequest {
            reader: archive.try_reader().unwrap(),
            header_reader: None,
            input_path: encrypted_archive,
            detached_header_path: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: output_dir.clone(),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        let result = execute_with_temp_artifact(stor, req, || {
            Ok(DropTrackingTempArtifact::new(dropped_for_factory))
        });

        assert!(matches!(result, Err(Error::UnsafeOutputPath(_))));
        assert!(dropped.get(), "plaintext temp artifact should be dropped");
        assert!(!output_dir.join("safe.txt").exists());
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
        let intent = UnpackIntent::new(
            archive,
            None,
            output_dir.clone(),
            Protected::new(PASSWORD.to_vec()),
            None,
            None,
            None,
        )
        .unwrap();

        let receipt = execute(intent).unwrap();

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
        let intent = UnpackIntent::new(
            archive,
            Some(header),
            output_dir.clone(),
            Protected::new(PASSWORD.to_vec()),
            None,
            None,
            None,
        )
        .unwrap();

        let receipt = execute(intent).unwrap();

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
        let intent = UnpackIntent::new(
            archive,
            None,
            output_dir.clone(),
            Protected::new(PASSWORD.to_vec()),
            None,
            None,
            None,
        )
        .unwrap();

        let receipt = execute(intent).unwrap();

        assert_eq!(receipt.artifacts.len(), 3);
        assert_text(&output_dir.join("bar/.hello.txt"), "hello");
        assert_text(&output_dir.join("bar/world.txt"), "world");
        assert_text(&output_dir.join("bar/.foo/world.txt"), "world");
    }
}

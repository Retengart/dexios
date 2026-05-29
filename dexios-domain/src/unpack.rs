//! This contains the logic for decrypting a packed manifest archive and extracting
//! each file to the target directory.
//!
//! This is known as "unpacking" within Dexios.
//!
//! unpack-side plaintext exposure is scoped to selected staged file bodies:
//! manifest metadata is validated before selected body staging, and final
//! outputs commit only after stream final authentication.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::archive::{ArchiveLimitError, ArchiveLimits};
use crate::decrypt;
use crate::storage::cleanup::{CleanupReceipt, ProcessedSourceCleanupResult};
use crate::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
#[cfg(any(test, feature = "test-support"))]
use crate::storage::test_support::FailureHooks;
use crate::storage::transaction::{
    CommitReceipt, CommittedArtifact, LinkedOutputTransaction, StagedWriteError, TransactionError,
};
use crate::storage::{self, Storage};
use crate::workflow_error::{
    WorkflowErrorClass, classify_identity_error, classify_storage_error, classify_transaction_error,
};
use core::payload::{
    ArchiveBodyFrameHeader, ArchiveManifest, ManifestEntryKind, PayloadError,
    PayloadFramingProfile, PayloadKind,
};
use core::protected::Protected;
use core::stream::{StreamError, V1PayloadDecryptingReader};

#[derive(Debug)]
pub enum Error {
    WriteData,
    WriteDataWithSource(io::Error),
    OpenArchive,
    ArchivePayload(PayloadError),
    ResetCursorPosition,
    ResetCursorPositionWithSource(io::Error),
    UnsafeOutputPath(PathBuf),
    DuplicateOutputPath(PathBuf),
    ArchiveLimit(ArchiveLimitError),
    Storage(storage::Error),
    PathIdentity(IdentityError),
    Transaction(TransactionError),
    Decrypt(decrypt::Error),
    ArchiveFileCallback(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WriteData | Error::WriteDataWithSource(_) => f.write_str("Unable to write data"),
            Error::OpenArchive => f.write_str("Unable to open archive"),
            Error::ArchivePayload(inner) => write!(f, "Archive payload error: {inner}"),
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
            Error::ArchiveFileCallback(inner) => write!(f, "Archive file callback error: {inner}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WriteDataWithSource(error) | Self::ResetCursorPositionWithSource(error) => {
                Some(error)
            }
            Self::ArchivePayload(error) => Some(error),
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
        match self {
            Self::Transaction(error) => classify_transaction_error(error),
            _ if self.is_resource_pressure() => WorkflowErrorClass::ResourcePressure,
            Self::UnsafeOutputPath(_) | Self::DuplicateOutputPath(_) | Self::ArchiveLimit(_) => {
                WorkflowErrorClass::UnsafePath
            }
            Self::ArchivePayload(error) => classify_payload_error(error),
            Self::OpenArchive => WorkflowErrorClass::MalformedFormat,
            Self::Decrypt(error) => error.workflow_class(),
            Self::Storage(error) => classify_storage_error(error),
            Self::PathIdentity(error) => classify_identity_error(error),
            Self::WriteData
            | Self::WriteDataWithSource(_)
            | Self::ResetCursorPosition
            | Self::ResetCursorPositionWithSource(_) => WorkflowErrorClass::IoFailure,
            Self::ArchiveFileCallback(_) => WorkflowErrorClass::Other,
        }
    }

    #[must_use]
    pub fn is_resource_pressure(&self) -> bool {
        storage::error_chain_contains_resource_pressure(self)
    }
}

fn classify_payload_error(error: &PayloadError) -> WorkflowErrorClass {
    match error {
        PayloadError::ManifestEntryCountLimitExceeded { .. }
        | PayloadError::NormalizedPathLimitExceeded { .. } => WorkflowErrorClass::UnsafePath,
        PayloadError::BodyFrameLimitExceeded { .. } => WorkflowErrorClass::ResourcePressure,
        PayloadError::Io(_) => WorkflowErrorClass::IoFailure,
        _ => WorkflowErrorClass::MalformedFormat,
    }
}

type OnArchiveInfo = Box<dyn FnOnce(usize)>;
type OnArchiveFileFn = Box<dyn Fn(PathBuf) -> Result<bool, String>>;

pub struct UnpackIntent {
    input: storage::Entry<fs::File>,
    detached_header: Option<storage::Entry<fs::File>>,
    cleanup_receipt: CleanupReceipt,
    raw_key: Protected<Vec<u8>>,
    output_dir_path: PathBuf,
    on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
    on_archive_info: Option<OnArchiveInfo>,
    on_archive_file: Option<OnArchiveFileFn>,
}

impl UnpackIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new<P, O>(
        input_path: P,
        detached_header_path: Option<&Path>,
        output_dir_path: O,
        raw_key: Protected<Vec<u8>>,
        on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
        on_archive_info: Option<OnArchiveInfo>,
        on_archive_file: Option<OnArchiveFileFn>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
        O: AsRef<Path>,
    {
        let input_path = input_path.as_ref().to_path_buf();
        let mut graph = PathIdentityGraph::new();
        let input_target = graph
            .add_existing(&input_path, PathRole::ProcessedSource)
            .map_err(Error::PathIdentity)?;
        let cleanup_receipt = CleanupReceipt::from_processed_sources([&input_target])
            .map_err(|source| Error::Storage(storage::Error::FileAccessWithSource(source)))?;
        let detached_header_target = detached_header_path
            .map(|path| graph.add_existing(path, PathRole::DetachedHeader))
            .transpose()
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        let stor = storage::FileStorage;
        let input = stor
            .read_resolved_existing_no_follow(&input_target)
            .map_err(Error::Storage)?;
        let detached_header = detached_header_target
            .as_ref()
            .map(|target| stor.read_resolved_existing_no_follow(target))
            .transpose()
            .map_err(Error::Storage)?;

        Ok(Self {
            input,
            detached_header,
            cleanup_receipt,
            raw_key,
            output_dir_path: output_dir_path.as_ref().to_path_buf(),
            on_decrypted_header,
            on_archive_info,
            on_archive_file,
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
    on_archive_file: Option<OnArchiveFileFn>,
}

struct ExtractionEntity {
    full_path: PathBuf,
    relative_path: PathBuf,
    archive_index: usize,
    kind: ExtractionKind,
}

enum ExtractionKind {
    Directory(ResolvedTarget),
    File(ResolvedTarget),
}

struct ScannedEntry {
    full_path: PathBuf,
    relative_path: PathBuf,
    archive_index: usize,
    kind: ExtractionKind,
}

struct UncommittedPlaintextReader<'a, R: Read>(&'a mut V1PayloadDecryptingReader<R>);

impl<R: Read> Read for UncommittedPlaintextReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read_uncommitted(buf).map_err(io::Error::other)
    }
}

struct DirectoryCreation {
    artifacts: Vec<CommittedArtifact>,
    rollback_dirs: Vec<PathBuf>,
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
    execute_with_cleanup(intent).map(ProcessedSourceCleanupResult::into_commit_receipt)
}

pub fn execute_with_cleanup(intent: UnpackIntent) -> Result<ProcessedSourceCleanupResult, Error> {
    execute_with_transaction(intent, LinkedOutputTransaction::new())
}

#[cfg(any(test, feature = "test-support"))]
pub fn execute_with_failure_hooks(
    intent: UnpackIntent,
    hooks: FailureHooks,
) -> Result<CommitReceipt, Error> {
    execute_with_transaction(intent, LinkedOutputTransaction::with_failure_hooks(hooks))
        .map(ProcessedSourceCleanupResult::into_commit_receipt)
}

fn execute_with_transaction(
    intent: UnpackIntent,
    transaction: LinkedOutputTransaction,
) -> Result<ProcessedSourceCleanupResult, Error> {
    let UnpackIntent {
        input,
        detached_header,
        cleanup_receipt,
        raw_key,
        output_dir_path,
        on_decrypted_header,
        on_archive_info,
        on_archive_file,
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
        on_archive_file,
    };

    let stor = Arc::new(storage::FileStorage);
    execute_manifest_archive(stor, req, transaction)
        .map(|commit_receipt| ProcessedSourceCleanupResult::new(commit_receipt, cleanup_receipt))
}

fn execute_manifest_archive<R>(
    stor: Arc<storage::FileStorage>,
    req: HandleRequest<'_, R>,
    transaction: LinkedOutputTransaction,
) -> Result<CommitReceipt, Error>
where
    R: Read + Seek,
{
    let payload =
        decrypt::read_v1_payload(req.header_reader, req.reader).map_err(Error::Decrypt)?;
    if let Some(on_decrypted_header) = req.on_decrypted_header {
        on_decrypted_header(payload.header());
    }
    if payload.header().payload_kind() != PayloadKind::ManifestArchive
        || payload.header().payload_framing() != PayloadFramingProfile::ManifestFirst
    {
        return Err(Error::OpenArchive);
    }

    let master_key = decrypt::decrypt_master_key(&payload, req.raw_key).map_err(Error::Decrypt)?;
    let mut encrypted_reader = req.reader.borrow_mut();
    let mut plaintext_reader =
        V1PayloadDecryptingReader::new(master_key, &payload, &mut *encrypted_reader)
            .map_err(decrypt::map_stream_error)
            .map_err(Error::Decrypt)?;

    let (output_dir, entities, transaction) = {
        let mut uncommitted_reader = UncommittedPlaintextReader(&mut plaintext_reader);
        let (output_dir, entities, transaction) = stage_manifest_extraction(
            &stor,
            &mut uncommitted_reader,
            &req.output_dir_path,
            &req.input_path,
            req.detached_header_path.as_deref(),
            req.on_archive_file.as_ref(),
            transaction,
        )?;
        drain_trailing_plaintext_to_final_auth(&mut uncommitted_reader)?;
        (output_dir, entities, transaction)
    };
    if let Some(on_archive_info) = req.on_archive_info {
        on_archive_info(entities.len());
    }

    let _final_auth = plaintext_reader
        .finish()
        .map_err(decrypt::map_stream_error)
        .map_err(Error::Decrypt)?;
    revalidate_extraction_targets(&stor, &output_dir, &entities)?;
    let directory_creation =
        create_selected_directories_after_final_auth(&stor, &output_dir, &entities)?;
    match transaction.commit_all() {
        Ok(mut receipt) => {
            receipt.extend_artifacts(directory_creation.artifacts);
            Ok(receipt)
        }
        Err(error) => {
            if !matches!(error, TransactionError::PartialCommit { .. }) {
                let _rollback = storage::cleanup::rollback_empty_directories_best_effort(
                    &directory_creation.rollback_dirs,
                );
            }
            Err(Error::Transaction(error))
        }
    }
}

fn stage_manifest_extraction<R: Read>(
    stor: &storage::FileStorage,
    plaintext_reader: &mut R,
    output_dir_path: &Path,
    input_path: &Path,
    detached_header_path: Option<&Path>,
    on_archive_file: Option<&OnArchiveFileFn>,
    mut transaction: LinkedOutputTransaction,
) -> Result<(PathBuf, Vec<ExtractionEntity>, LinkedOutputTransaction), Error> {
    let manifest = ArchiveManifest::read_from(plaintext_reader).map_err(map_payload_error)?;
    let (output_dir, entities) = prepare_manifest_extraction_entities(
        stor,
        &manifest,
        output_dir_path,
        input_path,
        detached_header_path,
        on_archive_file,
    )?;
    let mut file_entities_by_index = BTreeMap::new();
    for entity in &entities {
        if matches!(entity.kind, ExtractionKind::File(_)) {
            file_entities_by_index.insert(entity.archive_index, entity);
        }
    }

    for (index, entry) in manifest.entries().iter().enumerate() {
        if entry.kind() != ManifestEntryKind::File {
            continue;
        }
        let expected_index = u32::try_from(index).expect("manifest entry count is bounded");
        let frame_header = read_manifest_body_frame_header(plaintext_reader, expected_index)?;
        if frame_header.entry_index() != expected_index {
            return Err(Error::ArchivePayload(
                PayloadError::BodyFrameOrderMismatch {
                    expected: expected_index,
                    actual: frame_header.entry_index(),
                },
            ));
        }
        let expected_body_len = entry
            .body_len()
            .expect("file manifest entry has body length");
        if frame_header.body_len() != expected_body_len {
            return Err(Error::ArchivePayload(
                PayloadError::BodyFrameLengthMismatch {
                    expected: expected_body_len,
                    actual: frame_header.body_len(),
                },
            ));
        }

        if let Some(entity) = file_entities_by_index.get(&index) {
            stage_manifest_file_body(
                stor,
                plaintext_reader,
                &output_dir,
                &mut transaction,
                entity,
                frame_header.body_len(),
            )?;
        } else {
            drain_manifest_body(plaintext_reader, frame_header.body_len())?;
        }
    }

    Ok((output_dir, entities, transaction))
}

fn read_manifest_body_frame_header<R: Read>(
    plaintext_reader: &mut R,
    expected_index: u32,
) -> Result<ArchiveBodyFrameHeader, Error> {
    match ArchiveBodyFrameHeader::read_from(plaintext_reader) {
        Ok(header) => Ok(header),
        Err(PayloadError::TruncatedManifest) => Err(Error::ArchivePayload(
            PayloadError::MissingBodyFrame(expected_index),
        )),
        Err(error) => Err(map_payload_error(error)),
    }
}

fn prepare_manifest_extraction_entities(
    stor: &storage::FileStorage,
    manifest: &ArchiveManifest,
    output_dir_path: &Path,
    input_path: &Path,
    detached_header_path: Option<&Path>,
    on_archive_file: Option<&OnArchiveFileFn>,
) -> Result<(PathBuf, Vec<ExtractionEntity>), Error> {
    let output_dir = stor
        .prepare_unpack_root(output_dir_path)
        .map_err(map_storage_path_error)?;
    let limits = ArchiveLimits::default();
    limits
        .check_entry_count(manifest.entries().len())
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
    for (index, entry) in manifest.entries().iter().enumerate() {
        let path = manifest_entry_path(entry.normalized_path())?;
        limits
            .check_normalized_path(&path)
            .map_err(Error::ArchiveLimit)?;
        let archive_entry_kind = match entry.kind() {
            ManifestEntryKind::Directory => ArchiveEntryKind::Directory,
            ManifestEntryKind::File => ArchiveEntryKind::File,
        };
        archive_paths.insert(&path, archive_entry_kind)?;

        let full_path = stor
            .resolve_unpack_path(&output_dir, &path)
            .map_err(map_storage_path_error)?;

        let kind = if archive_entry_kind == ArchiveEntryKind::Directory {
            let overwrite_policy = overwrite_policy_for_extracted_directory(&full_path)?;
            let target = identity_graph
                .add_output(&full_path, PathRole::Output, overwrite_policy)
                .map_err(map_identity_error)?;
            ExtractionKind::Directory(target)
        } else {
            let overwrite_policy =
                overwrite_policy_for_extracted_file(&full_path, on_archive_file.is_some())?;
            let target = identity_graph
                .add_output(&full_path, PathRole::Output, overwrite_policy)
                .map_err(map_identity_error)?;
            ExtractionKind::File(target)
        };

        scanned_entries.push(ScannedEntry {
            full_path,
            relative_path: path,
            archive_index: index,
            kind,
        });
    }

    let mut entities = Vec::new();
    for entry in scanned_entries {
        if let Some(on_archive_file) = on_archive_file {
            let should_unpack =
                on_archive_file(entry.full_path.clone()).map_err(Error::ArchiveFileCallback)?;
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

fn stage_manifest_file_body<R: Read>(
    stor: &storage::FileStorage,
    plaintext_reader: &mut R,
    output_dir: &Path,
    transaction: &mut LinkedOutputTransaction,
    entity: &ExtractionEntity,
    body_len: u64,
) -> Result<(), Error> {
    let ExtractionKind::File(target) = &entity.kind else {
        unreachable!();
    };

    stor.revalidate_unpack_target(output_dir, &entity.relative_path, target)
        .map_err(map_storage_path_error)?;

    let transaction_index = transaction
        .stage_in(target.clone(), output_dir)
        .map_err(Error::Transaction)?;
    let staged = transaction
        .staged_output_mut(transaction_index)
        .ok_or_else(|| {
            Error::Transaction(TransactionError::Write {
                path: entity.full_path.clone(),
                source: None,
            })
        })?;

    staged
        .with_writer_result(|writer| copy_manifest_body(plaintext_reader, writer, body_len))
        .map_err(map_manifest_staged_write_error)
}

fn copy_manifest_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    body_len: u64,
) -> Result<(), io::Error> {
    let copied = io::copy(&mut reader.take(body_len), writer)?;
    if copied != body_len {
        return Err(io::Error::other(PayloadError::TruncatedManifest));
    }
    Ok(())
}

fn drain_manifest_body<R: Read>(reader: &mut R, body_len: u64) -> Result<(), Error> {
    let copied =
        io::copy(&mut reader.take(body_len), &mut io::sink()).map_err(map_body_io_error)?;
    if copied != body_len {
        return Err(Error::ArchivePayload(PayloadError::TruncatedManifest));
    }
    Ok(())
}

fn drain_trailing_plaintext_to_final_auth<R: Read>(reader: &mut R) -> Result<(), Error> {
    let trailing = io::copy(reader, &mut io::sink()).map_err(map_body_io_error)?;
    if trailing == 0 {
        return Ok(());
    }

    Err(Error::ArchivePayload(PayloadError::TrailingBytes(
        usize::try_from(trailing).unwrap_or(usize::MAX),
    )))
}

fn create_selected_directories_after_final_auth(
    stor: &storage::FileStorage,
    output_dir: &Path,
    entities: &[ExtractionEntity],
) -> Result<DirectoryCreation, Error> {
    let mut artifacts = Vec::new();
    let mut rollback_dirs = Vec::new();
    for entity in entities
        .iter()
        .filter(|entity| matches!(entity.kind, ExtractionKind::Directory(_)))
    {
        let ExtractionKind::Directory(target) = &entity.kind else {
            unreachable!();
        };
        if let Err(error) =
            stor.revalidate_unpack_directory_target(output_dir, &entity.relative_path, target)
        {
            let _rollback =
                storage::cleanup::rollback_empty_directories_best_effort(&rollback_dirs);
            return Err(map_storage_path_error(error));
        }
        match stor.create_unpack_dir_all(output_dir, &entity.relative_path) {
            Ok(created_dirs) => rollback_dirs.extend(created_dirs),
            Err(error) => {
                let _rollback =
                    storage::cleanup::rollback_empty_directories_best_effort(&rollback_dirs);
                return Err(map_storage_path_error(error));
            }
        }
        artifacts.push(CommittedArtifact::new(
            target.role(),
            entity.full_path.clone(),
        ));
    }
    Ok(DirectoryCreation {
        artifacts,
        rollback_dirs,
    })
}

fn revalidate_extraction_targets(
    stor: &storage::FileStorage,
    output_dir: &Path,
    entities: &[ExtractionEntity],
) -> Result<(), Error> {
    for entity in entities {
        match &entity.kind {
            ExtractionKind::Directory(target) => stor
                .revalidate_unpack_directory_target(output_dir, &entity.relative_path, target)
                .map_err(map_storage_path_error)?,
            ExtractionKind::File(target) => stor
                .revalidate_unpack_target(output_dir, &entity.relative_path, target)
                .map_err(map_storage_path_error)?,
        }
    }
    Ok(())
}

fn manifest_entry_path(normalized_path: &[u8]) -> Result<PathBuf, Error> {
    let normalized = std::str::from_utf8(normalized_path)
        .map_err(|_| Error::UnsafeOutputPath(PathBuf::from("<non-utf8>")))?;
    let mut path = PathBuf::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(Error::UnsafeOutputPath(PathBuf::from(normalized)));
        }
        path.push(part);
    }
    normalize_archive_path(&path)
}

fn map_payload_error(error: PayloadError) -> Error {
    match error {
        PayloadError::Io(error) => map_body_io_error(error),
        error => Error::ArchivePayload(error),
    }
}

fn map_manifest_staged_write_error(error: StagedWriteError<io::Error>) -> Error {
    match error {
        StagedWriteError::Operation(error) => map_body_io_error(error),
        StagedWriteError::Transaction(error) => map_manifest_staged_transaction_error(error),
    }
}

fn map_manifest_staged_transaction_error(error: TransactionError) -> Error {
    match error {
        TransactionError::Write {
            path,
            source: Some(source),
        } => {
            let kind = source.kind();
            let message = source.to_string();
            match source.into_inner() {
                Some(inner) => map_staged_inner_error(path, inner),
                None => Error::Transaction(TransactionError::Write {
                    path,
                    source: Some(io::Error::new(kind, message)),
                }),
            }
        }
        error => Error::Transaction(error),
    }
}

fn map_staged_inner_error(path: PathBuf, inner: Box<dyn std::error::Error + Send + Sync>) -> Error {
    match inner.downcast::<StreamError>() {
        Ok(stream_error) => Error::Decrypt(decrypt::map_stream_error(*stream_error)),
        Err(inner) => match inner.downcast::<PayloadError>() {
            Ok(payload_error) => Error::ArchivePayload(*payload_error),
            Err(inner) => Error::Transaction(TransactionError::Write {
                path,
                source: Some(io::Error::other(inner)),
            }),
        },
    }
}

fn map_body_io_error(error: io::Error) -> Error {
    let kind = error.kind();
    let message = error.to_string();
    match error.into_inner() {
        Some(inner) => match inner.downcast::<StreamError>() {
            Ok(stream_error) => Error::Decrypt(decrypt::map_stream_error(*stream_error)),
            Err(inner) => match inner.downcast::<PayloadError>() {
                Ok(payload_error) => Error::ArchivePayload(*payload_error),
                Err(inner) => Error::ArchivePayload(PayloadError::Io(io::Error::other(inner))),
            },
        },
        None => Error::ArchivePayload(PayloadError::Io(io::Error::new(kind, message))),
    }
}

fn overwrite_policy_for_extracted_file(
    path: &Path,
    consent_callback_present: bool,
) -> Result<OverwritePolicy, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(Error::UnsafeOutputPath(path.to_path_buf())),
        // An existing target is only replaced when a consent callback is wired up to drive
        // the decision; with no consent path we refuse to clobber silently (fs-4).
        Ok(_) if consent_callback_present => Ok(OverwritePolicy::ReplaceAtCommit),
        Ok(_) => Ok(OverwritePolicy::CreateNew),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(OverwritePolicy::CreateNew),
        Err(_) => Err(Error::Storage(storage::Error::FileAccess)),
    }
}

fn overwrite_policy_for_extracted_directory(path: &Path) -> Result<OverwritePolicy, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            Err(Error::UnsafeOutputPath(path.to_path_buf()))
        }
        Ok(metadata) if metadata.is_dir() => Ok(OverwritePolicy::ReplaceAtCommit),
        Ok(_) => Err(Error::UnsafeOutputPath(path.to_path_buf())),
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

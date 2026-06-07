//! This contains the logic for traversing one or more directories, placing
//! their files into a manifest-first archive streamed directly through V1 encryption.
//!
//! This is known as "packing" within Dexios.
//!
//! DISCLAIMER: Compression with encryption is generally risky in interactive
//! attacker-controlled settings. The Dexios `pack` workflow assumes offline
//! at-rest archival use, where the user controls the packed input.

use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use core::kdf::Kdf;
use core::payload::{ArchiveBodyFrameHeader, ArchiveManifest, ManifestEntry, PayloadError};
use core::primitives::BLOCK_SIZE;
use core::protected::Protected;

use crate::archive::{ArchiveLimitError, ArchiveLimits, ArchivePolicy};
use crate::archive_path::{ArchivePathError, NormalizedArchivePath};
use crate::storage::cleanup::{CleanupReceipt, ProcessedSourceCleanupResult};
use crate::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
use crate::storage::transaction::{
    CommitReceipt, DetachedPublicationFailure, LinkedOutputTransaction, TransactionError,
};
use crate::workflow_error::{
    WorkflowErrorClass, classify_identity_error, classify_storage_error, classify_transaction_error,
};

#[derive(Debug)]
pub enum Error {
    CreateArchive,
    CreateArchiveWithSource(crate::storage::Error),
    CreateArchiveIoWithSource(io::Error),
    AddDirToArchive,
    AddFileToArchive,
    FinishArchive,
    FinishArchiveIoWithSource(io::Error),
    ReadData,
    ReadDataWithSource(io::Error),
    ReadDataStorageWithSource(crate::storage::Error),
    WriteData,
    WriteDataWithSource(io::Error),
    Encrypt(crate::encrypt::Error),
    PathIdentity(IdentityError),
    Transaction(TransactionError),
    DetachedPublication(TransactionError),
    TransactionWriter,
    ArchiveLimit(ArchiveLimitError),
    ArchivePath(PathBuf),
    ArchivePayload(PayloadError),
    ArchiveRootName,
    SymlinkSource(PathBuf),
    ReadSource,
    ReadSourceWithSource(crate::storage::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateArchive
            | Self::CreateArchiveWithSource(_)
            | Self::CreateArchiveIoWithSource(_) => f.write_str("Unable to create archive"),
            Self::AddDirToArchive => f.write_str("Unable to add directory to archive"),
            Self::AddFileToArchive => f.write_str("Unable to add file to archive"),
            Self::FinishArchive | Self::FinishArchiveIoWithSource(_) => {
                f.write_str("Unable to finish archive")
            }
            Self::ReadData | Self::ReadDataWithSource(_) | Self::ReadDataStorageWithSource(_) => {
                f.write_str("Unable to read data")
            }
            Self::WriteData | Self::WriteDataWithSource(_) => f.write_str("Unable to write data"),
            Self::Encrypt(inner) => write!(f, "Unable to encrypt archive: {inner}"),
            Self::PathIdentity(inner) => write!(f, "Pack path identity check failed: {inner}"),
            Self::Transaction(inner) => write!(f, "Pack transaction failed: {inner}"),
            Self::DetachedPublication(inner) => {
                write!(f, "Detached publication incomplete: {inner}")
            }
            Self::TransactionWriter => f.write_str("Unable to release staged pack writers"),
            Self::ArchiveLimit(inner) => write!(f, "Archive limit error: {inner}"),
            Self::ArchivePath(path) => {
                write!(
                    f,
                    "Archive path error: Unsafe archive path: {}",
                    path.display()
                )
            }
            Self::ArchivePayload(inner) => write!(f, "Archive payload error: {inner}"),
            Self::ArchiveRootName => f.write_str("Unable to derive archive root names"),
            Self::SymlinkSource(path) => {
                write!(f, "Symlink pack source rejected: {}", path.display())
            }
            Self::ReadSource | Self::ReadSourceWithSource(_) => {
                f.write_str("Unable to read pack source")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateArchiveWithSource(error)
            | Self::ReadDataStorageWithSource(error)
            | Self::ReadSourceWithSource(error) => Some(error),
            Self::CreateArchiveIoWithSource(error)
            | Self::FinishArchiveIoWithSource(error)
            | Self::ReadDataWithSource(error)
            | Self::WriteDataWithSource(error) => Some(error),
            Self::Encrypt(error) => Some(error),
            Self::PathIdentity(error) => Some(error),
            Self::Transaction(error) | Self::DetachedPublication(error) => Some(error),
            Self::ArchivePayload(error) => Some(error),
            Self::ArchiveLimit(error) => Some(error),
            _ => None,
        }
    }
}

impl Error {
    #[must_use]
    pub fn workflow_class(&self) -> WorkflowErrorClass {
        match self {
            Self::Transaction(error) | Self::DetachedPublication(error) => {
                classify_transaction_error(error)
            }
            _ if self.is_resource_pressure() => WorkflowErrorClass::ResourcePressure,
            Self::Encrypt(error) => error.workflow_class(),
            Self::PathIdentity(error) => classify_identity_error(error),
            Self::CreateArchiveWithSource(error)
            | Self::ReadDataStorageWithSource(error)
            | Self::ReadSourceWithSource(error) => classify_storage_error(error),
            Self::ArchiveLimit(_)
            | Self::ArchivePath(_)
            | Self::ArchiveRootName
            | Self::SymlinkSource(_) => WorkflowErrorClass::UnsafePath,
            Self::ArchivePayload(error) => classify_payload_error(error),
            Self::CreateArchive
            | Self::CreateArchiveIoWithSource(_)
            | Self::AddDirToArchive
            | Self::AddFileToArchive
            | Self::FinishArchive
            | Self::FinishArchiveIoWithSource(_)
            | Self::ReadData
            | Self::ReadDataWithSource(_)
            | Self::WriteData
            | Self::WriteDataWithSource(_)
            | Self::TransactionWriter
            | Self::ReadSource => WorkflowErrorClass::IoFailure,
        }
    }

    #[must_use]
    pub fn is_resource_pressure(&self) -> bool {
        crate::storage::error_chain_contains_resource_pressure(self)
    }

    #[must_use]
    pub fn detached_publication_failure(&self) -> Option<DetachedPublicationFailure> {
        match self {
            Self::DetachedPublication(error) => error.detached_publication_failure(),
            _ => None,
        }
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

fn map_archive_path_error(error: ArchivePathError) -> Error {
    match error {
        ArchivePathError::Unsafe(path) => Error::ArchivePath(path),
    }
}

impl From<IdentityError> for Error {
    fn from(value: IdentityError) -> Self {
        Self::PathIdentity(value)
    }
}

impl From<TransactionError> for Error {
    fn from(value: TransactionError) -> Self {
        Self::Transaction(value)
    }
}

pub type OnArchiveEntryFn = Box<dyn Fn(&Path)>;

pub struct DetachedHeaderTarget {
    path: PathBuf,
    overwrite: OverwritePolicy,
}

impl DetachedHeaderTarget {
    pub fn new<P: AsRef<Path>>(path: P, overwrite: OverwritePolicy) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            overwrite,
        }
    }
}

struct PackSource {
    target: ResolvedTarget,
    archive_root: PathBuf,
}

pub struct PackIntent {
    sources: Vec<PackSource>,
    output_target: ResolvedTarget,
    detached_header_target: Option<ResolvedTarget>,
    cleanup_receipt: CleanupReceipt,
    raw_key: Protected<Vec<u8>>,
    kdf: Kdf,
    on_archive_entry: Option<OnArchiveEntryFn>,
    on_walked_entry_after_metadata: Option<OnArchiveEntryFn>,
}

impl PackIntent {
    #[expect(
        clippy::too_many_arguments,
        reason = "pack intent aggregates the full pack CLI surface in one constructor"
    )]
    pub fn new<S, O>(
        source_paths: Vec<S>,
        output_path: O,
        output_overwrite: OverwritePolicy,
        detached_header: Option<DetachedHeaderTarget>,
        raw_key: Protected<Vec<u8>>,
        kdf: Kdf,
        _archive_policy: ArchivePolicy,
        _recursive: bool,
        on_archive_entry: Option<OnArchiveEntryFn>,
    ) -> Result<Self, Error>
    where
        S: AsRef<Path>,
        O: AsRef<Path>,
    {
        let source_paths = source_paths
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect::<Vec<_>>();
        if source_paths.is_empty() {
            return Err(Error::ArchiveRootName);
        }

        for source_path in &source_paths {
            reject_symlink_source(source_path)?;
        }

        let archive_roots = archive_root_names(&source_paths)?;
        let mut graph = PathIdentityGraph::new();
        let sources = source_paths
            .iter()
            .zip(archive_roots)
            .map(|(source_path, archive_root)| {
                graph
                    .add_existing(source_path, PathRole::ProcessedSource)
                    .map(|target| PackSource {
                        target,
                        archive_root,
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::PathIdentity)?;
        let cleanup_receipt = CleanupReceipt::from_processed_source_trees(
            sources.iter().map(|source| &source.target),
        )
        .map_err(|source| {
            Error::ReadSourceWithSource(crate::storage::Error::FileAccessWithSource(source))
        })?;

        let output_target = graph
            .add_output(output_path, PathRole::GeneratedOutput, output_overwrite)
            .map_err(Error::PathIdentity)?;
        let detached_header_target = detached_header
            .map(|target| {
                graph.add_output(
                    target.path,
                    PathRole::GeneratedDetachedHeader,
                    target.overwrite,
                )
            })
            .transpose()
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        Ok(Self {
            sources,
            output_target,
            detached_header_target,
            cleanup_receipt,
            raw_key,
            kdf,
            on_archive_entry,
            on_walked_entry_after_metadata: None,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_walked_entry_after_metadata_observer(mut self, observer: OnArchiveEntryFn) -> Self {
        self.on_walked_entry_after_metadata = Some(observer);
        self
    }
}

struct HandleRequest<'a, SRW, W>
where
    SRW: Read + Write + Seek,
    W: Write,
{
    writer: &'a RefCell<W>,
    entries: Vec<ArchiveSourceEntry<SRW>>,
    header_writer: Option<&'a RefCell<W>>,
    raw_key: Protected<Vec<u8>>,
    kdf: Kdf,
}

struct ArchiveSourceEntry<RW>
where
    RW: Read + Write + Seek,
{
    source: crate::storage::Entry<RW>,
    archive_path: NormalizedArchivePath,
}

pub fn execute(intent: PackIntent) -> Result<CommitReceipt, Error> {
    execute_transactional(intent)
}

pub fn execute_transactional(intent: PackIntent) -> Result<CommitReceipt, Error> {
    execute_transactional_with_cleanup(intent)
        .map(ProcessedSourceCleanupResult::into_commit_receipt)
}

pub fn execute_transactional_with_cleanup(
    intent: PackIntent,
) -> Result<ProcessedSourceCleanupResult, Error> {
    let PackIntent {
        sources,
        output_target,
        detached_header_target,
        cleanup_receipt,
        raw_key,
        kdf,
        on_archive_entry,
        on_walked_entry_after_metadata,
    } = intent;

    let entries = materialize_archive_entries(
        &sources,
        on_archive_entry.as_deref(),
        on_walked_entry_after_metadata.as_deref(),
    )?;
    validate_generated_targets_against_entries(
        &entries,
        &output_target,
        detached_header_target.as_ref(),
    )?;

    let mut transaction = LinkedOutputTransaction::new();
    let output_index = transaction.stage(output_target)?;
    let detached_header_index = detached_header_target
        .map(|target| transaction.stage(target))
        .transpose()?;
    let has_detached_header = detached_header_index.is_some();

    let transaction = Rc::new(RefCell::new(transaction));
    let output_writer = RefCell::new(LinkedStagedWriter::new(
        Rc::clone(&transaction),
        output_index,
    ));
    let detached_header_writer = detached_header_index
        .map(|index| RefCell::new(LinkedStagedWriter::new(Rc::clone(&transaction), index)));

    let pack_result = execute_streaming_archive(HandleRequest {
        entries,
        writer: &output_writer,
        header_writer: detached_header_writer.as_ref(),
        raw_key,
        kdf,
    });
    if let Err(error) = pack_result {
        let resource_pressure = output_writer.borrow().resource_pressure_kind().or_else(|| {
            detached_header_writer
                .as_ref()
                .and_then(|writer| writer.borrow().resource_pressure_kind())
        });
        return Err(map_encrypt_output_resource_pressure(
            error,
            resource_pressure,
        ));
    }

    drop(output_writer);
    drop(detached_header_writer);
    let transaction = Rc::try_unwrap(transaction)
        .map_err(|_| Error::TransactionWriter)?
        .into_inner();
    transaction
        .commit_all()
        .map_err(|error| map_detached_publication_transaction_error(error, has_detached_header))
        .map(|commit_receipt| ProcessedSourceCleanupResult::new(commit_receipt, cleanup_receipt))
}

fn map_detached_publication_transaction_error(
    error: TransactionError,
    has_detached_header: bool,
) -> Error {
    if has_detached_header && error.detached_publication_failure().is_some() {
        Error::DetachedPublication(error)
    } else {
        Error::Transaction(error)
    }
}

#[expect(
    clippy::expect_used,
    reason = "entry index is bounded by the manifest entry count (< u32::MAX), so the width conversion cannot overflow"
)]
fn execute_streaming_archive<SRW, W>(req: HandleRequest<'_, SRW, W>) -> Result<(), Error>
where
    SRW: Read + Write + Seek,
    W: Write,
{
    let mut output_writer = req.writer.borrow_mut();
    let encrypting_writer = match req.header_writer {
        None => crate::encrypt::begin_v1_manifest_archive_writer(
            &mut *output_writer,
            None,
            req.raw_key,
            req.kdf,
        )
        .map_err(Error::Encrypt)?,
        Some(header_writer) => {
            let mut header_writer = header_writer.borrow_mut();
            crate::encrypt::begin_v1_manifest_archive_writer(
                &mut *output_writer,
                Some(&mut *header_writer),
                req.raw_key,
                req.kdf,
            )
            .map_err(Error::Encrypt)?
        }
    };

    let mut manifest_entries = Vec::with_capacity(req.entries.len());
    for entry in &req.entries {
        manifest_entries.push(manifest_entry_for(entry)?);
    }
    let manifest = ArchiveManifest::new(manifest_entries).map_err(Error::ArchivePayload)?;
    let mut encrypting_writer = encrypting_writer;
    manifest
        .write_to(&mut encrypting_writer)
        .map_err(Error::ArchivePayload)?;

    for (index, entry) in req.entries.iter().enumerate() {
        if entry.source.is_dir() {
            continue;
        }

        let body_len = entry_body_len(entry)?;
        let frame_header = ArchiveBodyFrameHeader::new(
            u32::try_from(index).expect("manifest entry count is bounded"),
            body_len,
        )
        .map_err(Error::ArchivePayload)?;
        frame_header
            .write_to(&mut encrypting_writer)
            .map_err(Error::ArchivePayload)?;
        write_archive_body(entry, body_len, &mut encrypting_writer)?;
    }

    crate::encrypt::finish_v1_payload_writer(encrypting_writer)
        .map(|_| ())
        .map_err(Error::Encrypt)
}

fn manifest_entry_for<RW>(entry: &ArchiveSourceEntry<RW>) -> Result<ManifestEntry, Error>
where
    RW: Read + Write + Seek,
{
    let normalized_path = entry.archive_path.as_manifest_bytes().to_vec();
    if entry.source.is_dir() {
        ManifestEntry::directory(normalized_path).map_err(Error::ArchivePayload)
    } else {
        let body_len = entry_body_len(entry)?;
        ManifestEntry::file(normalized_path, body_len).map_err(Error::ArchivePayload)
    }
}

fn entry_body_len<RW>(entry: &ArchiveSourceEntry<RW>) -> Result<u64, Error>
where
    RW: Read + Write + Seek,
{
    let mut reader = entry
        .source
        .try_reader()
        .map_err(Error::ReadDataStorageWithSource)?
        .borrow_mut();
    let current = reader
        .stream_position()
        .map_err(Error::ReadDataWithSource)?;
    let end = reader
        .seek(SeekFrom::End(0))
        .map_err(Error::ReadDataWithSource)?;
    reader
        .seek(SeekFrom::Start(current))
        .map_err(Error::ReadDataWithSource)?;
    Ok(end)
}

#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "limit = min(remaining, BLOCK_SIZE) <= buffer.len() and read_count <= limit keep the buffer ranges in bounds; both bounded sizes fit usize/u64, and remaining only decreases by the actual read_count (<= remaining)"
)]
fn write_archive_body<RW, W>(
    entry: &ArchiveSourceEntry<RW>,
    body_len: u64,
    writer: &mut W,
) -> Result<(), Error>
where
    RW: Read + Write + Seek,
    W: Write,
{
    let mut reader = entry
        .source
        .try_reader()
        .map_err(Error::ReadDataStorageWithSource)?
        .borrow_mut();
    reader.rewind().map_err(Error::ReadDataWithSource)?;

    let mut remaining = body_len;
    let mut buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(BLOCK_SIZE as u64))
            .expect("bounded read size fits in usize");
        let read_count = reader
            .read(&mut buffer[..limit])
            .map_err(Error::ReadDataWithSource)?;
        if read_count == 0 {
            return Err(Error::ReadData);
        }
        writer
            .write_all(&buffer[..read_count])
            .map_err(Error::WriteDataWithSource)?;
        remaining -= u64::try_from(read_count).expect("usize read count fits in u64");
    }

    Ok(())
}

fn reject_symlink_source(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(Error::SymlinkSource(path.to_path_buf()))
        }
        Ok(_) | Err(_) => Ok(()),
    }
}

fn materialize_archive_entries(
    sources: &[PackSource],
    on_archive_entry: Option<&dyn Fn(&Path)>,
    on_walked_entry_after_metadata: Option<&dyn Fn(&Path)>,
) -> Result<Vec<ArchiveSourceEntry<fs::File>>, Error> {
    materialize_archive_entries_with_limits(
        sources,
        on_archive_entry,
        on_walked_entry_after_metadata,
        ArchiveLimits::default(),
    )
}

fn materialize_archive_entries_with_limits(
    sources: &[PackSource],
    on_archive_entry: Option<&dyn Fn(&Path)>,
    on_walked_entry_after_metadata: Option<&dyn Fn(&Path)>,
    limits: ArchiveLimits,
) -> Result<Vec<ArchiveSourceEntry<fs::File>>, Error> {
    let stor = crate::storage::FileStorage;
    let mut entries = Vec::new();

    for source_root in sources {
        let file = stor
            .read_resolved_existing_no_follow(&source_root.target)
            .map_err(Error::ReadSourceWithSource)?;

        if file.is_dir() {
            let root_path = stor
                .revalidate_resolved_directory_root(&source_root.target)
                .map_err(Error::ReadSourceWithSource)?;
            for source in walkdir::WalkDir::new(&root_path) {
                let source = source.map_err(|error| {
                    Error::ReadSourceWithSource(match error.into_io_error() {
                        Some(source) => crate::storage::Error::DirEntriesWithSource(source),
                        None => crate::storage::Error::DirEntries,
                    })
                })?;
                if source.path_is_symlink() {
                    return Err(Error::SymlinkSource(source.path().to_path_buf()));
                }
                let walked_metadata = source.metadata().map_err(|error| {
                    Error::ReadSourceWithSource(match error.into_io_error() {
                        Some(source) => crate::storage::Error::FileAccessWithSource(source),
                        None => crate::storage::Error::FileAccess,
                    })
                })?;
                if let Some(on_walked_entry_after_metadata) = on_walked_entry_after_metadata {
                    on_walked_entry_after_metadata(source.path());
                }
                let source = stor
                    .read_file_no_follow(source.path())
                    .map_err(Error::ReadSourceWithSource)?;
                verify_walked_entry_matches_opened(&source, &walked_metadata)?;
                let relative = source
                    .path()
                    .strip_prefix(&root_path)
                    .map_err(|_| Error::ReadSource)?;
                let archive_path = if relative.as_os_str().is_empty() {
                    source_root.archive_root.clone()
                } else {
                    source_root.archive_root.join(relative)
                };

                push_archive_entry(&mut entries, source, archive_path, limits, on_archive_entry)?;
            }
        } else {
            push_archive_entry(
                &mut entries,
                file,
                source_root.archive_root.clone(),
                limits,
                on_archive_entry,
            )?;
        }
    }

    Ok(entries)
}

#[cfg(unix)]
fn verify_walked_entry_matches_opened(
    entry: &crate::storage::Entry<fs::File>,
    walked_metadata: &fs::Metadata,
) -> Result<(), Error> {
    // Unix pack traversal verifies the no-follow opened entry against walked
    // identity evidence before archive acceptance.
    if entry.is_dir() {
        let current_metadata = fs::symlink_metadata(entry.path()).map_err(|source| {
            Error::ReadSourceWithSource(crate::storage::Error::FileAccessWithSource(source))
        })?;
        if walked_metadata.is_dir()
            && current_metadata.is_dir()
            && current_metadata.dev() == walked_metadata.dev()
            && current_metadata.ino() == walked_metadata.ino()
        {
            return Ok(());
        }
        return Err(Error::ReadSourceWithSource(
            crate::storage::Error::UnsafePath(entry.path().to_path_buf()),
        ));
    }

    let opened_metadata = entry
        .try_reader()
        .map_err(Error::ReadSourceWithSource)?
        .borrow()
        .metadata()
        .map_err(|source| {
            Error::ReadSourceWithSource(crate::storage::Error::FileAccessWithSource(source))
        })?;
    if opened_metadata.dev() != walked_metadata.dev()
        || opened_metadata.ino() != walked_metadata.ino()
    {
        return Err(Error::ReadSourceWithSource(
            crate::storage::Error::UnsafePath(entry.path().to_path_buf()),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_walked_entry_matches_opened(
    _entry: &crate::storage::Entry<fs::File>,
    _walked_metadata: &fs::Metadata,
) -> Result<(), Error> {
    // non-Unix fallback is limited by platform identity APIs.
    // It does not provide Unix-equivalent identity evidence.
    Ok(())
}

fn push_archive_entry<RW>(
    entries: &mut Vec<ArchiveSourceEntry<RW>>,
    source: crate::storage::Entry<RW>,
    archive_path: PathBuf,
    limits: ArchiveLimits,
    on_archive_entry: Option<&dyn Fn(&Path)>,
) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    limits
        .check_entry_count(entries.len().saturating_add(1))
        .map_err(Error::ArchiveLimit)?;
    let archive_path =
        NormalizedArchivePath::from_path(&archive_path).map_err(map_archive_path_error)?;
    archive_path
        .check_limits(&limits)
        .map_err(Error::ArchiveLimit)?;

    if let Some(on_archive_entry) = on_archive_entry {
        on_archive_entry(archive_path.as_path());
    }

    entries.push(ArchiveSourceEntry {
        source,
        archive_path,
    });
    Ok(())
}

#[expect(
    clippy::expect_used,
    reason = "generated pack output/detached-header targets are always constructed with an overwrite policy, so these accessors are never None here"
)]
fn validate_generated_targets_against_entries<RW>(
    entries: &[ArchiveSourceEntry<RW>],
    output_target: &ResolvedTarget,
    detached_header_target: Option<&ResolvedTarget>,
) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let generated_target_exists =
        output_target.exists() || detached_header_target.is_some_and(ResolvedTarget::exists);

    if !generated_target_exists {
        return Ok(());
    }

    for entry in entries {
        if entry.source.is_dir() {
            continue;
        }

        let mut graph = PathIdentityGraph::new();
        graph.add_existing(entry.source.path(), PathRole::Input)?;
        graph.add_output(
            output_target.original_path(),
            PathRole::GeneratedOutput,
            output_target
                .overwrite_policy()
                .expect("generated output target has overwrite policy"),
        )?;
        if let Some(target) = detached_header_target {
            graph.add_output(
                target.original_path(),
                PathRole::GeneratedDetachedHeader,
                target
                    .overwrite_policy()
                    .expect("generated detached header target has overwrite policy"),
            )?;
        }
        graph.validate()?;
    }

    Ok(())
}

#[cfg(windows)]
fn prefix_label(prefix: std::path::PrefixComponent<'_>) -> OsString {
    use std::path::Prefix;

    match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
            OsString::from(format!("drive-{}", char::from(drive).to_ascii_uppercase()))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut label = OsString::from("unc-");
            label.push(server);
            label.push("-");
            label.push(share);
            label
        }
        Prefix::DeviceNS(device) => {
            let mut label = OsString::from("device-");
            label.push(device);
            label
        }
        Prefix::Verbatim(name) => {
            let mut label = OsString::from("verbatim-");
            label.push(name);
            label
        }
    }
}

fn normalized_absolute_components(path: &Path) -> Vec<OsString> {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            #[cfg(windows)]
            Component::Prefix(prefix) => components.push(prefix_label(prefix)),
            #[cfg(not(windows))]
            Component::Prefix(_) => {}
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                components.pop();
            }
            Component::Normal(part) => components.push(part.to_os_string()),
        }
    }

    components
}

fn normalized_path_components(path: &Path) -> Result<Vec<OsString>, Error> {
    let current_dir = std::env::current_dir().map_err(|_| Error::ArchiveRootName)?;
    let current_dir_components = normalized_absolute_components(&current_dir);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };
    let mut components = normalized_absolute_components(&resolved);

    if components.starts_with(&current_dir_components) {
        let relative = components.split_off(current_dir_components.len());
        if relative.is_empty() {
            let fallback = current_dir
                .file_name()
                .map_or_else(|| OsString::from("root"), std::ffi::OsStr::to_os_string);
            return Ok(vec![fallback]);
        }
        return Ok(relative);
    }

    if components.is_empty() {
        return Err(Error::ArchiveRootName);
    }

    Ok(components)
}

#[expect(
    clippy::indexing_slicing,
    reason = "start = components.len().saturating_sub(suffix_len) is always <= components.len(), so components[start..] is in bounds"
)]
fn suffix_path(components: &[OsString], suffix_len: usize) -> PathBuf {
    let start = components.len().saturating_sub(suffix_len);
    let mut path = PathBuf::new();
    for component in &components[start..] {
        path.push(component);
    }
    path
}

#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "suffix_lengths and components are the same length, and index always comes from enumerate() over the equally-sized roots vector; the increment is guarded by `suffix_lengths[index] < components[index].len()`"
)]
fn archive_root_names(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, Error> {
    let components = inputs
        .iter()
        .map(|input| normalized_path_components(input))
        .collect::<Result<Vec<_>, _>>()?;

    let mut suffix_lengths = vec![1usize; components.len()];

    loop {
        let roots = components
            .iter()
            .zip(&suffix_lengths)
            .map(|(parts, suffix_len)| suffix_path(parts, *suffix_len))
            .collect::<Vec<_>>();

        let mut collisions = std::collections::HashMap::<PathBuf, Vec<usize>>::new();
        for (index, root) in roots.iter().enumerate() {
            collisions.entry(root.clone()).or_default().push(index);
        }

        let mut progressed = false;
        let mut has_collision = false;

        for indexes in collisions.into_values() {
            if indexes.len() == 1 {
                continue;
            }

            has_collision = true;
            for index in indexes {
                if suffix_lengths[index] < components[index].len() {
                    suffix_lengths[index] += 1;
                    progressed = true;
                }
            }
        }

        if !has_collision {
            return Ok(roots);
        }

        if !progressed {
            return Err(Error::ArchiveRootName);
        }
    }
}

struct LinkedStagedWriter {
    transaction: Rc<RefCell<LinkedOutputTransaction>>,
    index: usize,
    resource_pressure: Cell<Option<io::ErrorKind>>,
}

impl LinkedStagedWriter {
    fn new(transaction: Rc<RefCell<LinkedOutputTransaction>>, index: usize) -> Self {
        Self {
            transaction,
            index,
            resource_pressure: Cell::new(None),
        }
    }

    fn resource_pressure_kind(&self) -> Option<io::ErrorKind> {
        self.resource_pressure.get()
    }

    fn with_staged_file<T>(
        &self,
        write: impl FnOnce(&mut fs::File) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut transaction = self.transaction.borrow_mut();
        let staged = transaction
            .staged_output_mut(self.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing staged pack output"))?;
        staged.with_writer(write).map_err(|error| {
            let error = transaction_to_io_error(error);
            if let Some(kind) = crate::storage::resource_pressure_kind_in_error_chain(&error) {
                self.resource_pressure.set(Some(kind));
            }
            error
        })
    }
}

impl Write for LinkedStagedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.with_staged_file(|file| file.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.with_staged_file(fs::File::flush)
    }
}

impl Seek for LinkedStagedWriter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.with_staged_file(|file| file.seek(pos))
    }
}

fn transaction_to_io_error(error: TransactionError) -> io::Error {
    io::Error::other(error)
}

fn map_encrypt_output_resource_pressure(
    error: Error,
    resource_pressure: Option<io::ErrorKind>,
) -> Error {
    match (&error, resource_pressure) {
        (
            Error::Encrypt(
                crate::encrypt::Error::EncryptFile
                | crate::encrypt::Error::WriteHeader
                | crate::encrypt::Error::ResetCursorPosition,
            )
            | Error::WriteDataWithSource(_)
            | Error::ArchivePayload(PayloadError::Io(_)),
            Some(kind),
        ) => Error::WriteDataWithSource(io::Error::from(kind)),
        _ => error,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Cursor, Read, Seek};
    use std::sync::Arc;

    use crate::archive::{ArchiveLimitKind, ArchiveLimits};
    use crate::encrypt::tests::PASSWORD;
    use crate::storage::{InMemoryStorage, Storage};

    #[expect(
        dead_code,
        reason = "captured ciphertext fixture retained for regression replay even when unused"
    )]
    pub(crate) const ENCRYPTED_PACKED_BAR_DIR: [u8; 1202] = [
        222, 5, 14, 1, 12, 1, 173, 240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124,
        190, 148, 91, 92, 129, 0, 0, 0, 0, 0, 0, 223, 181, 71, 240, 140, 106, 41, 36, 82, 150, 105,
        215, 159, 108, 234, 246, 25, 19, 65, 206, 177, 146, 15, 174, 209, 129, 82, 2, 62, 76, 129,
        34, 136, 189, 11, 98, 105, 54, 146, 71, 102, 166, 97, 177, 207, 62, 194, 132, 38, 87, 173,
        240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91, 92, 129, 50,
        126, 110, 254, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51, 119, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 64, 6, 177, 49,
        139, 218, 8, 121, 228, 19, 5, 8, 117, 33, 131, 131, 70, 76, 147, 108, 49, 191, 191, 127,
        223, 64, 127, 248, 65, 201, 130, 166, 129, 195, 245, 241, 188, 143, 148, 191, 86, 7, 102,
        124, 253, 12, 44, 172, 79, 236, 207, 68, 229, 117, 49, 250, 55, 6, 48, 86, 48, 244, 189,
        137, 27, 142, 241, 44, 118, 35, 5, 138, 237, 47, 248, 108, 30, 224, 42, 91, 16, 216, 14,
        235, 132, 33, 123, 83, 188, 196, 205, 18, 71, 152, 231, 231, 127, 182, 29, 156, 157, 203,
        178, 178, 3, 216, 51, 84, 28, 67, 91, 255, 14, 124, 180, 131, 80, 48, 27, 111, 195, 39,
        127, 37, 231, 111, 82, 132, 168, 253, 149, 230, 199, 161, 78, 6, 175, 98, 210, 9, 25, 145,
        199, 151, 38, 142, 199, 217, 35, 247, 168, 73, 138, 94, 175, 45, 0, 184, 252, 55, 250, 19,
        8, 79, 247, 38, 230, 133, 143, 66, 27, 69, 96, 183, 201, 238, 81, 114, 131, 123, 229, 78,
        39, 140, 151, 4, 196, 49, 37, 58, 12, 48, 243, 83, 111, 84, 6, 82, 249, 200, 120, 238, 190,
        136, 135, 189, 34, 237, 52, 18, 23, 43, 164, 113, 31, 111, 221, 119, 216, 110, 0, 74, 53,
        81, 86, 83, 234, 70, 69, 194, 224, 96, 26, 47, 133, 49, 147, 204, 96, 125, 165, 105, 182,
        161, 2, 143, 225, 195, 95, 64, 24, 49, 236, 210, 124, 32, 214, 69, 201, 5, 73, 5, 7, 160,
        233, 35, 202, 226, 40, 104, 45, 214, 0, 39, 55, 167, 203, 184, 145, 150, 233, 119, 115,
        246, 55, 162, 5, 154, 147, 144, 69, 217, 185, 39, 82, 223, 87, 132, 164, 148, 85, 234, 15,
        160, 2, 214, 133, 27, 73, 53, 27, 86, 53, 215, 96, 142, 85, 25, 127, 11, 111, 19, 1, 72,
        74, 92, 16, 14, 98, 20, 203, 163, 227, 160, 192, 158, 223, 99, 116, 212, 137, 101, 150,
        182, 125, 244, 59, 20, 157, 129, 149, 34, 21, 136, 185, 41, 242, 168, 45, 135, 100, 219,
        239, 132, 211, 238, 37, 242, 139, 218, 120, 112, 158, 75, 53, 172, 162, 136, 202, 94, 117,
        152, 175, 205, 34, 198, 99, 49, 174, 187, 80, 151, 225, 169, 120, 192, 77, 61, 38, 2, 158,
        45, 216, 78, 215, 134, 255, 7, 46, 144, 119, 60, 168, 202, 24, 239, 147, 122, 58, 48, 50,
        178, 58, 153, 243, 242, 169, 238, 42, 78, 123, 37, 181, 17, 109, 175, 84, 6, 212, 122, 89,
        60, 111, 248, 41, 156, 214, 222, 151, 212, 52, 10, 221, 69, 1, 215, 170, 76, 149, 134, 241,
        212, 217, 131, 179, 34, 240, 124, 224, 192, 105, 34, 254, 165, 211, 100, 169, 240, 171,
        131, 50, 80, 54, 254, 128, 179, 233, 223, 22, 39, 56, 205, 221, 76, 177, 197, 164, 140,
        181, 42, 154, 82, 239, 240, 127, 211, 45, 146, 57, 154, 151, 153, 112, 215, 222, 199, 37,
        44, 98, 118, 182, 189, 15, 139, 88, 227, 37, 149, 107, 13, 123, 201, 51, 61, 67, 220, 161,
        13, 72, 176, 39, 157, 128, 105, 144, 10, 46, 29, 113, 1, 76, 162, 157, 200, 213, 175, 107,
        128, 13, 47, 170, 216, 107, 48, 241, 149, 219, 20, 186, 74, 210, 5, 210, 18, 201, 78, 159,
        121, 180, 195, 154, 176, 154, 255, 21, 5, 86, 212, 181, 237, 131, 116, 59, 241, 57, 24,
        102, 126, 132, 135, 154, 99, 217, 2, 201, 139, 202, 125, 64, 165, 195, 210, 255, 165, 197,
        172, 166, 27, 200, 226, 158, 225, 224, 10, 150, 97, 2, 77, 73, 51, 112, 201, 146, 74, 245,
        95, 191, 244, 128, 170, 109, 227, 44, 24, 11, 216, 35, 137, 61, 120, 207, 212, 57, 229, 70,
        152, 118, 92, 235, 187, 55, 189, 231, 126, 15, 86, 66, 78, 251, 39, 181, 191, 193, 226,
        199, 131, 61, 145, 177, 76, 168, 0, 235, 172, 21, 213, 87, 81, 176, 135, 139, 61, 3, 91,
        67, 84, 199, 40, 113, 140, 68, 174, 34, 199, 50, 33, 187, 208, 209, 155, 237, 140, 16, 204,
        135, 151, 241, 28, 95, 87, 91, 169, 160, 1, 206, 18, 220, 65, 236, 52, 63, 184, 226, 237,
        129, 19, 170, 194, 11, 154, 168, 110, 242, 19, 167, 195, 205, 68, 4, 151, 99, 196, 164, 13,
        137, 140, 175, 134, 102, 47, 63, 0, 229, 73, 218, 226, 121, 230, 98, 31, 102, 161, 40, 233,
        229, 39, 224, 19, 92, 220, 151, 154, 193, 191, 30,
    ];

    #[test]
    fn packs_bar_directory() {
        let stor = Arc::new(InMemoryStorage::default());
        stor.add_hello_txt();
        stor.add_bar_foo_folder_with_hidden();

        let file = stor.read_file("bar/").unwrap();
        let mut compress_files = stor.read_dir(&file).unwrap();
        compress_files.sort_by(|a, b| a.path().cmp(b.path()));
        let entries = compress_files
            .into_iter()
            .map(|source| {
                let archive_path =
                    PathBuf::from(source.path().to_string_lossy().trim_end_matches('/'));
                ArchiveSourceEntry {
                    archive_path: NormalizedArchivePath::from_path(&archive_path).unwrap(),
                    source,
                }
            })
            .collect::<Vec<_>>();

        let output_file = stor.create_file("bar.zip.enc").unwrap();

        let req = HandleRequest {
            entries,
            writer: output_file.try_writer().unwrap(),
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Argon2id,
        };

        match execute_streaming_archive(req) {
            Ok(()) => {
                let reader = &mut *output_file.try_writer().unwrap().borrow_mut();
                reader.rewind().unwrap();

                let mut content = vec![];
                reader.read_to_end(&mut content).unwrap();
                let parsed = core::header::read_header(&mut Cursor::new(&content)).unwrap();

                let core::header::ParsedHeader::V1(payload) = parsed;
                let header = payload.header();
                assert_eq!(header.keyslots().len(), 1);
                assert!(!payload.aad().as_bytes().is_empty());
                assert!(content.len() > core::header::common::HEADER_LEN);
            }
            _ => unreachable!(),
        }
    }

    fn small_archive_limits(
        max_entries: usize,
        max_normalized_path_bytes: usize,
        max_normalized_path_depth: usize,
    ) -> ArchiveLimits {
        ArchiveLimits {
            max_entries,
            max_normalized_path_bytes,
            max_normalized_path_depth,
            max_total_body_bytes: ArchiveLimits::DEFAULT_MAX_TOTAL_BODY_BYTES,
        }
    }

    #[test]
    fn pack_archive_limits_reject_entry_count_before_zip_writing() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        let limits = small_archive_limits(1, 4096, 64);
        let mut entries = Vec::new();

        push_archive_entry(
            &mut entries,
            stor.read_file("hello.txt").unwrap(),
            PathBuf::from("one.txt"),
            limits,
            None,
        )
        .unwrap();
        let result = push_archive_entry(
            &mut entries,
            stor.read_file("hello.txt").unwrap(),
            PathBuf::from("two.txt"),
            limits,
            None,
        );

        assert!(matches!(
            result,
            Err(Error::ArchiveLimit(ArchiveLimitError {
                kind: ArchiveLimitKind::EntryCount,
                limit: 1,
                actual: 2,
            }))
        ));
    }

    #[test]
    fn pack_archive_limits_reject_path_bytes_before_zip_writing() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        let mut entries = Vec::new();
        let limits = small_archive_limits(10, 4, 64);

        let result = push_archive_entry(
            &mut entries,
            stor.read_file("hello.txt").unwrap(),
            PathBuf::from("long-name.txt"),
            limits,
            None,
        );

        assert!(matches!(
            result,
            Err(Error::ArchiveLimit(ArchiveLimitError {
                kind: ArchiveLimitKind::NormalizedPathBytes,
                limit: 4,
                ..
            }))
        ));
    }

    #[test]
    fn pack_archive_limits_reject_path_depth_before_zip_writing() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        let mut entries = Vec::new();
        let limits = small_archive_limits(10, 4096, 1);

        let result = push_archive_entry(
            &mut entries,
            stor.read_file("hello.txt").unwrap(),
            PathBuf::from("nested/file.txt"),
            limits,
            None,
        );

        assert!(matches!(
            result,
            Err(Error::ArchiveLimit(ArchiveLimitError {
                kind: ArchiveLimitKind::NormalizedPathDepth,
                limit: 1,
                ..
            }))
        ));
    }
}

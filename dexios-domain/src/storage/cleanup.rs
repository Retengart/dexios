use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use super::identity::{PathRole, ResolvedTarget};
use super::test_support::{FailureError, FailureHooks, FailurePoint};
use super::transaction::{CleanupAuthorizedReceipt, CommitReceipt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupTargetKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupTarget {
    path: PathBuf,
    kind: CleanupTargetKind,
    identity: CleanupTargetIdentity,
    stamp: CleanupTargetStamp,
    tree: Option<CleanupTreeIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupTargetIdentity {
    Verified {
        source: &'static str,
        handle: Arc<same_file::Handle>,
        is_symlink: bool,
    },
    Unchecked {
        source: &'static str,
    },
}

impl CleanupTargetIdentity {
    fn verified(path: &Path, is_symlink: bool) -> io::Result<Self> {
        let handle = same_file::Handle::from_path(path)?;
        Ok(Self::Verified {
            source: "cleanup target identity snapshot from same_file::Handle",
            handle: Arc::new(handle),
            is_symlink,
        })
    }

    #[must_use]
    pub fn source(&self) -> &'static str {
        match self {
            Self::Verified { source, .. } | Self::Unchecked { source } => source,
        }
    }
}

impl CleanupTarget {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn kind(&self) -> CleanupTargetKind {
        self.kind
    }

    #[must_use]
    pub fn identity(&self) -> &CleanupTargetIdentity {
        &self.identity
    }

    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: CleanupTargetKind::File,
            identity: CleanupTargetIdentity::Unchecked {
                source: "unchecked CleanupTarget::file constructor",
            },
            stamp: CleanupTargetStamp::unchecked(),
            tree: None,
        }
    }

    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn directory(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: CleanupTargetKind::Directory,
            identity: CleanupTargetIdentity::Unchecked {
                source: "unchecked CleanupTarget::directory constructor",
            },
            stamp: CleanupTargetStamp::unchecked(),
            tree: None,
        }
    }

    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        let kind = cleanup_kind(&metadata);
        let is_symlink = metadata.file_type().is_symlink();
        let identity = CleanupTargetIdentity::verified(path, is_symlink)?;
        let stamp = CleanupTargetStamp::capture(path, &metadata)?;

        Ok(Self {
            path: path.to_path_buf(),
            kind,
            identity,
            stamp,
            tree: None,
        })
    }

    fn from_processed_source(target: &ResolvedTarget, capture_tree: bool) -> io::Result<Self> {
        if target.role() != PathRole::ProcessedSource {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cleanup target is not processed-source evidence",
            ));
        }

        let mut cleanup_target = Self::from_path(target.target_path())?;
        if capture_tree && cleanup_target.kind == CleanupTargetKind::Directory {
            cleanup_target.tree = Some(CleanupTreeIdentity::capture(&cleanup_target.path)?);
        }
        Ok(cleanup_target)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl CleanupTarget {
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn unchecked_file_for_test(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: CleanupTargetKind::File,
            identity: CleanupTargetIdentity::Unchecked {
                source: "unchecked CleanupTarget::file constructor",
            },
            stamp: CleanupTargetStamp::unchecked(),
            tree: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CleanupTargetStamp {
    Verified {
        file_content: Option<CleanupFileStamp>,
    },
    Unchecked,
}

impl CleanupTargetStamp {
    fn capture(path: &Path, metadata: &fs::Metadata) -> io::Result<Self> {
        Ok(Self::Verified {
            file_content: CleanupFileStamp::capture(path, metadata)?,
        })
    }

    const fn unchecked() -> Self {
        Self::Unchecked
    }

    fn revalidate(&self, path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
        match self {
            Self::Verified { file_content } => {
                if *file_content != CleanupFileStamp::capture(path, metadata)? {
                    return Err(changed_target_error("changed cleanup target contents"));
                }
            }
            Self::Unchecked => {}
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupFileStamp {
    len: u64,
    digest: [u8; 32],
}

impl CleanupFileStamp {
    fn capture(path: &Path, metadata: &fs::Metadata) -> io::Result<Option<Self>> {
        if !metadata.file_type().is_file() {
            return Ok(None);
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update_reader(fs::File::open(path)?)?;
        Ok(Some(Self {
            len: metadata.len(),
            digest: *hasher.finalize().as_bytes(),
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupTreeIdentity {
    entries: Vec<CleanupTreeEntry>,
}

impl CleanupTreeIdentity {
    fn capture(root: &Path) -> io::Result<Self> {
        let mut entries = Vec::new();

        for entry in walkdir::WalkDir::new(root).min_depth(1) {
            let entry = entry.map_err(walkdir_error)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(path)?;
            let relative_path = path
                .strip_prefix(root)
                .map_err(|_| io::Error::other("cleanup tree entry escaped source root"))?
                .to_path_buf();
            let kind = cleanup_kind(&metadata);
            let is_symlink = metadata.file_type().is_symlink();
            let identity = CleanupTargetIdentity::verified(path, is_symlink)?;
            let stamp = CleanupTreeEntryStamp::capture(path, &metadata)?;

            entries.push(CleanupTreeEntry {
                relative_path,
                kind,
                identity,
                stamp,
            });
        }

        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(Self { entries })
    }

    fn revalidate(&self, root: &Path) -> io::Result<()> {
        let current = Self::capture(root)?;
        if current == *self {
            Ok(())
        } else {
            Err(changed_target_error("changed cleanup target tree"))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupTreeEntry {
    relative_path: PathBuf,
    kind: CleanupTargetKind,
    identity: CleanupTargetIdentity,
    stamp: CleanupTreeEntryStamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupTreeEntryStamp {
    len: u64,
    modified: Option<SystemTime>,
    file_content: Option<CleanupFileStamp>,
}

impl CleanupTreeEntryStamp {
    fn capture(path: &Path, metadata: &fs::Metadata) -> io::Result<Self> {
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            file_content: CleanupFileStamp::capture(path, metadata)?,
        })
    }
}

pub struct CleanupFailure {
    pub target: CleanupTarget,
    pub error: io::ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl CleanupFailure {
    #[must_use]
    pub fn without_source(target: CleanupTarget, error: io::ErrorKind) -> Self {
        Self {
            target,
            error,
            source: None,
        }
    }

    fn from_source(target: CleanupTarget, source: io::Error) -> Self {
        let error = source.kind();
        Self {
            target,
            error,
            source: Some(Box::new(source)),
        }
    }

    fn from_failure_hook(target: CleanupTarget, source: FailureError) -> Self {
        Self {
            target,
            error: io::ErrorKind::Other,
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Debug for CleanupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CleanupFailure")
            .field("target", &self.target)
            .field("error", &self.error)
            .field("has_source", &self.source.is_some())
            .finish()
    }
}

impl fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cleanup failed for {} ({:?})",
            self.target.path.display(),
            self.error
        )
    }
}

impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug, Default)]
pub struct CleanupResult {
    pub deleted: Vec<CleanupTarget>,
    pub failures: Vec<CleanupFailure>,
}

impl CleanupResult {
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.failures.is_empty()
    }
}

#[must_use]
pub(crate) fn rollback_empty_directories_best_effort(created_dirs: &[PathBuf]) -> CleanupResult {
    let mut result = CleanupResult::default();

    for path in created_dirs.iter().rev() {
        let target = match CleanupTarget::from_path(path) {
            Ok(target) if target.kind() == CleanupTargetKind::Directory => target,
            Ok(target) => {
                result.failures.push(CleanupFailure::without_source(
                    target,
                    io::ErrorKind::InvalidData,
                ));
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                result.failures.push(CleanupFailure::from_source(
                    CleanupTarget::directory(path.clone()),
                    error,
                ));
                continue;
            }
        };

        match delete_empty_directory_target(&target) {
            Ok(()) => result.deleted.push(target),
            Err(error) => result
                .failures
                .push(CleanupFailure::from_source(target, error)),
        }
    }

    result
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupReceipt {
    targets: Vec<CleanupTarget>,
}

impl CleanupReceipt {
    #[must_use]
    pub(crate) fn new(targets: Vec<CleanupTarget>) -> Self {
        Self { targets }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn from_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> io::Result<Self> {
        paths
            .into_iter()
            .map(CleanupTarget::from_path)
            .collect::<io::Result<Vec<_>>>()
            .map(Self::new)
    }

    pub(crate) fn from_processed_sources<'a>(
        targets: impl IntoIterator<Item = &'a ResolvedTarget>,
    ) -> io::Result<Self> {
        targets
            .into_iter()
            .map(|target| CleanupTarget::from_processed_source(target, false))
            .collect::<io::Result<Vec<_>>>()
            .map(Self::new)
    }

    pub(crate) fn from_processed_source_trees<'a>(
        targets: impl IntoIterator<Item = &'a ResolvedTarget>,
    ) -> io::Result<Self> {
        targets
            .into_iter()
            .map(|target| CleanupTarget::from_processed_source(target, true))
            .collect::<io::Result<Vec<_>>>()
            .map(Self::new)
    }

    #[must_use]
    pub fn targets(&self) -> &[CleanupTarget] {
        &self.targets
    }

    #[must_use]
    pub fn run(&self, proof: &PostCommitSuccess) -> CleanupResult {
        self.run_with_hooks(*proof, FailureHooks::none())
    }

    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn run_with_failure_hooks(
        &self,
        proof: &PostCommitSuccess,
        hooks: FailureHooks,
    ) -> CleanupResult {
        self.run_with_hooks(*proof, hooks)
    }

    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn unchecked_new_for_test(targets: Vec<CleanupTarget>) -> Self {
        Self { targets }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_paths_for_test<'a>(paths: impl IntoIterator<Item = &'a Path>) -> io::Result<Self> {
        Self::from_paths(paths)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_processed_sources_for_test<'a>(
        targets: impl IntoIterator<Item = &'a ResolvedTarget>,
    ) -> io::Result<Self> {
        Self::from_processed_sources(targets)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_processed_source_trees_for_test<'a>(
        targets: impl IntoIterator<Item = &'a ResolvedTarget>,
    ) -> io::Result<Self> {
        Self::from_processed_source_trees(targets)
    }

    fn run_with_hooks(&self, _proof: PostCommitSuccess, hooks: FailureHooks) -> CleanupResult {
        let mut result = CleanupResult::default();
        let mut injected_cleanup_failure = false;

        for target in self.targets.iter().cloned() {
            if !injected_cleanup_failure {
                match hooks.check(FailurePoint::Cleanup) {
                    Ok(()) => {}
                    Err(source) => {
                        injected_cleanup_failure = true;
                        result
                            .failures
                            .push(CleanupFailure::from_failure_hook(target, source));
                        continue;
                    }
                }
            }

            match delete_target(&target) {
                Ok(()) => result.deleted.push(target),
                Err(error) => result
                    .failures
                    .push(CleanupFailure::from_source(target, error)),
            }
        }

        result
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessedSourceCleanupResult {
    commit_receipt: CommitReceipt,
    cleanup_receipt: CleanupReceipt,
}

impl ProcessedSourceCleanupResult {
    #[must_use]
    pub(crate) fn new(commit_receipt: CommitReceipt, cleanup_receipt: CleanupReceipt) -> Self {
        Self {
            commit_receipt,
            cleanup_receipt,
        }
    }

    #[must_use]
    pub fn commit_receipt(&self) -> &CommitReceipt {
        &self.commit_receipt
    }

    #[must_use]
    pub fn cleanup_receipt(&self) -> &CleanupReceipt {
        &self.cleanup_receipt
    }

    #[must_use]
    pub fn into_commit_receipt(self) -> CommitReceipt {
        self.commit_receipt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashVerification {
    NotRequested,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostCommitSuccess {
    hash_verification: HashVerification,
}

impl PostCommitSuccess {
    pub fn from_commit_and_hash(
        receipt: &(impl CleanupAuthorizedReceipt + ?Sized),
        hash_verification: HashVerification,
    ) -> Result<Self, CleanupGateError> {
        if receipt.committed_artifacts().is_empty() {
            return Err(CleanupGateError::CommitNotAuthorized);
        }

        match hash_verification {
            HashVerification::NotRequested | HashVerification::Succeeded => {
                Ok(Self { hash_verification })
            }
            HashVerification::Failed => Err(CleanupGateError::HashNotVerified),
        }
    }

    #[must_use]
    pub fn hash_verification(&self) -> HashVerification {
        self.hash_verification
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupGateError {
    CommitNotAuthorized,
    HashNotVerified,
}

impl fmt::Display for CleanupGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitNotAuthorized => f.write_str("commit receipt is not cleanup-authorized"),
            Self::HashNotVerified => f.write_str("requested hash did not succeed"),
        }
    }
}

impl std::error::Error for CleanupGateError {}

fn delete_target(target: &CleanupTarget) -> io::Result<()> {
    revalidate_target(target)?;

    match target.kind {
        CleanupTargetKind::File => fs::remove_file(&target.path),
        CleanupTargetKind::Directory => fs::remove_dir_all(&target.path),
    }
}

fn delete_empty_directory_target(target: &CleanupTarget) -> io::Result<()> {
    revalidate_target(target)?;

    match target.kind {
        CleanupTargetKind::Directory => fs::remove_dir(&target.path),
        CleanupTargetKind::File => Err(io::Error::other("rollback target is not a directory")),
    }
}

fn revalidate_target(target: &CleanupTarget) -> io::Result<()> {
    let metadata = fs::symlink_metadata(&target.path)?;
    let current_kind = cleanup_kind(&metadata);
    if current_kind != target.kind {
        return Err(changed_target_error("changed cleanup target kind"));
    }

    let current_is_symlink = metadata.file_type().is_symlink();
    match &target.identity {
        CleanupTargetIdentity::Verified {
            handle, is_symlink, ..
        } => {
            if current_is_symlink != *is_symlink {
                return Err(changed_target_error(
                    "changed cleanup target symlink status",
                ));
            }

            let current_handle = same_file::Handle::from_path(&target.path)?;
            if handle.as_ref() != &current_handle {
                return Err(changed_target_error("changed cleanup identity"));
            }
        }
        CleanupTargetIdentity::Unchecked { .. } => {}
    }

    target.stamp.revalidate(&target.path, &metadata)?;

    if let Some(tree) = &target.tree {
        tree.revalidate(&target.path)?;
    }

    Ok(())
}

fn cleanup_kind(metadata: &fs::Metadata) -> CleanupTargetKind {
    if metadata.is_dir() {
        CleanupTargetKind::Directory
    } else {
        CleanupTargetKind::File
    }
}

fn changed_target_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn walkdir_error(error: walkdir::Error) -> io::Error {
    match error.into_io_error() {
        Some(error) => error,
        None => io::Error::other("unable to read cleanup target tree"),
    }
}

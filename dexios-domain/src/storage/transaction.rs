use std::path::{Path, PathBuf};
use std::{fmt, io};

use super::identity::{PathRole, ResolvedTarget};
use super::temp::NamedStagedOutput;
use super::test_support::FailureHooks;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    artifacts: Vec<CommittedArtifact>,
}

mod sealed {
    pub trait CleanupAuthorizedReceipt {}
}

pub trait CleanupAuthorizedReceipt: sealed::CleanupAuthorizedReceipt {
    fn committed_artifacts(&self) -> &[CommittedArtifact];
}

impl sealed::CleanupAuthorizedReceipt for CommitReceipt {}

impl CleanupAuthorizedReceipt for CommitReceipt {
    fn committed_artifacts(&self) -> &[CommittedArtifact] {
        &self.artifacts
    }
}

impl CommitReceipt {
    pub(crate) fn new(artifacts: Vec<CommittedArtifact>) -> Self {
        Self { artifacts }
    }

    #[must_use]
    pub fn committed_artifacts(&self) -> &[CommittedArtifact] {
        &self.artifacts
    }

    pub(crate) fn extend_artifacts(&mut self, artifacts: Vec<CommittedArtifact>) {
        self.artifacts.extend(artifacts);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialCommitReceipt {
    artifacts: Vec<CommittedArtifact>,
}

impl PartialCommitReceipt {
    pub(crate) fn new(artifacts: Vec<CommittedArtifact>) -> Self {
        Self { artifacts }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn unchecked_new_for_test(artifacts: Vec<CommittedArtifact>) -> Self {
        Self { artifacts }
    }

    #[must_use]
    pub fn committed_artifacts(&self) -> &[CommittedArtifact] {
        &self.artifacts
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedPairReceipt {
    receipt: CommitReceipt,
}

impl DetachedPairReceipt {
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn from_commit_receipt(receipt: CommitReceipt) -> Self {
        Self { receipt }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_commit_receipt_for_test(receipt: CommitReceipt) -> Self {
        Self { receipt }
    }

    #[must_use]
    pub fn committed_artifacts(&self) -> &[CommittedArtifact] {
        self.receipt.committed_artifacts()
    }

    #[must_use]
    pub fn into_commit_receipt(self) -> CommitReceipt {
        self.receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialDetachedPublication {
    committed_artifacts: Vec<CommittedArtifact>,
    failed_artifact: CommittedArtifact,
}

impl PartialDetachedPublication {
    #[must_use]
    pub(crate) fn from_partial_commit(
        receipt: PartialCommitReceipt,
        failed_artifact: CommittedArtifact,
    ) -> Self {
        Self {
            committed_artifacts: receipt.artifacts,
            failed_artifact,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_partial_commit_for_test(
        receipt: PartialCommitReceipt,
        failed_artifact: CommittedArtifact,
    ) -> Self {
        Self::from_partial_commit(receipt, failed_artifact)
    }

    #[must_use]
    pub fn committed_artifacts(&self) -> &[CommittedArtifact] {
        &self.committed_artifacts
    }

    #[must_use]
    pub fn failed_artifact(&self) -> &CommittedArtifact {
        &self.failed_artifact
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetachedPublicationFailure {
    Partial(PartialDetachedPublication),
    PostCommitSync(PartialCommitReceipt),
}

impl DetachedPublicationFailure {
    #[must_use]
    pub fn committed_artifacts(&self) -> &[CommittedArtifact] {
        match self {
            Self::Partial(receipt) => receipt.committed_artifacts(),
            Self::PostCommitSync(receipt) => receipt.committed_artifacts(),
        }
    }

    #[must_use]
    pub fn failed_artifact(&self) -> Option<&CommittedArtifact> {
        match self {
            Self::Partial(receipt) => Some(receipt.failed_artifact()),
            Self::PostCommitSync(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedArtifact {
    role: PathRole,
    path: PathBuf,
}

impl CommittedArtifact {
    pub(crate) fn new(role: PathRole, path: PathBuf) -> Self {
        Self { role, path }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn unchecked_new_for_test(role: PathRole, path: PathBuf) -> Self {
        Self { role, path }
    }

    #[must_use]
    pub fn role(&self) -> PathRole {
        self.role
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub enum TransactionError {
    Write {
        path: PathBuf,
        source: Option<io::Error>,
    },
    Flush {
        path: PathBuf,
        source: Option<io::Error>,
    },
    Sync {
        path: PathBuf,
        source: Option<io::Error>,
    },
    Persist {
        path: PathBuf,
        source: Option<io::Error>,
    },
    PartialCommit {
        receipt: PartialCommitReceipt,
        failed: CommittedArtifact,
        source: Option<io::Error>,
    },
    PostCommitSync {
        receipt: PartialCommitReceipt,
        source: Option<io::Error>,
    },
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write { path, .. } => {
                write!(f, "Unable to write staged output {}", path.display())
            }
            Self::Flush { path, .. } => {
                write!(f, "Unable to flush staged output {}", path.display())
            }
            Self::Sync { path, .. } => {
                write!(f, "Unable to sync staged output {}", path.display())
            }
            Self::Persist { path, .. } => {
                write!(f, "Unable to persist staged output {}", path.display())
            }
            Self::PartialCommit {
                receipt, failed, ..
            } => write!(
                f,
                "Partial transaction commit after {} artifact(s); failed to persist {}",
                receipt.committed_artifacts().len(),
                failed.path().display()
            ),
            Self::PostCommitSync { receipt, .. } => write!(
                f,
                "Transaction committed {} artifact(s) but failed to sync the output directory",
                receipt.committed_artifacts().len()
            ),
        }
    }
}

impl std::error::Error for TransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Write {
                source: Some(source),
                ..
            }
            | Self::Flush {
                source: Some(source),
                ..
            }
            | Self::Sync {
                source: Some(source),
                ..
            }
            | Self::Persist {
                source: Some(source),
                ..
            }
            | Self::PartialCommit {
                source: Some(source),
                ..
            }
            | Self::PostCommitSync {
                source: Some(source),
                ..
            } => Some(source),
            Self::Write { source: None, .. }
            | Self::Flush { source: None, .. }
            | Self::Sync { source: None, .. }
            | Self::Persist { source: None, .. }
            | Self::PartialCommit { source: None, .. }
            | Self::PostCommitSync { source: None, .. } => None,
        }
    }
}

impl TransactionError {
    #[must_use]
    pub fn is_resource_pressure(&self) -> bool {
        super::error_chain_contains_resource_pressure(self)
    }

    #[must_use]
    pub fn detached_publication_failure(&self) -> Option<DetachedPublicationFailure> {
        match self {
            Self::PartialCommit {
                receipt, failed, ..
            } => Some(DetachedPublicationFailure::Partial(
                PartialDetachedPublication::from_partial_commit(receipt.clone(), failed.clone()),
            )),
            Self::PostCommitSync { receipt, .. } => {
                Some(DetachedPublicationFailure::PostCommitSync(receipt.clone()))
            }
            Self::Write { .. } | Self::Flush { .. } | Self::Sync { .. } | Self::Persist { .. } => {
                None
            }
        }
    }
}

pub(crate) enum StagedWriteError<E> {
    Operation(E),
    Transaction(TransactionError),
}

pub struct StagedOutputTransaction {
    staged: NamedStagedOutput,
}

impl StagedOutputTransaction {
    pub fn new(target: ResolvedTarget) -> Result<Self, TransactionError> {
        Self::with_hooks(target, FailureHooks::none())
    }

    fn with_hooks(target: ResolvedTarget, hooks: FailureHooks) -> Result<Self, TransactionError> {
        reject_directory_target(&target)?;
        let path = target.target_path().to_path_buf();
        let staged = NamedStagedOutput::with_hooks(target, hooks).map_err(|source| {
            TransactionError::Write {
                path,
                source: Some(source),
            }
        })?;
        Ok(Self { staged })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_failure_hooks(
        target: ResolvedTarget,
        hooks: FailureHooks,
    ) -> Result<Self, TransactionError> {
        Self::with_hooks(target, hooks)
    }

    #[must_use]
    pub fn target(&self) -> &ResolvedTarget {
        self.staged.target()
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransactionError> {
        self.staged.write_all(bytes)
    }

    pub fn with_writer<T>(
        &mut self,
        write: impl FnOnce(&mut std::fs::File) -> io::Result<T>,
    ) -> Result<T, TransactionError> {
        self.staged.with_writer(write)
    }

    pub(crate) fn with_writer_result<T, E>(
        &mut self,
        write: impl FnOnce(&mut std::fs::File) -> Result<T, E>,
    ) -> Result<T, StagedWriteError<E>> {
        self.staged.with_writer_result(write)
    }

    pub fn commit(self) -> Result<CommitReceipt, TransactionError> {
        let artifact = self.staged.persist_replace_at_commit()?;
        Ok(CommitReceipt::new(vec![artifact]))
    }
}

pub struct LinkedOutputTransaction {
    staged: Vec<NamedStagedOutput>,
    hooks: FailureHooks,
}

impl LinkedOutputTransaction {
    #[must_use]
    pub fn new() -> Self {
        Self::with_hooks(FailureHooks::none())
    }

    #[must_use]
    fn with_hooks(hooks: FailureHooks) -> Self {
        Self {
            staged: Vec::new(),
            hooks,
        }
    }

    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_failure_hooks(hooks: FailureHooks) -> Self {
        Self::with_hooks(hooks)
    }

    pub fn stage(&mut self, target: ResolvedTarget) -> Result<usize, TransactionError> {
        reject_directory_target(&target)?;
        let path = target.target_path().to_path_buf();
        let staged = NamedStagedOutput::with_hooks(target, self.hooks).map_err(|source| {
            TransactionError::Write {
                path,
                source: Some(source),
            }
        })?;
        self.staged.push(staged);
        Ok(self.staged.len() - 1)
    }

    pub fn stage_in(
        &mut self,
        target: ResolvedTarget,
        staging_parent: &Path,
    ) -> Result<usize, TransactionError> {
        reject_directory_target(&target)?;
        let path = target.target_path().to_path_buf();
        let staged = NamedStagedOutput::with_staging_parent(target, staging_parent, self.hooks)
            .map_err(|source| TransactionError::Write {
                path,
                source: Some(source),
            })?;
        self.staged.push(staged);
        Ok(self.staged.len() - 1)
    }

    pub fn staged_output_mut(&mut self, index: usize) -> Option<&mut NamedStagedOutput> {
        self.staged.get_mut(index)
    }

    pub fn commit_all(mut self) -> Result<CommitReceipt, TransactionError> {
        for staged in &mut self.staged {
            staged.prepare_for_persist()?;
        }

        let mut receipt = CommitReceipt::new(Vec::with_capacity(self.staged.len()));
        for staged in self.staged {
            let failed = CommittedArtifact::new(
                staged.target().role(),
                staged.target().target_path().to_path_buf(),
            );
            match staged.persist_prepared() {
                Ok(artifact) => receipt.artifacts.push(artifact),
                Err(TransactionError::PostCommitSync {
                    receipt: post_commit_receipt,
                    source,
                }) => {
                    receipt.artifacts.extend(post_commit_receipt.artifacts);
                    return Err(TransactionError::PostCommitSync {
                        receipt: PartialCommitReceipt::new(receipt.artifacts),
                        source,
                    });
                }
                Err(TransactionError::Persist { source, .. }) if !receipt.artifacts.is_empty() => {
                    return Err(TransactionError::PartialCommit {
                        receipt: PartialCommitReceipt::new(receipt.artifacts),
                        failed,
                        source,
                    });
                }
                Err(error) => return Err(error),
            }
        }

        Ok(receipt)
    }
}

impl Default for LinkedOutputTransaction {
    fn default() -> Self {
        Self::new()
    }
}

fn reject_directory_target(target: &ResolvedTarget) -> Result<(), TransactionError> {
    if target.is_dir() {
        return Err(TransactionError::Write {
            path: target.target_path().to_path_buf(),
            source: None,
        });
    }

    Ok(())
}

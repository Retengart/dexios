use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::test_support::{FailureHooks, FailurePoint};
use super::transaction::CleanupAuthorizedReceipt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupTargetKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupTarget {
    pub path: PathBuf,
    pub kind: CleanupTargetKind,
    pub identity: CleanupTargetIdentity,
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
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: CleanupTargetKind::File,
            identity: CleanupTargetIdentity::Unchecked {
                source: "unchecked CleanupTarget::file constructor",
            },
        }
    }

    #[must_use]
    pub fn directory(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            kind: CleanupTargetKind::Directory,
            identity: CleanupTargetIdentity::Unchecked {
                source: "unchecked CleanupTarget::directory constructor",
            },
        }
    }

    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        let kind = cleanup_kind(&metadata);
        let is_symlink = metadata.file_type().is_symlink();
        let identity = CleanupTargetIdentity::verified(path, is_symlink)?;

        Ok(Self {
            path: path.to_path_buf(),
            kind,
            identity,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupFailure {
    pub target: CleanupTarget,
    pub error: io::ErrorKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupReceipt {
    pub targets: Vec<CleanupTarget>,
}

impl CleanupReceipt {
    #[must_use]
    pub fn new(targets: Vec<CleanupTarget>) -> Self {
        Self { targets }
    }

    pub fn from_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> io::Result<Self> {
        paths
            .into_iter()
            .map(CleanupTarget::from_path)
            .collect::<io::Result<Vec<_>>>()
            .map(Self::new)
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

    fn run_with_hooks(&self, _proof: PostCommitSuccess, hooks: FailureHooks) -> CleanupResult {
        let mut result = CleanupResult::default();
        let mut injected_cleanup_failure = false;

        for target in self.targets.iter().cloned() {
            let should_inject_failure =
                !injected_cleanup_failure && hooks.check(FailurePoint::Cleanup).is_err();
            let delete_result = if should_inject_failure {
                injected_cleanup_failure = true;
                Err(io::Error::from(io::ErrorKind::Other))
            } else {
                delete_target(&target)
            };

            match delete_result {
                Ok(()) => result.deleted.push(target),
                Err(error) => result.failures.push(CleanupFailure {
                    target,
                    error: error.kind(),
                }),
            }
        }

        result
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

impl std::fmt::Display for CleanupGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

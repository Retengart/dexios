use std::fmt;
use std::path::PathBuf;

use super::identity::{PathRole, ResolvedTarget};
use super::temp::NamedStagedOutput;
use super::test_support::FailureHooks;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    pub artifacts: Vec<CommittedArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedArtifact {
    pub role: PathRole,
    pub path: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub enum TransactionError {
    Write {
        path: PathBuf,
    },
    Flush {
        path: PathBuf,
    },
    Sync {
        path: PathBuf,
    },
    Persist {
        path: PathBuf,
    },
    PartialCommit {
        receipt: CommitReceipt,
        failed: CommittedArtifact,
    },
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write { path } => write!(f, "Unable to write staged output {}", path.display()),
            Self::Flush { path } => write!(f, "Unable to flush staged output {}", path.display()),
            Self::Sync { path } => write!(f, "Unable to sync staged output {}", path.display()),
            Self::Persist { path } => {
                write!(f, "Unable to persist staged output {}", path.display())
            }
            Self::PartialCommit { receipt, failed } => write!(
                f,
                "Partial transaction commit after {} artifact(s); failed to persist {}",
                receipt.artifacts.len(),
                failed.path.display()
            ),
        }
    }
}

impl std::error::Error for TransactionError {}

pub struct StagedOutputTransaction {
    staged: NamedStagedOutput,
}

impl StagedOutputTransaction {
    pub fn new(target: ResolvedTarget) -> Result<Self, TransactionError> {
        Self::with_failure_hooks(target, FailureHooks::none())
    }

    pub fn with_failure_hooks(
        target: ResolvedTarget,
        hooks: FailureHooks,
    ) -> Result<Self, TransactionError> {
        let path = target.target_path().to_path_buf();
        let staged = NamedStagedOutput::with_failure_hooks(target, hooks)
            .map_err(|_| TransactionError::Write { path })?;
        Ok(Self { staged })
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
        write: impl FnOnce(&mut std::fs::File) -> std::io::Result<T>,
    ) -> Result<T, TransactionError> {
        self.staged.with_writer(write)
    }

    pub fn commit(self) -> Result<CommitReceipt, TransactionError> {
        let artifact = self.staged.persist_replace_at_commit()?;
        Ok(CommitReceipt {
            artifacts: vec![artifact],
        })
    }
}

pub struct LinkedOutputTransaction {
    staged: Vec<NamedStagedOutput>,
    hooks: FailureHooks,
}

impl LinkedOutputTransaction {
    #[must_use]
    pub fn new() -> Self {
        Self::with_failure_hooks(FailureHooks::none())
    }

    #[must_use]
    pub fn with_failure_hooks(hooks: FailureHooks) -> Self {
        Self {
            staged: Vec::new(),
            hooks,
        }
    }

    pub fn stage(&mut self, target: ResolvedTarget) -> Result<usize, TransactionError> {
        let path = target.target_path().to_path_buf();
        let staged = NamedStagedOutput::with_failure_hooks(target, self.hooks)
            .map_err(|_| TransactionError::Write { path })?;
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

        let mut receipt = CommitReceipt {
            artifacts: Vec::with_capacity(self.staged.len()),
        };
        for staged in self.staged {
            let failed = CommittedArtifact {
                role: staged.target().role(),
                path: staged.target().target_path().to_path_buf(),
            };
            match staged.persist_prepared() {
                Ok(artifact) => receipt.artifacts.push(artifact),
                Err(TransactionError::Persist { .. }) if !receipt.artifacts.is_empty() => {
                    return Err(TransactionError::PartialCommit { receipt, failed });
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

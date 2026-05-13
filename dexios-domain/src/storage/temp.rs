use std::cell::RefCell;
use std::fs as std_fs;
use std::io::{self, Write};
use std::path::Path;

use super::Error;
use super::identity::{OverwritePolicy, ResolvedTarget};
use super::test_support::{FailureHooks, FailurePoint};
use super::transaction::{CommittedArtifact, StagedWriteError, TransactionError};

pub struct TempArtifact {
    file: RefCell<std_fs::File>,
}

impl TempArtifact {
    pub(super) fn new(file: std_fs::File) -> Self {
        Self {
            file: RefCell::new(file),
        }
    }

    pub fn with_reader<T, E>(
        &self,
        f: impl FnOnce(&mut std_fs::File) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut file = self.file.borrow_mut();
        f(&mut file)
    }

    pub fn with_writer<T, E>(
        &self,
        f: impl FnOnce(&mut std_fs::File) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut file = self.file.borrow_mut();
        f(&mut file)
    }

    pub fn len(&self) -> Result<usize, Error> {
        let file = self.file.borrow();
        let meta = file.metadata().map_err(|_| Error::FileLen)?;
        meta.len().try_into().map_err(|_| Error::FileLen)
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        self.len().map(|len| len == 0)
    }

    pub fn sync_all(&self) -> Result<(), Error> {
        self.file.borrow().sync_all().map_err(|_| Error::SyncFile)
    }
}

pub struct NamedStagedOutput {
    target: ResolvedTarget,
    file: Option<tempfile::NamedTempFile>,
    wrote: bool,
    flushed: bool,
    synced: bool,
    hooks: FailureHooks,
}

impl NamedStagedOutput {
    pub fn new(target: ResolvedTarget) -> io::Result<Self> {
        Self::with_hooks(target, FailureHooks::none())
    }

    pub(super) fn with_hooks(target: ResolvedTarget, hooks: FailureHooks) -> io::Result<Self> {
        let file = tempfile::NamedTempFile::new_in(target.target_parent())?;
        Ok(Self {
            target,
            file: Some(file),
            wrote: false,
            flushed: false,
            synced: false,
            hooks,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_failure_hooks(target: ResolvedTarget, hooks: FailureHooks) -> io::Result<Self> {
        Self::with_hooks(target, hooks)
    }

    #[must_use]
    pub fn target(&self) -> &ResolvedTarget {
        &self.target
    }

    #[must_use]
    pub fn staged_path(&self) -> Option<&Path> {
        self.file.as_ref().map(tempfile::NamedTempFile::path)
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransactionError> {
        self.with_writer(|file| file.write_all(bytes))
    }

    pub fn with_writer<T>(
        &mut self,
        write: impl FnOnce(&mut std_fs::File) -> io::Result<T>,
    ) -> Result<T, TransactionError> {
        self.with_writer_result(write).map_err(|error| match error {
            StagedWriteError::Operation(_) => TransactionError::Write {
                path: self.target.target_path().to_path_buf(),
            },
            StagedWriteError::Transaction(error) => error,
        })
    }

    pub(crate) fn with_writer_result<T, E>(
        &mut self,
        write: impl FnOnce(&mut std_fs::File) -> Result<T, E>,
    ) -> Result<T, StagedWriteError<E>> {
        self.hooks
            .check(FailurePoint::Write)
            .map_err(|_| StagedWriteError::Transaction(self.error_at(FailurePoint::Write)))?;

        let target_path = self.target.target_path().to_path_buf();
        let file =
            self.file
                .as_mut()
                .ok_or(StagedWriteError::Transaction(TransactionError::Write {
                    path: target_path,
                }))?;
        let result = write(file.as_file_mut()).map_err(StagedWriteError::Operation)?;
        self.wrote = true;
        self.flushed = false;
        self.synced = false;
        Ok(result)
    }

    pub fn flush(&mut self) -> Result<(), TransactionError> {
        self.hooks
            .check(FailurePoint::Flush)
            .map_err(|_| self.error_at(FailurePoint::Flush))?;

        let target_path = self.target.target_path().to_path_buf();
        let file = self
            .file
            .as_mut()
            .ok_or(TransactionError::Flush { path: target_path })?;
        file.as_file_mut()
            .flush()
            .map_err(|_| TransactionError::Flush {
                path: self.target.target_path().to_path_buf(),
            })?;
        self.flushed = true;
        Ok(())
    }

    pub fn sync_all(&mut self) -> Result<(), TransactionError> {
        self.hooks
            .check(FailurePoint::Sync)
            .map_err(|_| self.error_at(FailurePoint::Sync))?;

        let target_path = self.target.target_path().to_path_buf();
        let file = self
            .file
            .as_ref()
            .ok_or(TransactionError::Sync { path: target_path })?;
        file.as_file()
            .sync_all()
            .map_err(|_| TransactionError::Sync {
                path: self.target.target_path().to_path_buf(),
            })?;
        self.synced = true;
        Ok(())
    }

    pub fn persist_replace_at_commit(mut self) -> Result<CommittedArtifact, TransactionError> {
        self.prepare_for_persist()?;
        self.persist_prepared()
    }

    pub(crate) fn prepare_for_persist(&mut self) -> Result<(), TransactionError> {
        if !self.wrote {
            return Err(TransactionError::Write {
                path: self.target.target_path().to_path_buf(),
            });
        }
        self.flush()?;
        self.sync_all()
    }

    pub(crate) fn persist_prepared(mut self) -> Result<CommittedArtifact, TransactionError> {
        if !self.flushed {
            return Err(TransactionError::Flush {
                path: self.target.target_path().to_path_buf(),
            });
        }
        if !self.synced {
            return Err(TransactionError::Sync {
                path: self.target.target_path().to_path_buf(),
            });
        }

        self.hooks
            .check(FailurePoint::Persist)
            .map_err(|_| self.error_at(FailurePoint::Persist))?;

        let path = self.target.target_path().to_path_buf();
        let role = self.target.role();
        let file = self
            .file
            .take()
            .ok_or(TransactionError::Persist { path: path.clone() })?;

        match self.target.overwrite_policy() {
            Some(OverwritePolicy::CreateNew) => file.persist_noclobber(&path),
            Some(OverwritePolicy::ReplaceAtCommit) => file.persist(&path),
            None => return Err(TransactionError::Persist { path }),
        }
        .map_err(|_| TransactionError::Persist { path: path.clone() })?;

        Ok(CommittedArtifact { role, path })
    }

    fn error_at(&self, point: FailurePoint) -> TransactionError {
        let path = self.target.target_path().to_path_buf();
        match point {
            FailurePoint::Write => TransactionError::Write { path },
            FailurePoint::Flush => TransactionError::Flush { path },
            FailurePoint::Sync => TransactionError::Sync { path },
            FailurePoint::Persist | FailurePoint::Cleanup => TransactionError::Persist { path },
        }
    }
}

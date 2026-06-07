use std::cell::RefCell;
use std::fs as std_fs;
use std::io::{self, Write};
use std::path::Path;
#[cfg(not(unix))]
use std::path::{Component, PathBuf};

use super::Error;
#[cfg(not(unix))]
use super::identity::OverwritePolicy;
use super::identity::ResolvedTarget;
use super::test_support::{FailureHooks, FailurePoint};
use super::transaction::{
    CommittedArtifact, PartialCommitReceipt, StagedWriteError, TransactionError,
};

enum PersistError {
    BeforeCommit(io::Error),
    AfterCommit(io::Error),
}

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
    parent_creation: ParentCreation,
    wrote: bool,
    flushed: bool,
    synced: bool,
    hooks: FailureHooks,
}

#[derive(Clone, Copy)]
enum ParentCreation {
    Existing,
    OnPersist,
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
            parent_creation: ParentCreation::Existing,
            wrote: false,
            flushed: false,
            synced: false,
            hooks,
        })
    }

    pub(super) fn with_staging_parent(
        target: ResolvedTarget,
        staging_parent: &Path,
        hooks: FailureHooks,
    ) -> io::Result<Self> {
        let file = tempfile::NamedTempFile::new_in(staging_parent)?;
        Ok(Self {
            target,
            file: Some(file),
            parent_creation: ParentCreation::OnPersist,
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
            StagedWriteError::Operation(source) => TransactionError::Write {
                path: self.target.target_path().to_path_buf(),
                source: Some(source),
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
                    source: None,
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
        let file = self.file.as_mut().ok_or(TransactionError::Flush {
            path: target_path,
            source: None,
        })?;
        file.as_file_mut()
            .flush()
            .map_err(|source| TransactionError::Flush {
                path: self.target.target_path().to_path_buf(),
                source: Some(source),
            })?;
        self.flushed = true;
        Ok(())
    }

    pub fn sync_all(&mut self) -> Result<(), TransactionError> {
        self.hooks
            .check(FailurePoint::Sync)
            .map_err(|_| self.error_at(FailurePoint::Sync))?;

        let target_path = self.target.target_path().to_path_buf();
        let file = self.file.as_ref().ok_or(TransactionError::Sync {
            path: target_path,
            source: None,
        })?;
        file.as_file()
            .sync_all()
            .map_err(|source| TransactionError::Sync {
                path: self.target.target_path().to_path_buf(),
                source: Some(source),
            })?;
        self.synced = true;
        Ok(())
    }

    pub fn persist_replace_at_commit(mut self) -> Result<CommittedArtifact, TransactionError> {
        self.prepare_for_persist()?;
        self.persist_prepared()
    }

    // NamedStagedOutput::prepare_for_persist is the staged flush/sync gate
    // before persist.
    pub(crate) fn prepare_for_persist(&mut self) -> Result<(), TransactionError> {
        if !self.wrote {
            return Err(TransactionError::Write {
                path: self.target.target_path().to_path_buf(),
                source: None,
            });
        }
        self.flush()?;
        self.sync_all()
    }

    pub(crate) fn persist_prepared(mut self) -> Result<CommittedArtifact, TransactionError> {
        if !self.flushed {
            return Err(TransactionError::Flush {
                path: self.target.target_path().to_path_buf(),
                source: None,
            });
        }
        if !self.synced {
            return Err(TransactionError::Sync {
                path: self.target.target_path().to_path_buf(),
                source: None,
            });
        }

        self.hooks
            .check(FailurePoint::Persist)
            .map_err(|_| self.error_at(FailurePoint::Persist))?;

        let path = self.target.target_path().to_path_buf();
        let role = self.target.role();
        let file = self.file.take().ok_or_else(|| TransactionError::Persist {
            path: path.clone(),
            source: None,
        })?;

        let artifact = CommittedArtifact::new(role, path);

        persist_named_temp_file(
            file,
            &self.target,
            matches!(self.parent_creation, ParentCreation::OnPersist),
            self.hooks,
        )
        .map_err(|error| match error {
            PersistError::BeforeCommit(source) => TransactionError::Persist {
                path: artifact.path().to_path_buf(),
                source: Some(source),
            },
            PersistError::AfterCommit(source) => TransactionError::PostCommitSync {
                receipt: PartialCommitReceipt::new(vec![artifact.clone()]),
                source: Some(source),
            },
        })?;

        Ok(artifact)
    }

    fn error_at(&self, point: FailurePoint) -> TransactionError {
        let path = self.target.target_path().to_path_buf();
        match point {
            FailurePoint::Write => TransactionError::Write { path, source: None },
            FailurePoint::Flush => TransactionError::Flush { path, source: None },
            FailurePoint::Sync => TransactionError::Sync { path, source: None },
            FailurePoint::Persist | FailurePoint::PostCommitSync | FailurePoint::Cleanup => {
                TransactionError::Persist { path, source: None }
            }
        }
    }
}

#[cfg(unix)]
fn persist_named_temp_file(
    file: tempfile::NamedTempFile,
    target: &ResolvedTarget,
    create_parent: bool,
    hooks: FailureHooks,
) -> Result<(), PersistError> {
    unix_fd_persist::persist(file, target, create_parent, hooks)
}

#[cfg(not(unix))]
fn persist_named_temp_file(
    file: tempfile::NamedTempFile,
    target: &ResolvedTarget,
    create_parent: bool,
    _hooks: FailureHooks,
) -> Result<(), PersistError> {
    let path = target.target_path();
    ensure_target_path_safe_for_persist(path)
        .map_err(transaction_error_to_io)
        .map_err(PersistError::BeforeCommit)?;
    if create_parent {
        create_target_parent_portably(path).map_err(PersistError::BeforeCommit)?;
    }
    ensure_target_path_safe_for_persist(path)
        .map_err(transaction_error_to_io)
        .map_err(PersistError::BeforeCommit)?;

    match target.overwrite_policy() {
        Some(OverwritePolicy::CreateNew) => {
            tempfile::NamedTempFile::persist_noclobber(file, path).map(|_| ())
        }
        Some(OverwritePolicy::ReplaceAtCommit) => {
            tempfile::NamedTempFile::persist(file, path).map(|_| ())
        }
        None => {
            return Err(PersistError::BeforeCommit(io::Error::other(
                "missing overwrite policy",
            )));
        }
    }
    .map_err(|error| error.error)
    .map_err(PersistError::BeforeCommit)
}

#[cfg(not(unix))]
fn create_target_parent_portably(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut current = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => return Err(invalid_component_error()),
            Component::Normal(part) => {
                current.push(part);
                match std_fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => return Err(source),
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn invalid_component_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "unsafe directory component")
}

#[cfg(not(unix))]
fn transaction_error_to_io(error: TransactionError) -> io::Error {
    match error {
        TransactionError::Persist {
            source: Some(source),
            ..
        } => source,
        error => io::Error::other(error),
    }
}

#[cfg(not(unix))]
fn ensure_target_path_safe_for_persist(path: &Path) -> Result<(), TransactionError> {
    if let Some(parent) = path.parent() {
        ensure_parent_chain_safe(path, parent)?;
    }

    match std_fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(persist_unsafe_path_error(path, None))
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(persist_unsafe_path_error(path, Some(source))),
    }
}

#[cfg(not(unix))]
fn ensure_parent_chain_safe(target_path: &Path, parent: &Path) -> Result<(), TransactionError> {
    let mut current = PathBuf::new();

    for component in parent.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => return Err(persist_unsafe_path_error(target_path, None)),
            Component::Normal(part) => {
                current.push(part);
                match std_fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                        return Err(persist_unsafe_path_error(target_path, None));
                    }
                    Ok(_) => {}
                    Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(persist_unsafe_path_error(target_path, Some(source)));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(not(unix))]
fn persist_unsafe_path_error(path: &Path, source: Option<io::Error>) -> TransactionError {
    TransactionError::Persist {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
pub(super) use unix_fd_persist::{create_dirs_fd_relative, open_absolute_dir};

#[cfg(unix)]
mod unix_fd_persist {
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};

    use crate::storage::identity::{OverwritePolicy, ResolvedTarget, UnixFileIdentity};
    use crate::storage::test_support::{FailureHooks, FailurePoint};
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::{AtFlags, CWD, Mode, OFlags, fstat, fsync, openat, statat};

    use super::PersistError;

    pub(super) fn persist(
        file: tempfile::NamedTempFile,
        target: &ResolvedTarget,
        create_parent: bool,
        hooks: FailureHooks,
    ) -> Result<(), PersistError> {
        let source_path = file.path().to_path_buf();
        let source_identity = file_identity(file.as_file()).map_err(PersistError::BeforeCommit)?;
        let (source_parent, source_name) =
            open_parent_dir_and_name(&source_path).map_err(PersistError::BeforeCommit)?;
        let (target_parent, target_name) = open_target_parent_dir_and_name(target, create_parent)
            .map_err(PersistError::BeforeCommit)?;
        verify_named_source_matches(&source_parent, &source_name, source_identity)
            .map_err(PersistError::BeforeCommit)?;

        match target.overwrite_policy() {
            Some(OverwritePolicy::CreateNew) => linkat(
                &source_parent,
                &source_name,
                &target_parent,
                &target_name,
                AtFlags::empty(),
            ),
            Some(OverwritePolicy::ReplaceAtCommit) => {
                renameat(&source_parent, &source_name, &target_parent, &target_name)
            }
            None => Err(io::Error::other("missing overwrite policy")),
        }
        .map_err(PersistError::BeforeCommit)?;

        hooks
            .check(FailurePoint::PostCommitSync)
            .map_err(|source| PersistError::AfterCommit(io::Error::other(source)))?;
        fsync(&target_parent)
            .map_err(io::Error::from)
            .map_err(PersistError::AfterCommit)
    }

    fn open_target_parent_dir_and_name(
        target: &ResolvedTarget,
        create_parent: bool,
    ) -> io::Result<(OwnedFd, CString)> {
        let mut parent = open_absolute_dir(target.target_parent())?;
        let missing_components = target.missing_components();

        if missing_components.is_empty() {
            let final_parent = target
                .target_path()
                .parent()
                .ok_or_else(|| invalid_path("target path has no parent directory"))?;
            let name = target
                .target_path()
                .file_name()
                .ok_or_else(|| invalid_path("target path has no final file name"))?;
            let parent = open_absolute_dir(final_parent)?;
            verify_target_parent_identity(target, &parent)?;
            verify_existing_target_identity(target, &parent, name)?;
            return Ok((parent, component_to_cstring(name)?));
        }

        verify_target_parent_identity(target, &parent)?;

        let (name, dirs) = missing_components
            .split_last()
            .ok_or_else(|| invalid_path("target path has no final file name"))?;
        for component in dirs {
            parent = open_child_dir_or_create(&parent, component.as_os_str(), create_parent)?;
        }

        Ok((parent, component_to_cstring(name.as_os_str())?))
    }

    fn open_parent_dir_and_name(path: &Path) -> io::Result<(OwnedFd, CString)> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let parent = absolute
            .parent()
            .ok_or_else(|| invalid_path("path has no parent directory"))?;
        let name = absolute
            .file_name()
            .ok_or_else(|| invalid_path("path has no final file name"))?;
        Ok((open_absolute_dir(parent)?, component_to_cstring(name)?))
    }

    fn open_child_dir_or_create(
        parent: &OwnedFd,
        name: &OsStr,
        create: bool,
    ) -> io::Result<OwnedFd> {
        match open_child_dir(parent, name) {
            Ok(dir) => Ok(dir),
            Err(source) if source.kind() == io::ErrorKind::NotFound && create => {
                mkdir_child(parent, name)?;
                fsync(parent).map_err(io::Error::from)?;
                open_child_dir(parent, name)
            }
            Err(source) => Err(source),
        }
    }

    /// Walks `relative` (Normal components only) beneath the already-open, canonical
    /// `root` directory fd, creating missing components via mkdirat and refusing any
    /// symlinked or non-directory component (every hop opens `O_NOFOLLOW | O_DIRECTORY`,
    /// so a symlink yields `ELOOP` and a file yields `ENOTDIR` rather than being
    /// followed). Returns the absolute paths of the components it created. This closes
    /// the check-then-create TOCTOU window of a path-string component walk (fs-1, fs-2).
    pub(crate) fn create_dirs_fd_relative(
        root_dir: &OwnedFd,
        root_path: &Path,
        relative: &Path,
    ) -> io::Result<Vec<std::path::PathBuf>> {
        let mut dir = reopen_dir(root_dir)?;
        let mut current = root_path.to_path_buf();
        let mut created = Vec::new();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(invalid_path("unsafe directory component"));
            };
            current.push(name);
            let existed = open_child_dir(&dir, name).is_ok();
            dir = open_child_dir_or_create(&dir, name, true)?;
            if !existed {
                created.push(current.clone());
            }
        }
        Ok(created)
    }

    fn reopen_dir(dir: &OwnedFd) -> io::Result<OwnedFd> {
        openat(
            dir.as_fd(),
            c".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)
    }

    pub(crate) fn open_absolute_dir(path: &Path) -> io::Result<OwnedFd> {
        let mut dir = openat(
            CWD,
            c"/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    dir = open_child_dir(&dir, name)?;
                }
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(invalid_path("unsafe directory component"));
                }
            }
        }
        Ok(dir)
    }

    fn open_child_dir(parent: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
        let name = component_to_cstring(name)?;
        openat(
            parent.as_fd(),
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)
    }

    fn verify_target_parent_identity(target: &ResolvedTarget, parent: &OwnedFd) -> io::Result<()> {
        let Some(expected) = target.existing_parent_identity() else {
            return Ok(());
        };
        let actual = file_identity(parent)?;
        if actual != expected {
            return Err(io::Error::other(
                "target parent identity changed before persist",
            ));
        }
        Ok(())
    }

    fn verify_existing_target_identity(
        target: &ResolvedTarget,
        parent: &OwnedFd,
        name: &OsStr,
    ) -> io::Result<()> {
        let Some(expected) = target.existing_target_identity() else {
            return Ok(());
        };
        let name = component_to_cstring(name)?;
        let stat = statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        let actual = unix_file_identity(stat.st_dev, stat.st_ino)?;
        if actual != expected {
            return Err(io::Error::other(
                "target file identity changed before persist",
            ));
        }
        Ok(())
    }

    fn verify_named_source_matches(
        source_parent: &OwnedFd,
        source_name: &CString,
        expected: UnixFileIdentity,
    ) -> io::Result<()> {
        let opened_source = openat(
            source_parent.as_fd(),
            source_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let actual = file_identity(&opened_source)?;
        if actual != expected {
            return Err(io::Error::other(
                "staged file identity changed before persist",
            ));
        }
        Ok(())
    }

    fn file_identity(fd: impl AsFd) -> io::Result<UnixFileIdentity> {
        let stat = fstat(fd).map_err(io::Error::from)?;
        unix_file_identity(stat.st_dev, stat.st_ino)
    }

    fn unix_file_identity(
        dev: impl TryInto<u64>,
        ino: impl TryInto<u64>,
    ) -> io::Result<UnixFileIdentity> {
        Ok(UnixFileIdentity {
            dev: dev
                .try_into()
                .map_err(|_| invalid_path("file identity device id is out of range"))?,
            ino: ino
                .try_into()
                .map_err(|_| invalid_path("file identity inode is out of range"))?,
        })
    }

    fn mkdir_child(parent: &OwnedFd, name: &OsStr) -> io::Result<()> {
        let name = component_to_cstring(name)?;
        match rustix::fs::mkdirat(parent.as_fd(), &name, Mode::from_raw_mode(0o777)) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(source) => Err(io::Error::from(source)),
        }
    }

    fn linkat(
        source_parent: &OwnedFd,
        source_name: &CString,
        target_parent: &OwnedFd,
        target_name: &CString,
        flags: AtFlags,
    ) -> io::Result<()> {
        rustix::fs::linkat(
            source_parent.as_fd(),
            source_name,
            target_parent.as_fd(),
            target_name,
            flags,
        )
        .map_err(io::Error::from)
    }

    fn renameat(
        source_parent: &OwnedFd,
        source_name: &CString,
        target_parent: &OwnedFd,
        target_name: &CString,
    ) -> io::Result<()> {
        rustix::fs::renameat(
            source_parent.as_fd(),
            source_name,
            target_parent.as_fd(),
            target_name,
        )
        .map_err(io::Error::from)
    }

    fn component_to_cstring(component: &OsStr) -> io::Result<CString> {
        CString::new(component.as_bytes())
            .map_err(|_| invalid_path("path component contains an interior NUL byte"))
    }

    fn invalid_path(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }
}

use std::cell::RefCell;
use std::fs as std_fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use super::identity::ResolvedTarget;
use super::{Entry, Error, FileData, FileMode, Storage, TempArtifact};
#[cfg(unix)]
use rustix::fs::{CWD, Mode, OFlags, openat};

pub struct FileStorage;

impl FileStorage {
    pub fn create_temp_artifact(&self) -> Result<TempArtifact, Error> {
        let file = tempfile::tempfile().map_err(Error::CreateFileWithSource)?;

        Ok(TempArtifact::new(file))
    }

    pub fn read_file_no_follow<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Entry<std_fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let metadata = std_fs::symlink_metadata(&path).map_err(Error::FileAccessWithSource)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::UnsafePath(path));
        }
        if metadata.is_dir() {
            return Ok(Entry::Dir(path));
        }

        let file = open_no_follow(&path)?;
        #[cfg(unix)]
        verify_opened_file_matches_metadata(&file, &metadata, &path)?;
        Ok(Entry::File(FileData {
            path,
            stream: RefCell::new(file),
        }))
    }

    pub fn read_resolved_existing_no_follow(
        &self,
        target: &ResolvedTarget,
    ) -> Result<Entry<std_fs::File>, Error> {
        if !target.exists() {
            return Err(Error::UnsafePath(target.original_path().to_path_buf()));
        }

        let entry = self.read_file_no_follow(target.target_path())?;
        if entry.is_dir() != target.is_dir() {
            return Err(Error::UnsafePath(target.original_path().to_path_buf()));
        }

        #[cfg(unix)]
        verify_entry_matches_resolved_target(&entry, target)?;

        Ok(entry)
    }

    pub fn revalidate_resolved_directory_root(
        &self,
        root: &ResolvedTarget,
    ) -> Result<PathBuf, Error> {
        if !root.exists() || !root.is_dir() {
            return Err(Error::UnsafePath(root.original_path().to_path_buf()));
        }

        let entry = self.read_resolved_existing_no_follow(root)?;
        if !entry.is_dir() {
            return Err(Error::UnsafePath(root.original_path().to_path_buf()));
        }

        Ok(entry.path().to_path_buf())
    }

    pub fn revalidate_unpack_target<P: AsRef<Path>>(
        &self,
        root: P,
        relative: &Path,
        expected_target: &ResolvedTarget,
    ) -> Result<(), Error> {
        let root = root.as_ref();
        reject_mutated_root(root)?;

        let full_path = self.resolve_unpack_path(root, relative)?;
        if full_path != expected_target.original_path() {
            return Err(Error::UnsafePath(full_path));
        }

        match std_fs::symlink_metadata(&full_path) {
            Ok(meta) if meta.file_type().is_symlink() || meta.is_dir() => {
                Err(Error::UnsafePath(full_path))
            }
            Ok(_) if !expected_target.exists() => Err(Error::UnsafePath(full_path)),
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound && expected_target.exists() => {
                Err(Error::UnsafePath(full_path))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::FileAccessWithSource(err)),
        }
    }

    pub fn revalidate_unpack_directory_target<P: AsRef<Path>>(
        &self,
        root: P,
        relative: &Path,
        expected_target: &ResolvedTarget,
    ) -> Result<(), Error> {
        let root = root.as_ref();
        reject_mutated_root(root)?;

        let full_path = self.resolve_unpack_path(root, relative)?;
        if full_path != expected_target.original_path() {
            return Err(Error::UnsafePath(full_path));
        }

        match std_fs::symlink_metadata(&full_path) {
            Ok(meta) if meta.file_type().is_symlink() || meta.is_file() => {
                Err(Error::UnsafePath(full_path))
            }
            Ok(meta) if meta.is_dir() && expected_target.exists() => Ok(()),
            Ok(meta) if meta.is_dir() => Err(Error::UnsafePath(full_path)),
            Ok(_) => Err(Error::UnsafePath(full_path)),
            Err(err) if err.kind() == io::ErrorKind::NotFound && expected_target.exists() => {
                Err(Error::UnsafePath(full_path))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::FileAccessWithSource(err)),
        }
    }

    pub fn create_unpack_dir_all<P: AsRef<Path>>(
        &self,
        root: P,
        relative: &Path,
    ) -> Result<Vec<PathBuf>, Error> {
        let root = root.as_ref();
        reject_mutated_root(root)?;
        let full_path = root.join(relative);

        #[cfg(unix)]
        {
            // Create each component fd-relative to a trusted, O_NOFOLLOW-opened parent so
            // an intermediate component cannot be swapped for a symlink between check and
            // use (fs-1, fs-2). A symlinked/non-dir component is refused as UnsafePath.
            let root_fd = super::temp::open_absolute_dir(root)
                .map_err(|_| Error::UnsafePath(full_path.clone()))?;
            super::temp::create_dirs_fd_relative(&root_fd, root, relative).map_err(|err| {
                match err.kind() {
                    io::ErrorKind::AlreadyExists => Error::CreateDirWithSource(err),
                    _ => Error::UnsafePath(full_path.clone()),
                }
            })
        }

        #[cfg(not(unix))]
        {
            let mut current = root.to_path_buf();
            let mut created = Vec::new();
            for component in relative.components() {
                let Component::Normal(part) = component else {
                    return Err(Error::UnsafePath(full_path));
                };
                current.push(part);

                match std_fs::symlink_metadata(&current) {
                    Ok(meta) if meta.file_type().is_symlink() || meta.is_file() => {
                        return Err(Error::UnsafePath(full_path));
                    }
                    Ok(meta) if meta.is_dir() => {}
                    Ok(_) => return Err(Error::UnsafePath(full_path)),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        std_fs::create_dir(&current).map_err(Error::CreateDirWithSource)?;
                        created.push(current.clone());
                    }
                    Err(err) => return Err(Error::FileAccessWithSource(err)),
                }
            }

            Ok(created)
        }
    }
}

#[cfg(unix)]
fn verify_entry_matches_resolved_target(
    entry: &Entry<std_fs::File>,
    expected: &ResolvedTarget,
) -> Result<(), Error> {
    let Some(expected_identity) = expected.existing_target_identity() else {
        return Err(Error::UnsafePath(expected.original_path().to_path_buf()));
    };
    // Unix read-side reopen verifies the no-follow opened entry against
    // captured identity evidence.
    let actual = match entry {
        Entry::File(FileData { stream, .. }) => stream
            .borrow()
            .metadata()
            .map_err(Error::FileAccessWithSource)?,
        Entry::Dir(path) => std_fs::symlink_metadata(path).map_err(Error::FileAccessWithSource)?,
    };

    if actual.dev() != expected_identity.dev || actual.ino() != expected_identity.ino {
        return Err(Error::UnsafePath(expected.original_path().to_path_buf()));
    }

    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<std_fs::File, Error> {
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| Error::OpenFileWithSource {
        mode: FileMode::Read,
        source: io::Error::from(source),
    })?;
    Ok(fd.into())
}

#[cfg(unix)]
fn verify_opened_file_matches_metadata(
    file: &std_fs::File,
    expected: &std_fs::Metadata,
    path: &Path,
) -> Result<(), Error> {
    let actual = file.metadata().map_err(Error::FileAccessWithSource)?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(Error::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<std_fs::File, Error> {
    // non-Unix fallback is limited by platform identity APIs.
    // It does not provide Unix-equivalent identity evidence.
    std_fs::File::open(path).map_err(|source| Error::OpenFileWithSource {
        mode: FileMode::Read,
        source,
    })
}

fn reject_mutated_root(root: &Path) -> Result<(), Error> {
    let metadata = std_fs::symlink_metadata(root).map_err(|_| Error::UnsafePath(root.into()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::UnsafePath(root.into()));
    }

    let canonical_root = std_fs::canonicalize(root).map_err(|_| Error::UnsafePath(root.into()))?;
    if canonical_root != root {
        return Err(Error::UnsafePath(root.into()));
    }

    Ok(())
}

impl Storage<std_fs::File> for FileStorage {
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        std_fs::create_dir_all(&path).map_err(Error::CreateDirWithSource)
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<std_fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = std_fs::File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(Error::CreateFileWithSource)?;
        Ok(Entry::File(FileData {
            path,
            stream: RefCell::new(file),
        }))
    }

    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<std_fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        if path.is_dir() {
            Ok(Entry::Dir(path))
        } else {
            let file = std_fs::File::open(&path).map_err(|source| Error::OpenFileWithSource {
                mode: FileMode::Read,
                source,
            })?;
            Ok(Entry::File(FileData {
                path,
                stream: RefCell::new(file),
            }))
        }
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<std_fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = std_fs::File::options()
            .write(true)
            .read(true)
            .truncate(true)
            .open(&path)
            .map_err(|source| Error::OpenFileWithSource {
                mode: FileMode::Write,
                source,
            })?;

        Ok(Entry::File(FileData {
            path,
            stream: RefCell::new(file),
        }))
    }

    fn overwrite_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<std_fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = std_fs::File::options()
            .write(true)
            .read(true)
            .open(&path)
            .map_err(|source| Error::OpenFileWithSource {
                mode: FileMode::Write,
                source,
            })?;

        Ok(Entry::File(FileData {
            path,
            stream: RefCell::new(file),
        }))
    }

    fn flush_file(&self, file: &Entry<std_fs::File>) -> Result<(), Error> {
        file.try_writer()?
            .borrow_mut()
            .flush()
            .map_err(Error::FlushFileWithSource)
    }

    fn file_len(&self, file: &Entry<std_fs::File>) -> Result<usize, Error> {
        let fs_file = match file {
            Entry::File(FileData { stream, .. }) => stream.borrow(),
            Entry::Dir(_) => return Err(Error::FileAccess),
        };
        let file_meta = std_fs::File::metadata(&fs_file).map_err(Error::FileLenWithSource)?;
        file_meta.len().try_into().map_err(|_| Error::FileLen)
    }

    fn remove_file(&self, file: Entry<std_fs::File>) -> Result<(), Error> {
        if let Entry::File(FileData { stream, .. }) = &file {
            let mut stream = stream.borrow_mut();
            stream.set_len(0).map_err(Error::RemoveFileWithSource)?;
            stream.flush().map_err(Error::FlushFileWithSource)?;
        }

        std_fs::remove_file(file.path()).map_err(Error::RemoveFileWithSource)
    }

    fn remove_dir_all(&self, file: Entry<std_fs::File>) -> Result<(), Error> {
        if !file.is_dir() {
            return Err(Error::RemoveDir);
        }

        std_fs::remove_dir_all(file.path()).map_err(Error::RemoveDirWithSource)
    }

    fn read_dir(&self, file: &Entry<std_fs::File>) -> Result<Vec<Entry<std_fs::File>>, Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        walkdir::WalkDir::new(file.path())
            .into_iter()
            .map(|res| {
                res.map(|e| e.path().to_owned())
                    .map_err(|error| match error.into_io_error() {
                        Some(source) => Error::DirEntriesWithSource(source),
                        None => Error::DirEntries,
                    })
            })
            .map(|path| path.and_then(|path| self.read_file(path)))
            .collect()
    }

    fn prepare_unpack_root<P: AsRef<Path>>(&self, output_dir: P) -> Result<PathBuf, Error> {
        let output_dir = output_dir.as_ref();

        #[cfg(unix)]
        {
            // Establish the absolute base, then create the Normal components fd-relative
            // (O_NOFOLLOW per hop) so no intermediate component can be swapped for a
            // symlink between check and use (fs-1, fs-2).
            let mut base = if output_dir.is_absolute() {
                PathBuf::from("/")
            } else {
                std::env::current_dir().map_err(Error::FileAccessWithSource)?
            };
            let mut normal = PathBuf::new();
            for component in output_dir.components() {
                match component {
                    Component::Prefix(prefix) => base.push(prefix.as_os_str()),
                    Component::RootDir | Component::CurDir => {}
                    Component::ParentDir => {
                        return Err(Error::UnsafePath(output_dir.to_path_buf()));
                    }
                    Component::Normal(part) => normal.push(part),
                }
            }

            let base_fd = super::temp::open_absolute_dir(&base)
                .map_err(|_| Error::UnsafePath(output_dir.to_path_buf()))?;
            super::temp::create_dirs_fd_relative(&base_fd, &base, &normal)
                .map_err(|_| Error::UnsafePath(output_dir.to_path_buf()))?;

            std_fs::canonicalize(base.join(&normal))
                .map_err(|_| Error::UnsafePath(output_dir.to_path_buf()))
        }

        #[cfg(not(unix))]
        {
            let mut current = if output_dir.is_absolute() {
                PathBuf::new()
            } else {
                std::env::current_dir().map_err(Error::FileAccessWithSource)?
            };

            for component in output_dir.components() {
                match component {
                    Component::Prefix(prefix) => current.push(prefix.as_os_str()),
                    Component::RootDir => current.push(component.as_os_str()),
                    Component::CurDir => {}
                    Component::ParentDir => {
                        return Err(Error::UnsafePath(output_dir.to_path_buf()));
                    }
                    Component::Normal(part) => {
                        current.push(part);

                        match std_fs::symlink_metadata(&current) {
                            Ok(meta) if meta.file_type().is_symlink() => {
                                return Err(Error::UnsafePath(current));
                            }
                            Ok(meta) if meta.is_dir() => {}
                            Ok(_) => return Err(Error::UnsafePath(current)),
                            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                                std_fs::create_dir(&current).map_err(Error::CreateDirWithSource)?;
                            }
                            Err(err) => return Err(Error::FileAccessWithSource(err)),
                        }
                    }
                }
            }

            std_fs::canonicalize(&current).map_err(|_| Error::UnsafePath(output_dir.to_path_buf()))
        }
    }

    fn resolve_unpack_path<P: AsRef<Path>>(
        &self,
        root: P,
        relative: &Path,
    ) -> Result<PathBuf, Error> {
        let root = root.as_ref();
        let full_path = root.join(relative);
        let mut current = root.to_path_buf();
        let mut components = relative.components().peekable();

        while let Some(component) = components.next() {
            let Component::Normal(part) = component else {
                return Err(Error::UnsafePath(full_path));
            };

            current.push(part);

            match std_fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(Error::UnsafePath(full_path));
                }
                Ok(meta) if components.peek().is_some() && meta.is_file() => {
                    return Err(Error::UnsafePath(full_path));
                }
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(Error::FileAccessWithSource(err)),
            }
        }

        Ok(full_path)
    }
}

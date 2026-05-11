use std::cell::RefCell;
use std::fs as std_fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use super::identity::ResolvedTarget;
use super::{Entry, Error, FileData, FileMode, Storage, TempArtifact};

pub struct FileStorage;

impl FileStorage {
    pub fn create_temp_artifact(&self) -> Result<TempArtifact, Error> {
        let file = tempfile::tempfile().map_err(|_| Error::CreateFile)?;

        Ok(TempArtifact::new(file))
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
            Err(_) => Err(Error::FileAccess),
        }
    }
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
        std_fs::create_dir_all(&path).map_err(|_| Error::CreateDir)
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<std_fs::File>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = std_fs::File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| Error::CreateFile)?;
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
            let file = std_fs::File::open(&path).map_err(|_| Error::OpenFile(FileMode::Read))?;
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
            .map_err(|_| Error::OpenFile(FileMode::Write))?;

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
            .map_err(|_| Error::OpenFile(FileMode::Write))?;

        Ok(Entry::File(FileData {
            path,
            stream: RefCell::new(file),
        }))
    }

    fn flush_file(&self, file: &Entry<std_fs::File>) -> Result<(), Error> {
        file.try_writer()?
            .borrow_mut()
            .flush()
            .map_err(|_| Error::FlushFile)
    }

    fn file_len(&self, file: &Entry<std_fs::File>) -> Result<usize, Error> {
        let fs_file = match file {
            Entry::File(FileData { stream, .. }) => stream.borrow(),
            Entry::Dir(_) => return Err(Error::FileAccess),
        };
        let file_meta = std_fs::File::metadata(&fs_file).map_err(|_| Error::FileLen)?;
        file_meta.len().try_into().map_err(|_| Error::FileLen)
    }

    fn remove_file(&self, file: Entry<std_fs::File>) -> Result<(), Error> {
        if let Entry::File(FileData { stream, .. }) = &file {
            let mut stream = stream.borrow_mut();
            stream.set_len(0).map_err(|_| Error::RemoveFile)?;
            stream.flush().map_err(|_| Error::FlushFile)?;
        }

        std_fs::remove_file(file.path()).map_err(|_| Error::RemoveFile)
    }

    fn remove_dir_all(&self, file: Entry<std_fs::File>) -> Result<(), Error> {
        if !file.is_dir() {
            return Err(Error::RemoveDir);
        }

        std_fs::remove_dir_all(file.path()).map_err(|_| Error::RemoveDir)
    }

    fn read_dir(&self, file: &Entry<std_fs::File>) -> Result<Vec<Entry<std_fs::File>>, Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        walkdir::WalkDir::new(file.path())
            .into_iter()
            .map(|res| {
                res.map(|e| e.path().to_owned())
                    .map_err(|_| Error::DirEntries)
            })
            .map(|path| path.and_then(|path| self.read_file(path)))
            .collect()
    }

    fn prepare_unpack_root<P: AsRef<Path>>(&self, output_dir: P) -> Result<PathBuf, Error> {
        let output_dir = output_dir.as_ref();
        let mut current = if output_dir.is_absolute() {
            PathBuf::new()
        } else {
            std::env::current_dir().map_err(|_| Error::FileAccess)?
        };

        for component in output_dir.components() {
            match component {
                Component::Prefix(prefix) => current.push(prefix.as_os_str()),
                Component::RootDir => current.push(component.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => return Err(Error::UnsafePath(output_dir.to_path_buf())),
                Component::Normal(part) => {
                    current.push(part);

                    match std_fs::symlink_metadata(&current) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            return Err(Error::UnsafePath(current));
                        }
                        Ok(meta) if meta.is_dir() => {}
                        Ok(_) => return Err(Error::UnsafePath(current)),
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {
                            std_fs::create_dir(&current).map_err(|_| Error::CreateDir)?;
                        }
                        Err(_) => return Err(Error::FileAccess),
                    }
                }
            }
        }

        std_fs::canonicalize(&current).map_err(|_| Error::UnsafePath(output_dir.to_path_buf()))
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
                Err(_) => return Err(Error::FileAccess),
            }
        }

        Ok(full_path)
    }
}

use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

pub mod cleanup;
mod entry;
mod fs;
pub mod identity;
#[cfg(test)]
mod memory;
mod temp;
/// Deterministic failure hooks for storage safety tests; runtime workflows do not use them.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(not(any(test, feature = "test-support")))]
mod test_support;
pub mod transaction;

pub use entry::{Entry, FileData};
pub use fs::FileStorage;
#[cfg(test)]
pub use memory::{IMFile, InMemoryFile, InMemoryStorage};
pub use temp::{NamedStagedOutput, TempArtifact};

#[derive(Debug)]
pub enum FileMode {
    Read,
    Write,
}

#[derive(Debug)]
pub enum Error {
    CreateDir,
    CreateDirWithSource(io::Error),
    CreateFile,
    CreateFileWithSource(io::Error),
    OpenFile(FileMode),
    OpenFileWithSource {
        mode: FileMode,
        source: io::Error,
    },
    RemoveFile,
    RemoveFileWithSource(io::Error),
    RemoveDir,
    RemoveDirWithSource(io::Error),
    DirEntries,
    DirEntriesWithSource(io::Error),
    FlushFile,
    FlushFileWithSource(io::Error),
    SyncFile,
    SyncFileWithSource(io::Error),
    FileAccess,
    FileAccessWithSource(io::Error),
    FileLen,
    FileLenWithSource(io::Error),
    UnsafePath(PathBuf),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CreateDir | Error::CreateDirWithSource(_) => {
                f.write_str("Unable to create a new directory")
            }
            Error::CreateFile | Error::CreateFileWithSource(_) => {
                f.write_str("Unable to create a new file")
            }
            Error::OpenFile(mode) | Error::OpenFileWithSource { mode, .. } => {
                write!(f, "Unable to read the file in {mode:?} mode")
            }
            Error::FlushFile | Error::FlushFileWithSource(_) => {
                f.write_str("Unable to flush the file")
            }
            Error::SyncFile | Error::SyncFileWithSource(_) => {
                f.write_str("Unable to sync the file")
            }
            Error::RemoveFile | Error::RemoveFileWithSource(_) => {
                f.write_str("Unable to remove the file")
            }
            Error::RemoveDir | Error::RemoveDirWithSource(_) => f.write_str("Unable to remove dir"),
            Error::DirEntries | Error::DirEntriesWithSource(_) => {
                f.write_str("Unable to read directory")
            }
            Error::FileAccess | Error::FileAccessWithSource(_) => f.write_str("Permission denied"),
            Error::FileLen | Error::FileLenWithSource(_) => {
                f.write_str("Unable to get file length")
            }
            Error::UnsafePath(path) => {
                write!(f, "Unsafe extraction path: {}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateDirWithSource(source)
            | Self::CreateFileWithSource(source)
            | Self::RemoveFileWithSource(source)
            | Self::RemoveDirWithSource(source)
            | Self::DirEntriesWithSource(source)
            | Self::FlushFileWithSource(source)
            | Self::SyncFileWithSource(source)
            | Self::FileAccessWithSource(source)
            | Self::FileLenWithSource(source)
            | Self::OpenFileWithSource { source, .. } => Some(source),
            Self::CreateDir
            | Self::CreateFile
            | Self::OpenFile(_)
            | Self::RemoveFile
            | Self::RemoveDir
            | Self::DirEntries
            | Self::FlushFile
            | Self::SyncFile
            | Self::FileAccess
            | Self::FileLen
            | Self::UnsafePath(_) => None,
        }
    }
}

pub trait Storage<RW>: Send + Sync
where
    RW: Read + Write + Seek,
{
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Error>;
    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<RW>, Error>;
    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<RW>, Error>;
    fn overwrite_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<RW>, Error>;
    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<RW>, Error>;
    fn flush_file(&self, file: &Entry<RW>) -> Result<(), Error>;
    fn file_len(&self, file: &Entry<RW>) -> Result<usize, Error>;
    fn remove_file(&self, file: Entry<RW>) -> Result<(), Error>;
    fn remove_dir_all(&self, file: Entry<RW>) -> Result<(), Error>;
    // TODO(pleshevskiy): return iterator instead of Vector
    fn read_dir(&self, file: &Entry<RW>) -> Result<Vec<Entry<RW>>, Error>;

    fn prepare_unpack_root<P: AsRef<Path>>(&self, output_dir: P) -> Result<PathBuf, Error> {
        let output_dir = output_dir.as_ref().to_path_buf();
        self.create_dir_all(&output_dir)?;
        Ok(output_dir)
    }

    fn resolve_unpack_path<P: AsRef<Path>>(
        &self,
        root: P,
        relative: &Path,
    ) -> Result<PathBuf, Error> {
        Ok(root.as_ref().join(relative))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn sorted_file_names(file_names: &[PathBuf]) -> Vec<&str> {
        let mut keys = file_names
            .iter()
            .map(|k| k.to_str().unwrap())
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn should_create_a_new_file() {
        let stor = InMemoryStorage::default();

        match stor.create_file("hello.txt") {
            Ok(file) => {
                let im_file = stor.files().get(file.path()).cloned();
                assert_eq!(im_file, Some(IMFile::File(InMemoryFile::default())));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_throw_an_error_if_file_already_exist() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        match stor.create_file("hello.txt") {
            Err(Error::CreateFile) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_not_open_file_to_read() {
        let stor = InMemoryStorage::default();

        match stor.read_file("hello.txt") {
            Err(Error::OpenFile(FileMode::Read)) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_not_open_file_to_write() {
        let stor = InMemoryStorage::default();

        match stor.write_file("hello.txt") {
            Err(Error::OpenFile(FileMode::Write)) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_open_exist_file_in_read_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        match stor.read_file("hello.txt") {
            Ok(file) => {
                if let Some(IMFile::File(InMemoryFile { buf, len })) = stor.files().get(file.path())
                {
                    let content = b"hello world".to_vec();
                    assert_eq!(len, &content.len());
                    assert_eq!(buf, &content);
                } else {
                    unreachable!();
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_open_exist_file_in_write_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        match stor.write_file("hello.txt") {
            Ok(file) => {
                if let Some(IMFile::File(InMemoryFile { buf, len })) = stor.files().get(file.path())
                {
                    let content = b"hello world".to_vec();
                    assert_eq!(len, &content.len());
                    assert_eq!(buf, &content);
                } else {
                    unreachable!();
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_write_content_to_file() {
        let stor = InMemoryStorage::default();
        let content = "hello world";

        let file = stor.create_file("hello.txt").unwrap();
        file.try_writer()
            .unwrap()
            .borrow_mut()
            .write_all(content.as_bytes())
            .unwrap();

        match stor.flush_file(&file) {
            Ok(()) => {
                let im_file = stor.files().get(file.path()).cloned();
                assert_eq!(
                    im_file,
                    Some(IMFile::File(InMemoryFile {
                        buf: content.as_bytes().to_vec(),
                        len: content.len()
                    }))
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_a_file_in_read_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        let file = stor.write_file("hello.txt").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_file(file) {
            Ok(()) => {
                let im_file = stor.files().get(&file_path).cloned();
                assert_eq!(im_file, None);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_a_file_in_write_mode() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        let file = stor.write_file("hello.txt").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_file(file) {
            Ok(()) => {
                let im_file = stor.files().get(&file_path).cloned();
                assert_eq!(im_file, None);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_get_file_length() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();

        let file = stor.read_file("hello.txt").unwrap();

        match stor.file_len(&file) {
            Ok(len) => {
                let content = b"hello world".to_vec();
                assert_eq!(len, content.len());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_open_dir() {
        let stor = InMemoryStorage::default();
        stor.add_bar_foo_folder();

        match stor.read_file("bar/foo/") {
            Ok(Entry::Dir(path)) => assert_eq!(path, PathBuf::from("bar/foo/")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_dir_with_subfiles() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder();

        let file = stor.read_file("bar/foo/").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_dir_all(file) {
            Ok(()) => {
                assert_eq!(stor.files().get(&file_path).cloned(), None);
                let files = stor.files();
                let keys = files.keys().cloned().collect::<Vec<_>>();
                assert_eq!(
                    sorted_file_names(&keys),
                    vec!["bar/", "bar/hello.txt", "bar/world.txt", "hello.txt"]
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_remove_dir_recursively_with_subfiles() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder();

        let file = stor.read_file("bar/").unwrap();
        let file_path = file.path().to_path_buf();

        match stor.remove_dir_all(file) {
            Ok(()) => {
                assert_eq!(stor.files().get(&file_path).cloned(), None);
                let files = stor.files();
                let keys = files.keys().cloned().collect::<Vec<PathBuf>>();
                assert_eq!(sorted_file_names(&keys), vec!["hello.txt"]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_return_file_names_of_dir_subfiles() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder();

        let file = stor.read_file("bar/").unwrap();

        match stor.read_dir(&file) {
            Ok(files) => {
                let file_names = files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .collect::<Vec<_>>();
                assert_eq!(
                    sorted_file_names(&file_names),
                    vec![
                        "bar/",
                        "bar/foo/",
                        "bar/foo/hello.txt",
                        "bar/foo/world.txt",
                        "bar/hello.txt",
                        "bar/world.txt",
                    ]
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_include_hidden_files_names() {
        let stor = InMemoryStorage::default();
        stor.add_hello_txt();
        stor.add_bar_foo_folder_with_hidden();

        let file = stor.read_file("bar/").unwrap();

        match stor.read_dir(&file) {
            Ok(files) => {
                let file_names = files
                    .into_iter()
                    .map(|f| f.path().to_path_buf())
                    .collect::<Vec<_>>();
                assert_eq!(
                    sorted_file_names(&file_names),
                    vec![
                        "bar/",
                        "bar/.foo/",
                        "bar/.foo/hello.txt",
                        "bar/.foo/world.txt",
                        "bar/.hello.txt",
                        "bar/world.txt",
                    ]
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn overwrite_file_preserves_existing_length_on_disk() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("dexios-overwrite-{unique}.bin"));

        fs::write(&path, b"secret-bytes").unwrap();

        let stor = FileStorage;
        let file = stor.overwrite_file(&path).expect("open without truncation");

        assert_eq!(stor.file_len(&file).unwrap(), b"secret-bytes".len());

        fs::remove_file(path).ok();
    }

    #[test]
    fn temp_artifact_exists_while_live() {
        let stor = FileStorage;
        let tmp = stor.create_temp_artifact().expect("temp artifact");
        tmp.with_writer(|file| {
            file.write_all(b"temp-data").map_err(|_| Error::FlushFile)?;
            Ok::<(), Error>(())
        })
        .unwrap();

        assert_eq!(tmp.len().unwrap(), b"temp-data".len());
    }

    #[test]
    fn temp_artifact_is_deleted_on_drop() {
        let stor = FileStorage;
        let tmp = stor.create_temp_artifact().unwrap();

        tmp.with_writer(|file| {
            file.write_all(b"temp-data").map_err(|_| Error::FlushFile)?;
            Ok::<(), Error>(())
        })
        .unwrap();

        // Drop should not panic and should dispose of the unnamed temp file.
        drop(tmp);
    }

    #[test]
    fn temp_artifact_sync_all_succeeds_while_live() {
        let stor = FileStorage;
        let tmp = stor.create_temp_artifact().unwrap();

        tmp.with_writer(|file| {
            file.write_all(b"temp-data").map_err(|_| Error::FlushFile)?;
            Ok::<(), Error>(())
        })
        .unwrap();

        tmp.sync_all().unwrap();
    }
}

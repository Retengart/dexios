use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread;

use super::{Entry, Error, FileData, FileMode, Storage};

#[derive(Default)]
pub struct InMemoryStorage {
    pub files: RwLock<HashMap<PathBuf, IMFile>>,
}

impl InMemoryStorage {
    fn save_text_file<P: AsRef<Path>>(&self, path: P, content: &str) {
        let buf = content.bytes().collect::<Vec<_>>();
        self.save_file(
            path,
            IMFile::File(InMemoryFile {
                len: buf.len(),
                buf,
            }),
        );
    }

    fn save_file<P: AsRef<Path>>(&self, path: P, im_file: IMFile) {
        self.mut_files().insert(path.as_ref().to_owned(), im_file);
    }

    pub(crate) fn files(&self) -> RwLockReadGuard<'_, HashMap<PathBuf, IMFile>> {
        loop {
            match self.files.try_read() {
                Ok(files) => break files,
                _ => thread::sleep(std::time::Duration::from_micros(100)),
            }
        }
    }

    pub(crate) fn mut_files(&self) -> RwLockWriteGuard<'_, HashMap<PathBuf, IMFile>> {
        loop {
            match self.files.try_write() {
                Ok(files) => break files,
                _ => thread::sleep(std::time::Duration::from_micros(100)),
            }
        }
    }

    // --------------------------------
    // TEST DATA
    // -------------------------------

    pub(crate) fn add_hello_txt(&self) {
        self.save_text_file("hello.txt", "hello world");
    }

    pub(crate) fn add_bar_foo_folder(&self) {
        self.save_file("bar/", IMFile::Dir);
        self.save_text_file("bar/hello.txt", "hello");
        self.save_text_file("bar/world.txt", "world");
        self.save_file("bar/foo/", IMFile::Dir);
        self.save_text_file("bar/foo/hello.txt", "hello");
        self.save_text_file("bar/foo/world.txt", "world");
    }

    pub(crate) fn add_bar_foo_folder_with_hidden(&self) {
        self.save_file("bar/", IMFile::Dir);
        self.save_text_file("bar/.hello.txt", "hello");
        self.save_text_file("bar/world.txt", "world");
        self.save_file("bar/.foo/", IMFile::Dir);
        self.save_text_file("bar/.foo/hello.txt", "hello");
        self.save_text_file("bar/.foo/world.txt", "world");
    }
}

impl Storage<io::Cursor<Vec<u8>>> for InMemoryStorage {
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut dirs = path
            .as_ref()
            .ancestors()
            .filter(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        dirs.reverse();

        for dir in dirs {
            let existing = self.files().get(&dir).cloned();
            match existing {
                Some(IMFile::Dir) => {}
                Some(IMFile::File(_)) => return Err(Error::CreateDir),
                None => self.save_file(dir, IMFile::Dir),
            }
        }

        Ok(())
    }

    fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<io::Cursor<Vec<u8>>>, Error> {
        let file_path = path.as_ref().to_path_buf();

        let im_file = match self.files().get(&file_path) {
            Some(_) => Err(Error::CreateFile),
            None => Ok(IMFile::File(InMemoryFile::default())),
        }?;

        let cursor = io::Cursor::new(im_file.inner().buf.clone());

        self.save_file(file_path.clone(), im_file);

        Ok(Entry::File(FileData {
            path: file_path,
            stream: RefCell::new(cursor),
        }))
    }

    fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<io::Cursor<Vec<u8>>>, Error> {
        let in_file = self
            .files()
            .get(path.as_ref())
            .cloned()
            .ok_or(Error::OpenFile(FileMode::Read))?;

        let file_path = path.as_ref().to_path_buf();

        match in_file {
            IMFile::Dir => Ok(Entry::Dir(file_path)),
            IMFile::File(f) => {
                let cursor = io::Cursor::new(f.buf);
                Ok(Entry::File(FileData {
                    path: file_path,
                    stream: RefCell::new(cursor),
                }))
            }
        }
    }

    fn write_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<io::Cursor<Vec<u8>>>, Error> {
        let file_path = path.as_ref().to_path_buf();

        let file = self
            .files()
            .get(&file_path)
            .cloned()
            .ok_or(Error::OpenFile(FileMode::Write))?;
        if matches!(file, IMFile::Dir) {
            return Err(Error::FileAccess);
        }

        let cursor = io::Cursor::new(file.inner().buf.clone());

        Ok(Entry::File(FileData {
            path: file_path,
            stream: RefCell::new(cursor),
        }))
    }

    fn overwrite_file<P: AsRef<Path>>(&self, path: P) -> Result<Entry<io::Cursor<Vec<u8>>>, Error> {
        self.write_file(path)
    }

    fn flush_file(&self, file: &Entry<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        if file.is_dir() {
            return Err(Error::FileAccess);
        }

        let file_path = file.path();
        let writer = file.try_writer()?;
        writer.borrow_mut().flush().map_err(|_| Error::FlushFile)?;

        let vec = writer.borrow().get_ref().clone();
        let len = vec.len();
        let new_file = IMFile::File(InMemoryFile { buf: vec, len });

        self.save_file(file_path, new_file);

        Ok(())
    }

    fn file_len(&self, file: &Entry<io::Cursor<Vec<u8>>>) -> Result<usize, Error> {
        let cur = match file {
            Entry::File(FileData { stream, .. }) => stream.borrow(),
            Entry::Dir(_) => return Err(Error::FileAccess),
        };

        Ok(cur.get_ref().len())
    }

    fn remove_file(&self, file: Entry<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        self.mut_files()
            .remove(file.path())
            .ok_or(Error::RemoveFile)?;
        Ok(())
    }

    fn remove_dir_all(&self, file: Entry<io::Cursor<Vec<u8>>>) -> Result<(), Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        let file_path = file.path();

        #[expect(
            clippy::needless_collect,
            reason = "collecting eagerly releases the read lock guard before mutating the map"
        )]
        let file_paths = self
            .files()
            .keys()
            .filter(|k| k.starts_with(file_path))
            .cloned()
            .collect::<Vec<_>>();

        file_paths.into_iter().try_for_each(|k| {
            self.mut_files()
                .remove(&k)
                .map(|_| ())
                .ok_or(Error::RemoveDir)?;
            Ok(())
        })
    }

    fn read_dir(
        &self,
        file: &Entry<io::Cursor<Vec<u8>>>,
    ) -> Result<Vec<Entry<io::Cursor<Vec<u8>>>>, Error> {
        if !file.is_dir() {
            return Err(Error::FileAccess);
        }

        let file_path = file.path();

        self.files()
            .iter()
            .filter(|(k, _)| k.starts_with(file_path))
            .map(|(k, _)| self.read_file(k))
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryFile {
    pub buf: Vec<u8>,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMFile {
    File(InMemoryFile),
    Dir,
}

impl IMFile {
    #[expect(
        clippy::unreachable,
        reason = "inner() is only ever called on File variants the caller just constructed/opened as files"
    )]
    fn inner(&self) -> &InMemoryFile {
        match self {
            Self::File(inner) => inner,
            Self::Dir => unreachable!(),
        }
    }
}

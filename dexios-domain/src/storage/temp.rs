use std::cell::RefCell;
use std::fs as std_fs;

use super::Error;

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

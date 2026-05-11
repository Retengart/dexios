use std::cell::RefCell;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use super::Error;

pub struct FileData<RW>
where
    RW: Read + Write + Seek,
{
    pub(super) path: PathBuf,
    pub(super) stream: RefCell<RW>,
}

pub enum Entry<RW>
where
    RW: Read + Write + Seek,
{
    File(FileData<RW>),
    Dir(PathBuf),
}

impl<RW> Entry<RW>
where
    RW: Read + Write + Seek,
{
    pub fn path(&self) -> &Path {
        match self {
            Entry::File(FileData { path, .. }) | Entry::Dir(path) => path,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, Entry::Dir(_))
    }

    pub fn try_reader(&self) -> Result<&RefCell<RW>, Error> {
        match self {
            Entry::File(file) => Ok(&file.stream),
            Entry::Dir(_) => Err(Error::FileAccess),
        }
    }

    pub fn try_writer(&self) -> Result<&RefCell<RW>, Error> {
        match self {
            Entry::File(file) => Ok(&file.stream),
            Entry::Dir(_) => Err(Error::FileAccess),
        }
    }
}

//! This contains the logic for decrypting a zip file, and extracting each file to the target directory. The temporary zip file is then erased with one pass.
//!
//! This is known as "unpacking" within Dexios.

use std::cell::RefCell;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crate::storage::{self, Storage};
use crate::{decrypt, overwrite};
use core::protected::Protected;

trait TempArtifactLike {
    fn with_reader<T, E>(&self, f: impl FnOnce(&mut dyn ReadSeek) -> Result<T, E>) -> Result<T, E>;
    fn with_writer<T, E>(&self, f: impl FnOnce(&mut dyn WriteSeek) -> Result<T, E>)
    -> Result<T, E>;
    fn len(&self) -> Result<usize, Error>;
    fn secure_dispose(self) -> Result<(), Error>;
}

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

trait WriteSeek: Write + Seek {}
impl<T: Write + Seek + ?Sized> WriteSeek for T {}

impl TempArtifactLike for storage::TempArtifact {
    fn with_reader<T, E>(&self, f: impl FnOnce(&mut dyn ReadSeek) -> Result<T, E>) -> Result<T, E> {
        storage::TempArtifact::with_reader(self, |file| f(file))
    }

    fn with_writer<T, E>(
        &self,
        f: impl FnOnce(&mut dyn WriteSeek) -> Result<T, E>,
    ) -> Result<T, E> {
        storage::TempArtifact::with_writer(self, |file| f(file))
    }

    fn len(&self) -> Result<usize, Error> {
        storage::TempArtifact::len(self).map_err(Error::Storage)
    }

    fn secure_dispose(self) -> Result<(), Error> {
        storage::TempArtifact::secure_dispose(self).map_err(|_| Error::TempCleanup)
    }
}

#[derive(Debug)]
pub enum Error {
    WriteData,
    OpenArchive,
    OpenArchivedFile,
    ResetCursorPosition,
    Storage(storage::Error),
    Decrypt(decrypt::Error),
    TempCleanup,
    OnZipFile(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WriteData => f.write_str("Unable to write data"),
            Error::OpenArchive => f.write_str("Unable to open archive"),
            Error::OpenArchivedFile => f.write_str("Unable to open archived file"),
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::Storage(inner) => write!(f, "Storage error: {inner}"),
            Error::Decrypt(inner) => write!(f, "Decrypt error: {inner}"),
            Error::TempCleanup => f.write_str("Unable to securely clean up temporary archive"),
            Error::OnZipFile(inner) => write!(f, "Zip file callback error: {inner}"),
        }
    }
}

impl std::error::Error for Error {}

type OnArchiveInfo = Box<dyn FnOnce(usize)>;
type OnZipFileFn = Box<dyn Fn(PathBuf) -> Result<bool, String>>;

pub struct Request<'a, R>
where
    R: Read,
{
    pub reader: &'a RefCell<R>,
    pub header_reader: Option<&'a RefCell<R>>,
    pub raw_key: Protected<Vec<u8>>,
    pub output_dir_path: PathBuf,
    pub on_decrypted_header: Option<decrypt::OnDecryptedHeaderFn>,
    pub on_archive_info: Option<OnArchiveInfo>,
    pub on_zip_file: Option<OnZipFileFn>,
}

pub fn execute<RW: Read + Write + Seek>(
    stor: Arc<impl Storage<RW> + 'static>,
    req: Request<'_, RW>,
) -> Result<(), Error> {
    execute_with_temp_artifact(stor, req, || {
        storage::FileStorage
            .create_temp_artifact()
            .map_err(Error::Storage)
    })
}

fn execute_with_temp_artifact<RW, T, F>(
    stor: Arc<impl Storage<RW> + 'static>,
    req: Request<'_, RW>,
    temp_factory: F,
) -> Result<(), Error>
where
    RW: Read + Write + Seek,
    T: TempArtifactLike,
    F: FnOnce() -> Result<T, Error>,
{
    // 1. Create temp zip archive.
    let tmp_file = temp_factory()?;

    // 2. Decrypt input file to temp zip archive.
    tmp_file.with_writer(|tmp_writer| {
        tmp_writer
            .rewind()
            .map_err(|_| Error::Storage(storage::Error::OpenFile(storage::FileMode::Write)))?;
        let writer = RefCell::new(tmp_writer);
        decrypt::execute(decrypt::Request {
            header_reader: req.header_reader,
            reader: req.reader,
            writer: &writer,
            raw_key: req.raw_key,
            on_decrypted_header: req.on_decrypted_header,
        })
        .map_err(Error::Decrypt)
    })?;

    let buf_capacity = tmp_file.len()?;

    // 3. Recover files from temp archive.
    tmp_file.with_reader(|tmp_reader| {
        tmp_reader
            .rewind()
            .map_err(|_| Error::ResetCursorPosition)?;
        let mut archive = zip::ZipArchive::new(tmp_reader).map_err(|_| Error::OpenArchive)?;

        let output_dir = req.output_dir_path.clone();

        // 4. prepare phase
        let mut entities = Vec::new();
        for i in 0..archive.len() {
            let zip_file = archive.by_index(i).map_err(|_| Error::OpenArchive)?;
            let Some(path) = zip_file.enclosed_name() else {
                continue;
            };

            let mut full_path = output_dir.clone();
            full_path.push(path);

            if let Some(on_zip_file) = req.on_zip_file.as_ref() {
                let should_unpack = on_zip_file(full_path.clone()).map_err(Error::OnZipFile)?;
                if !should_unpack {
                    continue;
                }
            }

            entities.push((full_path, i, zip_file.is_dir()));
        }

        let files_count = entities.len();
        if let Some(on_archive_info) = req.on_archive_info {
            on_archive_info(files_count);
        }

        // 5. create dirs sequentially to avoid unbounded thread fan-out on large archives.
        entities
            .iter()
            .filter(|(_, _, is_dir)| *is_dir)
            .map(|(fp, ..)| fp)
            .chain([&output_dir])
            .try_for_each(|full_path| stor.create_dir_all(full_path).map_err(Error::Storage))?;

        // 6. create files
        entities
            .iter()
            .filter(|(_, _, is_dir)| !*is_dir)
            .try_for_each(|(full_path, i, _)| {
                if let Some(parent_dir) = full_path.parent() {
                    stor.create_dir_all(parent_dir).map_err(Error::Storage)?;
                }
                let mut zip_file = archive.by_index(*i).map_err(|_| Error::OpenArchivedFile)?;
                let file = stor
                    .create_file(full_path)
                    .or_else(|_| stor.write_file(full_path))
                    .map_err(Error::Storage)?;
                std::io::copy(
                    &mut zip_file,
                    &mut *file.try_writer().map_err(Error::Storage)?.borrow_mut(),
                )
                .map_err(|_| Error::WriteData)?;
                stor.flush_file(&file).map_err(Error::Storage)?;
                Ok(())
            })
    })?;

    cleanup_temp_archive(tmp_file, buf_capacity)?;

    Ok(())
}

fn cleanup_temp_archive(tmp_file: impl TempArtifactLike, buf_capacity: usize) -> Result<(), Error> {
    // Finally erase temp zip archive with zeros.
    tmp_file.with_writer(|tmp_writer| {
        let writer = RefCell::new(tmp_writer);
        overwrite::execute(overwrite::Request {
            buf_capacity,
            writer: &writer,
            passes: 1,
        })
        .map_err(|_| Error::TempCleanup)
    })?;

    tmp_file.secure_dispose()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use std::sync::Arc;

    use core::header::{HashingAlgorithm, HeaderType, HeaderVersion};
    use core::primitives::{Algorithm, Mode};
    use core::protected::Protected;

    use crate::encrypt::tests::PASSWORD;
    use crate::pack;
    use crate::pack::tests::ENCRYPTED_PACKED_BAR_DIR;
    use crate::storage::{IMFile, InMemoryFile, InMemoryStorage, Storage};

    fn pack_bar_directory(
        stor: Arc<InMemoryStorage>,
        output_path: &str,
        header_path: Option<&str>,
    ) {
        stor.add_hello_txt();
        stor.add_bar_foo_folder_with_hidden();

        let file = stor.read_file("bar/").unwrap();
        let mut compress_files = stor.read_dir(&file).unwrap();
        compress_files.sort_by(|a, b| a.path().cmp(b.path()));
        let entries = compress_files
            .into_iter()
            .map(|source| pack::ArchiveSourceEntry {
                archive_path: source.path().to_path_buf(),
                source,
            })
            .collect::<Vec<_>>();

        let output_file = stor.create_file(output_path).unwrap();
        let header_file = header_path.map(|path| stor.create_file(path).unwrap());

        let req = pack::Request {
            entries,
            compression_method: zip::CompressionMethod::Stored,
            writer: output_file.try_writer().unwrap(),
            header_writer: header_file.as_ref().map(|file| file.try_writer().unwrap()),
            raw_key: Protected::new(PASSWORD.to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V5,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
        };

        pack::execute(stor.clone(), req).unwrap();
        stor.flush_file(&output_file).unwrap();
        if let Some(header_file) = header_file {
            stor.flush_file(&header_file).unwrap();
        }
    }

    fn assert_text(stor: &InMemoryStorage, path: &str, expected: &str) {
        let file = stor.files().get(&PathBuf::from(path)).cloned();
        match file {
            Some(IMFile::File(InMemoryFile { buf, .. })) => {
                assert_eq!(buf, expected.as_bytes());
            }
            _ => panic!("missing file: {path}"),
        }
    }

    struct FailingTempArtifact {
        file: RefCell<Cursor<Vec<u8>>>,
    }

    impl TempArtifactLike for FailingTempArtifact {
        fn with_reader<T, E>(
            &self,
            f: impl FnOnce(&mut dyn ReadSeek) -> Result<T, E>,
        ) -> Result<T, E> {
            let mut file = self.file.borrow_mut();
            f(&mut *file)
        }

        fn with_writer<T, E>(
            &self,
            f: impl FnOnce(&mut dyn WriteSeek) -> Result<T, E>,
        ) -> Result<T, E> {
            let mut file = self.file.borrow_mut();
            f(&mut *file)
        }

        fn len(&self) -> Result<usize, Error> {
            Ok(self.file.borrow().get_ref().len())
        }

        fn secure_dispose(self) -> Result<(), Error> {
            Err(Error::TempCleanup)
        }
    }

    #[test]
    fn should_unpack_encrypted_archive_with_embedded_header() {
        let stor = Arc::new(InMemoryStorage::default());
        pack_bar_directory(stor.clone(), "archive.enc", None);

        let archive = stor.read_file("archive.enc").unwrap();
        let req = Request {
            reader: archive.try_reader().unwrap(),
            header_reader: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: PathBuf::from("out"),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        execute(stor.clone(), req).unwrap();

        assert_text(&stor, "out/bar/.hello.txt", "hello");
        assert_text(&stor, "out/bar/world.txt", "world");
        assert_text(&stor, "out/bar/.foo/world.txt", "world");
    }

    #[test]
    fn should_unpack_encrypted_archive_with_detached_header() {
        let stor = Arc::new(InMemoryStorage::default());
        pack_bar_directory(stor.clone(), "archive-detached.enc", Some("archive.hdr"));

        let archive = stor.read_file("archive-detached.enc").unwrap();
        let header = stor.read_file("archive.hdr").unwrap();
        let req = Request {
            reader: archive.try_reader().unwrap(),
            header_reader: Some(header.try_reader().unwrap()),
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: PathBuf::from("out-detached"),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        execute(stor.clone(), req).unwrap();

        assert_text(&stor, "out-detached/bar/.hello.txt", "hello");
        assert_text(&stor, "out-detached/bar/world.txt", "world");
        assert_text(&stor, "out-detached/bar/.foo/world.txt", "world");
    }

    #[test]
    fn should_unpack_legacy_master_generated_archive_fixture() {
        let stor = Arc::new(InMemoryStorage::default());
        let archive = stor.create_file("legacy.enc").unwrap();
        archive
            .try_writer()
            .unwrap()
            .borrow_mut()
            .write_all(&ENCRYPTED_PACKED_BAR_DIR)
            .unwrap();
        stor.flush_file(&archive).unwrap();
        let archive = stor.read_file("legacy.enc").unwrap();

        let req = Request {
            reader: archive.try_reader().unwrap(),
            header_reader: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: PathBuf::from("legacy-out"),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        execute(stor.clone(), req).unwrap();

        assert_text(&stor, "legacy-out/bar/.hello.txt", "hello");
        assert_text(&stor, "legacy-out/bar/world.txt", "world");
        assert_text(&stor, "legacy-out/bar/.foo/world.txt", "world");
    }

    #[test]
    fn unpack_fails_if_temp_artifact_disposal_fails() {
        let stor = Arc::new(InMemoryStorage::default());
        let setup_stor = Arc::new(InMemoryStorage::default());
        pack_bar_directory(setup_stor.clone(), "archive.enc", None);

        let archive = setup_stor.read_file("archive.enc").unwrap();
        let mut archive_buf = Vec::new();
        archive
            .try_reader()
            .unwrap()
            .borrow_mut()
            .read_to_end(&mut archive_buf)
            .unwrap();
        let archive_file = stor.create_file("archive.enc").unwrap();
        archive_file
            .try_writer()
            .unwrap()
            .borrow_mut()
            .write_all(&archive_buf)
            .unwrap();
        stor.flush_file(&archive_file).unwrap();

        let archive = stor.read_file("archive.enc").unwrap();
        let req = Request {
            reader: archive.try_reader().unwrap(),
            header_reader: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            output_dir_path: PathBuf::from("out"),
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: None,
        };

        let result = execute_with_temp_artifact(stor, req, || {
            Ok(FailingTempArtifact {
                file: RefCell::new(Cursor::new(Vec::new())),
            })
        });

        assert!(matches!(result, Err(Error::TempCleanup)));
    }
}

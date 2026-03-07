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

#[derive(Debug)]
pub enum Error {
    WriteData,
    OpenArchive,
    OpenArchivedFile,
    ResetCursorPosition,
    Storage(storage::Error),
    Decrypt(decrypt::Error),
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
        }
    }
}

impl std::error::Error for Error {}

type OnArchiveInfo = Box<dyn FnOnce(usize)>;
type OnZipFileFn = Box<dyn Fn(PathBuf) -> bool>;

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
    // 1. Create temp zip archive.
    let tmp_file = stor.create_temp_file().map_err(Error::Storage)?;

    // 2. Decrypt input file to temp zip archive.
    decrypt::execute(decrypt::Request {
        header_reader: req.header_reader,
        reader: req.reader,
        writer: tmp_file
            .try_writer()
            .expect("We sure that file in write mode"),
        raw_key: req.raw_key,
        on_decrypted_header: req.on_decrypted_header,
    })
    .map_err(Error::Decrypt)?;

    let buf_capacity = stor.file_len(&tmp_file).map_err(Error::Storage)?;

    // 3. Recover files from temp archive.
    {
        let mut reader = tmp_file
            .try_reader()
            .expect("We sure that file in read mode")
            .borrow_mut();

        reader.rewind().map_err(|_| Error::ResetCursorPosition)?;

        let mut archive = zip::ZipArchive::new(&mut *reader).map_err(|_| Error::OpenArchive)?;

        let output_dir = req.output_dir_path.clone();

        // 4. prepare phase
        let entities = (0..archive.len())
            .filter_map(|i| {
                let zip_file = archive.by_index(i).ok()?;
                let mut full_path = output_dir.clone();

                // Prevent zip slip attack
                //
                // Source: https://snyk.io/research/zip-slip-vulnerability
                zip_file.enclosed_name().map(|path| {
                    full_path.push(path);

                    (full_path, i, zip_file.is_dir())
                })
            })
            .filter(|(full_path, ..)| {
                if let Some(on_zip_file) = req.on_zip_file.as_ref() {
                    on_zip_file(full_path.clone())
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        let files_count = entities.len();
        if let Some(on_archive_info) = req.on_archive_info {
            on_archive_info(files_count);
        }

        // 5. create dirs
        #[allow(clippy::needless_collect)]
        let create_dirs_jobs = entities
            .iter()
            .filter(|(_, _, is_dir)| *is_dir)
            .map(|(fp, ..)| fp)
            .chain([&output_dir])
            .map(|full_path| {
                let stor = stor.clone();
                let full_path = full_path.clone();
                std::thread::spawn(move || stor.create_dir_all(full_path).map_err(Error::Storage))
            })
            .collect::<Vec<_>>();

        create_dirs_jobs
            .into_iter()
            .try_for_each(|th| th.join().unwrap())?;

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
            })?;
    }

    // 7. Finally eraze temp zip archive with zeros.
    overwrite::execute(overwrite::Request {
        buf_capacity,
        writer: tmp_file
            .try_writer()
            .expect("We sure that file in write mode"),
        passes: 1,
    })
    .ok();

    stor.remove_file(tmp_file).ok();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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

        let output_file = stor.create_file(output_path).unwrap();
        let header_file = header_path.map(|path| stor.create_file(path).unwrap());

        let req = pack::Request {
            compress_files,
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
}

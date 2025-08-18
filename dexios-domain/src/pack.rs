//! This contains the logic for traversing a given directory, placing all of the files within a zip file, and encrypting the zip file. The temporary zip file is then erased with one pass.
//!
//! This is known as "packing" within Dexios.
//!
//! DISCLAIMER: Encryption with compression is generally not recommended, however here it is fine. As the data is at-rest, and it's assumed you have complete control over the data you're encrypting (e.g. not attacker-controlled), there should be no problems. Feel free to use no compression if you feel otherwise.

use std::cell::RefCell;
use std::io::{BufWriter, Read, Seek, Write};
use std::sync::Arc;

use core::header::{HashingAlgorithm, HeaderType};
use core::primitives::BLOCK_SIZE;
use core::protected::Protected;
use zip::write::FileOptions;

use crate::storage::Storage;

#[derive(Debug)]
pub enum Error {
    CreateArchive,
    AddDirToArchive,
    AddFileToArchive,
    FinishArchive,
    ReadData,
    WriteData,
    Encrypt(crate::encrypt::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateArchive => f.write_str("Unable to create archive"),
            Self::AddDirToArchive => f.write_str("Unable to add directory to archive"),
            Self::AddFileToArchive => f.write_str("Unable to add file to archive"),
            Self::FinishArchive => f.write_str("Unable to finish archive"),
            Self::ReadData => f.write_str("Unable to read data"),
            Self::WriteData => f.write_str("Unable to write data"),
            Self::Encrypt(inner) => write!(f, "Unable to encrypt archive: {inner}"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub writer: &'a RefCell<RW>,
    pub compress_files: Vec<crate::storage::Entry<RW>>,
    pub compression_method: zip::CompressionMethod,
    pub header_writer: Option<&'a RefCell<RW>>,
    pub raw_key: Protected<Vec<u8>>,
    // TODO: don't use external types in logic
    pub header_type: HeaderType,
    pub hashing_algorithm: HashingAlgorithm,
}

pub fn execute<RW>(stor: Arc<impl Storage<RW>>, req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    // 1. Create zip archive.
    let tmp_file = stor.create_temp_file().map_err(|_| Error::CreateArchive)?;
    {
        let mut tmp_writer = tmp_file
            .try_writer()
            .map_err(|_| Error::CreateArchive)?
            .borrow_mut();
        let mut zip_writer = zip::ZipWriter::new(BufWriter::new(&mut *tmp_writer));

        let options = FileOptions::default()
            .compression_method(req.compression_method)
            .large_file(true)
            .unix_permissions(0o755);

        // 2. Add files to the archive.
        req.compress_files.into_iter().try_for_each(|f| {
            let file_path = f.path().to_str().ok_or(Error::ReadData)?;
            if f.is_dir() {
                zip_writer
                    .add_directory(file_path, options)
                    .map_err(|_| Error::AddDirToArchive)?;
            } else {
                zip_writer
                    .start_file(file_path, options)
                    .map_err(|_| Error::AddFileToArchive)?;

                let mut reader = f.try_reader().map_err(|_| Error::ReadData)?.borrow_mut();
                let mut buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();
                loop {
                    let read_count = reader.read(&mut buffer).map_err(|_| Error::ReadData)?;
                    zip_writer
                        .write_all(&buffer[..read_count])
                        .map_err(|_| Error::WriteData)?;
                    if read_count != BLOCK_SIZE {
                        break;
                    }
                }
            }

            Ok(())
        })?;

        // 3. Close archive and switch writer to reader.
        zip_writer.finish().map_err(|_| Error::FinishArchive)?;
    }

    let buf_capacity = stor.file_len(&tmp_file).map_err(|_| Error::FinishArchive)?;

    // 4. Encrypt zip archive
    let encrypt_res = crate::encrypt::execute(crate::encrypt::Request {
        reader: tmp_file.try_reader().map_err(|_| Error::FinishArchive)?,
        writer: req.writer,
        header_writer: req.header_writer,
        raw_key: req.raw_key,
        header_type: req.header_type,
        hashing_algorithm: req.hashing_algorithm,
    })
    .map_err(Error::Encrypt);

    // 5. Finally eraze zip archive with zeros.
    crate::overwrite::execute(crate::overwrite::Request {
        buf_capacity,
        writer: tmp_file.try_writer().map_err(|_| Error::FinishArchive)?,
        passes: 2,
    })
    .ok();

    stor.remove_file(tmp_file).ok();

    encrypt_res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use core::header::{HeaderType, HeaderVersion};
    use core::primitives::{Algorithm, Mode};

    use crate::encrypt::tests::PASSWORD;
    use crate::storage::{InMemoryStorage, Storage};

    const ENCRYPTED_PACKED_BAR_DIR: [u8; 1238] = [
        222, 5, 14, 1, 12, 1, 173, 240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91, 92, 129, 0, 0, 0, 0, 0, 0, 223, 181, 95, 105, 185, 21, 162, 109, 60, 146, 157, 42, 115, 68, 158, 213, 228, 100, 101, 63, 45, 205, 234, 143, 110, 91, 80, 242, 88, 136, 65, 165, 70, 4, 102, 72, 89, 122, 202, 166, 50, 25, 235, 133, 151, 252, 132, 7, 224, 16, 173, 240, 60, 45, 230, 243, 58, 160, 69, 50, 217, 192, 66, 223, 124, 190, 148, 91, 92, 129, 50, 126, 110, 254, 58, 206, 16, 183, 233, 128, 23, 223, 81, 30, 214, 132, 32, 104, 51, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 64, 6, 177, 49, 139, 218, 8, 121, 228, 19, 5, 8, 117, 33, 131, 131, 70, 76, 147, 108, 49, 191, 191, 127, 223, 64, 127, 248, 65, 201, 130, 166, 129, 195, 245, 241, 188, 143, 148, 191, 86, 7, 102, 124, 253, 12, 44, 172, 79, 236, 207, 68, 229, 117, 49, 250, 55, 6, 48, 86, 48, 244, 189, 137, 27, 142, 241, 44, 118, 35, 5, 138, 237, 47, 248, 108, 30, 224, 42, 91, 16, 216, 14, 235, 132, 33, 123, 83, 188, 196, 205, 18, 71, 152, 231, 231, 127, 182, 29, 156, 157, 203, 178, 178, 3, 216, 51, 84, 28, 67, 91, 255, 14, 124, 180, 131, 80, 48, 27, 111, 158, 39, 127, 37, 231, 111, 82, 132, 168, 253, 149, 230, 199, 161, 78, 6, 175, 98, 210, 9, 25, 145, 199, 151, 38, 142, 199, 217, 35, 247, 168, 73, 138, 94, 175, 45, 0, 184, 252, 55, 250, 19, 8, 79, 247, 38, 230, 133, 143, 66, 27, 69, 107, 183, 201, 238, 81, 114, 131, 123, 165, 158, 100, 29, 248, 12, 166, 50, 33, 70, 105, 92, 159, 60, 63, 31, 5, 119, 237, 139, 105, 153, 217, 119, 120, 66, 252, 18, 136, 252, 159, 3, 91, 154, 224, 242, 67, 250, 8, 191, 116, 37, 78, 126, 67, 93, 234, 5, 15, 138, 251, 119, 65, 89, 234, 83, 255, 173, 78, 9, 221, 29, 183, 161, 18, 138, 228, 195, 95, 64, 24, 49, 236, 165, 29, 82, 186, 33, 153, 78, 74, 1, 59, 21, 198, 222, 202, 186, 1, 104, 12, 161, 233, 243, 75, 245, 100, 12, 109, 109, 2, 136, 140, 9, 100, 162, 17, 154, 208, 241, 177, 80, 135, 121, 200, 76, 196, 20, 117, 31, 210, 97, 0, 160, 6, 214, 226, 122, 59, 26, 53, 62, 80, 187, 9, 225, 123, 109, 7, 127, 110, 19, 121, 45, 35, 48, 127, 94, 41, 23, 207, 183, 237, 160, 192, 158, 223, 99, 116, 245, 161, 147, 168, 60, 71, 83, 237, 235, 98, 22, 15, 177, 134, 234, 233, 118, 241, 206, 88, 245, 75, 172, 221, 246, 191, 138, 42, 134, 176, 191, 14, 74, 113, 180, 207, 83, 93, 119, 53, 161, 120, 152, 190, 205, 64, 167, 17, 30, 217, 212, 85, 148, 247, 235, 104, 232, 114, 61, 36, 60, 157, 60, 216, 78, 215, 134, 255, 7, 46, 191, 119, 60, 168, 202, 24, 239, 147, 82, 143, 31, 207, 178, 98, 180, 243, 242, 222, 129, 88, 34, 31, 117, 254, 16, 111, 108, 22, 18, 212, 122, 89, 94, 14, 138, 6, 237, 157, 223, 149, 250, 55, 30, 221, 69, 1, 215, 170, 76, 149, 163, 241, 212, 217, 131, 179, 34, 240, 124, 224, 192, 105, 207, 191, 172, 211, 100, 169, 146, 202, 241, 29, 0, 125, 255, 130, 112, 171, 253, 22, 39, 56, 175, 188, 62, 158, 202, 194, 227, 218, 5, 202, 25, 238, 242, 81, 208, 57, 146, 57, 147, 151, 153, 112, 215, 255, 199, 163, 138, 114, 64, 179, 80, 78, 189, 93, 227, 37, 247, 24, 127, 84, 231, 85, 82, 44, 243, 241, 70, 73, 178, 228, 31, 229, 105, 144, 10, 17, 124, 3, 46, 67, 196, 116, 1, 234, 241, 0, 236, 97, 64, 129, 172, 19, 68, 179, 222, 218, 22, 148, 73, 198, 5, 210, 18, 201, 78, 114, 248, 228, 195, 217, 161, 143, 164, 98, 42, 120, 178, 223, 130, 172, 28, 76, 157, 85, 119, 72, 10, 252, 243, 202, 40, 216, 0, 10, 9, 100, 125, 64, 165, 252, 179, 141, 138, 202, 202, 138, 101, 144, 175, 255, 147, 140, 110, 189, 21, 122, 57, 11, 120, 113, 203, 188, 73, 225, 95, 191, 244, 128, 170, 128, 98, 206, 24, 141, 126, 81, 222, 74, 87, 225, 178, 83, 138, 105, 239, 23, 46, 135, 223, 25, 201, 159, 10, 95, 29, 67, 76, 56, 165, 162, 190, 193, 226, 248, 226, 79, 190, 190, 36, 75, 202, 151, 245, 53, 161, 47, 37, 229, 204, 138, 63, 35, 88, 87, 84, 199, 40, 113, 140, 68, 174, 3, 199, 156, 177, 217, 235, 212, 155, 143, 237, 103, 227, 169, 255, 153, 112, 51, 56, 117, 221, 216, 117, 158, 89, 221, 67, 47, 182, 99, 185, 226, 237, 190, 114, 216, 237, 93, 245, 153, 19, 225, 7, 221, 187, 185, 20, 74, 146, 101, 196, 169, 13, 137, 138, 175, 128, 102, 79, 62, 0, 229, 197, 54, 99, 26, 231, 98, 88, 22, 226, 77, 56, 202, 19, 220, 127, 122, 174, 117, 196, 130, 28, 156, 40, 132, 23, 59, 194, 139, 172, 67, 41, 175, 244, 10, 45, 21, 47, 242, 104, 103, 92, 233, 97, 233, 148, 197, 106, 101, 160, 144, 69, 51, 198, 17, 13, 126, 195, 149
    ];

    #[test]
    fn should_pack_bar_directory() {
        let stor = Arc::new(InMemoryStorage::default());
        stor.add_hello_txt();
        stor.add_bar_foo_folder_with_hidden();

        let file = stor.read_file("bar/").unwrap();
        let mut compress_files = stor.read_dir(&file).unwrap();
        compress_files.sort_by(|a, b| a.path().cmp(b.path()));

        let output_file = stor.create_file("bar.zip.enc").unwrap();

        let req = Request {
            compress_files,
            compression_method: zip::CompressionMethod::Zstd,
            writer: output_file.try_writer().unwrap(),
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            header_type: HeaderType {
                version: HeaderVersion::V5,
                algorithm: Algorithm::XChaCha20Poly1305,
                mode: Mode::StreamMode,
            },
            hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
        };

        match execute(stor, req) {
            Ok(()) => {
                let reader = &mut *output_file.try_writer().unwrap().borrow_mut();
                reader.rewind().unwrap();

                let mut content = vec![];
                reader.read_to_end(&mut content).unwrap();

                assert_eq!(content, ENCRYPTED_PACKED_BAR_DIR.to_vec());
            }
            _ => unreachable!(),
        }
    }
}

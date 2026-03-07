use std::cell::RefCell;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::{HashingAlgorithm, HeaderType, HeaderVersion};
use core::primitives::{Algorithm, Mode};
use core::protected::Protected;
use dexios_domain::encrypt;
use dexios_domain::storage::{FileStorage, Storage};
use dexios_domain::unpack;
use zip::write::SimpleFileOptions;

const PASSWORD: &[u8; 8] = b"12345678";

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("target/test-artifacts/{prefix}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).ok();
    }
}

fn write_zip_without_directory_entries(path: &Path) {
    let file = File::create(path).unwrap();
    let mut zip_writer = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755);

    zip_writer
        .start_file("nested/inner/file.txt", options)
        .unwrap();
    zip_writer.write_all(b"nested hello").unwrap();
    zip_writer.finish().unwrap();
}

fn encrypt_archive(input_path: &Path, output_path: &Path) {
    let input = RefCell::new(File::open(input_path).unwrap());
    let output = RefCell::new(File::create(output_path).unwrap());

    encrypt::execute(encrypt::Request {
        reader: &input,
        writer: &output,
        header_writer: None,
        raw_key: Protected::new(PASSWORD.to_vec()),
        header_type: HeaderType {
            version: HeaderVersion::V5,
            algorithm: Algorithm::XChaCha20Poly1305,
            mode: Mode::StreamMode,
        },
        hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
    })
    .unwrap();

    output.borrow_mut().flush().unwrap();
}

#[test]
fn should_unpack_archive_without_explicit_directory_entries() {
    let test_dir = TestDir::new("unpack-no-dirs");
    let plain_zip = test_dir.path.join("plain-no-dirs.zip");
    let encrypted_archive = test_dir.path.join("archive.enc");
    let output_dir = test_dir.path.join("out");

    write_zip_without_directory_entries(&plain_zip);
    encrypt_archive(&plain_zip, &encrypted_archive);

    let stor = Arc::new(FileStorage);
    let archive = stor.read_file(&encrypted_archive).unwrap();
    let req = unpack::Request {
        reader: archive.try_reader().unwrap(),
        header_reader: None,
        raw_key: Protected::new(PASSWORD.to_vec()),
        output_dir_path: output_dir.clone(),
        on_decrypted_header: None,
        on_archive_info: None,
        on_zip_file: None,
    };

    unpack::execute(stor, req).unwrap();

    let restored = fs::read_to_string(output_dir.join("nested/inner/file.txt")).unwrap();
    assert_eq!(restored, "nested hello");
}

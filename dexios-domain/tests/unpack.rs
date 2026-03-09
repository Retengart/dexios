use std::cell::RefCell;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use core::header::{HashingAlgorithm, HeaderType, HeaderVersion};
use core::primitives::{Algorithm, Mode};
use core::protected::Protected;
use dexios_domain::encrypt;
use dexios_domain::storage::{FileStorage, Storage};
use dexios_domain::unpack;
use zip::write::SimpleFileOptions;

const PASSWORD: &[u8; 8] = b"12345678";

struct TestDir {
    dir: tempfile::TempDir,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[test]
fn test_dir_uses_system_temp_root() {
    let dir = TestDir::new("unpack-temp-root");

    assert!(dir.path().starts_with(std::env::temp_dir()));
    assert!(!dir.path().starts_with(Path::new("target/test-artifacts")));
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

fn write_zip_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut zip_writer = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755);

    for (name, body) in entries {
        zip_writer.start_file(*name, options).unwrap();
        zip_writer.write_all(body).unwrap();
    }

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
    let plain_zip = test_dir.path().join("plain-no-dirs.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

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

#[cfg(unix)]
fn symlink_dir(src: &Path, dst: &Path) {
    std::os::unix::fs::symlink(src, dst).unwrap();
}

#[cfg(windows)]
fn symlink_dir(src: &Path, dst: &Path) {
    std::os::windows::fs::symlink_dir(src, dst).unwrap();
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_rejects_symlinked_intermediate_output_paths() {
    let test_dir = TestDir::new("unpack-symlink-escape");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    symlink_dir(&outside_dir, &output_dir.join("payload"));

    write_zip_with_entries(&plain_zip, &[("payload/secret.txt", b"top secret")]);
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

    let result = unpack::execute(stor, req);

    assert!(
        matches!(
            result,
            Err(unpack::Error::UnsafeOutputPath(ref path))
                if path.ends_with("payload/secret.txt")
        ),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_rejects_symlinked_output_directory_prefix() {
    let test_dir = TestDir::new("unpack-symlink-output-prefix");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_prefix = test_dir.path().join("out-link");
    let output_dir = output_prefix.join("nested");

    fs::create_dir_all(&outside_dir).unwrap();
    symlink_dir(&outside_dir, &output_prefix);

    write_zip_with_entries(&plain_zip, &[("secret.txt", b"top secret")]);
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

    let result = unpack::execute(stor, req);

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("nested/secret.txt").exists());
}

#[test]
fn unpack_rejects_duplicate_targets_after_path_normalization() {
    let test_dir = TestDir::new("unpack-duplicate-targets");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_zip_with_entries(
        &plain_zip,
        &[
            ("payload/../collision.txt", b"first"),
            ("collision.txt", b"second"),
        ],
    );
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

    let result = unpack::execute(stor, req);

    assert!(
        matches!(
            result,
            Err(unpack::Error::DuplicateOutputPath(ref path))
                if path == Path::new("collision.txt")
        ),
        "expected duplicate output path error, got {result:?}"
    );
    assert!(!output_dir.join("collision.txt").exists());
}

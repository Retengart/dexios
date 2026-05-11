use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::encrypt;
use dexios_domain::storage::{FileStorage, Storage};
use dexios_domain::unpack;
use zip::write::SimpleFileOptions;

const PASSWORD: &[u8; 8] = b"12345678";

struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Self { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[test]
fn test_dir_uses_system_temp_root() {
    let dir = TestDir::new("unpack-temp-root");

    let temp_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(dir.path().starts_with(&temp_root));
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
    let intent = encrypt::EncryptIntent::new(
        input_path,
        output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        Protected::new(PASSWORD.to_vec()),
        Kdf::Blake3Balloon,
    )
    .unwrap();
    encrypt::execute(intent).unwrap();
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

#[test]
fn unpack_preserves_existing_file_when_later_extraction_fails() {
    let test_dir = TestDir::new("unpack-staged-preserve");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");
    let blocked_target = output_dir.join("blocked");

    fs::create_dir_all(&blocked_target).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_zip_with_entries(
        &plain_zip,
        &[
            ("existing.txt", b"candidate replacement"),
            ("blocked", b"cannot replace directory"),
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
            Err(unpack::Error::UnsafeOutputPath(ref path)) if path == &blocked_target
        ),
        "expected unsafe output path error, got {result:?}"
    );
    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert!(blocked_target.is_dir());
}

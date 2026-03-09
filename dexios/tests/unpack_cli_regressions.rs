use std::cell::RefCell;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::{HashingAlgorithm, HeaderType, HeaderVersion};
use core::primitives::{Algorithm, Mode};
use core::protected::Protected;
use domain::encrypt;
use zip::write::SimpleFileOptions;

const PASSWORD: &str = "12345678";
static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let seq = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dexios-{prefix}-{}-{seq}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn test_dir_path_is_canonical() {
    let test_dir = TestDir::new("unpack-cli-canonical");

    assert_eq!(&fs::canonicalize(test_dir.path()).unwrap(), test_dir.path());
}

fn run_unpack_with_args(input: &Path, output: &Path, extra_args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command.env("DEXIOS_KEY", PASSWORD).arg("unpack").arg("-f");

    for arg in extra_args {
        command.arg(arg);
    }

    command.arg(input).arg(output).output().unwrap()
}

fn run_unpack(input: &Path, output: &Path) -> std::process::Output {
    run_unpack_with_args(input, output, &[])
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
        raw_key: Protected::new(PASSWORD.as_bytes().to_vec()),
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
fn unpack_cli_rejects_symlinked_output_component() {
    let test_dir = TestDir::new("unpack-cli-symlink");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    symlink_dir(&outside_dir, &output_dir.join("payload"));

    write_zip_with_entries(&plain_zip, &[("payload/secret.txt", b"top secret")]);
    encrypt_archive(&plain_zip, &encrypted_archive);

    let output = run_unpack(&encrypted_archive, &output_dir);

    assert!(
        !output.status.success(),
        "unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Unsafe output path"),
        "stderr did not mention unsafe output path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!outside_dir.join("secret.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_cli_rejects_symlinked_output_prefix() {
    let test_dir = TestDir::new("unpack-cli-output-prefix");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_prefix = test_dir.path().join("out-link");
    let output_dir = output_prefix.join("nested");

    fs::create_dir_all(&outside_dir).unwrap();
    symlink_dir(&outside_dir, &output_prefix);

    write_zip_with_entries(&plain_zip, &[("secret.txt", b"top secret")]);
    encrypt_archive(&plain_zip, &encrypted_archive);

    let output = run_unpack(&encrypted_archive, &output_dir);

    assert!(
        !output.status.success(),
        "unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Unsafe output path"),
        "stderr did not mention unsafe output path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!outside_dir.join("nested/secret.txt").exists());
}

#[test]
fn unpack_cli_rejects_duplicate_normalized_targets() {
    let test_dir = TestDir::new("unpack-cli-duplicate");
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

    let output = run_unpack(&encrypted_archive, &output_dir);

    assert!(
        !output.status.success(),
        "unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Duplicate output path"),
        "stderr did not mention duplicate output path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_dir.join("collision.txt").exists());
}

#[test]
fn unpack_cli_erase_removes_archive_after_success() {
    let test_dir = TestDir::new("unpack-cli-erase");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_zip_with_entries(&plain_zip, &[("payload/file.txt", b"top secret")]);
    encrypt_archive(&plain_zip, &encrypted_archive);

    let output = run_unpack_with_args(&encrypted_archive, &output_dir, &["--erase"]);

    assert!(
        output.status.success(),
        "unpack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!encrypted_archive.exists());
    assert_eq!(
        fs::read_to_string(output_dir.join("payload/file.txt")).unwrap(),
        "top secret"
    );
}

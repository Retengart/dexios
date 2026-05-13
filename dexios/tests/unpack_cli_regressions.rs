use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::HEADER_LEN;
use core::kdf::Kdf;
use core::primitives::BLOCK_SIZE;
use core::protected::Protected;
use domain::encrypt;
use zip::write::SimpleFileOptions;

const PASSWORD: &str = "12345678";
const STREAM_TAG_LEN: usize = 16;
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
    let intent = encrypt::EncryptIntent::new(
        input_path,
        output_path,
        domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        Protected::new(PASSWORD.as_bytes().to_vec()),
        Kdf::Blake3Balloon,
    )
    .unwrap();
    encrypt::execute(intent).unwrap();
}

fn tamper_final_stream_chunk(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let final_offset = HEADER_LEN + (bytes[HEADER_LEN..].len().saturating_sub(STREAM_TAG_LEN));
    bytes[final_offset] ^= 0x40;
    fs::write(path, bytes).unwrap();
}

fn truncate_stream(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes.pop().expect("encrypted archive has payload bytes");
    fs::write(path, bytes).unwrap();
}

#[cfg(unix)]
fn symlink_dir(src: &Path, dst: &Path) {
    std::os::unix::fs::symlink(src, dst).unwrap();
}

#[cfg(windows)]
fn symlink_dir(src: &Path, dst: &Path) {
    std::os::windows::fs::symlink_dir(src, dst).unwrap();
}

#[test]
fn unpack_cli_corrupted_archive_never_extracts_outputs() {
    let test_dir = TestDir::new("unpack-cli-corrupted-stream");

    for (label, corrupt) in [
        ("final-tamper", tamper_final_stream_chunk as fn(&Path)),
        ("one-byte-truncation", truncate_stream as fn(&Path)),
    ] {
        let plain_zip = test_dir.path().join(format!("{label}.zip"));
        let encrypted_archive = test_dir.path().join(format!("{label}.enc"));
        let output_dir = test_dir.path().join(format!("{label}-out"));
        let payload = vec![0xA5; BLOCK_SIZE + 37];

        write_zip_with_entries(&plain_zip, &[("safe.txt", payload.as_slice())]);
        encrypt_archive(&plain_zip, &encrypted_archive);
        corrupt(&encrypted_archive);

        let output = run_unpack(&encrypted_archive, &output_dir);

        assert!(
            !output.status.success(),
            "{label}: corrupted CLI unpack unexpectedly succeeded: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Authentication failed") || stderr.contains("Malformed archive data"),
            "{label}: stderr should stay terse and typed: {stderr}"
        );
        assert!(
            !output_dir.join("safe.txt").exists(),
            "{label}: corrupted archive must not extract safe entries"
        );
    }
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
fn unpack_cli_rejects_file_prefix_collision() {
    let test_dir = TestDir::new("unpack-cli-prefix-collision");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_zip_with_entries(&plain_zip, &[("a", b"file"), ("a/b", b"child")]);
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
    assert!(!output_dir.join("a").exists());
    assert!(!output_dir.join("a/b").exists());
}

#[test]
fn unpack_cli_delete_input_removes_archive_after_success() {
    let test_dir = TestDir::new("unpack-cli-delete-input");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_zip_with_entries(&plain_zip, &[("payload/file.txt", b"top secret")]);
    encrypt_archive(&plain_zip, &encrypted_archive);

    let output = run_unpack_with_args(&encrypted_archive, &output_dir, &["--delete-input"]);

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

#[test]
fn unpack_cli_delete_input_rejects_archive_entry_that_aliases_input() {
    let test_dir = TestDir::new("unpack-cli-delete-input-alias");
    let plain_zip = test_dir.path().join("plain.zip");
    let encrypted_archive = test_dir.path().join("archive.enc");

    write_zip_with_entries(&plain_zip, &[("archive.enc", b"plaintext replacement")]);
    encrypt_archive(&plain_zip, &encrypted_archive);
    let original_archive = fs::read(&encrypted_archive).unwrap();

    let output = run_unpack_with_args(&encrypted_archive, test_dir.path(), &["--delete-input"]);

    assert!(
        !output.status.success(),
        "unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Unsafe archive path"),
        "stderr did not mention unsafe archive path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&encrypted_archive).unwrap(), original_archive);
}

#[test]
fn unpack_delete_input_waits_for_extraction_commit_receipt() {
    let test_dir = TestDir::new("unpack-cli-delete-waits");
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

    let output = run_unpack_with_args(&encrypted_archive, &output_dir, &["--delete-input"]);

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
    assert!(encrypted_archive.exists());
    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert!(blocked_target.is_dir());
}

#[test]
fn unpack_help_no_longer_mentions_secure_erase() {
    let test_dir = TestDir::new("unpack-help-surface");

    let output = run_unpack_with_args(
        test_dir.path().join("missing.enc").as_path(),
        test_dir.path().join("out").as_path(),
        &["--help"],
    );

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("--erase"));
    assert!(stdout.contains("--delete-input"));
}

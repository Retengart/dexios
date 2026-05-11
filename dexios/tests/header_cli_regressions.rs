use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::HEADER_LEN;

const PASSWORD: &str = "correct-password";
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

fn run_cli(current_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", PASSWORD)
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: &std::process::Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &std::process::Output, label: &str) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn encrypt_fixture(test_dir: &TestDir, name: &str, plaintext: &[u8]) -> PathBuf {
    let plain = test_dir.path().join(format!("{name}.txt"));
    let encrypted = test_dir.path().join(format!("{name}.enc"));
    fs::write(&plain, plaintext).unwrap();

    let output = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "--force",
            plain.file_name().unwrap().to_str().unwrap(),
            encrypted.file_name().unwrap().to_str().unwrap(),
        ],
    );
    assert_success(&output, "encrypt fixture");

    encrypted
}

fn dump_header(test_dir: &TestDir, encrypted_name: &str, header_name: &str) -> PathBuf {
    let output = run_cli(
        test_dir.path(),
        &["header", "dump", encrypted_name, header_name],
    );
    assert_success(&output, "header dump fixture");
    test_dir.path().join(header_name)
}

#[test]
fn header_dump_rejects_header_only_input_and_writes_exact_detached_header() {
    let test_dir = TestDir::new("header-dump-exact");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");

    let dump_output = run_cli(
        test_dir.path(),
        &["header", "dump", "plain.enc", "plain.hdr"],
    );
    assert_success(&dump_output, "header dump");

    let dumped = fs::read(test_dir.path().join("plain.hdr")).unwrap();
    assert_eq!(dumped.len(), HEADER_LEN);

    let header_only_output = run_cli(
        test_dir.path(),
        &["header", "dump", "plain.hdr", "second.hdr"],
    );
    assert_failure(&header_only_output, "header dump from header-only input");
    assert!(!test_dir.path().join("second.hdr").exists());
    assert!(fs::read(encrypted).unwrap().len() > HEADER_LEN);
}

#[test]
fn header_restore_rejects_inexact_headers_and_invalid_targets_without_mutation() {
    let test_dir = TestDir::new("header-restore-exact");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");
    let header = dump_header(&test_dir, "plain.enc", "plain.hdr");
    let header_bytes = fs::read(&header).unwrap();
    let original = fs::read(&encrypted).unwrap();
    let payload = original[HEADER_LEN..].to_vec();

    let short_header = test_dir.path().join("short.hdr");
    fs::write(&short_header, &header_bytes[..HEADER_LEN - 1]).unwrap();
    let stripped_for_short = test_dir.path().join("stripped-short.enc");
    let mut stripped_bytes = vec![0u8; HEADER_LEN];
    stripped_bytes.extend_from_slice(&payload);
    fs::write(&stripped_for_short, &stripped_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &["header", "restore", "short.hdr", "stripped-short.enc"],
    );
    assert_failure(&output, "restore with short detached header");
    assert_eq!(fs::read(&stripped_for_short).unwrap(), stripped_bytes);

    let trailing_header = test_dir.path().join("trailing.hdr");
    let mut trailing = header_bytes.clone();
    trailing.push(0xAA);
    fs::write(&trailing_header, trailing).unwrap();
    let stripped_for_trailing = test_dir.path().join("stripped-trailing.enc");
    fs::write(&stripped_for_trailing, &stripped_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &["header", "restore", "trailing.hdr", "stripped-trailing.enc"],
    );
    assert_failure(&output, "restore with trailing detached header");
    assert_eq!(fs::read(&stripped_for_trailing).unwrap(), stripped_bytes);

    let short_target = test_dir.path().join("short-target.enc");
    let short_target_bytes = vec![0u8; HEADER_LEN - 1];
    fs::write(&short_target, &short_target_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &["header", "restore", "plain.hdr", "short-target.enc"],
    );
    assert_failure(&output, "restore into short target");
    assert_eq!(fs::read(&short_target).unwrap(), short_target_bytes);

    let header_only_target = test_dir.path().join("header-only-target.enc");
    let header_only_bytes = vec![0u8; HEADER_LEN];
    fs::write(&header_only_target, &header_only_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &["header", "restore", "plain.hdr", "header-only-target.enc"],
    );
    assert_failure(&output, "restore into header-only target");
    assert_eq!(fs::read(&header_only_target).unwrap(), header_only_bytes);

    let non_zero_target = test_dir.path().join("non-zero-target.enc");
    fs::write(&non_zero_target, &original).unwrap();
    let output = run_cli(
        test_dir.path(),
        &["header", "restore", "plain.hdr", "non-zero-target.enc"],
    );
    assert_failure(&output, "restore into non-stripped target");
    assert_eq!(fs::read(&non_zero_target).unwrap(), original);
}

#[test]
fn header_strip_rejects_header_only_input_and_preserves_payload_bytes() {
    let test_dir = TestDir::new("header-strip-exact");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");
    let original = fs::read(&encrypted).unwrap();
    let payload = original[HEADER_LEN..].to_vec();

    let output = run_cli(test_dir.path(), &["header", "strip", "plain.enc"]);
    assert_success(&output, "header strip");

    let stripped = fs::read(&encrypted).unwrap();
    assert_eq!(stripped.len(), original.len());
    assert_eq!(&stripped[..HEADER_LEN], vec![0u8; HEADER_LEN].as_slice());
    assert_eq!(&stripped[HEADER_LEN..], payload.as_slice());

    let header_only = test_dir.path().join("header-only.enc");
    fs::write(&header_only, &original[..HEADER_LEN]).unwrap();
    let header_only_before = fs::read(&header_only).unwrap();
    let output = run_cli(test_dir.path(), &["header", "strip", "header-only.enc"]);
    assert_failure(&output, "header strip header-only input");
    assert_eq!(fs::read(header_only).unwrap(), header_only_before);
}

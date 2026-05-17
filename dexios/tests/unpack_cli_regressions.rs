use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::cipher::wrap_v1_master_key;
use core::header::common::{HEADER_LEN, KeyslotNonce, PayloadNonce, Salt as HeaderSalt};
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use core::payload::{
    ArchiveBodyFrame, ArchiveBodyFrameHeader, ArchiveManifest, ManifestEntry, ManifestFirstPayload,
};
use core::primitives::{BLOCK_SIZE, MasterKey, WrappingKey};
use core::protected::Protected;
use core::stream::V1PayloadStream;

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

fn write_manifest_archive_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let (header, encrypted_payload) = encrypted_manifest_archive_bytes(entries);
    let mut bytes = header;
    bytes.extend_from_slice(&encrypted_payload);
    fs::write(path, bytes).unwrap();
}

fn write_malformed_manifest_body_length_archive(path: &Path) {
    let manifest =
        ArchiveManifest::new(vec![ManifestEntry::file(b"safe.txt".to_vec(), 5).unwrap()]).unwrap();
    let mut payload = Vec::new();
    manifest.write_to(&mut payload).unwrap();
    ArchiveBodyFrameHeader::new(0, 4)
        .unwrap()
        .write_to(&mut payload)
        .unwrap();
    payload.extend_from_slice(b"body");
    write_encrypted_manifest_payload(path, payload);
}

fn encrypted_manifest_archive_bytes(entries: &[(&str, &[u8])]) -> (Vec<u8>, Vec<u8>) {
    let mut manifest_entries = Vec::with_capacity(entries.len());
    let mut body_frames = Vec::new();
    for (index, (path, body)) in entries.iter().enumerate() {
        let normalized_path = path.trim_end_matches('/').as_bytes().to_vec();
        if path.ends_with('/') {
            manifest_entries.push(ManifestEntry::directory(normalized_path).unwrap());
        } else {
            manifest_entries.push(
                ManifestEntry::file(
                    normalized_path,
                    u64::try_from(body.len()).expect("test body length fits in u64"),
                )
                .unwrap(),
            );
            body_frames.push(
                ArchiveBodyFrame::new(
                    u32::try_from(index).expect("test entry index fits in u32"),
                    body.to_vec(),
                )
                .unwrap(),
            );
        }
    }

    let payload =
        ManifestFirstPayload::new(ArchiveManifest::new(manifest_entries).unwrap(), body_frames)
            .unwrap()
            .serialize()
            .unwrap();
    encrypted_manifest_payload_bytes(payload)
}

fn write_encrypted_manifest_payload(path: &Path, payload: Vec<u8>) {
    let (header, encrypted_payload) = encrypted_manifest_payload_bytes(payload);
    let mut bytes = header;
    bytes.extend_from_slice(&encrypted_payload);
    fs::write(path, bytes).unwrap();
}

fn encrypted_manifest_payload_bytes(payload: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let (header, master_key) = manifest_archive_header_and_master_key();
    let mut encrypted_payload = Vec::new();
    V1PayloadStream::encrypt_file(
        master_key,
        &header,
        &mut Cursor::new(payload),
        &mut encrypted_payload,
    )
    .unwrap();

    (header.serialize().unwrap(), encrypted_payload)
}

fn manifest_archive_header_and_master_key() -> (V1Header, MasterKey) {
    let raw_key = Protected::new(PASSWORD.as_bytes().to_vec());
    let header_salt = HeaderSalt::new([17u8; 16]);
    let kdf_salt = header_salt.to_kdf_salt();
    let wrapping_key = Kdf::Blake3Balloon.derive(&raw_key, &kdf_salt).unwrap();
    let master_key = MasterKey::new([31u8; 32]);
    let keyslot_nonce = KeyslotNonce::new([13u8; 24]);
    let payload_nonce = PayloadNonce::new([7u8; 20]);
    let placeholder_keyslot =
        V1Keyslot::new(Kdf::Blake3Balloon, [0u8; 48], keyslot_nonce, header_salt);
    let placeholder_header =
        V1Header::new_manifest_archive(payload_nonce, V1Keyslots::single(placeholder_keyslot))
            .unwrap();
    let slot_wrapping_aad = placeholder_header
        .slot_wrapping_aad(0, &placeholder_keyslot)
        .unwrap();
    let encrypted_master_key = wrap_v1_master_key(
        WrappingKey::from(wrapping_key),
        &master_key,
        &keyslot_nonce,
        &slot_wrapping_aad,
    )
    .unwrap();
    let keyslot = V1Keyslot::new(
        Kdf::Blake3Balloon,
        *encrypted_master_key.as_bytes(),
        keyslot_nonce,
        header_salt,
    );
    let header =
        V1Header::new_manifest_archive(payload_nonce, V1Keyslots::single(keyslot)).unwrap();
    (header, master_key)
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
        let encrypted_archive = test_dir.path().join(format!("{label}.enc"));
        let output_dir = test_dir.path().join(format!("{label}-out"));
        let payload = vec![0xA5; BLOCK_SIZE + 37];

        write_manifest_archive_with_entries(
            &encrypted_archive,
            &[("safe.txt", payload.as_slice())],
        );
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

#[test]
fn unpack_cli_malformed_manifest_body_frame_never_extracts_outputs() {
    let test_dir = TestDir::new("unpack-cli-malformed-body-frame");
    let encrypted_archive = test_dir.path().join("malformed.enc");
    let output_dir = test_dir.path().join("out");

    write_malformed_manifest_body_length_archive(&encrypted_archive);

    let output = run_unpack(&encrypted_archive, &output_dir);

    assert!(
        !output.status.success(),
        "malformed manifest CLI unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Malformed archive data"),
        "stderr should stay terse and typed: {stderr}"
    );
    assert!(!output_dir.join("safe.txt").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn unpack_cli_rejects_symlinked_output_component() {
    let test_dir = TestDir::new("unpack-cli-symlink");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    symlink_dir(&outside_dir, &output_dir.join("payload"));

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("payload/secret.txt", b"top secret")],
    );

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
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_prefix = test_dir.path().join("out-link");
    let output_dir = output_prefix.join("nested");

    fs::create_dir_all(&outside_dir).unwrap();
    symlink_dir(&outside_dir, &output_prefix);

    write_manifest_archive_with_entries(&encrypted_archive, &[("secret.txt", b"top secret")]);

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
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("collision.txt", b"first"), ("collision.txt", b"second")],
    );

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
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(&encrypted_archive, &[("a", b"file"), ("a/b", b"child")]);

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
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(&encrypted_archive, &[("payload/file.txt", b"top secret")]);

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
    let encrypted_archive = test_dir.path().join("archive.enc");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("archive.enc", b"plaintext replacement")],
    );
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
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");
    let blocked_target = output_dir.join("blocked");

    fs::create_dir_all(&blocked_target).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("existing.txt", b"candidate replacement"),
            ("blocked", b"cannot replace directory"),
        ],
    );

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

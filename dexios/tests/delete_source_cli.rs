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
use core::payload::{ArchiveBodyFrame, ArchiveManifest, ManifestEntry, ManifestFirstPayload};
use core::primitives::{BLOCK_SIZE, MasterKey, WrappingKey};
use core::protected::Protected;
use core::stream::V1PayloadStream;

const PASSWORD: &str = "12345678";
const DEXIOS_SUBCOMMANDS_RS: &str = include_str!("../src/subcommands.rs");
const ENCRYPT_SUBCOMMAND_SOURCE: &str = include_str!("../src/subcommands/encrypt.rs");
const PACK_SUBCOMMAND_SOURCE: &str = include_str!("../src/subcommands/pack.rs");
const DETACHED_PUBLICATION_TEST_SOURCE: &str =
    include_str!("../../dexios-domain/tests/detached_publication.rs");
const STREAM_TAG_LEN: usize = 16;
const TRUNCATED_CANONICAL_V1_PREFIX: &[u8] = b"DXIO\x00\x01CV1\x00";
const RETIRED_CURRENT_V1_PREFIX: &[u8] = b"DXIO\x00\x01\x01\x00\x07\x07";
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
        .args(args);
    command.output().unwrap()
}

fn write_manifest_archive_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let (header, encrypted_payload) = encrypted_manifest_archive_bytes(entries);
    let mut bytes = header;
    bytes.extend_from_slice(&encrypted_payload);
    fs::write(path, bytes).unwrap();
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
    let wrapping_key = Kdf::Argon2id.derive(&raw_key, &kdf_salt).unwrap();
    let master_key = MasterKey::new([31u8; 32]);
    let keyslot_nonce = KeyslotNonce::new([13u8; 24]);
    let payload_nonce = PayloadNonce::new([7u8; 20]);
    let placeholder_keyslot =
        V1Keyslot::new(Kdf::Argon2id, [0u8; 48], keyslot_nonce, header_salt);
    let placeholder_header =
        V1Header::new_manifest_archive(payload_nonce, V1Keyslots::single(placeholder_keyslot))
            .unwrap();
    let slot_wrapping_aad = placeholder_header
        .slot_wrapping_aad_for_physical_slot(
            core::header::v1::V1KeyslotIndex::try_from_physical_index(0).expect("slot zero index"),
        )
        .unwrap();
    let encrypted_master_key = wrap_v1_master_key(
        WrappingKey::from(wrapping_key),
        &master_key,
        &keyslot_nonce,
        &slot_wrapping_aad,
    )
    .unwrap();
    let keyslot = V1Keyslot::new(
        Kdf::Argon2id,
        *encrypted_master_key.as_bytes(),
        keyslot_nonce,
        header_salt,
    );
    let header =
        V1Header::new_manifest_archive(payload_nonce, V1Keyslots::single(keyslot)).unwrap();
    (header, master_key)
}

fn multichunk_plaintext() -> Vec<u8> {
    (0..(BLOCK_SIZE * 3 + 37))
        .map(|index| (index % 251) as u8)
        .collect()
}

fn corrupt_final_chunk(bytes: &mut [u8]) {
    let final_offset = HEADER_LEN + (3 * (BLOCK_SIZE + STREAM_TAG_LEN));
    bytes[final_offset] ^= 0x40;
}

fn assert_source_contains(source_name: &str, source: &str, needle: &str) {
    assert!(
        source.contains(needle),
        "{source_name} must contain {needle:?}"
    );
}

#[test]
fn encrypt_delete_input_removes_plaintext_after_success() {
    let test_dir = TestDir::new("delete-input-encrypt");
    let input = test_dir.path().join("plain.txt");
    let output = test_dir.path().join("plain.enc");
    fs::write(&input, b"top secret").unwrap();

    let output_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            "--delete-input",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );

    assert!(
        output_cmd.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_cmd.stdout),
        String::from_utf8_lossy(&output_cmd.stderr)
    );
    assert!(!input.exists());
    assert!(output.exists());
}

#[test]
fn encrypt_delete_input_waits_for_hash_success() {
    let test_dir = TestDir::new("delete-input-encrypt-hash");
    let input = test_dir.path().join("plain.txt");
    let output = test_dir.path().join("plain.enc");
    fs::write(&input, b"top secret").unwrap();

    let output_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            "--hash",
            "--delete-input",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );

    assert!(
        output_cmd.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_cmd.stdout),
        String::from_utf8_lossy(&output_cmd.stderr)
    );
    let stdout = String::from_utf8_lossy(&output_cmd.stdout);
    assert!(stdout.contains(output.to_str().unwrap()), "stdout={stdout}");
    assert!(!input.exists());
    assert!(output.exists());
}

#[test]
fn encrypt_delete_input_keeps_plaintext_on_failure() {
    let test_dir = TestDir::new("delete-input-encrypt-fail");
    let input = test_dir.path().join("plain.txt");
    fs::write(&input, b"top secret").unwrap();

    let output_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "--delete-input",
            input.to_str().unwrap(),
            input.to_str().unwrap(),
        ],
    );

    assert!(
        !output_cmd.status.success(),
        "encrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_cmd.stdout),
        String::from_utf8_lossy(&output_cmd.stderr)
    );
    assert!(input.exists());
}

#[test]
fn decrypt_delete_input_waits_for_commit_success() {
    let test_dir = TestDir::new("delete-input-decrypt-commit-failure");
    let input = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output = test_dir.path().join("plain.out");
    fs::write(&input, b"top secret").unwrap();

    let encrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );
    assert!(encrypt_cmd.status.success());
    fs::write(&output, b"existing output").unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    let decrypt_cmd = command
        .current_dir(test_dir.path())
        .env("DEXIOS_KEY", "wrong-password")
        .args([
            "decrypt",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !decrypt_cmd.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stdout),
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(encrypted.exists());
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
}

#[test]
fn decrypt_delete_input_removes_encrypted_input_after_success() {
    let test_dir = TestDir::new("delete-input-decrypt");
    let input = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output = test_dir.path().join("plain.out");
    fs::write(&input, b"top secret").unwrap();

    let encrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "-f",
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );
    assert!(encrypt_cmd.status.success());

    let decrypt_cmd = run_cli(
        test_dir.path(),
        &[
            "decrypt",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output.to_str().unwrap(),
        ],
    );

    assert!(
        decrypt_cmd.status.success(),
        "decrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stdout),
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(!encrypted.exists());
    assert_eq!(fs::read_to_string(output).unwrap(), "top secret");
}

#[test]
fn decrypt_delete_input_preserves_source_and_output_on_final_auth_failure() {
    let test_dir = TestDir::new("delete-input-decrypt-final-auth-fail");
    let input = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output = test_dir.path().join("plain.out");
    fs::write(&input, multichunk_plaintext()).unwrap();

    let encrypt_cmd = run_cli(
        test_dir.path(),
        &["encrypt", "-f", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_cmd.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_cmd.stdout),
        String::from_utf8_lossy(&encrypt_cmd.stderr)
    );
    let mut encrypted_bytes = fs::read(&encrypted).unwrap();
    corrupt_final_chunk(&mut encrypted_bytes);
    fs::write(&encrypted, encrypted_bytes).unwrap();
    fs::write(&output, b"existing output").unwrap();

    let decrypt_cmd = run_cli(
        test_dir.path(),
        &["decrypt", "-f", "--delete-input", "plain.enc", "plain.out"],
    );

    assert!(
        !decrypt_cmd.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stdout),
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(
        String::from_utf8_lossy(&decrypt_cmd.stderr).contains("Authentication failed"),
        "stderr={}",
        String::from_utf8_lossy(&decrypt_cmd.stderr)
    );
    assert!(encrypted.exists());
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
}

#[test]
fn decrypt_delete_input_preserves_source_on_malformed_and_retired_v1_rejection() {
    let test_dir = TestDir::new("delete-input-decrypt-format-fail");
    fs::write(
        test_dir.path().join("malformed.enc"),
        TRUNCATED_CANONICAL_V1_PREFIX,
    )
    .unwrap();
    fs::write(
        test_dir.path().join("retired-current-v1.enc"),
        RETIRED_CURRENT_V1_PREFIX,
    )
    .unwrap();

    for (input, output, expected_stderr) in [
        (
            "malformed.enc",
            "malformed.out",
            "Malformed Dexios encrypted data",
        ),
        (
            "retired-current-v1.enc",
            "retired-current-v1.out",
            "Unsupported Dexios format",
        ),
    ] {
        let output_cmd = run_cli(
            test_dir.path(),
            &["decrypt", "-f", "--delete-input", input, output],
        );

        assert!(
            !output_cmd.status.success(),
            "{input} unexpectedly decrypted: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output_cmd.stdout),
            String::from_utf8_lossy(&output_cmd.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output_cmd.stderr).contains(expected_stderr),
            "{input} stderr did not contain {expected_stderr:?}: {}",
            String::from_utf8_lossy(&output_cmd.stderr)
        );
        assert!(test_dir.path().join(input).exists());
        assert!(!test_dir.path().join(output).exists());
    }
}

#[test]
fn unpack_delete_input_removes_encrypted_archive_after_success() {
    let test_dir = TestDir::new("delete-input-unpack");
    let encrypted = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(&encrypted, &[("payload/file.txt", b"top secret")]);

    let unpack_cmd = run_cli(
        test_dir.path(),
        &[
            "unpack",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        ],
    );

    assert!(
        unpack_cmd.status.success(),
        "unpack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&unpack_cmd.stdout),
        String::from_utf8_lossy(&unpack_cmd.stderr)
    );
    assert!(!encrypted.exists());
    assert_eq!(
        fs::read_to_string(output_dir.join("payload/file.txt")).unwrap(),
        "top secret"
    );
}

#[test]
fn unpack_delete_input_preserves_archive_on_archive_validation_failure() {
    let test_dir = TestDir::new("delete-input-unpack-validation-fail");
    let encrypted = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );
    let original_archive = fs::read(&encrypted).unwrap();

    let unpack_cmd = run_cli(
        test_dir.path(),
        &[
            "unpack",
            "-f",
            "--delete-input",
            encrypted.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        ],
    );

    assert!(
        !unpack_cmd.status.success(),
        "unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&unpack_cmd.stdout),
        String::from_utf8_lossy(&unpack_cmd.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unpack_cmd.stderr).contains("Unsafe archive path"),
        "stderr={}",
        String::from_utf8_lossy(&unpack_cmd.stderr)
    );
    assert_eq!(fs::read(&encrypted).unwrap(), original_archive);
    assert!(!output_dir.join("safe.txt").exists());
    assert!(!test_dir.path().join("escape.txt").exists());
}

#[test]
fn pack_delete_source_removes_source_directory_after_success() {
    let test_dir = TestDir::new("delete-source-pack");
    let source = test_dir.path().join("source");
    let nested = source.join("nested");
    let encrypted = test_dir.path().join("archive.enc");
    fs::create_dir_all(&nested).unwrap();
    fs::write(source.join("hello.txt"), b"hello").unwrap();
    fs::write(nested.join("world.txt"), b"world").unwrap();

    let pack_cmd = run_cli(
        test_dir.path(),
        &[
            "pack",
            "-f",
            "--delete-source",
            source.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );

    assert!(
        pack_cmd.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&pack_cmd.stdout),
        String::from_utf8_lossy(&pack_cmd.stderr)
    );
    assert!(!source.exists());
    assert!(encrypted.exists());
}

#[cfg(unix)]
#[test]
fn pack_delete_source_reports_partial_cleanup_failure() {
    use std::os::unix::fs::PermissionsExt;

    let test_dir = TestDir::new("delete-source-pack-partial-cleanup");
    let ok_source = test_dir.path().join("ok-source");
    let locked_parent = test_dir.path().join("locked-parent");
    let locked_source = locked_parent.join("locked-source");
    let encrypted = test_dir.path().join("archive.enc");
    fs::create_dir_all(&ok_source).unwrap();
    fs::create_dir_all(&locked_source).unwrap();
    fs::write(ok_source.join("ok.txt"), b"ok").unwrap();
    fs::write(locked_source.join("locked.txt"), b"locked").unwrap();
    fs::set_permissions(&locked_parent, fs::Permissions::from_mode(0o555)).unwrap();

    let pack_cmd = run_cli(
        test_dir.path(),
        &[
            "pack",
            "-f",
            "--delete-source",
            ok_source.to_str().unwrap(),
            locked_source.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );

    fs::set_permissions(&locked_parent, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        !pack_cmd.status.success(),
        "pack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&pack_cmd.stdout),
        String::from_utf8_lossy(&pack_cmd.stderr)
    );
    assert!(
        pack_cmd.stdout.is_empty(),
        "cleanup failure must not print normal-output success text: stdout={}",
        String::from_utf8_lossy(&pack_cmd.stdout)
    );
    assert_eq!(
        String::from_utf8_lossy(&pack_cmd.stderr),
        "Cleanup failed after output commit; committed outputs remain in place\n"
    );
    assert!(encrypted.exists());
    assert!(!ok_source.exists());
    assert!(locked_source.exists());
}

#[test]
fn cli_delete_after_success_hash_failure_and_identity_mismatch_are_source_gated() {
    for required in [
        "CleanupAfterCommitError",
        "CleanupFailed(CleanupResult)",
        "result.failures",
        "CleanupFailure",
        "HashVerification::Failed",
        "changed cleanup identity",
        "cleanup target identity",
        "ordinary delete-after-success cleanup",
        "PostCommitSuccess",
        "committed outputs remain in place",
    ] {
        assert_source_contains("dexios/src/subcommands.rs", DEXIOS_SUBCOMMANDS_RS, required);
    }
}

#[test]
fn delete_source_detached_partial_publication_cleanup_denial_is_source_gated() {
    assert_source_contains(
        "dexios-domain/tests/detached_publication.rs",
        DETACHED_PUBLICATION_TEST_SOURCE,
        "execute_transactional_with_cleanup",
    );
    assert_source_contains(
        "dexios-domain/tests/detached_publication.rs",
        DETACHED_PUBLICATION_TEST_SOURCE,
        "DetachedPublication(TransactionError::PartialCommit",
    );
    assert_source_contains(
        "dexios-domain/tests/detached_publication.rs",
        DETACHED_PUBLICATION_TEST_SOURCE,
        "fs::read(&input_path)",
    );
    assert_source_contains(
        "dexios-domain/tests/detached_publication.rs",
        DETACHED_PUBLICATION_TEST_SOURCE,
        "fs::read(source_dir.join(\"plain.txt\"))",
    );
    assert_source_contains(
        "dexios/src/subcommands/encrypt.rs",
        ENCRYPT_SUBCOMMAND_SOURCE,
        "execute_transactional_with_cleanup(intent).map_err(map_encrypt_error)?",
    );
    assert_source_contains(
        "dexios/src/subcommands/pack.rs",
        PACK_SUBCOMMAND_SOURCE,
        "execute_transactional_with_cleanup(intent).map_err(map_pack_error)?",
    );
}

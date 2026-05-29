use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::{
    CANONICAL_V1_DISCRIMINATOR, HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN, MAGIC,
};
use core::header::{ParsedHeader, read_header};
use domain::encrypt;

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

fn run_cli(current_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command.current_dir(current_dir).env("DEXIOS_KEY", PASSWORD);
    command.args(args).output().unwrap()
}

fn encrypt_fixture(input_path: &Path, output_path: &Path) {
    let intent = encrypt::EncryptIntent::new(
        input_path,
        output_path,
        domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        core::protected::Protected::new(PASSWORD.as_bytes().to_vec()),
        core::kdf::Kdf::Argon2id,
    )
    .unwrap();
    encrypt::execute(intent).unwrap();
}

fn write_legacy_header_fixture(output_path: &Path) {
    let mut file = File::create(output_path).unwrap();
    file.write_all(&[0xDE, 0x05]).unwrap();
    file.write_all(&[7u8; 126]).unwrap();
    file.flush().unwrap();
}

fn write_malformed_v1_header_fixture(output_path: &Path) {
    let mut bytes = vec![0u8; HEADER_LEN];
    bytes[0..4].copy_from_slice(b"DXIO");
    bytes[4..6].copy_from_slice(&[0x00, 0x01]);
    bytes[6..10].copy_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    bytes[10] = 0x01;
    bytes[11] = 0x01;
    bytes[12] = 0x01;
    bytes[13] = 0x01;
    bytes[14] = 0x04;
    bytes[15] = 1;

    let mut file = File::create(output_path).unwrap();
    file.write_all(&bytes).unwrap();
    file.flush().unwrap();
}

fn mark_keyslot_unsupported_kdf_profile(path: &Path, index: usize) {
    let mut bytes = fs::read(path).unwrap();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
    bytes[offset + 2] = 0x02;
    fs::write(path, bytes).unwrap();
}

#[test]
fn help_does_not_list_aes_or_erase_commands() {
    let test_dir = TestDir::new("help-surface");

    let top_level = run_cli(test_dir.path(), &["--help"]);
    let encrypt_help = run_cli(test_dir.path(), &["encrypt", "--help"]);
    let pack_help = run_cli(test_dir.path(), &["pack", "--help"]);

    assert!(top_level.status.success());
    assert!(encrypt_help.status.success());
    assert!(pack_help.status.success());

    let top_level_stdout = String::from_utf8_lossy(&top_level.stdout);
    let encrypt_stdout = String::from_utf8_lossy(&encrypt_help.stdout);
    let pack_stdout = String::from_utf8_lossy(&pack_help.stdout);

    assert!(!top_level_stdout.contains(" erase "));
    assert!(!encrypt_stdout.contains("--aes"));
    assert!(!pack_stdout.contains("--aes"));
}

#[test]
fn header_details_reports_v1_profile() {
    let test_dir = TestDir::new("header-details");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    fs::write(&plain, b"top secret").unwrap();
    encrypt_fixture(&plain, &encrypted);

    let output = run_cli(
        test_dir.path(),
        &["header", "details", encrypted.to_str().unwrap()],
    );

    assert!(
        output.status.success(),
        "header details failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Header version: V1"));
    assert!(stdout.contains("Cipher suite: XChaCha20-Poly1305 / LE31 stream"));
    assert!(!stdout.contains("V5"));
    assert!(!stdout.contains("AES-256-GCM"));
    assert!(!stdout.contains("(legacy)"));
}

#[test]
fn header_details_reports_supported_argon2id_keyslot() {
    let test_dir = TestDir::new("header-details-kdf");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    fs::write(&plain, b"top secret").unwrap();
    encrypt_fixture(&plain, &encrypted);

    let output = run_cli(
        test_dir.path(),
        &["header", "details", encrypted.to_str().unwrap()],
    );

    assert!(
        output.status.success(),
        "header details failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("KDF: Argon2id"),
        "header details did not show supported KDF: stdout={stdout}"
    );
    assert!(
        !stdout.contains(PASSWORD),
        "header details leaked the raw password: stdout={stdout}"
    );
    assert!(
        !stdout.contains("top secret"),
        "header details leaked plaintext fixture data: stdout={stdout}"
    );
    assert!(
        !stdout.contains("Wrapping Key"),
        "header details should not print wrapping keys: stdout={stdout}"
    );
    assert!(
        !stdout.contains("Decrypted Master Key"),
        "header details should not print decrypted master keys: stdout={stdout}"
    );
    assert!(
        !stdout.contains("  Master Key:"),
        "header details should label only encrypted master-key metadata: stdout={stdout}"
    );
}

// Extracts the per-keyslot encrypted master-key hex from a real V1 header so the
// redaction tests can assert against the exact bytes that `header details` would print.
fn encrypted_master_key_hex(encrypted: &Path) -> String {
    let mut file = File::open(encrypted).unwrap();
    let ParsedHeader::V1(payload) = read_header(&mut file).unwrap();
    payload
        .header()
        .keyslots()
        .iter()
        .map(|keyslot| {
            keyslot
                .encrypted_master_key()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .next()
        .expect("canonical V1 fixture has at least one keyslot")
}

#[test]
fn header_details_redacts_encrypted_master_key_by_default() {
    let test_dir = TestDir::new("header-details-redact");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    fs::write(&plain, b"top secret").unwrap();
    encrypt_fixture(&plain, &encrypted);

    let master_key_hex = encrypted_master_key_hex(&encrypted);

    let output = run_cli(
        test_dir.path(),
        &["header", "details", encrypted.to_str().unwrap()],
    );

    assert!(
        output.status.success(),
        "header details failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(&master_key_hex),
        "default header details leaked the encrypted master-key hex: stdout={stdout}"
    );
    assert!(
        stdout.contains("Encrypted master key: <hidden — use --raw to show> (hex)"),
        "default header details must show the encrypted master-key redaction placeholder: stdout={stdout}"
    );
    // Every other field/label stays intact in the default (redacted) mode.
    assert!(stdout.contains("Header version: V1"));
    assert!(stdout.contains("Cipher suite: XChaCha20-Poly1305 / LE31 stream"));
    assert!(stdout.contains("Payload nonce: "));
    assert!(stdout.contains("AAD: "));
    assert!(stdout.contains("KDF: Argon2id"));
    assert!(stdout.contains("Salt: "));
    assert!(stdout.contains("Keyslot nonce: "));
}

#[test]
fn header_details_raw_flag_reveals_encrypted_master_key() {
    let test_dir = TestDir::new("header-details-raw");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    fs::write(&plain, b"top secret").unwrap();
    encrypt_fixture(&plain, &encrypted);

    let master_key_hex = encrypted_master_key_hex(&encrypted);

    let output = run_cli(
        test_dir.path(),
        &["header", "details", "--raw", encrypted.to_str().unwrap()],
    );

    assert!(
        output.status.success(),
        "header details --raw failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("Encrypted master key: {master_key_hex} (hex)")),
        "header details --raw must print the encrypted master-key hex: stdout={stdout}"
    );
    assert!(
        !stdout.contains("<hidden — use --raw to show>"),
        "header details --raw must not show the redaction placeholder: stdout={stdout}"
    );
    // All the other fields/labels remain unchanged in --raw mode.
    assert!(stdout.contains("Header version: V1"));
    assert!(stdout.contains("Cipher suite: XChaCha20-Poly1305 / LE31 stream"));
    assert!(stdout.contains("Payload nonce: "));
    assert!(stdout.contains("AAD: "));
    assert!(stdout.contains("KDF: Argon2id"));
    assert!(stdout.contains("Salt: "));
    assert!(stdout.contains("Keyslot nonce: "));
}

#[test]
fn header_details_rejects_unsupported_kdf_profile() {
    let test_dir = TestDir::new("header-details-unsupported-kdf");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    fs::write(&plain, b"top secret").unwrap();
    encrypt_fixture(&plain, &encrypted);
    mark_keyslot_unsupported_kdf_profile(&encrypted, 0);

    let output = run_cli(
        test_dir.path(),
        &["header", "details", encrypted.to_str().unwrap()],
    );

    assert!(
        !output.status.success(),
        "header details unexpectedly accepted unsupported KDF profile: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid canonical V1 KDF profile"),
        "header details did not reject unsupported KDF profile: stderr={stderr}"
    );
}

#[test]
fn detached_header_canonical_v1_fixture_keeps_header_separate() {
    let test_dir = TestDir::new("detached-header-canonical-v1");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let header = test_dir.path().join("plain.hdr");
    fs::write(&plain, b"top secret").unwrap();

    // Manifest fixture: detached-header-canonical-v1.
    let output = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "--header",
            header.to_str().unwrap(),
            plain.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ],
    );

    assert!(
        output.status.success(),
        "detached encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let header_bytes = fs::read(&header).unwrap();
    let payload_bytes = fs::read(&encrypted).unwrap();
    let parsed = read_header(&mut std::io::Cursor::new(&header_bytes))
        .expect("detached header should parse");
    let ParsedHeader::V1(parsed) = parsed;

    assert_eq!(parsed.header().keyslots().len(), 1);
    assert_eq!(header_bytes.len(), HEADER_LEN);
    assert_eq!(payload_bytes.len(), b"top secret".len() + 16);
    assert!(!payload_bytes.starts_with(&MAGIC));
}

#[test]
fn header_details_rejects_legacy_headers_without_fallback() {
    let test_dir = TestDir::new("header-details-legacy");
    let legacy = test_dir.path().join("legacy.hdr");
    write_legacy_header_fixture(&legacy);

    let output = run_cli(
        test_dir.path(),
        &["header", "details", legacy.to_str().unwrap()],
    );

    assert!(
        !output.status.success(),
        "header details unexpectedly succeeded"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unsupported Dexios format"),
        "stderr did not reject legacy format: {stderr}"
    );
}

#[test]
fn malformed_v1_headers_report_specific_parse_errors() {
    let test_dir = TestDir::new("header-details-malformed-v1");
    let malformed = test_dir.path().join("broken.enc");
    write_malformed_v1_header_fixture(&malformed);

    let details_output = run_cli(
        test_dir.path(),
        &["header", "details", malformed.to_str().unwrap()],
    );

    assert!(
        !details_output.status.success(),
        "header details unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&details_output.stdout),
        String::from_utf8_lossy(&details_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&details_output.stderr)
            .contains("non-zero reserved bytes in V1 header"),
        "stderr did not preserve V1 parse class: {}",
        String::from_utf8_lossy(&details_output.stderr)
    );

    let key_output = run_cli(
        test_dir.path(),
        &["key", "verify", malformed.to_str().unwrap()],
    );

    assert!(
        !key_output.status.success(),
        "key verify unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&key_output.stdout),
        String::from_utf8_lossy(&key_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&key_output.stderr).contains("Malformed Dexios V1 header"),
        "stderr did not identify malformed V1 header: {}",
        String::from_utf8_lossy(&key_output.stderr)
    );
}

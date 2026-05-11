use core::header::common::{HEADER_LEN, KeyslotNonce, PayloadNonce, Salt};
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use dexios_domain::header::{self, restore};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
            "dexios-domain-{prefix}-{}-{seq}-{nanos}",
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

fn v1_header_bytes() -> Vec<u8> {
    let keyslot = V1Keyslot::new(
        Kdf::Blake3Balloon,
        [1u8; 48],
        KeyslotNonce::new([2u8; 24]),
        Salt::new([3u8; 16]),
    );
    let header = V1Header::new(PayloadNonce::new([4u8; 20]), V1Keyslots::single(keyslot))
        .expect("create V1 header");

    header.serialize().expect("serialize V1 header")
}

#[test]
fn restores_valid_v1_header_into_stripped_artifact_with_payload() {
    let test_dir = TestDir::new("restore-valid");
    let header_path = test_dir.path().join("plain.hdr");
    let target_path = test_dir.path().join("plain.enc");
    let header_bytes = v1_header_bytes();
    let payload = b"ciphertext payload";
    let mut stripped = vec![0u8; HEADER_LEN];
    stripped.extend_from_slice(payload);
    fs::write(&header_path, &header_bytes).unwrap();
    fs::write(&target_path, &stripped).unwrap();

    let intent = restore::RestoreIntent::new(&header_path, &target_path).expect("restore intent");
    restore::execute(intent).expect("restore into stripped artifact");

    let restored = fs::read(&target_path).unwrap();
    assert_eq!(&restored[..HEADER_LEN], header_bytes.as_slice());
    assert_eq!(&restored[HEADER_LEN..], payload);
}

#[test]
fn header_restore_rejects_short_target_without_writing() {
    let test_dir = TestDir::new("restore-short-target");
    let header_path = test_dir.path().join("plain.hdr");
    let target_path = test_dir.path().join("plain.enc");
    let target = vec![0u8; HEADER_LEN - 1];
    fs::write(&header_path, v1_header_bytes()).unwrap();
    fs::write(&target_path, &target).unwrap();

    let intent = restore::RestoreIntent::new(&header_path, &target_path).expect("restore intent");
    let error = restore::execute(intent).expect_err("short restore target should be rejected");

    assert!(matches!(
        error,
        header::Error::TargetTooShort {
            actual_len
        } if actual_len == HEADER_LEN - 1
    ));
    assert_eq!(fs::read(&target_path).unwrap(), target);
}

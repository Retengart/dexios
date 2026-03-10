use std::cell::RefCell;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::kdf::Kdf;
use core::protected::Protected;
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
    let input = RefCell::new(File::open(input_path).unwrap());
    let output = RefCell::new(File::create(output_path).unwrap());

    encrypt::execute(encrypt::Request {
        reader: &input,
        writer: &output,
        header_writer: None,
        raw_key: Protected::new(PASSWORD.as_bytes().to_vec()),
        kdf: Kdf::Blake3Balloon,
    })
    .unwrap();

    output.borrow_mut().flush().unwrap();
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
}

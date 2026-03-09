use std::cell::RefCell;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::protected::Protected;
use domain::decrypt;

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

fn run_pack(
    current_dir: &Path,
    extra_args: &[&str],
    inputs: &[&str],
    output_name: &str,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", PASSWORD)
        .arg("pack")
        .arg("-f");

    for arg in extra_args {
        command.arg(arg);
    }

    for input in inputs {
        command.arg(input);
    }

    command.arg(output_name).output().unwrap()
}

fn decrypt_archive_entry_names(archive_path: &Path, header_path: Option<&Path>) -> Vec<String> {
    let archive = fs::File::open(archive_path).unwrap();
    let archive_reader = RefCell::new(archive);
    let header_reader = header_path.map(|path| RefCell::new(fs::File::open(path).unwrap()));
    let decrypted = RefCell::new(Cursor::new(Vec::new()));

    decrypt::execute(decrypt::Request {
        header_reader: header_reader.as_ref(),
        reader: &archive_reader,
        writer: &decrypted,
        raw_key: Protected::new(PASSWORD.as_bytes().to_vec()),
        on_decrypted_header: None,
    })
    .unwrap();

    let bytes = decrypted.into_inner().into_inner();
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut names = (0..zip.len())
        .map(|index| zip.by_index(index).unwrap().name().to_string())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn pack_dot_input_uses_current_directory_name_and_skips_generated_artifacts() {
    let test_dir = TestDir::new("pack-dot");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();

    let output = run_pack(
        &source_dir,
        &["--header", "header.bin"],
        &["."],
        "archive.enc",
    );

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let names = decrypt_archive_entry_names(
        &source_dir.join("archive.enc"),
        Some(&source_dir.join("header.bin")),
    );

    assert_eq!(
        names,
        vec![
            "source/",
            "source/hello.txt",
            "source/nested/",
            "source/nested/world.txt",
        ]
    );
}

#[test]
fn pack_duplicate_basenames_uses_unique_archive_roots() {
    let test_dir = TestDir::new("pack-duplicate-basenames");
    let parent1 = test_dir.path().join("parent1/foo/sub");
    let parent2 = test_dir.path().join("parent2/foo/sub");
    fs::create_dir_all(&parent1).unwrap();
    fs::create_dir_all(&parent2).unwrap();
    fs::write(parent1.join("one.txt"), b"one").unwrap();
    fs::write(parent2.join("two.txt"), b"two").unwrap();

    let output = run_pack(
        test_dir.path(),
        &[],
        &["parent1/foo", "parent2/foo"],
        "archive.enc",
    );

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let names = decrypt_archive_entry_names(&test_dir.path().join("archive.enc"), None);

    assert_eq!(
        names,
        vec![
            "parent1/foo/",
            "parent1/foo/sub/",
            "parent1/foo/sub/one.txt",
            "parent2/foo/",
            "parent2/foo/sub/",
            "parent2/foo/sub/two.txt",
        ]
    );
}

#[test]
fn pack_mixed_nested_roots_do_not_leak_current_directory_name() {
    let test_dir = TestDir::new("pack-mixed-nested-roots");
    let foo_dir = test_dir.path().join("foo");
    let nested_dir = test_dir.path().join("bar/foo");
    fs::create_dir_all(&foo_dir).unwrap();
    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(foo_dir.join("one.txt"), b"one").unwrap();
    fs::write(nested_dir.join("two.txt"), b"two").unwrap();

    let output = run_pack(test_dir.path(), &[], &["foo", "bar/foo"], "archive.enc");

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let names = decrypt_archive_entry_names(&test_dir.path().join("archive.enc"), None);

    assert_eq!(
        names,
        vec!["bar/foo/", "bar/foo/two.txt", "foo/", "foo/one.txt",]
    );
}

#[test]
fn pack_verbose_reports_archived_entries() {
    let test_dir = TestDir::new("pack-verbose");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();

    let output = run_pack(&source_dir, &["-v"], &["."], "archive.enc");

    assert!(
        output.status.success(),
        "pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[i] Packing source/hello.txt"));
    assert!(stdout.contains("[i] Packing source/nested/world.txt"));
}

#[test]
fn pack_recursive_flag_matches_default_recursive_behavior() {
    let test_dir = TestDir::new("pack-recursive-alias");
    let default_dir = test_dir.path().join("default/source");
    let recursive_dir = test_dir.path().join("recursive/source");
    fs::create_dir_all(default_dir.join("nested/deeper")).unwrap();
    fs::create_dir_all(recursive_dir.join("nested/deeper")).unwrap();
    fs::write(default_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(default_dir.join("nested/deeper/world.txt"), b"world").unwrap();
    fs::write(recursive_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(recursive_dir.join("nested/deeper/world.txt"), b"world").unwrap();

    let default_output = run_pack(&default_dir, &[], &["."], "default.enc");
    let recursive_output = run_pack(&recursive_dir, &["-r"], &["."], "recursive.enc");

    assert!(
        default_output.status.success(),
        "default pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&default_output.stdout),
        String::from_utf8_lossy(&default_output.stderr)
    );
    assert!(
        recursive_output.status.success(),
        "recursive pack failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&recursive_output.stdout),
        String::from_utf8_lossy(&recursive_output.stderr)
    );

    let default_names = decrypt_archive_entry_names(&default_dir.join("default.enc"), None);
    let recursive_names = decrypt_archive_entry_names(&recursive_dir.join("recursive.enc"), None);

    assert_eq!(default_names, recursive_names);
    assert!(default_names.contains(&"source/nested/deeper/world.txt".to_string()));
}

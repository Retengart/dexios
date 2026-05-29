#[path = "support/unpack_v1.rs"]
mod unpack_support;

use unpack_support::*;

// fs-4: unpack with no overwrite-consent callback must default existing-file targets to
// CreateNew (refuse to clobber) instead of silently replacing them.
#[test]
fn unpack_without_consent_callback_refuses_to_clobber_existing_file() {
    let test_dir = TestDir::new("unpack-overwrite-default");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing = output_dir.join("existing.txt");

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing, b"original contents").unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("existing.txt", b"replacement")]);

    // No consent callback => non-clobber default.
    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        result.is_err(),
        "unpack without a consent callback must refuse to clobber an existing file, got {result:?}"
    );
    assert_eq!(
        fs::read(&existing).unwrap(),
        b"original contents",
        "existing file must be preserved when overwrite is refused"
    );
}

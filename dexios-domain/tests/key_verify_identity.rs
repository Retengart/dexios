//! Path-identity / no-follow safety evidence for `key verify` (verify-1).
//!
//! `key verify` reads a header to test a key against a keyslot. It must resolve and
//! read the target through the same hardened no-follow path-identity layer the other
//! intents use, so a symlinked target cannot redirect the read to an unintended file
//! (a path-identity / TOCTOU footgun). The operation stays strictly read-only.

#[path = "support/keyslots_v1.rs"]
mod keyslots_support;

use keyslots_support::*;

#[cfg(unix)]
#[test]
fn key_verify_rejects_symlinked_target_without_following_it() {
    use std::os::unix::fs::symlink;

    let (dir, real_path) = encrypted_v1_file("verify-identity-symlink-real");
    let real_bytes = fs::read(&real_path).expect("read real encrypted fixture");

    // A symlink whose name differs from the real file; verify must refuse it instead
    // of dereferencing the link to read the real header behind it.
    let link_path = dir.path().join("verify-identity-symlink-link.enc");
    symlink(&real_path, &link_path).expect("create symlink to encrypted fixture");

    match key::verify::VerifyIntent::new(&link_path) {
        Err(key::Error::PathIdentity(
            dexios_domain::storage::identity::IdentityError::UnsafePath(_),
        )) => {}
        Err(other) => panic!("verify must reject the symlinked target as unsafe: {other:?}"),
        Ok(_) => panic!("verify must not follow a symlinked target to read the real header"),
    }

    // The real file behind the link must be untouched (read-only contract).
    assert_eq!(
        fs::read(&real_path).expect("read real fixture after rejected verify"),
        real_bytes,
        "verify must not mutate the symlink target"
    );
}

#[test]
fn key_verify_regular_file_happy_path_unlocks_keyslot() {
    let (_dir, encrypted_path) = encrypted_v1_file("verify-identity-regular");
    let original = fs::read(&encrypted_path).expect("read encrypted fixture");

    // Correct key unlocks the keyslot through the hardened read path.
    verify_file(&encrypted_path, b"old-pass").expect("correct key must verify");

    // Wrong key is still reported as incorrect (read path did resolve + parse).
    let wrong = verify_file(&encrypted_path, b"wrong-pass");
    assert!(
        matches!(wrong, Err(key::Error::IncorrectKey)),
        "wrong key must report IncorrectKey: {wrong:?}"
    );

    // Verify stays strictly read-only.
    assert_eq!(
        fs::read(&encrypted_path).expect("read fixture after verify"),
        original,
        "verify must not mutate the regular-file target"
    );
}

#[test]
fn key_verify_missing_target_still_reports_read_io() {
    let dir = tempfile::tempdir().expect("temp dir");
    let missing = dir.path().join("verify-identity-missing.enc");

    match key::verify::VerifyIntent::new(&missing) {
        Err(key::Error::ReadIo) => {}
        Err(other) => panic!("missing verify target must report ReadIo, got: {other:?}"),
        Ok(_) => panic!("missing verify target must not produce a usable intent"),
    }
}

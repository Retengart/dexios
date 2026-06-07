#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::panic,
        reason = "source gate asserts archive path authority structure"
    )
)]

const DOMAIN_LIB_RS: &str = include_str!("../../dexios-domain/src/lib.rs");
const DOMAIN_ARCHIVE_PATH_RS: &str = include_str!("../../dexios-domain/src/archive_path.rs");
const DOMAIN_PACK_RS: &str = include_str!("../../dexios-domain/src/pack.rs");
const DOMAIN_UNPACK_RS: &str = include_str!("../../dexios-domain/src/unpack.rs");
const PACK_PATHS_TESTS: &str = include_str!("../../dexios-domain/tests/pack_paths.rs");
const UNPACK_MANIFEST_TESTS: &str = include_str!("../../dexios-domain/tests/unpack_manifest_v1.rs");

#[test]
fn normalized_archive_path_stays_private_to_domain() {
    assert!(DOMAIN_LIB_RS.contains("mod archive_path;"));
    assert!(!DOMAIN_LIB_RS.contains("pub mod archive_path;"));
    assert!(DOMAIN_ARCHIVE_PATH_RS.contains("pub(crate) struct NormalizedArchivePath"));
    assert!(DOMAIN_ARCHIVE_PATH_RS.contains("pub(crate) enum ArchivePathError"));
}

#[test]
fn pack_and_unpack_use_normalized_archive_path_helper() {
    assert!(DOMAIN_PACK_RS.contains("NormalizedArchivePath::from_path"));
    assert!(DOMAIN_PACK_RS.contains(".as_manifest_bytes()"));
    assert!(!DOMAIN_PACK_RS.contains("fn normalized_archive_path_bytes"));
    assert!(DOMAIN_UNPACK_RS.contains("NormalizedArchivePath::from_manifest_bytes"));
    assert!(!DOMAIN_UNPACK_RS.contains("fn manifest_entry_path"));
    assert!(!DOMAIN_UNPACK_RS.contains("fn normalize_archive_path"));
}

#[test]
fn archive_path_regressions_cover_cross_platform_separators() {
    assert!(PACK_PATHS_TESTS.contains("pack_rejects_filename_containing_windows_separator_byte"));
    assert!(UNPACK_MANIFEST_TESTS.contains("unpack_rejects_manifest_path_with_backslash_separator"));
    assert!(UNPACK_MANIFEST_TESTS.contains("unpack_rejects_non_utf8_manifest_path"));
    assert!(UNPACK_MANIFEST_TESTS.contains("unpack_rejects_manifest_path_with_nul_byte"));
}

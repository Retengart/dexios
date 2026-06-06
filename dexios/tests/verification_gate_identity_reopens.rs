#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::string_slice,
        clippy::too_many_lines,
        clippy::items_after_statements,
        reason = "integration gates assert exact source-order safety anchors"
    )
)]
mod verification_gate_support;

use verification_gate_support::*;

#[test]
fn read_side_domain_consumers_reopen_captured_existing_targets_through_storage_boundary() {
    let encrypt_execute = normalized_rust_production_section(
        "dexios-domain/src/encrypt.rs",
        DEXIOS_DOMAIN_ENCRYPT_RS,
        "pub fn execute(intent: EncryptIntent)",
        "pub fn execute_transactional",
    );
    assert_normalized_section_order(
        "dexios-domain/src/encrypt.rs::execute",
        &encrypt_execute,
        &[
            "let stor = crate::storage::FileStorage;",
            ".read_resolved_existing_no_follow(&input_target)",
            "execute_transactional_targets",
        ],
    );
    assert!(
        !encrypt_execute.contains("File::open(input_target.target_path())"),
        "encrypt must not bypass identity-bound reopen after capturing input_target"
    );

    let decrypt_execute = normalized_rust_production_section(
        "dexios-domain/src/decrypt.rs",
        DEXIOS_DOMAIN_DECRYPT_RS,
        "pub fn execute(intent: DecryptIntent)",
        "pub fn execute_transactional",
    );
    assert_normalized_section_order(
        "dexios-domain/src/decrypt.rs::execute",
        &decrypt_execute,
        &[
            "let stor = crate::storage::FileStorage;",
            ".read_resolved_existing_no_follow(&input_target)",
            "detached_header_target",
            "stor.read_resolved_existing_no_follow(target)",
            "execute_transactional_target",
        ],
    );
    for forbidden in [
        "File::open(input_target.target_path())",
        "File::open(target.target_path())",
    ] {
        assert!(
            !decrypt_execute.contains(forbidden),
            "decrypt must not bypass identity-bound reopen with {forbidden}"
        );
    }

    let dump_execute = normalized_rust_production_section(
        "dexios-domain/src/header/dump.rs",
        DEXIOS_DOMAIN_HEADER_DUMP_RS,
        "pub fn execute(intent: DumpIntent)",
        "pub fn execute_transactional",
    );
    assert_normalized_section_order(
        "dexios-domain/src/header/dump.rs::execute",
        &dump_execute,
        &[
            "let stor = crate::storage::FileStorage;",
            ".read_resolved_existing_no_follow(&input_target)",
            "read_header_only",
        ],
    );
    assert_rust_production_source_excludes(
        "dexios-domain/src/header/dump.rs",
        DEXIOS_DOMAIN_HEADER_DUMP_RS,
        &[
            "fs::File::open(path)",
            "File::open(input_target.target_path())",
        ],
    );

    let storage_reopen = normalized_rust_production_section(
        "dexios-domain/src/storage/fs.rs",
        DEXIOS_DOMAIN_STORAGE_FS_RS,
        "pub fn read_resolved_existing_no_follow",
        "pub fn revalidate_resolved_directory_root",
    );
    assert_normalized_section_order(
        "dexios-domain/src/storage/fs.rs::read_resolved_existing_no_follow",
        &storage_reopen,
        &[
            "if !target.exists()",
            "let entry = self.read_file_no_follow(target.target_path())?",
            "if entry.is_dir() != target.is_dir()",
            "verify_entry_matches_resolved_target(&entry, target)?",
            "Ok(entry)",
        ],
    );
    assert_rust_production_source_excludes(
        "dexios-domain/src/storage/fs.rs",
        DEXIOS_DOMAIN_STORAGE_FS_RS,
        &[
            "std_fs::File::open(target.target_path())",
            "read_file(target.target_path())",
        ],
    );

    let unix_storage_identity = normalized_rust_production_section(
        "dexios-domain/src/storage/fs.rs",
        DEXIOS_DOMAIN_STORAGE_FS_RS,
        "fn verify_entry_matches_resolved_target",
        "fn open_no_follow",
    );
    assert_normalized_section_order(
        "dexios-domain/src/storage/fs.rs::verify_entry_matches_resolved_target",
        &unix_storage_identity,
        &[
            "expected.existing_target_identity()",
            "actual.dev() != expected_identity.dev || actual.ino() != expected_identity.ino",
            "Error::UnsafePath(expected.original_path().to_path_buf())",
            "Ok(())",
        ],
    );

    let unpack_intent = normalized_rust_production_section(
        "dexios-domain/src/unpack.rs",
        DEXIOS_DOMAIN_UNPACK_RS,
        "impl UnpackIntent",
        "struct HandleRequest",
    );
    assert_normalized_section_order(
        "dexios-domain/src/unpack.rs::UnpackIntent::new",
        &unpack_intent,
        &[
            ".add_existing(&input_path, PathRole::ProcessedSource)",
            ".add_existing(path, PathRole::DetachedHeader)",
            ".read_resolved_existing_no_follow(&input_target)",
            "stor.read_resolved_existing_no_follow(target)",
        ],
    );

    let pack_materialization = normalized_rust_production_section(
        "dexios-domain/src/pack.rs",
        DEXIOS_DOMAIN_PACK_RS,
        "fn materialize_archive_entries_with_limits",
        "#[cfg(unix)]",
    );
    assert_normalized_section_order(
        "dexios-domain/src/pack.rs::materialize_archive_entries_with_limits",
        &pack_materialization,
        &[
            ".read_resolved_existing_no_follow(&source_root.target)",
            ".revalidate_resolved_directory_root(&source_root.target)",
            "walkdir::WalkDir::new(&root_path)",
            ".read_file_no_follow(source.path())",
            "verify_walked_entry_matches_opened(&source, &walked_metadata)?",
            "push_archive_entry",
        ],
    );
}

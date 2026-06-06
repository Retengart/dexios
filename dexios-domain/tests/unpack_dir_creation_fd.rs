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
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::match_same_arms,
        clippy::items_after_statements,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_collect,
        clippy::manual_let_else,
        clippy::format_collect,
        clippy::case_sensitive_file_extension_comparisons,
        clippy::struct_excessive_bools,
        reason = "integration tests assert exact behavior and may panic on failure"
    )
)]
#![cfg(unix)]

#[path = "support/unpack_v1.rs"]
mod unpack_support;

use dexios_domain::storage::{Error, FileStorage};
use std::path::Path;
use unpack_support::*;

// fs-1 / fs-2: create_unpack_dir_all must create each component fd-relative with
// O_NOFOLLOW so a symlinked intermediate component (swapped in after validation) is
// refused instead of being followed outside the unpack root.
#[test]
fn create_unpack_dir_all_rejects_symlinked_intermediate_component() {
    let test_dir = TestDir::new("create-unpack-dir-fd-toctou");
    let root = fs::canonicalize(test_dir.path()).unwrap().join("root");
    let outside = test_dir.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();

    // root/a starts as a real directory, then is swapped for a symlink to `outside`.
    fs::create_dir(root.join("a")).unwrap();
    fs::remove_dir(root.join("a")).unwrap();
    symlink_dir(&outside, &root.join("a"));

    let result = FileStorage.create_unpack_dir_all(&root, Path::new("a/b"));

    assert!(
        matches!(result, Err(Error::UnsafePath(_))),
        "symlinked intermediate component must be refused, got {result:?}"
    );
    assert!(
        !outside.join("b").exists(),
        "must not create the child dir through the symlink"
    );
}

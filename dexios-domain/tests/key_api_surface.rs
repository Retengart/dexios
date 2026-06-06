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
// Source-level guard: the master-key wrap helper must stay crate-private so external
// callers cannot supply a reused keyslot nonce (crypto-3). The public, contract-bearing
// wrap/unwrap API lives in dexios-core (crypto-2).
const KEY_RS: &str = include_str!("../src/key.rs");

#[test]
fn encrypt_master_key_is_crate_private() {
    assert!(
        KEY_RS.contains("pub(crate) fn encrypt_master_key("),
        "encrypt_master_key must be pub(crate), never bare pub"
    );
    assert!(
        !KEY_RS.contains("\npub fn encrypt_master_key("),
        "encrypt_master_key must not be a bare pub fn"
    );
}

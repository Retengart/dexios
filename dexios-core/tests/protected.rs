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
use dexios_core::protected::Protected;

#[test]
fn debug_output_is_redacted() {
    let secret = Protected::new(b"secret debug bytes".to_vec());

    assert_eq!(format!("{secret:?}"), "[REDACTED]");
}

#[test]
fn with_exposed_scopes_secret_access_to_closure() {
    let secret = Protected::new(vec![1, 2, 3, 4]);

    let observed_len = secret.with_exposed(|bytes| {
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4]);
        bytes.len()
    });

    assert_eq!(observed_len, 4);
}

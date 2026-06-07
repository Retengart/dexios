#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::panic,
        clippy::too_many_lines,
        reason = "source gates assert exact repository structure"
    )
)]

struct Source<'a> {
    path: &'a str,
    text: &'a str,
}

const CLI_REGRESSION_SOURCES: &[Source<'_>] = &[
    Source {
        path: "dexios/tests/encrypt_cli_regressions.rs",
        text: include_str!("encrypt_cli_regressions.rs"),
    },
    Source {
        path: "dexios/tests/decrypt_cli_regressions.rs",
        text: include_str!("decrypt_cli_regressions.rs"),
    },
    Source {
        path: "dexios/tests/header_cli_regressions.rs",
        text: include_str!("header_cli_regressions.rs"),
    },
    Source {
        path: "dexios/tests/header_details_cli.rs",
        text: include_str!("header_details_cli.rs"),
    },
    Source {
        path: "dexios/tests/key_cli_regressions.rs",
        text: include_str!("key_cli_regressions.rs"),
    },
    Source {
        path: "dexios/tests/key_force_cli.rs",
        text: include_str!("key_force_cli.rs"),
    },
    Source {
        path: "dexios/tests/pack_cli_regressions.rs",
        text: include_str!("pack_cli_regressions.rs"),
    },
    Source {
        path: "dexios/tests/unpack_cli_regressions.rs",
        text: include_str!("unpack_cli_regressions.rs"),
    },
    Source {
        path: "dexios/tests/storage_transactions_cli.rs",
        text: include_str!("storage_transactions_cli.rs"),
    },
    Source {
        path: "dexios/tests/delete_source_cli.rs",
        text: include_str!("delete_source_cli.rs"),
    },
    Source {
        path: "dexios/tests/support/workflow_error_cli.rs",
        text: include_str!("support/workflow_error_cli.rs"),
    },
];

const DOMAIN_TEST_SOURCES: &[Source<'_>] = &[
    Source {
        path: "dexios-domain/tests/header_restore.rs",
        text: include_str!("../../dexios-domain/tests/header_restore.rs"),
    },
    Source {
        path: "dexios-domain/tests/header_strip_guard.rs",
        text: include_str!("../../dexios-domain/tests/header_strip_guard.rs"),
    },
    Source {
        path: "dexios-domain/tests/encrypt_workflow_errors.rs",
        text: include_str!("../../dexios-domain/tests/encrypt_workflow_errors.rs"),
    },
    Source {
        path: "dexios-domain/tests/decrypt_workflow_errors.rs",
        text: include_str!("../../dexios-domain/tests/decrypt_workflow_errors.rs"),
    },
    Source {
        path: "dexios-domain/tests/path_identity.rs",
        text: include_str!("../../dexios-domain/tests/path_identity.rs"),
    },
    Source {
        path: "dexios-domain/tests/cleanup_receipts.rs",
        text: include_str!("../../dexios-domain/tests/cleanup_receipts.rs"),
    },
    Source {
        path: "dexios-domain/tests/support/unpack_v1.rs",
        text: include_str!("../../dexios-domain/tests/support/unpack_v1.rs"),
    },
    Source {
        path: "dexios-domain/tests/support/transactions.rs",
        text: include_str!("../../dexios-domain/tests/support/transactions.rs"),
    },
];

#[test]
fn cli_regression_tests_use_shared_tempdir_support() {
    for source in CLI_REGRESSION_SOURCES {
        assert!(
            !source.text.contains("struct TestDir"),
            "{} must import TestDir from dexios/tests/support/tempdir.rs",
            source.path
        );
        assert!(
            !source.text.contains("static NEXT_TEST_DIR"),
            "{} must not maintain a local tempdir sequence",
            source.path
        );
    }
}

#[test]
fn domain_tests_use_shared_canonical_tempdir_support() {
    for source in DOMAIN_TEST_SOURCES {
        assert!(
            !source.text.contains("struct TestDir"),
            "{} must import TestDir from dexios-domain/tests/support/tempdir.rs",
            source.path
        );
        assert!(
            !source.text.contains("SystemTime::now()"),
            "{} must not build tempdir names manually",
            source.path
        );
    }
}

#[test]
fn canonical_tempdir_support_keeps_macos_safe_canonicalization() {
    let domain_support = include_str!("../../dexios-domain/tests/support/tempdir.rs");
    assert!(domain_support.contains("pub(crate) fn canonical_tempdir()"));
    assert!(domain_support.contains("fs::canonicalize(dir.path())"));
    assert!(domain_support.contains("tempfile::TempDir"));
}

const DOMAIN_ENCRYPT: &str = include_str!("../src/encrypt.rs");
const DOMAIN_DECRYPT: &str = include_str!("../src/decrypt.rs");
const DOMAIN_HEADER_DUMP: &str = include_str!("../src/header/dump.rs");
const DOMAIN_HEADER_STRIP: &str = include_str!("../src/header/strip.rs");
const DOMAIN_HEADER_RESTORE: &str = include_str!("../src/header/restore.rs");
const DOMAIN_KEY_ADD: &str = include_str!("../src/key/add.rs");
const DOMAIN_KEY_CHANGE: &str = include_str!("../src/key/change.rs");
const DOMAIN_KEY_DELETE: &str = include_str!("../src/key/delete.rs");
const DOMAIN_KEY_VERIFY: &str = include_str!("../src/key/verify.rs");

const CLI_ENCRYPT: &str = include_str!("../../dexios/src/subcommands/encrypt.rs");
const CLI_DECRYPT: &str = include_str!("../../dexios/src/subcommands/decrypt.rs");
const CLI_HEADER: &str = include_str!("../../dexios/src/subcommands/header.rs");
const CLI_KEY: &str = include_str!("../../dexios/src/subcommands/key.rs");
const CLI_ERRORS: &str = include_str!("../../dexios/src/subcommands/errors.rs");

const DOMAIN_WORKFLOW_ERRORS_TESTS: &str = include_str!("workflow_errors.rs");
const DOMAIN_HEADER_RESTORE_TESTS: &str = include_str!("header_restore.rs");
const DOMAIN_KEYSLOTS_TESTS: &str = include_str!("keyslots_v1.rs");

#[derive(Clone, Copy)]
struct Source<'a> {
    path: &'a str,
    text: &'a str,
}

fn domain_workflow_sources() -> Vec<Source<'static>> {
    vec![
        Source {
            path: "dexios-domain/src/encrypt.rs",
            text: DOMAIN_ENCRYPT,
        },
        Source {
            path: "dexios-domain/src/decrypt.rs",
            text: DOMAIN_DECRYPT,
        },
        Source {
            path: "dexios-domain/src/header/dump.rs",
            text: DOMAIN_HEADER_DUMP,
        },
        Source {
            path: "dexios-domain/src/header/strip.rs",
            text: DOMAIN_HEADER_STRIP,
        },
        Source {
            path: "dexios-domain/src/header/restore.rs",
            text: DOMAIN_HEADER_RESTORE,
        },
        Source {
            path: "dexios-domain/src/key/add.rs",
            text: DOMAIN_KEY_ADD,
        },
        Source {
            path: "dexios-domain/src/key/change.rs",
            text: DOMAIN_KEY_CHANGE,
        },
        Source {
            path: "dexios-domain/src/key/delete.rs",
            text: DOMAIN_KEY_DELETE,
        },
        Source {
            path: "dexios-domain/src/key/verify.rs",
            text: DOMAIN_KEY_VERIFY,
        },
    ]
}

fn cli_adapter_sources() -> Vec<Source<'static>> {
    vec![
        Source {
            path: "dexios/src/subcommands/encrypt.rs",
            text: CLI_ENCRYPT,
        },
        Source {
            path: "dexios/src/subcommands/decrypt.rs",
            text: CLI_DECRYPT,
        },
        Source {
            path: "dexios/src/subcommands/header.rs",
            text: CLI_HEADER,
        },
        Source {
            path: "dexios/src/subcommands/key.rs",
            text: CLI_KEY,
        },
        Source {
            path: "dexios/src/subcommands/errors.rs",
            text: CLI_ERRORS,
        },
    ]
}

fn d05_policy_sources() -> Vec<Source<'static>> {
    let mut sources = domain_workflow_sources();
    sources.extend([
        Source {
            path: "dexios-domain/tests/workflow_errors.rs",
            text: DOMAIN_WORKFLOW_ERRORS_TESTS,
        },
        Source {
            path: "dexios-domain/tests/header_restore.rs",
            text: DOMAIN_HEADER_RESTORE_TESTS,
        },
        Source {
            path: "dexios-domain/tests/keyslots_v1.rs",
            text: DOMAIN_KEYSLOTS_TESTS,
        },
    ]);
    sources
}

fn assert_no_public_api_bypasses(sources: &[Source<'_>]) -> Result<(), String> {
    collect_violations(sources, public_api_bypass_violations)
}

fn assert_no_cli_raw_request_constructors(sources: &[Source<'_>]) -> Result<(), String> {
    collect_violations(sources, cli_raw_request_constructor_violations)
}

fn assert_no_formatted_error_control_flow(sources: &[Source<'_>]) -> Result<(), String> {
    collect_violations(sources, formatted_error_control_flow_violations)
}

fn assert_d05_test_support_escape_hatches(_sources: &[Source<'_>]) -> Result<(), String> {
    Ok(())
}

fn assert_d05_fixture_names(_sources: &[Source<'_>]) -> Result<(), String> {
    Ok(())
}

fn collect_violations(
    sources: &[Source<'_>],
    scan: fn(Source<'_>) -> Vec<String>,
) -> Result<(), String> {
    let violations: Vec<_> = sources.iter().copied().flat_map(scan).collect();

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("\n"))
    }
}

fn public_api_bypass_violations(source: Source<'_>) -> Vec<String> {
    let mut violations = Vec::new();
    let lines: Vec<_> = source.text.lines().collect();

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();

        for pattern in [
            "pub struct Request",
            "pub(crate) struct Request",
            "pub struct TransactionalRequest",
            "pub(crate) struct TransactionalRequest",
        ] {
            if trimmed.starts_with(pattern) {
                violations.push(violation(source.path, index, pattern));
            }
        }

        if starts_public_execute_signature(trimmed) {
            let signature = signature_window(&lines, index);
            if mentions_raw_request_type(&signature) {
                violations.push(violation(
                    source.path,
                    index,
                    "public execute signature accepts raw Request",
                ));
            }
        }

        if trimmed.starts_with("pub ") && trimmed.contains("RefCell") {
            violations.push(violation(
                source.path,
                index,
                "public workflow contract exposes RefCell",
            ));
        }
    }

    violations
}

fn starts_public_execute_signature(trimmed: &str) -> bool {
    [
        "pub fn execute(",
        "pub(crate) fn execute(",
        "pub fn execute_transactional(",
        "pub(crate) fn execute_transactional(",
    ]
    .into_iter()
    .any(|prefix| trimmed.starts_with(prefix))
}

fn signature_window(lines: &[&str], start: usize) -> String {
    lines
        .iter()
        .skip(start)
        .take(6)
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

fn mentions_raw_request_type(signature: &str) -> bool {
    signature.contains(" Request")
        || signature.contains("(Request")
        || signature.contains("::Request")
        || signature.contains(" TransactionalRequest")
        || signature.contains("(TransactionalRequest")
        || signature.contains("::TransactionalRequest")
}

fn cli_raw_request_constructor_violations(source: Source<'_>) -> Vec<String> {
    let mut violations = Vec::new();
    let workflow_modules = [
        "domain::encrypt",
        "domain::decrypt",
        "domain::header::dump",
        "domain::header::strip",
        "domain::header::restore",
        "domain::key::add",
        "domain::key::change",
        "domain::key::delete",
        "domain::key::verify",
    ];

    for (index, line) in source.text.lines().enumerate() {
        let compact = line.split_whitespace().collect::<String>();

        for module in workflow_modules {
            for request_type in ["Request", "TransactionalRequest"] {
                if compact.contains(&format!("{module}::{request_type}"))
                    || compact.contains(&format!("{module}::{{{request_type}"))
                    || compact.contains(&format!("{module}::{{Request,TransactionalRequest}}"))
                {
                    violations.push(violation(
                        source.path,
                        index,
                        "CLI constructs raw workflow request",
                    ));
                }
            }
        }

        for grouped in [
            "domain::header::{dump,strip,restore}::{Request,TransactionalRequest}",
            "domain::key::{add,change,delete,verify}::{Request,TransactionalRequest}",
        ] {
            if compact.contains(grouped) {
                violations.push(violation(
                    source.path,
                    index,
                    "CLI imports grouped raw workflow requests",
                ));
            }
        }
    }

    violations
}

fn formatted_error_control_flow_violations(source: Source<'_>) -> Vec<String> {
    let mut violations = Vec::new();

    for (index, line) in source.text.lines().enumerate() {
        let compact = line.split_whitespace().collect::<String>();
        let inspects_formatted_error = compact.contains(".to_string().contains(")
            || (compact.contains("format!(") && compact.contains(").contains("))
            || compact.contains(".contains(error.to_string")
            || compact.contains(".contains(err.to_string")
            || compact.contains(".contains(&error.to_string")
            || compact.contains(".contains(&err.to_string")
            || compact.contains(".contains(format!(");

        if inspects_formatted_error {
            violations.push(violation(
                source.path,
                index,
                "workflow control flow inspects formatted error text",
            ));
        }
    }

    violations
}

fn violation(path: &str, zero_based_line: usize, detail: &str) -> String {
    format!("{path}:{}: {detail}", zero_based_line + 1)
}

#[test]
fn public_workflow_api_rejects_request_structs_execute_signatures_and_refcell_contracts() {
    let bad_sources = [
        Source {
            path: "synthetic/public-request.rs",
            text: "pub struct Request { raw: () }",
        },
        Source {
            path: "synthetic/crate-request.rs",
            text: "pub(crate) struct TransactionalRequest { raw: () }",
        },
        Source {
            path: "synthetic/public-execute.rs",
            text: "pub fn execute(request: Request) -> Result<(), Error> { todo!() }",
        },
        Source {
            path: "synthetic/public-refcell.rs",
            text: "pub fn execute(reader: &std::cell::RefCell<Vec<u8>>) {}",
        },
    ];

    for source in bad_sources {
        assert!(
            assert_no_public_api_bypasses(&[source]).is_err(),
            "source gate must reject {}",
            source.path
        );
    }
}

#[test]
fn raw_workflow_bypass_scans_domain_and_cli_sources() {
    let domain_sources = domain_workflow_sources();
    assert_no_public_api_bypasses(&domain_sources).expect("domain workflow sources");

    let paths: Vec<_> = domain_sources.iter().map(|source| source.path).collect();
    for expected in [
        "dexios-domain/src/encrypt.rs",
        "dexios-domain/src/decrypt.rs",
        "dexios-domain/src/header/dump.rs",
        "dexios-domain/src/header/strip.rs",
        "dexios-domain/src/header/restore.rs",
        "dexios-domain/src/key/add.rs",
        "dexios-domain/src/key/change.rs",
        "dexios-domain/src/key/delete.rs",
        "dexios-domain/src/key/verify.rs",
    ] {
        assert!(
            paths.contains(&expected),
            "workflow_public_api must scan {expected}"
        );
    }

    let bad_cli_sources = [
        Source {
            path: "synthetic/encrypt-cli.rs",
            text: "let req = domain::encrypt::Request { raw: () };",
        },
        Source {
            path: "synthetic/header-cli.rs",
            text: "let req = domain::header::dump::TransactionalRequest { raw: () };",
        },
        Source {
            path: "synthetic/key-cli.rs",
            text: "use domain::key::change::{Request, TransactionalRequest};",
        },
    ];

    for source in bad_cli_sources {
        assert!(
            assert_no_cli_raw_request_constructors(&[source]).is_err(),
            "CLI source gate must reject {}",
            source.path
        );
    }

    assert_no_cli_raw_request_constructors(&cli_adapter_sources()).expect("CLI adapter sources");
}

#[test]
fn formatted_error_control_flow_rejects_string_inspection() {
    let bad_sources = [
        Source {
            path: "synthetic/to-string.rs",
            text: r#"if error.to_string().contains("missing payload") { return Ok(()); }"#,
        },
        Source {
            path: "synthetic/format.rs",
            text: r#"if format!("{err}").contains("unsupported") { return Ok(()); }"#,
        },
        Source {
            path: "synthetic/contains-to-string.rs",
            text: "if message.contains(error.to_string().as_str()) { return Ok(()); }",
        },
    ];

    for source in bad_sources {
        assert!(
            assert_no_formatted_error_control_flow(&[source]).is_err(),
            "formatted-error control-flow gate must reject {}",
            source.path
        );
    }

    assert_no_formatted_error_control_flow(&domain_workflow_sources())
        .expect("domain workflow sources");
    assert_no_formatted_error_control_flow(&cli_adapter_sources()).expect("CLI adapter sources");
}

#[test]
fn test_support_escape_hatches_are_scoped_and_named_by_d05() {
    let bad_production_sources = [
        Source {
            path: "synthetic/unchecked-production-helper.rs",
            text: "pub fn unchecked_request_builder() {}",
        },
        Source {
            path: "synthetic/bypass-production-module.rs",
            text: "pub mod bypass_request_builders {}",
        },
    ];

    for source in bad_production_sources {
        assert!(
            assert_d05_test_support_escape_hatches(&[source]).is_err(),
            "D-05 gate must reject production-visible escape hatch in {}",
            source.path
        );
    }

    assert_d05_test_support_escape_hatches(&d05_policy_sources())
        .expect("D-05 source and test-support placement");
}

#[test]
fn d05_fixture_helpers_are_valid_by_default_or_explicitly_negative() {
    let bad_fixture_name = Source {
        path: "synthetic/ambiguous-fixture.rs",
        text: "fn broken_header_fixture() {}",
    };
    assert!(
        assert_d05_fixture_names(&[bad_fixture_name]).is_err(),
        "D-05 fixture gate must reject ambiguous invalid-state fixture names"
    );

    let allowed_fixture_names = Source {
        path: "synthetic/allowed-fixtures.rs",
        text: r#"
            fn encrypted_v1_fixture() {}
            fn valid_header_fixture() {}
            fn invalid_header_fixture() {}
            fn malformed_v1_fixture() {}
            fn unsupported_format_fixture() {}
        "#,
    };
    assert_d05_fixture_names(&[allowed_fixture_names])
        .expect("valid and explicitly negative fixture names");

    assert_d05_fixture_names(&d05_policy_sources()).expect("D-05 fixture/helper names");
}

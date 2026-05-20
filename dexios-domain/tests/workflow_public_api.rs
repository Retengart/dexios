const DOMAIN_CARGO_TOML: &str = include_str!("../Cargo.toml");

const DOMAIN_WORKFLOW_ERROR: &str = include_str!("../src/workflow_error.rs");
const DOMAIN_ENCRYPT: &str = include_str!("../src/encrypt.rs");
const DOMAIN_DECRYPT: &str = include_str!("../src/decrypt.rs");
const DOMAIN_PACK: &str = include_str!("../src/pack.rs");
const DOMAIN_UNPACK: &str = include_str!("../src/unpack.rs");
const DOMAIN_HEADER: &str = include_str!("../src/header.rs");
const DOMAIN_HEADER_DUMP: &str = include_str!("../src/header/dump.rs");
const DOMAIN_HEADER_STRIP: &str = include_str!("../src/header/strip.rs");
const DOMAIN_HEADER_RESTORE: &str = include_str!("../src/header/restore.rs");
const DOMAIN_KEY: &str = include_str!("../src/key.rs");
const DOMAIN_KEY_ADD: &str = include_str!("../src/key/add.rs");
const DOMAIN_KEY_CHANGE: &str = include_str!("../src/key/change.rs");
const DOMAIN_KEY_DELETE: &str = include_str!("../src/key/delete.rs");
const DOMAIN_KEY_VERIFY: &str = include_str!("../src/key/verify.rs");
const STORAGE_MOD: &str = include_str!("../src/storage/mod.rs");
const STORAGE_TEST_SUPPORT: &str = include_str!("../src/storage/test_support.rs");
const STORAGE_IDENTITY: &str = include_str!("../src/storage/identity.rs");
const STORAGE_TRANSACTION: &str = include_str!("../src/storage/transaction.rs");
const STORAGE_TEMP: &str = include_str!("../src/storage/temp.rs");
const STORAGE_CLEANUP: &str = include_str!("../src/storage/cleanup.rs");

const CLI_MAIN: &str = include_str!("../../dexios/src/main.rs");
const CLI_SUBCOMMANDS: &str = include_str!("../../dexios/src/subcommands.rs");
const CLI_ENCRYPT: &str = include_str!("../../dexios/src/subcommands/encrypt.rs");
const CLI_DECRYPT: &str = include_str!("../../dexios/src/subcommands/decrypt.rs");
const CLI_PACK: &str = include_str!("../../dexios/src/subcommands/pack.rs");
const CLI_UNPACK: &str = include_str!("../../dexios/src/subcommands/unpack.rs");
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
            path: "dexios-domain/src/workflow_error.rs",
            text: DOMAIN_WORKFLOW_ERROR,
        },
        Source {
            path: "dexios-domain/src/encrypt.rs",
            text: DOMAIN_ENCRYPT,
        },
        Source {
            path: "dexios-domain/src/decrypt.rs",
            text: DOMAIN_DECRYPT,
        },
        Source {
            path: "dexios-domain/src/pack.rs",
            text: DOMAIN_PACK,
        },
        Source {
            path: "dexios-domain/src/unpack.rs",
            text: DOMAIN_UNPACK,
        },
        Source {
            path: "dexios-domain/src/header.rs",
            text: DOMAIN_HEADER,
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
            path: "dexios-domain/src/key.rs",
            text: DOMAIN_KEY,
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
            path: "dexios/src/main.rs",
            text: CLI_MAIN,
        },
        Source {
            path: "dexios/src/subcommands.rs",
            text: CLI_SUBCOMMANDS,
        },
        Source {
            path: "dexios/src/subcommands/encrypt.rs",
            text: CLI_ENCRYPT,
        },
        Source {
            path: "dexios/src/subcommands/decrypt.rs",
            text: CLI_DECRYPT,
        },
        Source {
            path: "dexios/src/subcommands/pack.rs",
            text: CLI_PACK,
        },
        Source {
            path: "dexios/src/subcommands/unpack.rs",
            text: CLI_UNPACK,
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
        Source {
            path: "dexios-domain/src/storage/mod.rs",
            text: STORAGE_MOD,
        },
        Source {
            path: "dexios-domain/src/storage/test_support.rs",
            text: STORAGE_TEST_SUPPORT,
        },
        Source {
            path: "dexios-domain/src/storage/identity.rs",
            text: STORAGE_IDENTITY,
        },
        Source {
            path: "dexios-domain/src/storage/transaction.rs",
            text: STORAGE_TRANSACTION,
        },
        Source {
            path: "dexios-domain/src/storage/temp.rs",
            text: STORAGE_TEMP,
        },
        Source {
            path: "dexios-domain/src/storage/cleanup.rs",
            text: STORAGE_CLEANUP,
        },
    ]);
    sources
}

fn phase04_migration_sources() -> Vec<Source<'static>> {
    let mut sources = domain_workflow_sources();
    sources.extend(cli_adapter_sources());
    sources.extend([
        Source {
            path: "dexios-domain/src/storage/mod.rs",
            text: STORAGE_MOD,
        },
        Source {
            path: "dexios-domain/src/storage/test_support.rs",
            text: STORAGE_TEST_SUPPORT,
        },
        Source {
            path: "dexios-domain/src/storage/transaction.rs",
            text: STORAGE_TRANSACTION,
        },
        Source {
            path: "dexios-domain/src/storage/temp.rs",
            text: STORAGE_TEMP,
        },
        Source {
            path: "dexios-domain/src/storage/cleanup.rs",
            text: STORAGE_CLEANUP,
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

fn assert_d05_test_support_escape_hatches(sources: &[Source<'_>]) -> Result<(), String> {
    collect_violations(sources, d05_escape_hatch_violations)
}

fn assert_d05_fixture_names(sources: &[Source<'_>]) -> Result<(), String> {
    collect_violations(sources, d05_fixture_name_violations)
}

fn assert_test_support_feature_is_non_default(manifest: &str) -> Result<(), String> {
    let test_support = feature_items(manifest, "test-support")
        .ok_or_else(|| "dexios-domain Cargo.toml must declare test-support feature".to_string())?;
    if !test_support.is_empty() {
        return Err("test-support feature should not enable additional features".to_string());
    }

    let default_features = feature_items(manifest, "default")
        .ok_or_else(|| "dexios-domain Cargo.toml must declare default features".to_string())?;
    if default_features.contains(&"test-support") {
        return Err("test-support must not be enabled by default".to_string());
    }

    Ok(())
}

fn feature_items<'a>(manifest: &'a str, feature: &str) -> Option<Vec<&'a str>> {
    let prefix = format!("{feature} = [");
    let line = manifest
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))?;
    let items = line
        .strip_prefix(&prefix)?
        .strip_suffix(']')?
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.trim_matches('"'))
        .collect();
    Some(items)
}

fn assert_public_test_support_export_is_cfg_gated(source: Source<'_>) -> Result<(), String> {
    let lines: Vec<_> = source.text.lines().collect();
    let Some(index) = lines
        .iter()
        .position(|line| is_test_support_export(line.trim_start()))
    else {
        return Err(format!(
            "{}: missing public test_support export",
            source.path
        ));
    };

    if has_test_support_cfg_before(&lines, index) {
        Ok(())
    } else {
        Err(violation(
            source.path,
            index,
            "D-05 test_support export must be cfg-gated",
        ))
    }
}

fn assert_failure_hook_entrypoints_are_cfg_gated(sources: &[Source<'_>]) -> Result<(), String> {
    let mut violations = Vec::new();

    for source in sources {
        let lines: Vec<_> = source.text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if is_public_failure_hook_declaration(trimmed)
                && !has_test_support_cfg_before(&lines, index)
            {
                violations.push(violation(
                    source.path,
                    index,
                    "D-05 failure-hook entry point must be cfg-gated",
                ));
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("\n"))
    }
}

fn has_test_support_cfg_before(lines: &[&str], index: usize) -> bool {
    lines[..index]
        .iter()
        .rev()
        .take(4)
        .map(|line| line.trim_start())
        .any(is_test_or_test_support_cfg)
}

fn assert_retained_public_storage_exports() {
    for expected in [
        "pub use entry::{Entry, FileData};",
        "pub use fs::FileStorage;",
        "pub use temp::{NamedStagedOutput, TempArtifact};",
        "pub enum Error",
        "pub trait Storage",
    ] {
        assert!(
            STORAGE_MOD.contains(expected),
            "D-06 storage public API must retain {expected}"
        );
    }

    for expected in [
        "pub enum PathRole",
        "pub enum OverwritePolicy",
        "pub struct ResolvedTarget",
        "pub enum IdentityError",
        "pub struct PathIdentityGraph",
    ] {
        assert!(
            STORAGE_IDENTITY.contains(expected),
            "D-06 identity public API must retain {expected}"
        );
    }

    for expected in [
        "pub struct CommitReceipt",
        "pub struct CommittedArtifact",
        "pub enum TransactionError",
        "pub struct StagedOutputTransaction",
        "pub struct LinkedOutputTransaction",
    ] {
        assert!(
            STORAGE_TRANSACTION.contains(expected),
            "D-07 transaction evidence API must retain {expected}"
        );
    }

    for expected in [
        "pub enum CleanupTargetKind",
        "pub struct CleanupTarget",
        "pub struct CleanupFailure",
        "pub struct CleanupResult",
        "pub struct CleanupReceipt",
        "pub enum HashVerification",
        "pub struct PostCommitSuccess",
        "pub enum CleanupGateError",
    ] {
        assert!(
            STORAGE_CLEANUP.contains(expected),
            "D-07 cleanup evidence API must retain {expected}"
        );
    }

    for sealed in [
        "pub(crate) fn file(",
        "pub(crate) fn directory(",
        "pub(crate) fn new(targets:",
    ] {
        assert!(
            STORAGE_CLEANUP.contains(sealed),
            "APIS-03 cleanup constructor must be crate-sealed: {sealed}"
        );
    }

    for forbidden in [
        "pub path: PathBuf",
        "pub kind: CleanupTargetKind",
        "pub identity: CleanupTargetIdentity",
        "pub targets: Vec<CleanupTarget>",
    ] {
        assert!(
            !STORAGE_CLEANUP.contains(forbidden),
            "APIS-04 cleanup receipt state must not be externally constructible: {forbidden}"
        );
    }
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
        "domain::unpack",
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
    let mut formatted_error_bindings: Vec<(String, usize)> = Vec::new();
    let mut test_context = TestContext::new(source.path);
    let mut brace_depth = 0usize;

    for (index, line) in source.text.lines().enumerate() {
        let trimmed = line.trim_start();
        test_context.update_before_line(trimmed);
        formatted_error_bindings.retain(|(_, depth)| *depth <= brace_depth);

        if test_context.is_test_only() {
            test_context.update_after_line(trimmed);
            brace_depth = apply_brace_delta(brace_depth, trimmed);
            continue;
        }

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

        if let Some(binding) = formatted_error_binding_name(&compact) {
            formatted_error_bindings.push((binding, brace_depth));
        }

        for (binding, _) in &formatted_error_bindings {
            if binding_contains_call(&compact, binding) {
                violations.push(violation(
                    source.path,
                    index,
                    "workflow control flow inspects formatted error text through an intermediate binding",
                ));
            }
        }

        test_context.update_after_line(trimmed);
        brace_depth = apply_brace_delta(brace_depth, trimmed);
    }

    violations
}

fn formatted_error_binding_name(compact: &str) -> Option<String> {
    let (_, rhs) = compact.split_once('=')?;
    let rhs_is_formatted_error =
        formatted_error_to_string_receiver(rhs) || format_uses_error_identifier(rhs);
    if !rhs_is_formatted_error {
        return None;
    }

    let binding = compact
        .strip_prefix("letmut")
        .or_else(|| compact.strip_prefix("let"))?;
    let (name, _) = binding.split_once('=')?;
    let name = name.split_once(':').map_or(name, |(name, _)| name);
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn formatted_error_to_string_receiver(rhs: &str) -> bool {
    let Some((receiver, _)) = rhs.split_once(".to_string()") else {
        return false;
    };
    let receiver = receiver
        .trim_start_matches('&')
        .trim_start_matches('(')
        .trim_end_matches(')');
    receiver == "err"
        || receiver.ends_with("_err")
        || receiver == "error"
        || receiver.ends_with("_error")
}

fn format_uses_error_identifier(rhs: &str) -> bool {
    let Some((_, format_args)) = rhs.split_once("format!(") else {
        return false;
    };

    format_interpolates_error_identifier(format_args)
        || format_passes_error_identifier_argument(format_args)
}

fn format_interpolates_error_identifier(format_args: &str) -> bool {
    let mut rest = format_args;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        if let Some(stripped) = after_open.strip_prefix('{') {
            rest = stripped;
            continue;
        }

        let identifier_end = after_open
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .unwrap_or(after_open.len());
        if is_error_identifier(&after_open[..identifier_end]) {
            return true;
        }
        rest = &after_open[identifier_end..];
    }

    false
}

fn format_passes_error_identifier_argument(format_args: &str) -> bool {
    let Some(argument_tail) = format_args_after_first_comma(format_args) else {
        return false;
    };

    contains_error_identifier_outside_string(argument_tail)
}

fn format_args_after_first_comma(format_args: &str) -> Option<&str> {
    let mut in_string = false;
    let mut escaped = false;

    for (index, ch) in format_args.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
        } else if ch == ',' {
            return Some(&format_args[index + 1..]);
        } else if ch == ')' {
            return None;
        }
    }

    None
}

fn contains_error_identifier_outside_string(text: &str) -> bool {
    let mut in_string = false;
    let mut escaped = false;
    let mut identifier = String::new();

    for ch in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            if is_error_identifier(&identifier) {
                return true;
            }
            identifier.clear();
            in_string = true;
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            identifier.push(ch);
        } else {
            if is_error_identifier(&identifier) {
                return true;
            }
            identifier.clear();
        }
    }

    is_error_identifier(&identifier)
}

fn is_error_identifier(identifier: &str) -> bool {
    identifier == "err"
        || identifier.ends_with("_err")
        || identifier == "error"
        || identifier.ends_with("_error")
}

fn binding_contains_call(compact: &str, binding: &str) -> bool {
    [
        format!("{binding}.contains("),
        format!("{binding}.as_str().contains("),
        format!("(&{binding}).contains("),
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

fn d05_escape_hatch_violations(source: Source<'_>) -> Vec<String> {
    let mut violations = Vec::new();
    let mut test_context = TestContext::new(source.path);

    for (index, line) in source.text.lines().enumerate() {
        let trimmed = line.trim_start();
        test_context.update_before_line(trimmed);

        if !test_context.is_test_only()
            && declaration_name(trimmed).is_some_and(is_escape_hatch_declaration)
        {
            violations.push(violation(
                source.path,
                index,
                "D-05 escape hatch must be test-only or test-support scoped",
            ));
        }

        if !test_context.is_test_only() && is_public_failure_hook_declaration(trimmed) {
            violations.push(violation(
                source.path,
                index,
                "D-05 failure hooks must be test-support scoped",
            ));
        }

        if !test_context.is_test_only() && is_test_support_export(trimmed) {
            violations.push(violation(
                source.path,
                index,
                "D-05 test_support export must be cfg(test) or feature-gated",
            ));
        }

        if !test_context.is_test_only() && is_failure_injection_trigger(trimmed) {
            violations.push(violation(
                source.path,
                index,
                "D-05 failure injection must not be exposed through production env or CLI triggers",
            ));
        }

        test_context.update_after_line(trimmed);
    }

    violations
}

fn d05_fixture_name_violations(source: Source<'_>) -> Vec<String> {
    let mut violations = Vec::new();
    let mut test_context = TestContext::new(source.path);
    let mut pending_test_attribute = false;

    for (index, line) in source.text.lines().enumerate() {
        let trimmed = line.trim_start();
        test_context.update_before_line(trimmed);

        if trimmed.starts_with("#[test]") {
            pending_test_attribute = true;
            test_context.update_after_line(trimmed);
            continue;
        }

        if test_context.is_test_only()
            && let Some(name) = declaration_name(trimmed)
        {
            if pending_test_attribute {
                pending_test_attribute = false;
                test_context.update_after_line(trimmed);
                continue;
            }

            if is_fixture_or_helper_name(name)
                && has_ambiguous_invalid_word(name)
                && !has_explicit_negative_word(name)
            {
                violations.push(violation(
                    source.path,
                    index,
                    "D-05 invalid-state helper needs explicit negative wording",
                ));
            }
        }

        if !trimmed.starts_with("#[") && !trimmed.is_empty() {
            pending_test_attribute = false;
        }

        test_context.update_after_line(trimmed);
    }

    violations
}

struct TestContext {
    integration_test: bool,
    test_support_file: bool,
    cfg_test_pending: bool,
    cfg_test_depth: usize,
    cfg_item_waiting_for_body: bool,
}

impl TestContext {
    fn new(path: &str) -> Self {
        Self {
            integration_test: path.contains("/tests/"),
            test_support_file: path.ends_with("/test_support.rs"),
            cfg_test_pending: false,
            cfg_test_depth: 0,
            cfg_item_waiting_for_body: false,
        }
    }

    fn is_test_only(&self) -> bool {
        self.integration_test
            || self.test_support_file
            || self.cfg_test_depth > 0
            || self.cfg_test_pending
            || self.cfg_item_waiting_for_body
    }

    fn update_before_line(&mut self, trimmed: &str) {
        if is_test_or_test_support_cfg(trimmed) {
            self.cfg_test_pending = true;
        }

        if self.cfg_test_pending && declares_cfg_scoped_item(trimmed) {
            self.cfg_test_pending = false;
            self.cfg_item_waiting_for_body = true;
        }
    }

    fn update_after_line(&mut self, trimmed: &str) {
        if self.cfg_item_waiting_for_body {
            if trimmed.contains('{') {
                self.cfg_test_depth = brace_delta(trimmed).max(0) as usize;
                self.cfg_item_waiting_for_body = false;
            } else if trimmed.ends_with(';') {
                self.cfg_item_waiting_for_body = false;
            }
            return;
        }

        if self.cfg_test_depth > 0 {
            let delta = brace_delta(trimmed);
            if delta.is_negative() {
                self.cfg_test_depth = self.cfg_test_depth.saturating_sub(delta.unsigned_abs());
            } else {
                self.cfg_test_depth = self.cfg_test_depth.saturating_add(delta as usize);
            }
        } else if self.cfg_test_pending && !is_test_or_test_support_cfg(trimmed) {
            self.cfg_test_pending = false;
        }
    }
}

fn is_test_or_test_support_cfg(trimmed: &str) -> bool {
    trimmed.starts_with("#[cfg(test)]")
        || (trimmed.starts_with("#[cfg(") && trimmed.contains("feature = \"test-support\""))
}

fn declares_cfg_scoped_item(trimmed: &str) -> bool {
    [
        "fn ",
        "pub fn ",
        "pub(crate) fn ",
        "mod ",
        "pub mod ",
        "pub(crate) mod ",
        "impl ",
    ]
    .into_iter()
    .any(|prefix| trimmed.starts_with(prefix))
}

fn brace_delta(line: &str) -> isize {
    let opens = line.chars().filter(|ch| *ch == '{').count() as isize;
    let closes = line.chars().filter(|ch| *ch == '}').count() as isize;
    opens - closes
}

fn apply_brace_delta(depth: usize, line: &str) -> usize {
    let delta = brace_delta(line);
    if delta.is_negative() {
        depth.saturating_sub(delta.unsigned_abs())
    } else {
        depth.saturating_add(delta as usize)
    }
}

fn declaration_name(trimmed: &str) -> Option<&str> {
    for prefix in [
        "pub(crate) fn ",
        "pub fn ",
        "fn ",
        "pub(crate) mod ",
        "pub mod ",
        "mod ",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let name_end = rest
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .unwrap_or(rest.len());
            return Some(&rest[..name_end]);
        }
    }

    None
}

fn is_escape_hatch_declaration(name: &str) -> bool {
    let has_escape_word = ["raw", "unchecked", "bypass"]
        .into_iter()
        .any(|word| name.contains(word));
    let has_request_word = [
        "request", "intent", "workflow", "builder", "helper", "fixture",
    ]
    .into_iter()
    .any(|word| name.contains(word));

    has_escape_word && has_request_word
}

fn is_public_failure_hook_declaration(trimmed: &str) -> bool {
    (trimmed.starts_with("pub fn ") || trimmed.starts_with("pub(crate) fn "))
        && trimmed.contains("with_failure_hooks")
}

fn is_test_support_export(trimmed: &str) -> bool {
    trimmed.starts_with("pub mod test_support") || trimmed.starts_with("pub use test_support")
}

fn is_failure_injection_trigger(trimmed: &str) -> bool {
    let compact = trimmed.split_whitespace().collect::<String>();
    let lower = compact.to_ascii_lowercase();
    let has_failure_word = ["fail", "failure", "hook", "test-support", "test_support"]
        .into_iter()
        .any(|word| lower.contains(word));
    let reads_env = lower.contains("std::env::var(")
        || lower.contains("std::env::var_os(")
        || lower.contains("env::var(")
        || lower.contains("env::var_os(");
    let adds_cli_trigger = lower.contains("arg::new(\"") || lower.contains(".long(\"");

    has_failure_word && (reads_env || adds_cli_trigger)
}

fn is_fixture_or_helper_name(name: &str) -> bool {
    name.contains("fixture")
        || name.contains("sample")
        || name.starts_with("write_")
        || name.starts_with("mark_")
        || name.starts_with("build_")
        || name.starts_with("make_")
        || name.starts_with("append_")
}

fn has_explicit_negative_word(name: &str) -> bool {
    [
        "invalid",
        "malformed",
        "negative",
        "corrupt",
        "short",
        "trailing",
        "unsupported",
    ]
    .into_iter()
    .any(|word| name.contains(word))
}

fn has_ambiguous_invalid_word(name: &str) -> bool {
    [
        "bad",
        "broken",
        "wrong",
        "failing",
        "unsafe",
        "unchecked",
        "bypass",
        "raw",
    ]
    .into_iter()
    .any(|word| name.contains(word))
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
            path: "synthetic/public-unpack-request.rs",
            text: "pub struct Request<'a> { reader: &'a std::cell::RefCell<Vec<u8>> }",
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
        "dexios-domain/src/unpack.rs",
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
        Source {
            path: "synthetic/unpack-cli.rs",
            text: "let req = domain::unpack::Request { raw: () };",
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
        Source {
            path: "synthetic/indirect-rendered-error.rs",
            text: r#"
                let rendered = error.to_string();
                if rendered.contains("unsupported") {
                    return Ok(());
                }
            "#,
        },
        Source {
            path: "synthetic/indirect-rendered-error-as-str.rs",
            text: r#"
                let rendered = error.to_string();
                if rendered.as_str().contains("unsupported") {
                    return Ok(());
                }
            "#,
        },
        Source {
            path: "synthetic/indirect-workflow-error.rs",
            text: r#"
                let rendered = workflow_error.to_string();
                if rendered.contains("unsupported") {
                    return Ok(());
                }
            "#,
        },
        Source {
            path: "synthetic/indirect-format-workflow-error.rs",
            text: r#"
                let rendered = format!("{workflow_error}");
                if rendered.contains("unsupported") {
                    return Ok(());
                }
            "#,
        },
        Source {
            path: "synthetic/indirect-format-workflow-error-argument.rs",
            text: r#"
                let rendered = format!("{}", workflow_error);
                if rendered.contains("unsupported") {
                    return Ok(());
                }
            "#,
        },
    ];

    for source in bad_sources {
        assert!(
            assert_no_formatted_error_control_flow(&[source]).is_err(),
            "formatted-error control-flow gate must reject {}",
            source.path
        );
    }

    let allowed_sources = [
        Source {
            path: "synthetic/unrelated-rebinding.rs",
            text: r#"
                fn render_error(error: WorkflowError) -> String {
                    let rendered = error.to_string();
                    rendered
                }

                fn classify_message(message: &str) -> bool {
                    let rendered = message.trim();
                    rendered.contains("unsupported")
                }
            "#,
        },
        Source {
            path: "synthetic/unrelated-format-string.rs",
            text: r#"
                let rendered = format!("{}", "workflow_error");
                if rendered.contains("workflow_error") {
                    return Ok(());
                }
            "#,
        },
        Source {
            path: "synthetic/cfg-test-message-assertion.rs",
            text: r#"
                #[cfg(test)]
                mod tests {
                    #[test]
                    fn reports_unsupported_error() {
                        let error = build_error();
                        let rendered = error.to_string();
                        assert!(rendered.contains("unsupported"));
                    }
                }
            "#,
        },
        Source {
            path: "synthetic/cfg-test-function-message-assertion.rs",
            text: r#"
                #[cfg(test)]
                fn reports_unsupported_error() {
                    let error = build_error();
                    let rendered = error.to_string();
                    assert!(rendered.contains("unsupported"));
                }
            "#,
        },
        Source {
            path: "synthetic/test-support-function-message-assertion.rs",
            text: r#"
                #[cfg(feature = "test-support")]
                pub(crate) fn assert_test_support_error(error: WorkflowError) {
                    let rendered = error.to_string();
                    assert!(rendered.contains("unsupported"));
                }
            "#,
        },
        Source {
            path: "synthetic/cfg-test-multiline-function-message-assertion.rs",
            text: r#"
                #[cfg(test)]
                fn reports_unsupported_error(
                    error: WorkflowError,
                ) {
                    let rendered = error.to_string();
                    assert!(rendered.contains("unsupported"));
                }
            "#,
        },
        Source {
            path: "synthetic/test-support-multiline-function-message-assertion.rs",
            text: r#"
                #[cfg(feature = "test-support")]
                pub(crate) fn assert_test_support_error(
                    error: WorkflowError,
                ) {
                    let rendered = error.to_string();
                    assert!(rendered.contains("unsupported"));
                }
            "#,
        },
    ];

    for source in allowed_sources {
        assert!(
            assert_no_formatted_error_control_flow(&[source]).is_ok(),
            "formatted-error control-flow gate must allow {}",
            source.path
        );
    }

    assert_no_formatted_error_control_flow(&domain_workflow_sources())
        .expect("domain workflow sources");
    assert_no_formatted_error_control_flow(&cli_adapter_sources()).expect("CLI adapter sources");
}

#[test]
fn phase04_source_gates_cover_all_migration_boundary_sources() {
    let domain_paths: Vec<_> = domain_workflow_sources()
        .iter()
        .map(|source| source.path)
        .collect();
    for expected in [
        "dexios-domain/src/workflow_error.rs",
        "dexios-domain/src/pack.rs",
        "dexios-domain/src/header.rs",
        "dexios-domain/src/key.rs",
    ] {
        assert!(
            domain_paths.contains(&expected),
            "workflow_public_api must scan {expected}"
        );
    }

    let cli_paths: Vec<_> = cli_adapter_sources()
        .iter()
        .map(|source| source.path)
        .collect();
    for expected in [
        "dexios/src/main.rs",
        "dexios/src/subcommands.rs",
        "dexios/src/subcommands/pack.rs",
    ] {
        assert!(
            cli_paths.contains(&expected),
            "workflow_public_api must scan {expected}"
        );
    }
}

#[test]
fn test_support_escape_hatches_are_scoped_and_named_by_d05() {
    let bad_manifest = r#"
        [features]
        default = ["test-support"]
        test-support = []
    "#;
    assert!(
        assert_test_support_feature_is_non_default(bad_manifest).is_err(),
        "D-05 gate must reject test-support in default features"
    );

    let bad_production_sources = [
        Source {
            path: "synthetic/unchecked-production-helper.rs",
            text: "pub fn unchecked_request_builder() {}",
        },
        Source {
            path: "synthetic/bypass-production-module.rs",
            text: "pub mod bypass_request_builders {}",
        },
        Source {
            path: "synthetic/public-failure-hooks.rs",
            text: "pub fn with_failure_hooks() {}",
        },
        Source {
            path: "synthetic/unscoped-test-support.rs",
            text: "pub mod test_support;",
        },
        Source {
            path: "synthetic/env-failure-hook.rs",
            text: r#"let _ = std::env::var("DEXIOS_FAIL_POINT");"#,
        },
        Source {
            path: "synthetic/cli-failure-hook.rs",
            text: r#"Command::new("dexios").arg(Arg::new("fail-on").long("fail-on"));"#,
        },
    ];

    for source in bad_production_sources {
        assert!(
            assert_d05_test_support_escape_hatches(&[source]).is_err(),
            "D-05 gate must reject production-visible escape hatch in {}",
            source.path
        );
    }

    assert_test_support_feature_is_non_default(DOMAIN_CARGO_TOML)
        .expect("test-support must be an explicit non-default feature");
    assert_public_test_support_export_is_cfg_gated(Source {
        path: "dexios-domain/src/storage/mod.rs",
        text: STORAGE_MOD,
    })
    .expect("storage::test_support export must be cfg-gated");
    assert_failure_hook_entrypoints_are_cfg_gated(&[
        Source {
            path: "dexios-domain/src/storage/transaction.rs",
            text: STORAGE_TRANSACTION,
        },
        Source {
            path: "dexios-domain/src/storage/temp.rs",
            text: STORAGE_TEMP,
        },
        Source {
            path: "dexios-domain/src/storage/cleanup.rs",
            text: STORAGE_CLEANUP,
        },
    ])
    .expect("failure-hook entry points must be cfg-gated");
    assert_retained_public_storage_exports();

    assert_d05_test_support_escape_hatches(&d05_policy_sources())
        .expect("D-05 source and test-support placement");
    assert_d05_test_support_escape_hatches(&phase04_migration_sources())
        .expect("Phase 4 migration sources keep failure injection test-scoped");
}

#[test]
fn d05_fixture_helpers_are_valid_by_default_or_explicitly_negative() {
    let bad_fixture_name = Source {
        path: "dexios-domain/tests/ambiguous_fixture.rs",
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

use std::fs;
use std::path::Path;

const DOMAIN_PACK: &str = include_str!("../src/pack.rs");
const DOMAIN_UNPACK: &str = include_str!("../src/unpack.rs");
const CLI_STATES: &str = include_str!("../../dexios/src/global/states.rs");
const CLI_PARAMETERS: &str = include_str!("../../dexios/src/global/parameters.rs");
const CLI: &str = include_str!("../../dexios/src/cli.rs");
const CLI_PACK: &str = include_str!("../../dexios/src/subcommands/pack.rs");
const CLI_UNPACK: &str = include_str!("../../dexios/src/subcommands/unpack.rs");
const CLI_ERRORS: &str = include_str!("../../dexios/src/subcommands/errors.rs");

#[derive(Clone, Copy)]
struct Source<'a> {
    path: &'a str,
    text: &'a str,
}

fn archive_source_text() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/archive.rs");
    fs::read_to_string(path).unwrap_or_default()
}

fn domain_archive_sources(archive: &str) -> Vec<Source<'_>> {
    vec![
        Source {
            path: "dexios-domain/src/pack.rs",
            text: DOMAIN_PACK,
        },
        Source {
            path: "dexios-domain/src/unpack.rs",
            text: DOMAIN_UNPACK,
        },
        Source {
            path: "dexios-domain/src/archive.rs",
            text: archive,
        },
    ]
}

fn cli_archive_sources() -> Vec<Source<'static>> {
    vec![
        Source {
            path: "dexios/src/global/states.rs",
            text: CLI_STATES,
        },
        Source {
            path: "dexios/src/global/parameters.rs",
            text: CLI_PARAMETERS,
        },
        Source {
            path: "dexios/src/cli.rs",
            text: CLI,
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
            path: "dexios/src/subcommands/errors.rs",
            text: CLI_ERRORS,
        },
    ]
}

#[test]
fn d01_domain_archive_contracts_do_not_expose_zip_crate_api_types() {
    let archive = archive_source_text();
    let violations = collect_violations(&domain_archive_sources(&archive), |source| {
        source
            .text
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let trimmed = line.trim_start();
                if public_line_exposes_zip_type(trimmed) {
                    Some(violation(
                        source.path,
                        index,
                        "D-01 public archive contracts must use Dexios-owned policy types, not zip crate API types",
                    ))
                } else {
                    None
                }
            })
            .collect()
    });

    assert_no_violations(violations);
}

#[test]
fn d03_public_archive_policy_has_no_stored_or_no_compression_variant() {
    let archive = archive_source_text();
    let violations = collect_violations(&domain_archive_sources(&archive), |source| {
        source
            .text
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let trimmed = line.trim();
                if public_stored_or_no_compression_policy(trimmed) {
                    Some(violation(
                        source.path,
                        index,
                        "D-03 public archive policy must not expose Stored or no-compression modes",
                    ))
                } else {
                    None
                }
            })
            .collect()
    });

    assert_no_violations(violations);
}

#[test]
fn d05_public_archive_contract_has_no_zip_metadata_knobs() {
    let archive = archive_source_text();
    let violations = collect_violations(&domain_archive_sources(&archive), |source| {
        source
            .text
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let trimmed = line.trim_start();
                if public_line_exposes_zip_metadata_knob(trimmed) {
                    Some(violation(
                        source.path,
                        index,
                        "D-05 public archive metadata contract is path plus file/directory only",
                    ))
                } else {
                    None
                }
            })
            .collect()
    });

    assert_no_violations(violations);
}

#[test]
fn d03_cli_exposes_no_stored_or_no_compression_selector() {
    let violations = collect_violations(&cli_archive_sources(), |source| {
        source
            .text
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let compact = line.split_whitespace().collect::<String>();
                if cli_exposes_compression_selector(&compact) {
                    Some(violation(
                        source.path,
                        index,
                        "D-03 CLI must not expose Stored/no-compression or a compression selector",
                    ))
                } else {
                    None
                }
            })
            .collect()
    });

    assert_no_violations(violations);
}

#[test]
fn d02_d04_pack_source_keeps_private_zstd_offline_archive_boundary() {
    assert!(
        DOMAIN_PACK.contains("zip::CompressionMethod::Zstd"),
        "D-02 private ZIP writer setup should map the Dexios default policy to Zstd"
    );
    assert!(
        DOMAIN_PACK.contains("offline") && DOMAIN_PACK.contains("at-rest"),
        "D-04 pack compression must stay framed as offline at-rest archival"
    );

    let violations = collect_violations(
        &[Source {
            path: "dexios-domain/src/pack.rs",
            text: DOMAIN_PACK,
        }],
        |source| {
            source
                .text
                .lines()
                .enumerate()
                .filter_map(|(index, line)| {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("pub ") && trimmed.contains("zip::CompressionMethod") {
                        Some(violation(
                            source.path,
                            index,
                            "D-01 only private implementation code may mention zip::CompressionMethod",
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        },
    );

    assert_no_violations(violations);
}

#[test]
fn d10_pack_execution_requires_validated_domain_intent() {
    assert!(
        DOMAIN_PACK.contains("pub struct PackIntent"),
        "D-10 public pack execution must be anchored on a validated PackIntent"
    );

    let domain_violations = collect_violations(
        &[Source {
            path: "dexios-domain/src/pack.rs",
            text: DOMAIN_PACK,
        }],
        |source| {
            source
                .text
                .lines()
                .enumerate()
                .filter_map(|(index, line)| {
                    let trimmed = line.trim_start();
                    if public_raw_pack_execution_bypass(trimmed) {
                        Some(violation(
                            source.path,
                            index,
                            "D-10 public pack APIs must not expose raw request or entry construction bypasses",
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        },
    );
    assert_no_violations(domain_violations);

    let cli_violations = collect_violations(
        &[Source {
            path: "dexios/src/subcommands/pack.rs",
            text: CLI_PACK,
        }],
        |source| {
            source
                .text
                .lines()
                .enumerate()
                .filter_map(|(index, line)| {
                    let compact = line.split_whitespace().collect::<String>();
                    if cli_constructs_raw_pack_request_or_entry(&compact) {
                        Some(violation(
                            source.path,
                            index,
                            "D-10 CLI must construct PackIntent, not raw domain pack requests or entries",
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        },
    );
    assert_no_violations(cli_violations);
}

#[test]
fn d04_unpack_execution_requires_checked_domain_intent() {
    let bad_domain_sources = [
        Source {
            path: "synthetic/public-unpack-request.rs",
            text: "pub struct Request<'a> { reader: &'a std::cell::RefCell<Vec<u8>> }",
        },
        Source {
            path: "synthetic/public-unpack-execute.rs",
            text: "pub fn execute(request: Request) -> Result<(), Error> { todo!() }",
        },
    ];
    for source in bad_domain_sources {
        assert!(
            !unpack_checked_intent_violations(source).is_empty(),
            "unpack intent gate must reject {}",
            source.path
        );
    }

    let bad_cli_source = Source {
        path: "synthetic/unpack-cli.rs",
        text: "let req = domain::unpack::Request { raw: () };",
    };
    assert!(
        !collect_violations(&[bad_cli_source], |source| {
            source
                .text
                .lines()
                .enumerate()
                .filter_map(|(index, line)| {
                    let compact = line.split_whitespace().collect::<String>();
                    if cli_constructs_raw_unpack_request(&compact) {
                        Some(violation(
                            source.path,
                            index,
                            "D-04 CLI must construct checked unpack intent, not raw domain unpack requests",
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .is_empty(),
        "unpack CLI gate must reject raw domain request construction"
    );

    let mut violations = Vec::new();
    if !domain_unpack_exposes_checked_boundary() {
        violations.push(violation(
            "dexios-domain/src/unpack.rs",
            0,
            "D-04 public unpack execution must expose UnpackIntent or an equivalent checked boundary",
        ));
    }
    violations.extend(unpack_checked_intent_violations(Source {
        path: "dexios-domain/src/unpack.rs",
        text: DOMAIN_UNPACK,
    }));
    violations.extend(collect_violations(
        &[Source {
            path: "dexios/src/subcommands/unpack.rs",
            text: CLI_UNPACK,
        }],
        |source| {
            source
                .text
                .lines()
                .enumerate()
                .filter_map(|(index, line)| {
                    let compact = line.split_whitespace().collect::<String>();
                    if cli_constructs_raw_unpack_request(&compact) {
                        Some(violation(
                            source.path,
                            index,
                            "D-04 CLI must construct checked unpack intent, not raw domain unpack requests",
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        },
    ));

    assert_no_violations(violations);
}

#[test]
fn archive_cli_errors_use_typed_mappers_without_formatted_error_control_flow() {
    assert!(
        CLI_ERRORS.contains("map_pack_error") && CLI_PACK.contains("map_pack_error"),
        "pack CLI must route domain errors through map_pack_error"
    );
    assert!(
        CLI_ERRORS.contains("map_unpack_error") && CLI_UNPACK.contains("map_unpack_error"),
        "unpack CLI must route domain errors through map_unpack_error"
    );

    let bad_source = Source {
        path: "synthetic/unpack-string-matching.rs",
        text: r#"if error.to_string().contains("unsafe path") { return Ok(()); }"#,
    };
    assert!(
        !formatted_archive_error_control_flow_violations(bad_source).is_empty(),
        "archive CLI scanner must reject formatted-error control flow"
    );

    let violations = collect_violations(
        &[
            Source {
                path: "dexios/src/subcommands/errors.rs",
                text: CLI_ERRORS,
            },
            Source {
                path: "dexios/src/subcommands/pack.rs",
                text: CLI_PACK,
            },
            Source {
                path: "dexios/src/subcommands/unpack.rs",
                text: CLI_UNPACK,
            },
        ],
        formatted_archive_error_control_flow_violations,
    );

    assert_no_violations(violations);
}

fn collect_violations(
    sources: &[Source<'_>],
    scan: impl Fn(Source<'_>) -> Vec<String>,
) -> Vec<String> {
    sources.iter().copied().flat_map(scan).collect()
}

fn assert_no_violations(violations: Vec<String>) {
    assert!(
        violations.is_empty(),
        "archive policy source gate violations:\n{}",
        violations.join("\n")
    );
}

fn public_line_exposes_zip_type(trimmed: &str) -> bool {
    trimmed.starts_with("pub ")
        && (trimmed.contains("zip::")
            || trimmed.contains("CompressionMethod")
            || trimmed.contains("SimpleFileOptions"))
}

fn public_stored_or_no_compression_policy(trimmed: &str) -> bool {
    trimmed == "Stored," || trimmed == "NoCompression," || trimmed == "Uncompressed,"
}

fn public_line_exposes_zip_metadata_knob(trimmed: &str) -> bool {
    trimmed.starts_with("pub ")
        && [
            "compression_level",
            "SimpleFileOptions",
            "unix_permissions",
            "permissions",
            "last_modified",
            "timestamp",
            "extra_field",
            "alignment",
            "zip64",
            "encrypt",
        ]
        .iter()
        .any(|pattern| trimmed.contains(pattern))
}

fn cli_exposes_compression_selector(compact: &str) -> bool {
    compact.contains("pubenumCompression")
        || compact.contains("Compression::None")
        || compact.contains("Compression::Zstd")
        || compact.contains("Arg::new(\"zstd\")")
        || compact.contains(".long(\"zstd\")")
        || compact.contains("zip::CompressionMethod")
}

fn public_raw_pack_execution_bypass(trimmed: &str) -> bool {
    [
        "pub struct Request",
        "pub struct TransactionalPackRequest",
        "pub struct ArchiveSourceEntry",
    ]
    .into_iter()
    .any(|pattern| trimmed.starts_with(pattern))
}

fn cli_constructs_raw_pack_request_or_entry(compact: &str) -> bool {
    compact.contains("domain::pack::TransactionalPackRequest")
        || compact.contains("domain::pack::ArchiveSourceEntry{")
}

fn domain_unpack_exposes_checked_boundary() -> bool {
    DOMAIN_UNPACK.contains("pub struct UnpackIntent")
        || DOMAIN_UNPACK.contains("pub struct CheckedUnpackIntent")
        || DOMAIN_UNPACK.contains("pub struct ValidatedUnpackIntent")
}

fn unpack_checked_intent_violations(source: Source<'_>) -> Vec<String> {
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
                violations.push(violation(
                    source.path,
                    index,
                    "D-04 public unpack APIs must not expose raw request construction",
                ));
            }
        }

        if starts_public_unpack_execute_signature(trimmed) {
            let signature = signature_window(&lines, index);
            if mentions_raw_unpack_request(&signature) {
                violations.push(violation(
                    source.path,
                    index,
                    "D-04 public unpack execute signature must accept checked intent",
                ));
            }
        }

        if trimmed.starts_with("pub ") && trimmed.contains("RefCell") {
            violations.push(violation(
                source.path,
                index,
                "D-04 public unpack contract must not expose RefCell handles",
            ));
        }
    }

    violations
}

fn starts_public_unpack_execute_signature(trimmed: &str) -> bool {
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

fn mentions_raw_unpack_request(signature: &str) -> bool {
    signature.contains(" Request")
        || signature.contains("(Request")
        || signature.contains("::Request")
        || signature.contains(" TransactionalRequest")
        || signature.contains("(TransactionalRequest")
        || signature.contains("::TransactionalRequest")
}

fn cli_constructs_raw_unpack_request(compact: &str) -> bool {
    compact.contains("domain::unpack::Request")
        || compact.contains("domain::unpack::{Request")
        || compact.contains("domain::unpack::{Request,TransactionalRequest}")
}

fn formatted_archive_error_control_flow_violations(source: Source<'_>) -> Vec<String> {
    source
        .text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let compact = line.split_whitespace().collect::<String>();
            if compact.contains("to_string()")
                || (compact.contains("format!(") && compact.contains("{err"))
                || compact.contains("contains(err")
                || compact.contains("contains(error")
            {
                Some(violation(
                    source.path,
                    index,
                    "archive CLI mapping must not inspect formatted error text",
                ))
            } else {
                None
            }
        })
        .collect()
}

fn violation(path: &str, index: usize, message: &str) -> String {
    format!("{path}:{}: {message}", index + 1)
}

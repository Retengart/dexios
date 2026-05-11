use std::fs;
use std::path::Path;

const DOMAIN_PACK: &str = include_str!("../src/pack.rs");
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
fn archive_cli_errors_use_typed_mappers_without_formatted_error_control_flow() {
    assert!(
        CLI_ERRORS.contains("map_pack_error") && CLI_PACK.contains("map_pack_error"),
        "pack CLI must route domain errors through map_pack_error"
    );
    assert!(
        CLI_ERRORS.contains("map_unpack_error") && CLI_UNPACK.contains("map_unpack_error"),
        "unpack CLI must route domain errors through map_unpack_error"
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
        |source| {
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
        },
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

fn violation(path: &str, index: usize, message: &str) -> String {
    format!("{path}:{}: {message}", index + 1)
}

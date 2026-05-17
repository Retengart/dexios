const CORE_PAYLOAD: &str = include_str!("../../dexios-core/src/payload.rs");
const CORE_HEADER_V1: &str = include_str!("../../dexios-core/src/header/v1.rs");
const DOMAIN_ARCHIVE: &str = include_str!("../src/archive.rs");
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

fn domain_archive_sources() -> Vec<Source<'static>> {
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
            text: DOMAIN_ARCHIVE,
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
    let violations = collect_violations(&domain_archive_sources(), |source| {
        public_archive_contract_violations(
            source,
            public_line_exposes_zip_type,
            "D-01 public archive contracts must use Dexios-owned policy types, not zip crate API types",
        )
    });

    assert_no_violations(violations);

    let bad_public_enum = Source {
        path: "synthetic/public-zip-error.rs",
        text: r#"
            pub enum Error {
                Legacy(zip::result::ZipError),
            }
        "#,
    };
    assert!(
        !public_archive_contract_violations(
            bad_public_enum,
            public_line_exposes_zip_type,
            "D-01 public archive contracts must use Dexios-owned policy types, not zip crate API types",
        )
        .is_empty(),
        "D-01 source gate must reject public enum variants carrying zip crate types"
    );
}

#[test]
fn d03_public_archive_policy_has_no_stored_or_no_compression_variant() {
    let violations = collect_violations(&domain_archive_sources(), |source| {
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
    let violations = collect_violations(&domain_archive_sources(), |source| {
        public_archive_contract_violations(
            source,
            public_line_exposes_zip_metadata_knob,
            "D-05 public archive metadata contract is path plus file/directory only",
        )
    });

    assert_no_violations(violations);

    let bad_public_enum = Source {
        path: "synthetic/public-zip-metadata.rs",
        text: r#"
            pub enum ArchiveMetadata {
                UnixPermissions,
                LastModified,
                Zip64,
            }
        "#,
    };
    assert!(
        !public_archive_contract_violations(
            bad_public_enum,
            public_line_exposes_zip_metadata_knob,
            "D-05 public archive metadata contract is path plus file/directory only",
        )
        .is_empty(),
        "D-05 source gate must reject public archive metadata enum variants"
    );

    let private_implementation = Source {
        path: "synthetic/private-implementation.rs",
        text: r#"
            // Compression with encryption is discussed in implementation comments.
            fn inspect_private_path(path: &Path) {
                let _ = fs::symlink_metadata(path);
                let _ = crate::encrypt::Error::EncryptFile;
            }
        "#,
    };
    assert!(
        public_archive_contract_violations(
            private_implementation,
            public_line_exposes_zip_metadata_knob,
            "D-05 public archive metadata contract is path plus file/directory only",
        )
        .is_empty(),
        "D-05 source gate must ignore comments and private implementation details"
    );
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
        DOMAIN_PACK.contains("begin_v1_manifest_archive_writer"),
        "ARCH-01 pack must write through the manifest archive V1 writer"
    );
    assert!(
        DOMAIN_PACK.contains("ArchiveManifest") && DOMAIN_PACK.contains("ArchiveBodyFrameHeader"),
        "ARCH-01 pack must use Dexios-owned manifest-first payload framing"
    );
    assert!(
        !DOMAIN_PACK.contains("zip::CompressionMethod")
            && !DOMAIN_PACK.contains("ZipWriter::new_stream"),
        "ARCH-05 canonical pack must not depend on normal-path ZIP writer setup"
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
fn phase05_manifest_archive_normal_path_stays_private_and_zip_free() {
    assert!(
        DOMAIN_PACK.contains("begin_v1_manifest_archive_writer"),
        "ARCH-01 pack must write through the manifest archive V1 writer"
    );
    assert!(
        DOMAIN_PACK.contains("ArchiveManifest") && DOMAIN_PACK.contains("ArchiveBodyFrameHeader"),
        "ARCH-01 pack must use Dexios-owned manifest-first payload framing"
    );
    assert!(
        !DOMAIN_PACK.contains("ZipWriter::new_stream"),
        "ARCH-05 canonical pack must not use ZIP writer setup"
    );

    let unpack_normal_path = source_section(
        "dexios-domain/src/unpack.rs",
        DOMAIN_UNPACK,
        "fn execute_manifest_archive",
        "fn stage_manifest_extraction",
    );
    for required in [
        "V1PayloadDecryptingReader::new",
        "stage_manifest_extraction",
        "drain_trailing_plaintext_to_final_auth",
        ".finish()",
        "revalidate_extraction_targets",
        "create_selected_directories_after_final_auth",
        "commit_all",
    ] {
        assert!(
            unpack_normal_path.contains(required),
            "ARCH-01/ARCH-03 normal unpack path must contain {required:?}"
        );
    }
    for forbidden in ["ZipArchive", "OpenArchiveWithSource", "_temp_factory()"] {
        assert!(
            !unpack_normal_path.contains(forbidden),
            "ARCH-01 normal manifest unpack path must not contain {forbidden:?}"
        );
    }

    let manifest_staging = source_section(
        "dexios-domain/src/unpack.rs",
        DOMAIN_UNPACK,
        "fn stage_manifest_extraction",
        "fn prepare_manifest_extraction_entities",
    );
    for required in [
        "ArchiveManifest::read_from",
        "ArchiveBodyFrameHeader::read_from",
        "stage_manifest_file_body",
        "drain_manifest_body",
    ] {
        assert!(
            manifest_staging.contains(required),
            "ARCH-02/ARCH-04 manifest staging must contain {required:?}"
        );
    }
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

#[test]
fn phase4_archive_boundary_rejects_phase5_dxar_extraction_surface() {
    let bad_domain_source = Source {
        path: "synthetic/public-dxar-extractor.rs",
        text: "pub fn extract_dxar_manifest_first_archive() {}",
    };
    assert!(
        !phase5_archive_surface_violations(bad_domain_source).is_empty(),
        "archive API gate must reject public DXAR extraction before Phase 5"
    );

    let bad_cli_source = Source {
        path: "synthetic/dxar-cli-flag.rs",
        text: r#"Command::new("dexios").arg(Arg::new("dxar").long("dxar"));"#,
    };
    assert!(
        !phase5_archive_surface_violations(bad_cli_source).is_empty(),
        "archive API gate must reject CLI flags for DXAR extraction before Phase 5"
    );

    let violations =
        collect_violations(&domain_archive_sources(), phase5_archive_surface_violations);
    assert_no_violations(violations);

    let violations = collect_violations(&cli_archive_sources(), phase5_archive_surface_violations);
    assert_no_violations(violations);
}

#[test]
fn payload_kind_and_framing_bytes_stay_core_owned_not_cli_duplicated() {
    for required in ["pub enum PayloadKind", "pub enum PayloadFramingProfile"] {
        assert!(
            CORE_PAYLOAD.contains(required),
            "core payload module must own {required}"
        );
    }
    for required in ["PayloadKind::RawFile", "PayloadFramingProfile::RawLe31"] {
        assert!(
            CORE_HEADER_V1.contains(required),
            "core header module must consume {required}"
        );
    }

    let bad_cli_source = Source {
        path: "synthetic/cli-payload-byte-duplication.rs",
        text: r#"
            const PAYLOAD_KIND_MANIFEST_ARCHIVE: u8 = 0x02;
            let _ = PayloadFramingProfile::ManifestFirst;
        "#,
    };
    assert!(
        !payload_contract_duplication_violations(bad_cli_source).is_empty(),
        "CLI source gate must reject payload kind/framing duplication"
    );

    let violations = collect_violations(
        &cli_archive_sources(),
        payload_contract_duplication_violations,
    );
    assert_no_violations(violations);
}

fn collect_violations(
    sources: &[Source<'_>],
    scan: impl Fn(Source<'_>) -> Vec<String>,
) -> Vec<String> {
    sources.iter().copied().flat_map(scan).collect()
}

fn source_section<'a>(source_name: &str, source: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = source
        .find(start)
        .unwrap_or_else(|| panic!("{source_name} must contain section start {start:?}"));
    let end_index = source[start_index..]
        .find(end)
        .map(|index| start_index + index)
        .unwrap_or_else(|| panic!("{source_name} must contain section end {end:?}"));
    &source[start_index..end_index]
}

fn assert_no_violations(violations: Vec<String>) {
    assert!(
        violations.is_empty(),
        "archive policy source gate violations:\n{}",
        violations.join("\n")
    );
}

fn public_archive_contract_violations(
    source: Source<'_>,
    exposes_forbidden_contract: fn(&str) -> bool,
    message: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    let mut brace_depth = 0isize;
    let mut public_enum_depth = None;

    for (index, line) in source.text.lines().enumerate() {
        let trimmed = line.trim_start();
        let public_contract_line = is_public_surface_line(trimmed) || public_enum_depth.is_some();
        if public_contract_line
            && !is_comment_or_blank(trimmed)
            && exposes_forbidden_contract(trimmed)
        {
            violations.push(violation(source.path, index, message));
        }

        let starts_public_enum = starts_public_enum_block(trimmed) && line.contains('{');
        brace_depth += brace_delta(line);

        if starts_public_enum {
            public_enum_depth = Some(brace_depth);
        }
        if let Some(depth) = public_enum_depth
            && brace_depth < depth
        {
            public_enum_depth = None;
        }
    }

    violations
}

fn is_public_surface_line(trimmed: &str) -> bool {
    trimmed.starts_with("pub ") || trimmed.starts_with("pub(crate) ")
}

fn starts_public_enum_block(trimmed: &str) -> bool {
    ["pub enum ", "pub(crate) enum "]
        .into_iter()
        .any(|prefix| trimmed.starts_with(prefix))
}

fn is_comment_or_blank(trimmed: &str) -> bool {
    trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[")
}

fn brace_delta(line: &str) -> isize {
    let opens = line.chars().filter(|character| *character == '{').count() as isize;
    let closes = line.chars().filter(|character| *character == '}').count() as isize;
    opens - closes
}

fn public_line_exposes_zip_type(trimmed: &str) -> bool {
    trimmed.contains("zip::")
        || trimmed.contains("CompressionMethod")
        || trimmed.contains("SimpleFileOptions")
}

fn public_stored_or_no_compression_policy(trimmed: &str) -> bool {
    trimmed == "Stored," || trimmed == "NoCompression," || trimmed == "Uncompressed,"
}

fn public_line_exposes_zip_metadata_knob(trimmed: &str) -> bool {
    let normalized = trimmed
        .chars()
        .filter(|character| *character != '_')
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "compressionlevel",
        "simplefileoptions",
        "unixpermissions",
        "permissions",
        "lastmodified",
        "timestamp",
        "extrafield",
        "alignment",
        "zip64",
    ]
    .iter()
    .any(|pattern| normalized.contains(pattern))
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

fn phase5_archive_surface_violations(source: Source<'_>) -> Vec<String> {
    source
        .text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim_start();
            let compact = line.split_whitespace().collect::<String>();
            let lower = compact.to_ascii_lowercase();
            let public_symbol = trimmed.starts_with("pub ") || trimmed.starts_with("pub(crate) ");
            let cli_flag = lower.contains("arg::new(\"dxar")
                || lower.contains(".long(\"dxar")
                || lower.contains("arg::new(\"manifest")
                || lower.contains(".long(\"manifest");
            let phase5_archive_symbol = [
                "dxar",
                "manifestfirst",
                "manifest_first",
                "manifest-first",
                "manifestarchive",
                "manifestpayload",
                "archivemanifest",
                "archivebodyframe",
            ]
            .into_iter()
            .any(|symbol| lower.contains(symbol));

            if (public_symbol || cli_flag) && phase5_archive_symbol {
                Some(violation(
                    source.path,
                    index,
                    "Phase 4 must not expose Phase 5 DXAR extraction surface",
                ))
            } else {
                None
            }
        })
        .collect()
}

fn payload_contract_duplication_violations(source: Source<'_>) -> Vec<String> {
    source
        .text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let compact = line.split_whitespace().collect::<String>();
            let duplicates_payload_contract = [
                "PayloadKind",
                "PayloadFramingProfile",
                "PAYLOAD_KIND",
                "PAYLOAD_FRAMING",
                "RawFile",
                "ManifestArchive",
                "RawLe31",
                "ManifestFirst",
                "DXAR",
                "DXBF",
            ]
            .into_iter()
            .any(|symbol| compact.contains(symbol));

            if duplicates_payload_contract {
                Some(violation(
                    source.path,
                    index,
                    "CLI must not duplicate core-owned payload kind/framing contract",
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

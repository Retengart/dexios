use crate::global::states::{DeleteInput, DeleteSource, ForceMode, HashMode, HeaderLocation};
use crate::global::structs::CryptoParams;
use crate::global::structs::PackParams;
use anyhow::{Result, anyhow};
use clap::ArgMatches;
use clap::parser::MatchesError;
use core::kdf::Kdf;

use super::states::{DirectoryMode, Key, KeyParams, PrintMode};
use super::structs::KeyManipulationParams;

pub(crate) fn get_params(name: &str, sub_matches: &ArgMatches) -> Result<Vec<String>> {
    let values = sub_matches
        .try_get_many::<String>(name)
        .map_err(|_| {
            anyhow!(
                "internal CLI adapter error: required repeated argument '{name}' unreadable after clap validation"
            )
        })?
        .ok_or_else(|| {
            anyhow!(
                "internal CLI adapter error: required repeated argument '{name}' missing after clap validation"
            )
        })?
        .map(String::from)
        .collect();
    Ok(values)
}

pub(crate) fn get_param(name: &str, sub_matches: &ArgMatches) -> Result<String> {
    let value = sub_matches
        .try_get_one::<String>(name)
        .map_err(|_| {
            anyhow!(
                "internal CLI adapter error: required argument '{name}' unreadable after clap validation"
            )
        })?
        .ok_or_else(|| {
            anyhow!(
                "internal CLI adapter error: required argument '{name}' missing after clap validation"
            )
        })?
        .clone();
    Ok(value)
}

pub(crate) fn get_optional_param<'a>(
    name: &str,
    sub_matches: &'a ArgMatches,
) -> Result<Option<&'a str>> {
    match sub_matches.try_get_one::<String>(name) {
        Ok(value) => Ok(value.map(String::as_str)),
        // An OPTIONAL argument that isn't defined for this subcommand is legitimately
        // *absent*, which is exactly what an optional getter should report. clap only
        // detects this (via `try_get_one`) in debug builds — release returns `Ok(None)`
        // — so without this arm `Key::init` reading `autogenerate` would fail in debug
        // for every subcommand that doesn't define it (key del/verify, decrypt).
        // `MatchesError` and its `UnknownArgument` variant are both `#[non_exhaustive]`.
        Err(MatchesError::UnknownArgument { .. }) => Ok(None),
        Err(_) => Err(anyhow!(
            "internal CLI adapter error: optional argument '{name}' unreadable after clap validation"
        )),
    }
}

// `delete_input` is taken as a parameter instead of being read from the matches:
// not every subcommand routed through here defines the `delete-input` flag
// (pack governs source removal via `delete-source` on `PackParams` instead).
fn crypto_params(sub_matches: &ArgMatches, delete_input: DeleteInput) -> Result<CryptoParams> {
    let key = Key::init(sub_matches, &KeyParams::default(), "keyfile")?;

    let hash_mode = if sub_matches.get_flag("hash") {
        HashMode::CalculateHash
    } else {
        HashMode::NoHash
    };

    let force = forcemode(sub_matches);

    let header_location = match get_optional_param("header", sub_matches)? {
        Some(header) => HeaderLocation::Detached(header.to_owned()),
        None => HeaderLocation::Embedded,
    };

    let kdf = kdf(sub_matches);

    Ok(CryptoParams {
        hash_mode,
        force,
        delete_input,
        key,
        header_location,
        kdf,
    })
}

pub(crate) fn parameter_handler(sub_matches: &ArgMatches) -> Result<CryptoParams> {
    let delete_input = if sub_matches.get_flag("delete-input") {
        DeleteInput::Delete
    } else {
        DeleteInput::Retain
    };

    crypto_params(sub_matches, delete_input)
}

pub(crate) fn kdf(_sub_matches: &ArgMatches) -> Kdf {
    Kdf::Argon2id
}

pub(crate) fn pack_params(sub_matches: &ArgMatches) -> Result<(CryptoParams, PackParams)> {
    let crypto_params = crypto_params(sub_matches, DeleteInput::Retain)?;

    let print_mode = if sub_matches.get_flag("verbose") {
        PrintMode::Verbose
    } else {
        PrintMode::Quiet
    };

    let dir_mode = if sub_matches.get_flag("recursive") {
        DirectoryMode::Recursive
    } else {
        DirectoryMode::Singular
    };

    let delete_source = if sub_matches.get_flag("delete-source") {
        DeleteSource::Delete
    } else {
        DeleteSource::Retain
    };

    let pack_params = PackParams {
        dir_mode,
        print_mode,
        delete_source,
    };

    Ok((crypto_params, pack_params))
}

pub(crate) fn forcemode(sub_matches: &ArgMatches) -> ForceMode {
    if sub_matches.get_flag("force") {
        ForceMode::Force
    } else {
        ForceMode::Prompt
    }
}

pub(crate) fn key_manipulation_params(sub_matches: &ArgMatches) -> Result<KeyManipulationParams> {
    let key_old = Key::init(
        sub_matches,
        &KeyParams {
            user: true,
            env: true,
            autogenerate: false,
            keyfile: true,
        },
        "keyfile-old",
    )?;

    let key_new = Key::init(
        sub_matches,
        &KeyParams {
            user: true,
            env: false,
            autogenerate: true,
            keyfile: true,
        },
        "keyfile-new",
    )?;

    let kdf = kdf(sub_matches);

    Ok(KeyManipulationParams {
        key_old,
        key_new,
        kdf,
        force: ForceMode::Prompt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::build_cli;
    use clap::{Arg, ArgAction, Command, value_parser};
    use core::key::PassphraseWordCount;

    #[test]
    fn required_parameter_missing_returns_internal_adapter_error() {
        let matches = Command::new("synthetic")
            .arg(Arg::new("input"))
            .try_get_matches_from(["synthetic"])
            .expect("synthetic matches should parse");

        let error = get_param("input", &matches).expect_err("missing required parameter");

        assert_eq!(
            error.to_string(),
            "internal CLI adapter error: required argument 'input' missing after clap validation"
        );
    }

    #[test]
    fn repeated_parameter_missing_returns_internal_adapter_error() {
        let matches = Command::new("synthetic")
            .arg(Arg::new("input").action(ArgAction::Append).num_args(1..))
            .try_get_matches_from(["synthetic"])
            .expect("synthetic matches should parse");

        let error = get_params("input", &matches).expect_err("missing repeated parameter");

        assert_eq!(
            error.to_string(),
            "internal CLI adapter error: required repeated argument 'input' missing after clap validation"
        );
    }

    #[test]
    fn optional_parameter_absent_returns_none() {
        let matches = Command::new("synthetic")
            .arg(Arg::new("header").long("header"))
            .try_get_matches_from(["synthetic"])
            .expect("synthetic matches should parse");

        let value = get_optional_param("header", &matches).expect("optional parameter");

        assert_eq!(value, None);
    }

    #[test]
    fn optional_parameter_present_returns_borrowed_value() {
        let matches = Command::new("synthetic")
            .arg(Arg::new("header").long("header"))
            .try_get_matches_from(["synthetic", "--header", "file.hdr"])
            .expect("synthetic matches should parse");

        let value = get_optional_param("header", &matches).expect("optional parameter");

        assert_eq!(value, Some("file.hdr"));
    }

    #[test]
    fn optional_parameter_undefined_for_subcommand_returns_none() {
        // `autogenerate` is only defined for encrypt/key add/key change/pack, but
        // `Key::init` reads it for every subcommand routed through it (key del/verify,
        // decrypt). clap's undefined-arg detection in `try_get_one` is debug-only:
        // in release it returns `Ok(None)`, in debug it returns
        // `Err(MatchesError::UnknownArgument {..})`. An undefined OPTIONAL argument is
        // legitimately absent, so the optional getter must report `None` in BOTH profiles.
        let matches = Command::new("synthetic")
            .arg(Arg::new("input"))
            .try_get_matches_from(["synthetic"])
            .expect("synthetic matches should parse");

        let value =
            get_optional_param("autogenerate", &matches).expect("undefined optional argument");

        assert_eq!(value, None);
    }

    #[test]
    fn optional_parameter_mismatched_access_returns_internal_adapter_error() {
        let matches = Command::new("synthetic")
            .arg(
                Arg::new("header")
                    .long("header")
                    .value_parser(value_parser!(u16)),
            )
            .try_get_matches_from(["synthetic", "--header", "7"])
            .expect("synthetic matches should parse");

        let error = get_optional_param("header", &matches).expect_err("mismatched optional access");

        assert!(
            error.to_string().contains(
                "internal CLI adapter error: optional argument 'header' unreadable after clap validation"
            ),
            "error should explain optional adapter access failure: {error}"
        );
    }

    #[test]
    fn decrypt_key_init_falls_back_to_user_without_autogenerate_arg() {
        let matches = build_cli()
            .try_get_matches_from(["dexios", "decrypt", "cipher.enc", "plain.txt"])
            .expect("CLI should parse");
        let (_, sub_matches) = matches.subcommand().expect("subcommand");

        let key = Key::init(
            sub_matches,
            &KeyParams {
                user: true,
                env: false,
                autogenerate: true,
                keyfile: true,
            },
            "keyfile",
        )
        .expect("key selection");

        assert_eq!(key, Key::User);
    }

    #[test]
    fn decrypt_parameter_handler_defaults_to_argon2id() {
        let matches = build_cli()
            .try_get_matches_from([
                "dexios",
                "decrypt",
                "-k",
                "keyfile",
                "cipher.enc",
                "plain.txt",
            ])
            .expect("CLI should parse");
        let (_, sub_matches) = matches.subcommand().expect("subcommand");

        let params = parameter_handler(sub_matches).expect("params");

        assert_eq!(params.kdf, Kdf::Argon2id);
    }

    #[test]
    fn unpack_parameter_handler_defaults_to_argon2id() {
        let matches = build_cli()
            .try_get_matches_from([
                "dexios",
                "unpack",
                "-k",
                "keyfile",
                "archive.enc",
                "out-dir",
            ])
            .expect("CLI should parse");
        let (_, sub_matches) = matches.subcommand().expect("subcommand");

        let params = parameter_handler(sub_matches).expect("params");

        assert_eq!(params.kdf, Kdf::Argon2id);
    }

    #[test]
    fn pack_params_always_retain_the_encrypted_input() {
        // pack does not define the `delete-input` flag: removal of the packed
        // source tree is governed exclusively by `PackParams::delete_source`,
        // so the shared crypto-params path must pin `DeleteInput::Retain`.
        let matches = build_cli()
            .try_get_matches_from(["dexios", "pack", "-k", "keyfile", "dir", "out.enc"])
            .expect("CLI should parse");
        let (_, sub_matches) = matches.subcommand().expect("subcommand");

        let (crypto_params, pack_params) = pack_params(sub_matches).expect("params");

        assert!(
            matches!(crypto_params.delete_input, DeleteInput::Retain),
            "pack must never delete its input through CryptoParams"
        );
        assert!(
            matches!(pack_params.delete_source, DeleteSource::Retain),
            "source deletion must stay opt-in via --delete-source"
        );
        assert_eq!(crypto_params.kdf, Kdf::Argon2id);
    }

    #[test]
    fn explicit_autogenerate_beats_environment_key() {
        let matches = build_cli()
            .try_get_matches_from(["dexios", "encrypt", "--auto=7", "in.bin", "out.enc"])
            .expect("CLI should parse");
        let (_, sub_matches) = matches.subcommand().expect("subcommand");

        let key = Key::resolve_key_source(
            sub_matches
                .try_get_one::<String>("keyfile")
                .ok()
                .flatten()
                .map(String::as_str),
            sub_matches
                .try_get_one::<String>("autogenerate")
                .ok()
                .flatten()
                .map(String::as_str),
            true,
            true,
            &KeyParams::default(),
        )
        .expect("key selection");

        assert_eq!(key, Key::Generate(PassphraseWordCount::try_new(7).unwrap()));
    }
}

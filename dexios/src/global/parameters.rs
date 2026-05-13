// this file handles getting parameters from clap's ArgMatches
// it returns information (e.g. CryptoParams) to functions that require it

use crate::global::states::{DeleteInput, DeleteSource, ForceMode, HashMode, HeaderLocation};
use crate::global::structs::CryptoParams;
use crate::global::structs::PackParams;
use anyhow::{Context, Result};
use clap::ArgMatches;
use core::kdf::Kdf;

use super::states::{DirectoryMode, Key, KeyParams, PrintMode};
use super::structs::KeyManipulationParams;

pub fn get_params(name: &str, sub_matches: &ArgMatches) -> Result<Vec<String>> {
    let values = sub_matches
        .get_many::<String>(name)
        .with_context(|| format!("No {name} provided"))?
        .map(String::from)
        .collect();
    Ok(values)
}

pub fn get_param(name: &str, sub_matches: &ArgMatches) -> Result<String> {
    let value = sub_matches
        .get_one::<String>(name)
        .with_context(|| format!("No {name} provided"))?
        .clone();
    Ok(value)
}

// the main parameter handler for encrypt/decrypt
pub fn parameter_handler(sub_matches: &ArgMatches) -> Result<CryptoParams> {
    let key = Key::init(sub_matches, &KeyParams::default(), "keyfile")?;

    let hash_mode = if sub_matches.get_flag("hash") {
        //specify to emit hash after operation
        HashMode::CalculateHash
    } else {
        // default
        HashMode::NoHash
    };

    let force = forcemode(sub_matches);

    let delete_input = if sub_matches.get_flag("delete-input") {
        DeleteInput::Delete
    } else {
        DeleteInput::Retain
    };

    let header_location = if sub_matches.get_one::<String>("header").is_some() {
        HeaderLocation::Detached(
            sub_matches
                .get_one::<String>("header")
                .context("No header/invalid text provided")?
                .clone(),
        )
    } else {
        HeaderLocation::Embedded
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

pub fn kdf(_sub_matches: &ArgMatches) -> Kdf {
    Kdf::Blake3Balloon
}

pub fn pack_params(sub_matches: &ArgMatches) -> Result<(CryptoParams, PackParams)> {
    let key = Key::init(sub_matches, &KeyParams::default(), "keyfile")?;

    let hash_mode = if sub_matches.get_flag("hash") {
        //specify to emit hash after operation
        HashMode::CalculateHash
    } else {
        // default
        HashMode::NoHash
    };

    let force = forcemode(sub_matches);

    let header_location = if sub_matches.get_one::<String>("header").is_some() {
        HeaderLocation::Detached(
            sub_matches
                .get_one::<String>("header")
                .context("No header/invalid text provided")?
                .clone(),
        )
    } else {
        HeaderLocation::Embedded
    };

    let kdf = kdf(sub_matches);

    let crypto_params = CryptoParams {
        hash_mode,
        force,
        delete_input: DeleteInput::Retain,
        key,
        header_location,
        kdf,
    };

    let print_mode = if sub_matches.get_flag("verbose") {
        //specify to emit hash after operation
        PrintMode::Verbose
    } else {
        // default
        PrintMode::Quiet
    };

    let dir_mode = if sub_matches.get_flag("recursive") {
        //specify to emit hash after operation
        DirectoryMode::Recursive
    } else {
        // default
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

pub fn forcemode(sub_matches: &ArgMatches) -> ForceMode {
    if sub_matches.get_flag("force") {
        ForceMode::Force
    } else {
        ForceMode::Prompt
    }
}

pub fn key_manipulation_params(sub_matches: &ArgMatches) -> Result<KeyManipulationParams> {
    let key_old = Key::init(
        sub_matches,
        &KeyParams {
            user: true,
            env: false,
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::build_cli;
    use core::key::PassphraseWordCount;

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
    fn decrypt_parameter_handler_defaults_to_blake3_balloon() {
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

        assert_eq!(params.kdf, Kdf::Blake3Balloon);
    }

    #[test]
    fn unpack_parameter_handler_defaults_to_blake3_balloon() {
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

        assert_eq!(params.kdf, Kdf::Blake3Balloon);
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
            &KeyParams::default(),
        )
        .expect("key selection");

        assert_eq!(key, Key::Generate(PassphraseWordCount::try_new(7).unwrap()));
    }
}

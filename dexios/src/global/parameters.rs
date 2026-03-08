// this file handles getting parameters from clap's ArgMatches
// it returns information (e.g. CryptoParams) to functions that require it

use crate::global::states::{EraseMode, EraseSourceDir, ForceMode, HashMode, HeaderLocation};
use crate::global::structs::CryptoParams;
use crate::global::structs::PackParams;
use crate::warn;
use anyhow::{Context, Result};
use clap::ArgMatches;
use core::header::{ARGON2ID_LATEST, BLAKE3BALLOON_LATEST, HashingAlgorithm};
use core::primitives::Algorithm;

use super::states::{Compression, DirectoryMode, Key, KeyParams, PrintMode};
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

    let erase = if sub_matches.get_one::<String>("erase").is_some() {
        let result = sub_matches
            .get_one::<String>("erase")
            .context("No amount of passes specified")?
            .parse();

        if let Ok(value) = result {
            EraseMode::EraseFile(value)
        } else {
            warn!("No amount of passes provided - using the default.");
            EraseMode::EraseFile(1)
        }
    } else {
        EraseMode::IgnoreFile
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

    let hashing_algorithm = hashing_algorithm(sub_matches);

    Ok(CryptoParams {
        hash_mode,
        force,
        erase,
        key,
        header_location,
        hashing_algorithm,
    })
}

pub fn hashing_algorithm(sub_matches: &ArgMatches) -> HashingAlgorithm {
    let use_argon = sub_matches
        .try_get_one::<bool>("argon")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false);

    if use_argon {
        HashingAlgorithm::Argon2id(ARGON2ID_LATEST)
    } else {
        HashingAlgorithm::Blake3Balloon(BLAKE3BALLOON_LATEST)
    }
}

// gets the algorithm, primarily for encrypt functions
pub fn algorithm(sub_matches: &ArgMatches) -> Algorithm {
    if sub_matches.get_flag("aes") {
        Algorithm::Aes256Gcm
    } else {
        Algorithm::XChaCha20Poly1305
    }
}

pub fn erase_params(sub_matches: &ArgMatches) -> Result<(i32, ForceMode)> {
    let passes = if sub_matches.get_one::<String>("passes").is_some() {
        let result = sub_matches
            .get_one::<String>("passes")
            .context("No amount of passes specified")?
            .parse::<i32>();
        if let Ok(value) = result {
            value
        } else {
            warn!("Unable to read number of passes provided - using the default.");
            1
        }
    } else {
        warn!("Number of passes not provided - using the default.");
        1
    };

    let force = forcemode(sub_matches);

    Ok((passes, force))
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

    let erase = EraseMode::IgnoreFile;

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

    let hashing_algorithm = hashing_algorithm(sub_matches);

    let crypto_params = CryptoParams {
        hash_mode,
        force,
        erase,
        key,
        header_location,
        hashing_algorithm,
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

    let erase_source = if sub_matches.get_flag("erase") {
        EraseSourceDir::Erase
    } else {
        EraseSourceDir::Retain
    };

    let compression = if sub_matches.get_flag("zstd") {
        Compression::Zstd
    } else {
        Compression::None
    };

    let pack_params = PackParams {
        dir_mode,
        print_mode,
        erase_source,
        compression,
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

    let hashing_algorithm = hashing_algorithm(sub_matches);

    Ok(KeyManipulationParams {
        key_old,
        key_new,
        hashing_algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::build_cli;

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

        assert_eq!(
            params.hashing_algorithm,
            HashingAlgorithm::Blake3Balloon(BLAKE3BALLOON_LATEST)
        );
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

        assert_eq!(
            params.hashing_algorithm,
            HashingAlgorithm::Blake3Balloon(BLAKE3BALLOON_LATEST)
        );
    }
}

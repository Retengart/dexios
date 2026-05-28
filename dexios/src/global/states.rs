// this file contains enums found all around the codebase
// they act as toggles for certain features, so they can be
// enabled if selected by the user

use anyhow::{Context, Result};
use clap::ArgMatches;
use core::protected::Protected;

use crate::cli::prompt::get_password;
use crate::global::parameters::get_optional_param;
use crate::warn;
use core::key::{PassphraseWordCount, generate_passphrase};

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DirectoryMode {
    Singular,
    Recursive,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DeleteSource {
    Delete,
    Retain,
}

#[derive(PartialEq, Eq)]
pub enum PrintMode {
    Verbose,
    Quiet,
}

pub enum HeaderLocation {
    Embedded,
    Detached(String),
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum DeleteInput {
    Delete,
    Retain,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum ForceMode {
    Force,
    Prompt,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Key {
    Keyfile(String),
    Env,
    Generate(PassphraseWordCount),
    User,
}

#[derive(PartialEq, Eq)]
pub enum PasswordState {
    Validate,
    Direct, // maybe not the best name
}

fn get_bytes<R: std::io::Read>(reader: &mut R) -> Result<Protected<Vec<u8>>> {
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .context("Unable to read data")?;
    Ok(Protected::new(data))
}

fn generated_passphrase_disclosure(passphrase: &str) -> String {
    format!(
        "Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: {passphrase}"
    )
}

fn generated_passphrase_secret<F>(
    total_words: PassphraseWordCount,
    mut disclose: F,
) -> Protected<Vec<u8>>
where
    F: FnMut(&str),
{
    let passphrase = generate_passphrase(total_words);
    let key = passphrase.with_exposed(|passphrase| {
        let message = generated_passphrase_disclosure(passphrase);
        disclose(&message);
        Protected::new(passphrase.as_bytes().to_vec())
    });
    drop(passphrase);
    key
}

fn parse_generated_passphrase_word_count(words: &str) -> Result<PassphraseWordCount> {
    let parsed = words
        .parse::<u16>()
        .with_context(|| format!("Invalid generated passphrase word count '{words}'"))?;
    PassphraseWordCount::try_new(parsed)
        .with_context(|| format!("Invalid generated passphrase word count '{words}'"))
}

impl Key {
    #[must_use]
    pub fn reads_stdin(&self) -> bool {
        matches!(self, Self::Keyfile(path) if path == "-")
    }

    pub(crate) fn resolve_key_source(
        keyfile: Option<&str>,
        autogenerate: Option<&str>,
        env_available: bool,
        params: &KeyParams,
    ) -> Result<Self> {
        let key = if let (Some(path), true) = (keyfile, params.keyfile) {
            Key::Keyfile(path.to_owned())
        } else if let (Some(words), true) = (autogenerate, params.autogenerate) {
            Key::Generate(parse_generated_passphrase_word_count(words)?)
        } else if env_available && params.env {
            Key::Env
        } else if params.user {
            Key::User
        } else {
            return Err(anyhow::anyhow!(
                "No key sources found with the parameters/arguments provided"
            ));
        };

        Ok(key)
    }

    // this handles getting the secret, and returning it
    // it relies on `parameters.rs`' handling and logic to determine which route to get the key
    // it can handle keyfiles, env variables, automatically generating and letting the user enter a key
    // it has a check for if the keyfile is empty or not
    pub fn get_secret(&self, pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
        let secret = match self {
            Key::Keyfile(path) if path == "-" => {
                let mut reader = std::io::stdin();
                let secret = get_bytes(&mut reader)?;
                if secret.with_exposed(|secret| secret.is_empty()) {
                    return Err(anyhow::anyhow!("STDIN is empty"));
                }
                secret
            }
            Key::Keyfile(path) => {
                let mut reader = std::fs::File::open(path)
                    .with_context(|| format!("Unable to read file: {path}"))?;
                let secret = get_bytes(&mut reader)?;
                if secret.with_exposed(|secret| secret.is_empty()) {
                    return Err(anyhow::anyhow!(format!("Keyfile '{path}' is empty")));
                }
                secret
            }
            Key::Env => Protected::new(
                std::env::var("DEXIOS_KEY")
                    .context("Unable to read DEXIOS_KEY from environment variable")?
                    .into_bytes(),
            ),
            Key::User => get_password(pass_state)?,
            Key::Generate(i) => generated_passphrase_secret(*i, |message| warn!("{message}")),
        };

        if secret.with_exposed(|secret| secret.is_empty()) {
            Err(anyhow::anyhow!("The specified key is empty!"))
        } else {
            Ok(secret)
        }
    }

    pub fn init(
        sub_matches: &ArgMatches,
        params: &KeyParams,
        keyfile_descriptor: &str,
    ) -> Result<Self> {
        let keyfile = get_optional_param(keyfile_descriptor, sub_matches)?;
        let autogenerate = get_optional_param("autogenerate", sub_matches)?;

        Self::resolve_key_source(
            keyfile,
            autogenerate,
            std::env::var("DEXIOS_KEY").is_ok(),
            params,
        )
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct KeyParams {
    pub user: bool,
    pub env: bool,
    pub autogenerate: bool,
    pub keyfile: bool,
}

impl KeyParams {
    pub fn default() -> Self {
        KeyParams {
            user: true,
            env: true,
            autogenerate: true,
            keyfile: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, Command, value_parser};
    use core::key::PassphraseWordCount;

    const DISCLOSURE_PREFIX: &str = "Your generated passphrase is intentionally shown here and may be captured by terminal scrollback or logs: ";

    #[test]
    fn generated_passphrase_disclosure_message_includes_secret() {
        let message = generated_passphrase_disclosure("alpha-beta");

        assert!(
            message.contains("intentionally shown"),
            "generated passphrase disclosure should state intentional display: {message}"
        );
        assert!(
            message.contains("terminal scrollback") || message.contains("logs"),
            "generated passphrase disclosure should warn about terminal/log capture: {message}"
        );
        assert!(
            message.contains("alpha-beta"),
            "generated passphrase disclosure should keep the secret available to the user: {message}"
        );
    }

    #[test]
    fn generated_passphrase_secret_discloses_once_and_returns_same_bytes() {
        let mut messages = Vec::new();

        let key =
            generated_passphrase_secret(PassphraseWordCount::try_new(3).unwrap(), |message| {
                messages.push(message.to_owned());
            });

        assert_eq!(messages.len(), 1);
        let phrase = messages[0]
            .strip_prefix(DISCLOSURE_PREFIX)
            .expect("generated passphrase message should use the CLI disclosure prefix");
        assert_eq!(phrase.split('-').count(), 3);
        assert!(key.with_exposed(|key| key == phrase.as_bytes()));
    }

    #[test]
    fn generated_passphrase_secret_uses_closure_scoped_access() {
        let source = include_str!("states.rs");
        let required = ["passphrase", "with_exposed"].join(".");
        let forbidden = ["passphrase", "expose("].join(".");

        assert!(source.contains(&required));
        assert!(!source.contains(&forbidden));
    }

    #[test]
    fn generated_passphrase_debug_does_not_disclose_secret() {
        let mut messages = Vec::new();

        let key =
            generated_passphrase_secret(PassphraseWordCount::try_new(2).unwrap(), |message| {
                messages.push(message.to_owned());
            });
        let phrase = messages[0]
            .strip_prefix(DISCLOSURE_PREFIX)
            .expect("generated passphrase message should use the CLI disclosure prefix");

        assert!(!format!("{key:?}").contains(phrase));
        assert!(
            !format!(
                "{:?}",
                Key::Generate(PassphraseWordCount::try_new(2).unwrap())
            )
            .contains(phrase)
        );
    }

    #[test]
    fn autogenerate_key_source_accepts_positive_word_count() {
        let key = Key::resolve_key_source(None, Some("7"), true, &KeyParams::default()).unwrap();

        assert_eq!(key, Key::Generate(PassphraseWordCount::try_new(7).unwrap()));
    }

    #[test]
    fn invalid_explicit_autogenerate_word_counts_are_rejected() {
        for words in ["0", "-1", "abc"] {
            let error = Key::resolve_key_source(None, Some(words), true, &KeyParams::default())
                .expect_err("invalid explicit generated-passphrase count should fail");
            let error = error.to_string();

            assert!(
                error.contains("generated passphrase word count"),
                "error should name the generated passphrase count: {error}"
            );
            assert!(
                !error.contains(DISCLOSURE_PREFIX),
                "invalid count error must not include generated-passphrase disclosure"
            );
        }
    }

    #[test]
    fn key_source_true_absence_preserves_user_fallback() {
        let matches = Command::new("synthetic")
            .arg(Arg::new("keyfile").long("keyfile"))
            .arg(Arg::new("autogenerate").long("auto"))
            .try_get_matches_from(["synthetic"])
            .expect("synthetic matches should parse");

        let key = Key::init(
            &matches,
            &KeyParams {
                user: true,
                env: false,
                autogenerate: true,
                keyfile: true,
            },
            "keyfile",
        )
        .expect("true optional absence should still fall back to user");

        assert_eq!(key, Key::User);
    }

    #[test]
    fn key_source_unreadable_keyfile_returns_adapter_error_before_fallback() {
        let matches = Command::new("synthetic")
            .arg(
                Arg::new("keyfile")
                    .long("keyfile")
                    .value_parser(value_parser!(u16)),
            )
            .arg(Arg::new("autogenerate").long("auto"))
            .try_get_matches_from(["synthetic", "--keyfile", "7"])
            .expect("synthetic matches should parse");

        let error = Key::init(
            &matches,
            &KeyParams {
                user: true,
                env: true,
                autogenerate: true,
                keyfile: true,
            },
            "keyfile",
        )
        .expect_err("unreadable keyfile access should fail before fallback");

        assert!(
            error.to_string().contains(
                "internal CLI adapter error: optional argument 'keyfile' unreadable after clap validation"
            ),
            "error should name the unreadable keyfile adapter access: {error}"
        );
    }

    #[test]
    fn key_source_unreadable_autogenerate_returns_adapter_error_before_fallback() {
        let matches = Command::new("synthetic")
            .arg(Arg::new("keyfile").long("keyfile"))
            .arg(
                Arg::new("autogenerate")
                    .long("auto")
                    .value_parser(value_parser!(u16)),
            )
            .try_get_matches_from(["synthetic", "--auto", "7"])
            .expect("synthetic matches should parse");

        let error = Key::init(
            &matches,
            &KeyParams {
                user: true,
                env: true,
                autogenerate: true,
                keyfile: true,
            },
            "keyfile",
        )
        .expect_err("unreadable autogenerate access should fail before fallback");

        assert!(
            error.to_string().contains(
                "internal CLI adapter error: optional argument 'autogenerate' unreadable after clap validation"
            ),
            "error should name the unreadable autogenerate adapter access: {error}"
        );
    }
}

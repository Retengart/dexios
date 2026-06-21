use anyhow::{Context, Result};
use clap::ArgMatches;
use core::protected::Protected;
use std::io::Read;
use zeroize::Zeroize;

use crate::cli::prompt::get_password;
use crate::global::parameters::get_optional_param;
use crate::warn;
use core::key::{PassphraseWordCount, generate_passphrase};

const MAX_KEY_MATERIAL_BYTES: usize = 1_048_576;
const MAX_KEY_MATERIAL_READ_BYTES: u64 = 1_048_577;

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum DirectoryMode {
    Singular,
    Recursive,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum DeleteSource {
    Delete,
    Retain,
}

#[derive(PartialEq, Eq)]
pub(crate) enum PrintMode {
    Verbose,
    Quiet,
}

pub(crate) enum HeaderLocation {
    Embedded,
    Detached(String),
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum DeleteInput {
    Delete,
    Retain,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum HashMode {
    CalculateHash,
    NoHash,
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub(crate) enum ForceMode {
    Force,
    Prompt,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Keyfile(String),
    Generate(PassphraseWordCount),
    User,
}

#[derive(PartialEq, Eq)]
pub(crate) enum PasswordState {
    Validate,
    Direct,
}

fn get_bytes<R: Read>(reader: &mut R) -> Result<Protected<Vec<u8>>> {
    let mut data = Vec::with_capacity(MAX_KEY_MATERIAL_BYTES + 1);
    if let Err(error) = reader
        .take(MAX_KEY_MATERIAL_READ_BYTES)
        .read_to_end(&mut data)
    {
        data.zeroize();
        return Err(error).context("Unable to read data");
    }
    if data.len() > MAX_KEY_MATERIAL_BYTES {
        data.zeroize();
        anyhow::bail!("key material exceeds 1 MiB limit");
    }
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
    pub(crate) fn reads_stdin(&self) -> bool {
        matches!(self, Self::Keyfile(path) if path == "-")
    }

    pub(crate) fn resolve_key_source(
        keyfile: Option<&str>,
        autogenerate: Option<&str>,
        params: &KeyParams,
    ) -> Result<Self> {
        let key = if let (Some(path), true) = (keyfile, params.keyfile) {
            Self::Keyfile(path.to_owned())
        } else if let (Some(words), true) = (autogenerate, params.autogenerate) {
            Self::Generate(parse_generated_passphrase_word_count(words)?)
        } else if params.user {
            Self::User
        } else {
            return Err(anyhow::anyhow!(
                "No key sources found with the parameters/arguments provided"
            ));
        };

        Ok(key)
    }

    pub(crate) fn get_secret(&self, pass_state: &PasswordState) -> Result<Protected<Vec<u8>>> {
        let secret = match self {
            Self::Keyfile(path) if path == "-" => {
                let mut reader = std::io::stdin();
                let secret = get_bytes(&mut reader)?;
                if secret.with_exposed(Vec::is_empty) {
                    return Err(anyhow::anyhow!("STDIN is empty"));
                }
                secret
            }
            Self::Keyfile(path) => {
                let mut reader = std::fs::File::open(path)
                    .with_context(|| format!("Unable to read file: {path}"))?;
                let secret = get_bytes(&mut reader)?;
                if secret.with_exposed(Vec::is_empty) {
                    return Err(anyhow::anyhow!(format!("Keyfile '{path}' is empty")));
                }
                secret
            }
            Self::User => get_password(pass_state)?,
            Self::Generate(i) => generated_passphrase_secret(*i, |message| warn!("{message}")),
        };

        if secret.with_exposed(Vec::is_empty) {
            Err(anyhow::anyhow!("The specified key is empty!"))
        } else {
            Ok(secret)
        }
    }

    pub(crate) fn init(
        sub_matches: &ArgMatches,
        params: &KeyParams,
        keyfile_descriptor: &str,
    ) -> Result<Self> {
        let keyfile = get_optional_param(keyfile_descriptor, sub_matches)?;
        let autogenerate = get_optional_param("autogenerate", sub_matches)?;

        Self::resolve_key_source(keyfile, autogenerate, params)
    }
}

pub(crate) struct KeyParams {
    pub user: bool,
    pub autogenerate: bool,
    pub keyfile: bool,
}

impl Default for KeyParams {
    fn default() -> Self {
        Self {
            user: true,
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
        let key = Key::resolve_key_source(None, Some("7"), &KeyParams::default()).unwrap();

        assert_eq!(key, Key::Generate(PassphraseWordCount::try_new(7).unwrap()));
    }

    #[test]
    fn absent_explicit_key_source_uses_user_prompt_fallback() {
        let key = Key::resolve_key_source(None, None, &KeyParams::default()).unwrap();

        assert_eq!(key, Key::User);
    }

    #[test]
    fn key_resolution_without_user_prompt_fails_closed() {
        let error = Key::resolve_key_source(
            None,
            None,
            &KeyParams {
                user: false,
                autogenerate: true,
                keyfile: true,
            },
        )
        .expect_err("key resolution without any enabled source must fail");

        assert!(
            error
                .to_string()
                .contains("No key sources found with the parameters/arguments provided"),
            "error should explain that no key source is available: {error}"
        );
    }

    #[test]
    fn key_material_larger_than_one_mib_is_rejected_before_wrapping() {
        let mut reader = std::io::Cursor::new(vec![b'x'; 1_048_577]);

        let error = get_bytes(&mut reader)
            .expect_err("oversized key material must be rejected before it is wrapped");

        assert!(
            error.to_string().contains("key material exceeds 1 MiB"),
            "error should name the key material limit: {error}"
        );
    }

    #[test]
    fn partial_key_material_read_error_fails_before_wrapping() {
        struct PartialThenError {
            emitted: bool,
        }

        impl Read for PartialThenError {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.emitted {
                    return Err(std::io::Error::other("synthetic partial key read failure"));
                }

                self.emitted = true;
                buf[..6].copy_from_slice(b"secret");
                Ok(6)
            }
        }

        let mut reader = PartialThenError { emitted: false };

        let error = get_bytes(&mut reader)
            .expect_err("partial key material read failure must not produce a wrapped secret");

        assert!(
            error.to_string().contains("Unable to read data"),
            "error should keep the key-read context: {error}"
        );
    }

    #[test]
    fn invalid_explicit_autogenerate_word_counts_are_rejected() {
        for words in ["0", "-1", "abc"] {
            let error = Key::resolve_key_source(None, Some(words), &KeyParams::default())
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

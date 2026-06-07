use std::path::{Path, PathBuf};

use anyhow::Result;
use domain::storage::identity::OverwritePolicy;

use crate::cli::prompt::overwrite_check;
use crate::global::states::ForceMode;
use crate::global::structs::CryptoParams;

const STDIN_KEYFILE_PROMPT_CONFLICT: &str = "--keyfile - cannot be combined with interactive overwrite prompts; pass --force to avoid reading confirmation from stdin";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExistingPathProbe {
    Metadata,
    SymlinkMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlannedOverwrite {
    path: PathBuf,
    exists: bool,
}

impl PlannedOverwrite {
    pub(crate) fn new(path: impl AsRef<Path>, probe: ExistingPathProbe) -> Self {
        let path = path.as_ref().to_path_buf();
        let exists = match probe {
            ExistingPathProbe::Metadata => std::fs::metadata(&path).is_ok(),
            ExistingPathProbe::SymlinkMetadata => std::fs::symlink_metadata(&path).is_ok(),
        };
        Self { path, exists }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn exists(&self) -> bool {
        self.exists
    }

    pub(crate) fn policy(&self) -> OverwritePolicy {
        if self.exists {
            OverwritePolicy::ReplaceAtCommit
        } else {
            OverwritePolicy::CreateNew
        }
    }
}

pub(crate) fn confirm_overwrites<'a>(
    targets: impl IntoIterator<Item = &'a PlannedOverwrite>,
    force: ForceMode,
) -> Result<bool> {
    confirm_overwrites_with(targets, force, overwrite_check)
}

pub(crate) fn confirm_overwrites_with<'a, F>(
    targets: impl IntoIterator<Item = &'a PlannedOverwrite>,
    force: ForceMode,
    mut ask: F,
) -> Result<bool>
where
    F: FnMut(&str, ForceMode) -> Result<bool>,
{
    for target in targets {
        if target.exists() && !ask(target.path().to_string_lossy().as_ref(), force)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn reject_stdin_keyfile_prompt_conflict(
    params: &CryptoParams,
    prompt_needed: bool,
) -> Result<()> {
    if prompt_needed && params.force == ForceMode::Prompt && params.key.reads_stdin() {
        return Err(anyhow::anyhow!(STDIN_KEYFILE_PROMPT_CONFLICT));
    }
    Ok(())
}

pub(crate) fn reject_stdin_keyfile_dynamic_prompt_conflict(params: &CryptoParams) -> Result<()> {
    if params.force == ForceMode::Prompt && params.key.reads_stdin() {
        return Err(anyhow::anyhow!(STDIN_KEYFILE_PROMPT_CONFLICT));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::states::{DeleteInput, HashMode, HeaderLocation, Key};
    use crate::global::structs::CryptoParams;

    fn crypto_params_with_stdin_key(force: ForceMode) -> CryptoParams {
        CryptoParams {
            key: Key::Keyfile("-".to_owned()),
            kdf: core::kdf::Kdf::Argon2id,
            force,
            hash_mode: HashMode::NoHash,
            header_location: HeaderLocation::Embedded,
            delete_input: DeleteInput::Retain,
        }
    }

    #[test]
    fn planned_overwrite_policy_tracks_existing_target() {
        let dir = tempfile::tempdir().expect("temp dir");
        let existing = dir.path().join("existing.txt");
        std::fs::write(&existing, b"data").expect("write existing");
        let planned = PlannedOverwrite::new(&existing, ExistingPathProbe::Metadata);
        assert!(planned.exists());
        assert_eq!(planned.policy(), OverwritePolicy::ReplaceAtCommit);
    }

    #[test]
    fn planned_overwrite_policy_tracks_missing_target() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("missing.txt");
        let planned = PlannedOverwrite::new(&missing, ExistingPathProbe::Metadata);
        assert!(!planned.exists());
        assert_eq!(planned.policy(), OverwritePolicy::CreateNew);
    }

    #[test]
    fn confirm_overwrites_short_circuits_after_decline() {
        let first = PlannedOverwrite {
            path: PathBuf::from("first"),
            exists: true,
        };
        let second = PlannedOverwrite {
            path: PathBuf::from("second"),
            exists: true,
        };
        let mut prompts = Vec::new();
        let allowed = confirm_overwrites_with([&first, &second], ForceMode::Prompt, |path, _| {
            prompts.push(path.to_owned());
            Ok(false)
        })
        .expect("prompt result");
        assert!(!allowed);
        assert_eq!(prompts, vec!["first"]);
    }

    #[test]
    fn missing_targets_do_not_prompt() {
        let missing = PlannedOverwrite {
            path: PathBuf::from("missing"),
            exists: false,
        };
        let allowed = confirm_overwrites_with([&missing], ForceMode::Prompt, |_path, _| {
            panic!("missing targets must not prompt")
        })
        .expect("prompt result");
        assert!(allowed);
    }

    #[test]
    fn stdin_keyfile_conflict_preserves_message() {
        let params = crypto_params_with_stdin_key(ForceMode::Prompt);
        let error = reject_stdin_keyfile_prompt_conflict(&params, true).expect_err("conflict");
        assert_eq!(error.to_string(), STDIN_KEYFILE_PROMPT_CONFLICT);
    }
}

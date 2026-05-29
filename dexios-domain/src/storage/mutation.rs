use std::fmt;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use super::identity::{PathRole, ResolvedTarget};

/// Snapshot of a file targeted by an in-place header/key-slot mutation.
///
/// `original` deliberately holds the **full** file contents so [`ensure_fresh`] can
/// detect *any* change between intent creation and commit (a byte-exact freshness
/// contract), not just header or length drift. This is a conscious decision (add-1):
/// streaming the payload tail with a metadata-only freshness check (identity + length +
/// header prefix) would avoid buffering large files, but it weakens the mutation
/// freshness guarantee on the security-sensitive keyslot-rewrite path, so it is not taken
/// here. The read-only `header dump` path, which has no freshness contract, reads only the
/// header region (see `header::dump`).
#[derive(Debug)]
pub struct MutationSnapshot {
    target: ResolvedTarget,
    original: Vec<u8>,
}

impl MutationSnapshot {
    pub fn read(target: ResolvedTarget) -> Result<Self, MutationFreshnessError> {
        let original = fs::read(target.target_path()).map_err(|source| {
            MutationFreshnessError::read(target.role(), target.target_path().to_path_buf(), source)
        })?;
        Ok(Self { target, original })
    }

    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn from_bytes(target: ResolvedTarget, original: Vec<u8>) -> Self {
        Self { target, original }
    }

    #[must_use]
    pub fn target(&self) -> &ResolvedTarget {
        &self.target
    }

    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    #[must_use]
    pub fn into_parts(self) -> (ResolvedTarget, Vec<u8>) {
        (self.target, self.original)
    }

    pub fn ensure_fresh(&self) -> Result<(), MutationFreshnessError> {
        ensure_fresh(&self.target, &self.original)
    }
}

pub fn ensure_fresh(
    target: &ResolvedTarget,
    original: &[u8],
) -> Result<(), MutationFreshnessError> {
    ensure_identity_fresh(target)?;
    let current = fs::read(target.target_path()).map_err(|source| {
        MutationFreshnessError::read(target.role(), target.target_path().to_path_buf(), source)
    })?;
    if current != original {
        return Err(MutationFreshnessError::ContentChanged {
            role: target.role(),
            path: target.target_path().to_path_buf(),
        });
    }
    Ok(())
}

#[derive(Debug)]
pub enum MutationFreshnessError {
    Read {
        role: PathRole,
        path: PathBuf,
        source: io::Error,
    },
    IdentityChanged {
        role: PathRole,
        path: PathBuf,
    },
    ContentChanged {
        role: PathRole,
        path: PathBuf,
    },
}

impl MutationFreshnessError {
    fn read(role: PathRole, path: PathBuf, source: io::Error) -> Self {
        Self::Read { role, path, source }
    }

    #[must_use]
    pub fn role(&self) -> PathRole {
        match self {
            Self::Read { role, .. }
            | Self::IdentityChanged { role, .. }
            | Self::ContentChanged { role, .. } => *role,
        }
    }

    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        match self {
            Self::Read { path, .. }
            | Self::IdentityChanged { path, .. }
            | Self::ContentChanged { path, .. } => path,
        }
    }
}

impl fmt::Display for MutationFreshnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { role, path, .. } => {
                write!(f, "Unable to read {} {}", role_label(*role), path.display())
            }
            Self::IdentityChanged { role, path } => {
                write!(
                    f,
                    "{} identity changed before commit: {}",
                    role_label(*role),
                    path.display()
                )
            }
            Self::ContentChanged { role, path } => {
                write!(
                    f,
                    "{} content changed before commit: {}",
                    role_label(*role),
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for MutationFreshnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::IdentityChanged { .. } | Self::ContentChanged { .. } => None,
        }
    }
}

#[cfg(unix)]
fn ensure_identity_fresh(target: &ResolvedTarget) -> Result<(), MutationFreshnessError> {
    let Some(expected) = target.existing_target_identity() else {
        return Ok(());
    };
    let metadata = fs::symlink_metadata(target.target_path()).map_err(|source| {
        MutationFreshnessError::read(target.role(), target.target_path().to_path_buf(), source)
    })?;
    if metadata.file_type().is_symlink()
        || metadata.dev() != expected.dev
        || metadata.ino() != expected.ino
    {
        return Err(MutationFreshnessError::IdentityChanged {
            role: target.role(),
            path: target.target_path().to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_identity_fresh(_target: &ResolvedTarget) -> Result<(), MutationFreshnessError> {
    Ok(())
}

fn role_label(role: PathRole) -> &'static str {
    match role {
        PathRole::Input => "input",
        PathRole::Output | PathRole::GeneratedOutput => "output",
        PathRole::DetachedHeader | PathRole::GeneratedDetachedHeader => "detached header",
        PathRole::UnpackRoot => "unpack root",
        PathRole::MutationTarget => "mutation target",
        PathRole::ProcessedSource => "processed source",
        PathRole::CleanupTarget => "cleanup target",
    }
}

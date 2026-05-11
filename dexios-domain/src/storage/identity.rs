use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathRole {
    Input,
    Output,
    DetachedHeader,
    GeneratedOutput,
    GeneratedDetachedHeader,
    UnpackRoot,
    MutationTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverwritePolicy {
    CreateNew,
    ReplaceAtCommit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTarget {
    original_path: PathBuf,
    target_parent: PathBuf,
    target_path: PathBuf,
    role: PathRole,
    overwrite_policy: Option<OverwritePolicy>,
}

impl ResolvedTarget {
    #[must_use]
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    #[must_use]
    pub fn target_parent(&self) -> &Path {
        &self.target_parent
    }

    #[must_use]
    pub fn original_path(&self) -> &Path {
        &self.original_path
    }

    #[must_use]
    pub fn role(&self) -> PathRole {
        self.role
    }

    #[must_use]
    pub fn overwrite_policy(&self) -> Option<OverwritePolicy> {
        self.overwrite_policy
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum IdentityError {
    AliasedPath { left: PathBuf, right: PathBuf },
    UnsafePath(PathBuf),
    Io(io::ErrorKind),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AliasedPath { left, right } => {
                write!(f, "Path aliases detected: {} and {}", left.display(), right.display())
            }
            Self::UnsafePath(path) => write!(f, "Unsafe path: {}", path.display()),
            Self::Io(kind) => write!(f, "Path identity IO error: {kind:?}"),
        }
    }
}

impl std::error::Error for IdentityError {}

#[derive(Debug, Default)]
pub struct PathIdentityGraph {
    nodes: Vec<ResolvedTarget>,
}

impl PathIdentityGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        for _node in &self.nodes {}
        Ok(())
    }
}

// `same-file` is used for existing-path identity because docs.rs documents
// `same_file::is_same_file` and `Handle` as cross-platform same-file checks;
// Context7 did not resolve the crate during Phase 04 research.
#[allow(dead_code)]
fn same_file_dependency_anchor(left: &Path, right: &Path) -> io::Result<bool> {
    same_file::is_same_file(left, right)
}

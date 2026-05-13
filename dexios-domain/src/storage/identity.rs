use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

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
    missing_components: Vec<OsString>,
    exists: bool,
    is_dir: bool,
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

    #[must_use]
    pub fn missing_components(&self) -> &[OsString] {
        &self.missing_components
    }

    #[must_use]
    pub fn exists(&self) -> bool {
        self.exists
    }
}

#[derive(Debug)]
pub enum IdentityError {
    AliasedPath {
        left: PathBuf,
        right: PathBuf,
    },
    UnsafePath(PathBuf),
    Io(io::ErrorKind),
    IoWithSource {
        kind: io::ErrorKind,
        source: io::Error,
    },
}

impl IdentityError {
    #[must_use]
    pub fn from_io_error(source: io::Error) -> Self {
        Self::IoWithSource {
            kind: source.kind(),
            source,
        }
    }
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AliasedPath { left, right } => {
                write!(
                    f,
                    "Path aliases detected: {} and {}",
                    left.display(),
                    right.display()
                )
            }
            Self::UnsafePath(path) => write!(f, "Unsafe path: {}", path.display()),
            Self::Io(kind) | Self::IoWithSource { kind, .. } => {
                write!(f, "Path identity IO error: {kind:?}")
            }
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoWithSource { source, .. } => Some(source),
            Self::AliasedPath { .. } | Self::UnsafePath(_) | Self::Io(_) => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct PathIdentityGraph {
    nodes: Vec<ResolvedTarget>,
}

impl PathIdentityGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_existing<P: AsRef<Path>>(
        &mut self,
        path: P,
        role: PathRole,
    ) -> Result<ResolvedTarget, IdentityError> {
        let original_path = path.as_ref().to_path_buf();
        let canonical_path =
            fs::canonicalize(&original_path).map_err(IdentityError::from_io_error)?;
        let is_dir = fs::metadata(&canonical_path)
            .map_err(IdentityError::from_io_error)?
            .is_dir();
        let target = ResolvedTarget {
            original_path,
            target_parent: target_parent_for(&canonical_path, is_dir),
            target_path: canonical_path,
            role,
            overwrite_policy: None,
            missing_components: Vec::new(),
            exists: true,
            is_dir,
        };

        self.push(target)
    }

    pub fn add_output<P: AsRef<Path>>(
        &mut self,
        path: P,
        role: PathRole,
        overwrite_policy: OverwritePolicy,
    ) -> Result<ResolvedTarget, IdentityError> {
        let original_path = path.as_ref().to_path_buf();
        let absolute_path = absolute_normalized_path(&original_path)?;

        match fs::symlink_metadata(&absolute_path) {
            Ok(meta) => {
                let canonical_path =
                    fs::canonicalize(&absolute_path).map_err(IdentityError::from_io_error)?;
                let is_dir = meta.is_dir();
                self.push(ResolvedTarget {
                    original_path,
                    target_parent: target_parent_for(&canonical_path, is_dir),
                    target_path: canonical_path,
                    role,
                    overwrite_policy: Some(overwrite_policy),
                    missing_components: Vec::new(),
                    exists: true,
                    is_dir,
                })
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let (target_parent, missing_components) =
                    resolve_missing_target_parent(&absolute_path)?;
                let target_path =
                    target_parent.join(missing_components.iter().collect::<PathBuf>());

                self.push(ResolvedTarget {
                    original_path,
                    target_parent,
                    target_path,
                    role,
                    overwrite_policy: Some(overwrite_policy),
                    missing_components,
                    exists: false,
                    is_dir: false,
                })
            }
            Err(err) => Err(IdentityError::from_io_error(err)),
        }
    }

    pub fn add_generated<P: AsRef<Path>>(
        &mut self,
        path: P,
        role: PathRole,
    ) -> Result<ResolvedTarget, IdentityError> {
        self.add_output(path, role, OverwritePolicy::CreateNew)
    }

    pub fn add_unpack_root<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<ResolvedTarget, IdentityError> {
        self.add_output(path, PathRole::UnpackRoot, OverwritePolicy::CreateNew)
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        for (index, left) in self.nodes.iter().enumerate() {
            for right in &self.nodes[index + 1..] {
                ensure_distinct(left, right)?;
            }
        }
        Ok(())
    }

    fn push(&mut self, target: ResolvedTarget) -> Result<ResolvedTarget, IdentityError> {
        for existing in &self.nodes {
            ensure_distinct(existing, &target)?;
        }

        self.nodes.push(target.clone());
        Ok(target)
    }
}

// `same-file` is used for existing-path identity because docs.rs documents
// `same_file::is_same_file` and `Handle` as cross-platform same-file checks;
// Context7 did not resolve the crate during Phase 04 research.
fn ensure_distinct(left: &ResolvedTarget, right: &ResolvedTarget) -> Result<(), IdentityError> {
    let exact_alias = left.target_path == right.target_path;
    let platform_alias = if left.exists && right.exists {
        same_file::is_same_file(&left.target_path, &right.target_path)
            .map_err(IdentityError::from_io_error)?
    } else {
        false
    };

    if exact_alias || platform_alias || generated_output_inside_input(left, right) {
        return Err(IdentityError::AliasedPath {
            left: left.original_path.clone(),
            right: right.original_path.clone(),
        });
    }

    Ok(())
}

fn generated_output_inside_input(left: &ResolvedTarget, right: &ResolvedTarget) -> bool {
    generated_target_inside_input(left, right) || generated_target_inside_input(right, left)
}

fn generated_target_inside_input(input: &ResolvedTarget, generated: &ResolvedTarget) -> bool {
    input.role == PathRole::Input
        && input.is_dir
        && matches!(
            generated.role,
            PathRole::GeneratedOutput | PathRole::GeneratedDetachedHeader
        )
        && generated.target_path.starts_with(&input.target_path)
}

fn absolute_normalized_path(path: &Path) -> Result<PathBuf, IdentityError> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(IdentityError::from_io_error)?
            .join(path)
    };

    normalize_components(&path)
}

fn normalize_components(path: &Path) -> Result<PathBuf, IdentityError> {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(IdentityError::UnsafePath(path.to_path_buf()));
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    Ok(normalized)
}

fn resolve_missing_target_parent(path: &Path) -> Result<(PathBuf, Vec<OsString>), IdentityError> {
    let (existing_parent, missing_components) = nearest_existing_ancestor(path)?;

    reject_symlinked_prefix(&existing_parent)?;
    let canonical_parent =
        fs::canonicalize(&existing_parent).map_err(IdentityError::from_io_error)?;

    Ok((canonical_parent, missing_components))
}

fn nearest_existing_ancestor(path: &Path) -> Result<(PathBuf, Vec<OsString>), IdentityError> {
    let mut ancestor = path.to_path_buf();
    let mut suffix = Vec::new();

    loop {
        match fs::symlink_metadata(&ancestor) {
            Ok(meta) if meta.is_dir() => {
                suffix.reverse();
                return Ok((ancestor, suffix));
            }
            Ok(_) => return Err(IdentityError::UnsafePath(path.to_path_buf())),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or_else(|| IdentityError::UnsafePath(path.to_path_buf()))?;
                suffix.push(name.to_os_string());
                if !ancestor.pop() {
                    return Err(IdentityError::UnsafePath(path.to_path_buf()));
                }
            }
            Err(err) => return Err(IdentityError::from_io_error(err)),
        }
    }
}

fn reject_symlinked_prefix(existing_parent: &Path) -> Result<(), IdentityError> {
    let mut current = PathBuf::new();

    for component in existing_parent.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => return Err(IdentityError::UnsafePath(existing_parent.into())),
            Component::Normal(part) => {
                current.push(part);
                let meta = fs::symlink_metadata(&current).map_err(IdentityError::from_io_error)?;
                if meta.file_type().is_symlink() {
                    return Err(IdentityError::UnsafePath(current));
                }
            }
        }
    }

    Ok(())
}

fn target_parent_for(target_path: &Path, is_dir: bool) -> PathBuf {
    if is_dir {
        return target_path.to_path_buf();
    }

    target_path
        .parent()
        .map_or_else(|| target_path.to_path_buf(), Path::to_path_buf)
}

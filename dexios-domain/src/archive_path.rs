use std::fmt;
use std::path::{Component, Path, PathBuf};

use crate::archive::{ArchiveLimitError, ArchiveLimits};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NormalizedArchivePath {
    relative_path: PathBuf,
    manifest_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ArchivePathError {
    Unsafe(PathBuf),
}

impl fmt::Display for ArchivePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsafe(path) => write!(f, "Unsafe archive path: {}", path.display()),
        }
    }
}

impl std::error::Error for ArchivePathError {}

impl NormalizedArchivePath {
    pub(crate) fn from_path(path: &Path) -> Result<Self, ArchivePathError> {
        let text = path
            .to_str()
            .ok_or_else(|| ArchivePathError::Unsafe(path.to_path_buf()))?;
        reject_empty_or_dot_raw_components(text, path)?;

        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::CurDir => return Err(ArchivePathError::Unsafe(path.to_path_buf())),
                Component::Normal(part) => {
                    let part = part
                        .to_str()
                        .ok_or_else(|| ArchivePathError::Unsafe(path.to_path_buf()))?;
                    reject_manifest_component(part, path)?;
                    components.push(part.to_owned());
                }
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(ArchivePathError::Unsafe(path.to_path_buf()));
                }
            }
        }
        Self::from_components(components, path)
    }

    pub(crate) fn from_manifest_bytes(bytes: &[u8]) -> Result<Self, ArchivePathError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ArchivePathError::Unsafe(PathBuf::from("<non-utf8>")))?;
        let original = Path::new(text);
        reject_empty_or_dot_raw_components(text, original)?;
        reject_non_relative_path_components(original)?;

        let mut components = Vec::new();
        for component in text.split('/') {
            reject_manifest_component(component, original)?;
            components.push(component.to_owned());
        }
        Self::from_components(components, original)
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.relative_path
    }

    pub(crate) fn as_manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub(crate) fn check_limits(&self, limits: &ArchiveLimits) -> Result<(), ArchiveLimitError> {
        limits.check_normalized_path(&self.relative_path)
    }

    fn from_components(components: Vec<String>, original: &Path) -> Result<Self, ArchivePathError> {
        if components.is_empty() {
            return Err(ArchivePathError::Unsafe(original.to_path_buf()));
        }

        let mut relative_path = PathBuf::new();
        for component in &components {
            relative_path.push(component);
        }
        let manifest_bytes = components.join("/").into_bytes();
        Ok(Self {
            relative_path,
            manifest_bytes,
        })
    }
}

fn reject_empty_or_dot_raw_components(text: &str, original: &Path) -> Result<(), ArchivePathError> {
    for component in text.split(is_raw_path_separator) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ArchivePathError::Unsafe(original.to_path_buf()));
        }
    }
    Ok(())
}

fn is_raw_path_separator(character: char) -> bool {
    character == '/' || (cfg!(windows) && character == '\\')
}

fn reject_non_relative_path_components(path: &Path) -> Result<(), ArchivePathError> {
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(ArchivePathError::Unsafe(path.to_path_buf()));
            }
        }
    }
    Ok(())
}

fn reject_manifest_component(component: &str, original: &Path) -> Result<(), ArchivePathError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('\\')
        || component.contains('\0')
    {
        return Err(ArchivePathError::Unsafe(original.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_relative_archive_path() {
        let path = NormalizedArchivePath::from_path(Path::new("dir/file.txt")).unwrap();

        assert_eq!(path.as_path(), Path::new("dir/file.txt"));
        assert_eq!(path.as_manifest_bytes(), b"dir/file.txt");
    }

    #[test]
    fn rejects_unsafe_filesystem_archive_paths() {
        for path in [
            "",
            ".",
            "..",
            "dir/..",
            "dir/../file",
            "/abs",
            "dir/",
            "dir/\0file.txt",
        ] {
            assert!(
                NormalizedArchivePath::from_path(Path::new(path)).is_err(),
                "{path:?} must be rejected"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn rejects_filesystem_path_containing_windows_separator_byte() {
        for path in ["dir\\file.txt", "dir/..\\escape.txt"] {
            assert!(
                NormalizedArchivePath::from_path(Path::new(path)).is_err(),
                "{path:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_unsafe_manifest_paths() {
        for path in [
            b"".as_slice(),
            b".".as_slice(),
            b"..".as_slice(),
            b"dir/..".as_slice(),
            b"dir/../file".as_slice(),
            b"/abs".as_slice(),
            b"dir/".as_slice(),
            b"dir\\file.txt".as_slice(),
            b"dir/..\\escape.txt".as_slice(),
            b"dir/\0file.txt".as_slice(),
        ] {
            assert!(
                NormalizedArchivePath::from_manifest_bytes(path).is_err(),
                "{path:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_non_utf8_manifest_bytes() {
        assert!(NormalizedArchivePath::from_manifest_bytes(b"dir/\xFF.txt").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_absolute_filesystem_archive_path() {
        assert!(NormalizedArchivePath::from_path(Path::new("C:/abs/file.txt")).is_err());
    }
}

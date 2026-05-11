//! Archive policy types owned by Dexios, not by the ZIP implementation.

use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveCompression {
    Zstd,
}

impl ArchiveCompression {
    const fn default_public() -> Self {
        Self::Zstd
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchivePolicy {
    compression: ArchiveCompression,
}

impl ArchivePolicy {
    #[must_use]
    pub const fn zstd() -> Self {
        Self {
            compression: ArchiveCompression::default_public(),
        }
    }

    #[must_use]
    pub const fn compression(self) -> ArchiveCompression {
        self.compression
    }
}

impl Default for ArchivePolicy {
    fn default() -> Self {
        Self::zstd()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveLimitKind {
    EntryCount,
    NormalizedPathBytes,
    NormalizedPathDepth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimitError {
    pub kind: ArchiveLimitKind,
    pub limit: usize,
    pub actual: usize,
}

impl std::fmt::Display for ArchiveLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self.kind {
            ArchiveLimitKind::EntryCount => "archive entry count",
            ArchiveLimitKind::NormalizedPathBytes => "normalized path byte length",
            ArchiveLimitKind::NormalizedPathDepth => "normalized path depth",
        };
        write!(
            f,
            "{label} exceeds Dexios limit: actual {}, limit {}",
            self.actual, self.limit
        )
    }
}

impl std::error::Error for ArchiveLimitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    pub max_normalized_path_bytes: usize,
    pub max_normalized_path_depth: usize,
}

impl ArchiveLimits {
    pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
    pub const DEFAULT_MAX_NORMALIZED_PATH_BYTES: usize = 4096;
    pub const DEFAULT_MAX_NORMALIZED_PATH_DEPTH: usize = 64;

    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            max_normalized_path_bytes: Self::DEFAULT_MAX_NORMALIZED_PATH_BYTES,
            max_normalized_path_depth: Self::DEFAULT_MAX_NORMALIZED_PATH_DEPTH,
        }
    }

    pub fn check_entry_count(self, count: usize) -> Result<(), ArchiveLimitError> {
        if count > self.max_entries {
            return Err(ArchiveLimitError {
                kind: ArchiveLimitKind::EntryCount,
                limit: self.max_entries,
                actual: count,
            });
        }

        Ok(())
    }

    pub fn check_normalized_path(self, path: &Path) -> Result<(), ArchiveLimitError> {
        let byte_len = path.as_os_str().as_encoded_bytes().len();
        if byte_len > self.max_normalized_path_bytes {
            return Err(ArchiveLimitError {
                kind: ArchiveLimitKind::NormalizedPathBytes,
                limit: self.max_normalized_path_bytes,
                actual: byte_len,
            });
        }

        let depth = path
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        if depth > self.max_normalized_path_depth {
            return Err(ArchiveLimitError {
                kind: ArchiveLimitKind::NormalizedPathDepth,
                limit: self.max_normalized_path_depth,
                actual: depth,
            });
        }

        Ok(())
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_limits_reject_entry_count_above_default() {
        let result = ArchiveLimits::default()
            .check_entry_count(ArchiveLimits::DEFAULT_MAX_ENTRIES.checked_add(1).unwrap());

        assert!(matches!(
            result,
            Err(ArchiveLimitError {
                kind: ArchiveLimitKind::EntryCount,
                limit: ArchiveLimits::DEFAULT_MAX_ENTRIES,
                actual,
            }) if actual == ArchiveLimits::DEFAULT_MAX_ENTRIES + 1
        ));
    }

    #[test]
    fn archive_limits_reject_path_depth_above_default() {
        let path = (0..=ArchiveLimits::DEFAULT_MAX_NORMALIZED_PATH_DEPTH)
            .map(|index| format!("dir{index}"))
            .collect::<std::path::PathBuf>();

        let result = ArchiveLimits::default().check_normalized_path(&path);

        assert!(matches!(
            result,
            Err(ArchiveLimitError {
                kind: ArchiveLimitKind::NormalizedPathDepth,
                limit: ArchiveLimits::DEFAULT_MAX_NORMALIZED_PATH_DEPTH,
                ..
            })
        ));
    }
}

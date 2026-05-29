//! Archive policy types owned by Dexios, not by the ZIP implementation.

use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArchivePolicy {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveLimitKind {
    EntryCount,
    NormalizedPathBytes,
    NormalizedPathDepth,
    TotalBodyBytes,
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
            ArchiveLimitKind::TotalBodyBytes => "aggregate archive body byte length",
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
    pub max_total_body_bytes: u64,
}

impl ArchiveLimits {
    pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
    pub const DEFAULT_MAX_NORMALIZED_PATH_BYTES: usize = 4096;
    pub const DEFAULT_MAX_NORMALIZED_PATH_DEPTH: usize = 64;
    /// Aggregate decompressed/extracted body-byte ceiling for a single archive (64 GiB).
    pub const DEFAULT_MAX_TOTAL_BODY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            max_normalized_path_bytes: Self::DEFAULT_MAX_NORMALIZED_PATH_BYTES,
            max_normalized_path_depth: Self::DEFAULT_MAX_NORMALIZED_PATH_DEPTH,
            max_total_body_bytes: Self::DEFAULT_MAX_TOTAL_BODY_BYTES,
        }
    }

    /// Fails once the running total of staged body bytes exceeds the aggregate cap,
    /// before the offending frame is staged (parse-1).
    pub fn check_total_body_bytes(self, running_total: u64) -> Result<(), ArchiveLimitError> {
        if running_total > self.max_total_body_bytes {
            return Err(ArchiveLimitError {
                kind: ArchiveLimitKind::TotalBodyBytes,
                limit: usize::try_from(self.max_total_body_bytes).unwrap_or(usize::MAX),
                actual: usize::try_from(running_total).unwrap_or(usize::MAX),
            });
        }

        Ok(())
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
    fn check_total_body_bytes_enforces_aggregate_cap() {
        let limits = ArchiveLimits::defaults();
        let max = limits.max_total_body_bytes;
        assert!(limits.check_total_body_bytes(max).is_ok());
        let err = limits.check_total_body_bytes(max + 1).unwrap_err();
        assert_eq!(err.kind, ArchiveLimitKind::TotalBodyBytes);
    }

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

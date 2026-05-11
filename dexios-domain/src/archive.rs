//! Archive policy types owned by Dexios, not by the ZIP implementation.

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

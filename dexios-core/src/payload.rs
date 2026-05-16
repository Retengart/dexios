//! Canonical V1 payload kind and Dexios-owned archive framing primitives.

use std::fmt::{Display, Formatter};

pub const MANIFEST_MAGIC: [u8; 4] = *b"DXAR";
const BODY_FRAME_MAGIC: [u8; 4] = *b"DXBF";
pub const MANIFEST_VERSION: u16 = 0x0001;
pub const MAX_MANIFEST_ENTRY_COUNT: u32 = 65_536;
pub const MAX_NORMALIZED_PATH_BYTES: usize = 4096;
pub const MAX_BODY_FRAME_LEN: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PayloadKind {
    RawFile = 0x01,
    ManifestArchive = 0x02,
}

impl PayloadKind {
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn try_from_byte(byte: u8) -> Result<Self, PayloadError> {
        match byte {
            0x01 => Ok(Self::RawFile),
            0x02 => Ok(Self::ManifestArchive),
            _ => Err(PayloadError::UnsupportedPayloadKind(byte)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PayloadFramingProfile {
    RawLe31 = 0x01,
    ManifestFirst = 0x02,
}

impl PayloadFramingProfile {
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn try_from_byte(byte: u8) -> Result<Self, PayloadError> {
        match byte {
            0x01 => Ok(Self::RawLe31),
            0x02 => Ok(Self::ManifestFirst),
            _ => Err(PayloadError::UnsupportedPayloadFramingProfile(byte)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadError {
    UnsupportedPayloadKind(u8),
    UnsupportedPayloadFramingProfile(u8),
    UnsupportedManifestVersion(u16),
    InvalidManifestMagic([u8; 4]),
    InvalidBodyFrameMagic([u8; 4]),
    InvalidEntryKind(u8),
    EmptyNormalizedPath,
    ManifestEntryCountLimitExceeded { limit: u32, actual: u32 },
    NormalizedPathLimitExceeded { limit: usize, actual: usize },
    BodyFrameLimitExceeded { limit: u64, actual: u64 },
    MissingBodyLength,
    UnexpectedBodyFrameForDirectory(u32),
    DuplicateBodyFrame(u32),
    MissingBodyFrame(u32),
    BodyFrameOrderMismatch { expected: u32, actual: u32 },
    BodyFrameLengthMismatch { expected: u64, actual: u64 },
    TruncatedManifest,
    TrailingBytes(usize),
}

impl Display for PayloadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPayloadKind(byte) => {
                write!(f, "unsupported canonical V1 payload kind: {byte}")
            }
            Self::UnsupportedPayloadFramingProfile(byte) => {
                write!(
                    f,
                    "unsupported canonical V1 payload framing profile: {byte}"
                )
            }
            Self::UnsupportedManifestVersion(version) => {
                write!(f, "unsupported manifest-first payload version: {version}")
            }
            Self::InvalidManifestMagic(magic) => {
                write!(f, "invalid manifest-first payload magic: {magic:02X?}")
            }
            Self::InvalidBodyFrameMagic(magic) => {
                write!(f, "invalid manifest-first body frame magic: {magic:02X?}")
            }
            Self::InvalidEntryKind(kind) => write!(f, "invalid manifest entry kind: {kind}"),
            Self::EmptyNormalizedPath => f.write_str("manifest entry path is empty"),
            Self::ManifestEntryCountLimitExceeded { limit, actual } => write!(
                f,
                "manifest entry count {actual} exceeds structural limit {limit}"
            ),
            Self::NormalizedPathLimitExceeded { limit, actual } => write!(
                f,
                "manifest path length {actual} exceeds structural limit {limit}"
            ),
            Self::BodyFrameLimitExceeded { limit, actual } => write!(
                f,
                "manifest body frame length {actual} exceeds structural limit {limit}"
            ),
            Self::MissingBodyLength => f.write_str("file manifest entry is missing body length"),
            Self::UnexpectedBodyFrameForDirectory(index) => {
                write!(
                    f,
                    "directory manifest entry {index} cannot have a body frame"
                )
            }
            Self::DuplicateBodyFrame(index) => {
                write!(f, "duplicate manifest body frame for entry {index}")
            }
            Self::MissingBodyFrame(index) => {
                write!(f, "missing manifest body frame for entry {index}")
            }
            Self::BodyFrameOrderMismatch { expected, actual } => write!(
                f,
                "manifest body frame order mismatch: expected entry {expected}, got {actual}"
            ),
            Self::BodyFrameLengthMismatch { expected, actual } => write!(
                f,
                "manifest body frame length mismatch: expected {expected}, got {actual}"
            ),
            Self::TruncatedManifest => f.write_str("truncated manifest-first payload"),
            Self::TrailingBytes(count) => {
                write!(f, "manifest-first payload has {count} trailing byte(s)")
            }
        }
    }
}

impl std::error::Error for PayloadError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ManifestEntryKind {
    File = 0x01,
    Directory = 0x02,
}

impl ManifestEntryKind {
    fn try_from_byte(byte: u8) -> Result<Self, PayloadError> {
        match byte {
            0x01 => Ok(Self::File),
            0x02 => Ok(Self::Directory),
            _ => Err(PayloadError::InvalidEntryKind(byte)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    kind: ManifestEntryKind,
    normalized_path: Vec<u8>,
    body_len: Option<u64>,
}

impl ManifestEntry {
    pub fn file(normalized_path: impl Into<Vec<u8>>, body_len: u64) -> Result<Self, PayloadError> {
        let entry = Self {
            kind: ManifestEntryKind::File,
            normalized_path: normalized_path.into(),
            body_len: Some(body_len),
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn directory(normalized_path: impl Into<Vec<u8>>) -> Result<Self, PayloadError> {
        let entry = Self {
            kind: ManifestEntryKind::Directory,
            normalized_path: normalized_path.into(),
            body_len: None,
        };
        entry.validate()?;
        Ok(entry)
    }

    #[must_use]
    pub const fn kind(&self) -> ManifestEntryKind {
        self.kind
    }

    #[must_use]
    pub fn normalized_path(&self) -> &[u8] {
        &self.normalized_path
    }

    #[must_use]
    pub const fn body_len(&self) -> Option<u64> {
        self.body_len
    }

    fn validate(&self) -> Result<(), PayloadError> {
        if self.normalized_path.is_empty() {
            return Err(PayloadError::EmptyNormalizedPath);
        }
        if self.normalized_path.len() > MAX_NORMALIZED_PATH_BYTES {
            return Err(PayloadError::NormalizedPathLimitExceeded {
                limit: MAX_NORMALIZED_PATH_BYTES,
                actual: self.normalized_path.len(),
            });
        }
        if let Some(body_len) = self.body_len {
            validate_body_len(body_len)?;
        } else if self.kind == ManifestEntryKind::File {
            return Err(PayloadError::MissingBodyLength);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveManifest {
    entries: Vec<ManifestEntry>,
}

impl ArchiveManifest {
    pub fn new(entries: Vec<ManifestEntry>) -> Result<Self, PayloadError> {
        let entry_count = u32::try_from(entries.len()).map_err(|_| {
            PayloadError::ManifestEntryCountLimitExceeded {
                limit: MAX_MANIFEST_ENTRY_COUNT,
                actual: u32::MAX,
            }
        })?;
        if entry_count > MAX_MANIFEST_ENTRY_COUNT {
            return Err(PayloadError::ManifestEntryCountLimitExceeded {
                limit: MAX_MANIFEST_ENTRY_COUNT,
                actual: entry_count,
            });
        }
        for entry in &entries {
            entry.validate()?;
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveBodyFrame {
    entry_index: u32,
    body: Vec<u8>,
}

impl ArchiveBodyFrame {
    pub fn new(entry_index: u32, body: impl Into<Vec<u8>>) -> Result<Self, PayloadError> {
        let frame = Self {
            entry_index,
            body: body.into(),
        };
        validate_body_len(frame.body_len())?;
        Ok(frame)
    }

    #[must_use]
    pub const fn entry_index(&self) -> u32 {
        self.entry_index
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn body_len(&self) -> u64 {
        u64::try_from(self.body.len()).expect("usize body length fits in u64")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestFirstPayload {
    manifest: ArchiveManifest,
    body_frames: Vec<ArchiveBodyFrame>,
}

impl ManifestFirstPayload {
    pub fn new(
        manifest: ArchiveManifest,
        body_frames: Vec<ArchiveBodyFrame>,
    ) -> Result<Self, PayloadError> {
        validate_body_frames(&manifest, &body_frames)?;
        Ok(Self {
            manifest,
            body_frames,
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &ArchiveManifest {
        &self.manifest
    }

    #[must_use]
    pub fn body_frames(&self) -> &[ArchiveBodyFrame] {
        &self.body_frames
    }

    pub fn serialize(&self) -> Result<Vec<u8>, PayloadError> {
        validate_body_frames(&self.manifest, &self.body_frames)?;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MANIFEST_MAGIC);
        bytes.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.manifest.entries.len())
                .expect("manifest entry count is bounded")
                .to_le_bytes(),
        );

        for entry in &self.manifest.entries {
            bytes.push(entry.kind as u8);
            bytes.extend_from_slice(
                &u16::try_from(entry.normalized_path.len())
                    .expect("normalized path length is bounded")
                    .to_le_bytes(),
            );
            if let Some(body_len) = entry.body_len {
                bytes.extend_from_slice(&body_len.to_le_bytes());
            }
            bytes.extend_from_slice(&entry.normalized_path);
        }

        for (index, entry) in self.manifest.entries.iter().enumerate() {
            if entry.kind != ManifestEntryKind::File {
                continue;
            }
            let index = u32::try_from(index).expect("manifest entry count is bounded");
            let frame = body_frame_for(&self.body_frames, index)?;
            bytes.extend_from_slice(&BODY_FRAME_MAGIC);
            bytes.extend_from_slice(&frame.entry_index.to_le_bytes());
            bytes.extend_from_slice(&frame.body_len().to_le_bytes());
            bytes.extend_from_slice(&frame.body);
        }

        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut offset = 0;
        let magic = read_array::<4>(bytes, &mut offset)?;
        if magic != MANIFEST_MAGIC {
            return Err(PayloadError::InvalidManifestMagic(magic));
        }
        let version = read_u16(bytes, &mut offset)?;
        if version != MANIFEST_VERSION {
            return Err(PayloadError::UnsupportedManifestVersion(version));
        }
        let entry_count = read_u32(bytes, &mut offset)?;
        if entry_count > MAX_MANIFEST_ENTRY_COUNT {
            return Err(PayloadError::ManifestEntryCountLimitExceeded {
                limit: MAX_MANIFEST_ENTRY_COUNT,
                actual: entry_count,
            });
        }

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let kind = ManifestEntryKind::try_from_byte(read_u8(bytes, &mut offset)?)?;
            let path_len = usize::from(read_u16(bytes, &mut offset)?);
            let body_len = if kind == ManifestEntryKind::File {
                Some(read_u64(bytes, &mut offset)?)
            } else {
                None
            };
            let path = read_bytes(bytes, &mut offset, path_len)?.to_vec();
            let entry = ManifestEntry {
                kind,
                normalized_path: path,
                body_len,
            };
            entry.validate()?;
            entries.push(entry);
        }

        let manifest = ArchiveManifest::new(entries)?;
        let mut body_frames = Vec::new();
        for (expected_index, entry) in manifest.entries.iter().enumerate() {
            if entry.kind != ManifestEntryKind::File {
                continue;
            }
            let expected_index = u32::try_from(expected_index).expect("entry count is bounded");
            let magic = read_array::<4>(bytes, &mut offset)?;
            if magic != BODY_FRAME_MAGIC {
                return Err(PayloadError::InvalidBodyFrameMagic(magic));
            }
            let actual_index = read_u32(bytes, &mut offset)?;
            if actual_index != expected_index {
                return Err(PayloadError::BodyFrameOrderMismatch {
                    expected: expected_index,
                    actual: actual_index,
                });
            }
            let body_len = read_u64(bytes, &mut offset)?;
            validate_body_len(body_len)?;
            if Some(body_len) != entry.body_len {
                return Err(PayloadError::BodyFrameLengthMismatch {
                    expected: entry.body_len.expect("file entry has body length"),
                    actual: body_len,
                });
            }
            let body_len =
                usize::try_from(body_len).map_err(|_| PayloadError::BodyFrameLimitExceeded {
                    limit: MAX_BODY_FRAME_LEN,
                    actual: body_len,
                })?;
            let body = read_bytes(bytes, &mut offset, body_len)?.to_vec();
            body_frames.push(ArchiveBodyFrame {
                entry_index: actual_index,
                body,
            });
        }

        if offset != bytes.len() {
            return Err(PayloadError::TrailingBytes(bytes.len() - offset));
        }

        Self::new(manifest, body_frames)
    }
}

fn validate_body_len(body_len: u64) -> Result<(), PayloadError> {
    if body_len > MAX_BODY_FRAME_LEN {
        return Err(PayloadError::BodyFrameLimitExceeded {
            limit: MAX_BODY_FRAME_LEN,
            actual: body_len,
        });
    }
    Ok(())
}

fn validate_body_frames(
    manifest: &ArchiveManifest,
    body_frames: &[ArchiveBodyFrame],
) -> Result<(), PayloadError> {
    let mut seen = Vec::new();
    for frame in body_frames {
        let index =
            usize::try_from(frame.entry_index).map_err(|_| PayloadError::MissingBodyFrame(0))?;
        let entry = manifest
            .entries
            .get(index)
            .ok_or(PayloadError::MissingBodyFrame(frame.entry_index))?;
        if entry.kind != ManifestEntryKind::File {
            return Err(PayloadError::UnexpectedBodyFrameForDirectory(
                frame.entry_index,
            ));
        }
        if seen.contains(&frame.entry_index) {
            return Err(PayloadError::DuplicateBodyFrame(frame.entry_index));
        }
        seen.push(frame.entry_index);
        let actual = frame.body_len();
        validate_body_len(actual)?;
        if Some(actual) != entry.body_len {
            return Err(PayloadError::BodyFrameLengthMismatch {
                expected: entry.body_len.expect("file entry has body length"),
                actual,
            });
        }
    }

    for (index, entry) in manifest.entries.iter().enumerate() {
        if entry.kind != ManifestEntryKind::File {
            continue;
        }
        let index = u32::try_from(index).expect("manifest entry count is bounded");
        if !seen.contains(&index) {
            return Err(PayloadError::MissingBodyFrame(index));
        }
    }

    Ok(())
}

fn body_frame_for(
    body_frames: &[ArchiveBodyFrame],
    index: u32,
) -> Result<&ArchiveBodyFrame, PayloadError> {
    body_frames
        .iter()
        .find(|frame| frame.entry_index == index)
        .ok_or(PayloadError::MissingBodyFrame(index))
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, PayloadError> {
    let value = *bytes.get(*offset).ok_or(PayloadError::TruncatedManifest)?;
    *offset += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, PayloadError> {
    Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, PayloadError> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, PayloadError> {
    Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], PayloadError> {
    let slice = read_bytes(bytes, offset, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], PayloadError> {
    let end = offset
        .checked_add(len)
        .ok_or(PayloadError::TruncatedManifest)?;
    if end > bytes.len() {
        return Err(PayloadError::TruncatedManifest);
    }
    let slice = &bytes[*offset..end];
    *offset = end;
    Ok(slice)
}

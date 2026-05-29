//! Canonical V1 payload kind and Dexios-owned archive framing primitives.

use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};

pub const MANIFEST_MAGIC: [u8; 4] = *b"DXAR";
const BODY_FRAME_MAGIC: [u8; 4] = *b"DXBF";
pub const MANIFEST_VERSION: u16 = 0x0001;
pub const MAX_MANIFEST_ENTRY_COUNT: u32 = 65_536;
pub const MAX_NORMALIZED_PATH_BYTES: usize = 4096;
pub const MAX_BODY_FRAME_LEN: u64 = 1024 * 1024 * 1024;
/// Aggregate ceiling across all buffered body frames for the in-memory [`ManifestFirstPayload::parse`] path (64 GiB).
pub const MAX_TOTAL_BODY_FRAME_BYTES: u64 = 64 * 1024 * 1024 * 1024;

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

#[derive(Debug)]
pub enum PayloadError {
    Io(io::Error),
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

impl PartialEq for PayloadError {
    #[expect(
        clippy::match_same_arms,
        reason = "each variant pair is matched explicitly for clarity; collapsing arms with identical bodies would obscure which error variants are compared"
    )]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
            (Self::UnsupportedPayloadKind(left), Self::UnsupportedPayloadKind(right)) => {
                left == right
            }
            (
                Self::UnsupportedPayloadFramingProfile(left),
                Self::UnsupportedPayloadFramingProfile(right),
            ) => left == right,
            (Self::UnsupportedManifestVersion(left), Self::UnsupportedManifestVersion(right)) => {
                left == right
            }
            (Self::InvalidManifestMagic(left), Self::InvalidManifestMagic(right)) => left == right,
            (Self::InvalidBodyFrameMagic(left), Self::InvalidBodyFrameMagic(right)) => {
                left == right
            }
            (Self::InvalidEntryKind(left), Self::InvalidEntryKind(right)) => left == right,
            (Self::EmptyNormalizedPath, Self::EmptyNormalizedPath) => true,
            (
                Self::ManifestEntryCountLimitExceeded {
                    limit: left_limit,
                    actual: left_actual,
                },
                Self::ManifestEntryCountLimitExceeded {
                    limit: right_limit,
                    actual: right_actual,
                },
            ) => left_limit == right_limit && left_actual == right_actual,
            (
                Self::NormalizedPathLimitExceeded {
                    limit: left_limit,
                    actual: left_actual,
                },
                Self::NormalizedPathLimitExceeded {
                    limit: right_limit,
                    actual: right_actual,
                },
            ) => left_limit == right_limit && left_actual == right_actual,
            (
                Self::BodyFrameLimitExceeded {
                    limit: left_limit,
                    actual: left_actual,
                },
                Self::BodyFrameLimitExceeded {
                    limit: right_limit,
                    actual: right_actual,
                },
            ) => left_limit == right_limit && left_actual == right_actual,
            (Self::MissingBodyLength, Self::MissingBodyLength) => true,
            (
                Self::UnexpectedBodyFrameForDirectory(left),
                Self::UnexpectedBodyFrameForDirectory(right),
            ) => left == right,
            (Self::DuplicateBodyFrame(left), Self::DuplicateBodyFrame(right)) => left == right,
            (Self::MissingBodyFrame(left), Self::MissingBodyFrame(right)) => left == right,
            (
                Self::BodyFrameOrderMismatch {
                    expected: left_expected,
                    actual: left_actual,
                },
                Self::BodyFrameOrderMismatch {
                    expected: right_expected,
                    actual: right_actual,
                },
            ) => left_expected == right_expected && left_actual == right_actual,
            (
                Self::BodyFrameLengthMismatch {
                    expected: left_expected,
                    actual: left_actual,
                },
                Self::BodyFrameLengthMismatch {
                    expected: right_expected,
                    actual: right_actual,
                },
            ) => left_expected == right_expected && left_actual == right_actual,
            (Self::TruncatedManifest, Self::TruncatedManifest) => true,
            (Self::TrailingBytes(left), Self::TrailingBytes(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for PayloadError {}

impl Display for PayloadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "manifest-first payload IO failed: {error}"),
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

impl std::error::Error for PayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

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

    #[expect(
        clippy::expect_used,
        reason = "entry count and path lengths are bounded below MAX_MANIFEST_ENTRY_COUNT / u16::MAX by construction-time validation, so these width conversions cannot overflow"
    )]
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), PayloadError> {
        writer
            .write_all(&MANIFEST_MAGIC)
            .map_err(map_payload_io_error)?;
        writer
            .write_all(&MANIFEST_VERSION.to_le_bytes())
            .map_err(map_payload_io_error)?;
        writer
            .write_all(
                &u32::try_from(self.entries.len())
                    .expect("manifest entry count is bounded")
                    .to_le_bytes(),
            )
            .map_err(map_payload_io_error)?;

        for entry in &self.entries {
            writer
                .write_all(&[entry.kind as u8])
                .map_err(map_payload_io_error)?;
            writer
                .write_all(
                    &u16::try_from(entry.normalized_path.len())
                        .expect("normalized path length is bounded")
                        .to_le_bytes(),
                )
                .map_err(map_payload_io_error)?;
            if let Some(body_len) = entry.body_len {
                writer
                    .write_all(&body_len.to_le_bytes())
                    .map_err(map_payload_io_error)?;
            }
            writer
                .write_all(&entry.normalized_path)
                .map_err(map_payload_io_error)?;
        }

        Ok(())
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self, PayloadError> {
        let magic = read_array_from::<4>(reader)?;
        if magic != MANIFEST_MAGIC {
            return Err(PayloadError::InvalidManifestMagic(magic));
        }
        let version = read_u16_from(reader)?;
        if version != MANIFEST_VERSION {
            return Err(PayloadError::UnsupportedManifestVersion(version));
        }
        let entry_count = read_u32_from(reader)?;
        if entry_count > MAX_MANIFEST_ENTRY_COUNT {
            return Err(PayloadError::ManifestEntryCountLimitExceeded {
                limit: MAX_MANIFEST_ENTRY_COUNT,
                actual: entry_count,
            });
        }

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let kind = ManifestEntryKind::try_from_byte(read_u8_from(reader)?)?;
            let path_len = usize::from(read_u16_from(reader)?);
            let body_len = if kind == ManifestEntryKind::File {
                Some(read_u64_from(reader)?)
            } else {
                None
            };
            let path = read_vec_from(reader, path_len)?;
            let entry = ManifestEntry {
                kind,
                normalized_path: path,
                body_len,
            };
            entry.validate()?;
            entries.push(entry);
        }

        Self::new(entries)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArchiveBodyFrame {
    entry_index: u32,
    body: Vec<u8>,
}

impl fmt::Debug for ArchiveBodyFrame {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveBodyFrame")
            .field("entry_index", &self.entry_index)
            .field("body_len", &self.body.len())
            .finish()
    }
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
    #[expect(
        clippy::expect_used,
        reason = "on every supported target usize fits in u64, so this in-memory body length conversion cannot fail"
    )]
    pub fn body_len(&self) -> u64 {
        u64::try_from(self.body.len()).expect("usize body length fits in u64")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveBodyFrameHeader {
    entry_index: u32,
    body_len: u64,
}

impl ArchiveBodyFrameHeader {
    pub fn new(entry_index: u32, body_len: u64) -> Result<Self, PayloadError> {
        validate_body_len(body_len)?;
        Ok(Self {
            entry_index,
            body_len,
        })
    }

    #[must_use]
    pub const fn entry_index(&self) -> u32 {
        self.entry_index
    }

    #[must_use]
    pub const fn body_len(&self) -> u64 {
        self.body_len
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), PayloadError> {
        writer
            .write_all(&BODY_FRAME_MAGIC)
            .map_err(map_payload_io_error)?;
        writer
            .write_all(&self.entry_index.to_le_bytes())
            .map_err(map_payload_io_error)?;
        writer
            .write_all(&self.body_len.to_le_bytes())
            .map_err(map_payload_io_error)
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self, PayloadError> {
        let magic = read_array_from::<4>(reader)?;
        if magic != BODY_FRAME_MAGIC {
            return Err(PayloadError::InvalidBodyFrameMagic(magic));
        }
        let entry_index = read_u32_from(reader)?;
        let body_len = read_u64_from(reader)?;
        Self::new(entry_index, body_len)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ManifestFirstPayload {
    manifest: ArchiveManifest,
    body_frames: Vec<ArchiveBodyFrame>,
}

impl fmt::Debug for ManifestFirstPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManifestFirstPayload")
            .field("manifest", &self.manifest)
            .field("body_frame_count", &self.body_frames.len())
            .finish()
    }
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

    #[expect(
        clippy::expect_used,
        reason = "the manifest entry count is bounded below MAX_MANIFEST_ENTRY_COUNT (< u32::MAX), so the index conversion cannot overflow"
    )]
    pub fn serialize(&self) -> Result<Vec<u8>, PayloadError> {
        validate_body_frames(&self.manifest, &self.body_frames)?;

        let mut bytes = Vec::new();
        self.manifest.write_to(&mut bytes)?;

        for (index, entry) in self.manifest.entries.iter().enumerate() {
            if entry.kind != ManifestEntryKind::File {
                continue;
            }
            let index = u32::try_from(index).expect("manifest entry count is bounded");
            let frame = body_frame_for(&self.body_frames, index)?;
            ArchiveBodyFrameHeader::new(frame.entry_index, frame.body_len())?
                .write_to(&mut bytes)?;
            bytes.extend_from_slice(&frame.body);
        }

        Ok(bytes)
    }

    /// Parses an entire manifest archive into memory, buffering every body frame.
    ///
    /// This is intended for trusted, in-memory use (round-trip tests, small archives).
    /// It enforces the per-frame [`MAX_BODY_FRAME_LEN`] and the aggregate
    /// [`MAX_TOTAL_BODY_FRAME_BYTES`] caps, but still allocates each frame fully. Production
    /// extraction streams bodies via the unpack workflow's `reader.take(..)` path and never
    /// calls this. Do not call `parse` on untrusted, large archives.
    #[expect(
        clippy::expect_used,
        reason = "entry count is bounded below MAX_MANIFEST_ENTRY_COUNT (< u32::MAX) and File entries always carry a validated body length, so these conversions/unwraps cannot fail"
    )]
    pub fn parse(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut reader = io::Cursor::new(bytes);
        let manifest = ArchiveManifest::read_from(&mut reader)?;
        let mut body_frames = Vec::new();
        let mut total_body: u64 = 0;
        for (expected_index, entry) in manifest.entries.iter().enumerate() {
            if entry.kind != ManifestEntryKind::File {
                continue;
            }
            let expected_index = u32::try_from(expected_index).expect("entry count is bounded");
            let header = ArchiveBodyFrameHeader::read_from(&mut reader)?;
            let actual_index = header.entry_index();
            if actual_index != expected_index {
                return Err(PayloadError::BodyFrameOrderMismatch {
                    expected: expected_index,
                    actual: actual_index,
                });
            }
            let body_len = header.body_len();
            total_body = total_body.saturating_add(body_len);
            if total_body > MAX_TOTAL_BODY_FRAME_BYTES {
                return Err(PayloadError::BodyFrameLimitExceeded {
                    limit: MAX_TOTAL_BODY_FRAME_BYTES,
                    actual: total_body,
                });
            }
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
            let body = read_vec_from(&mut reader, body_len)?;
            body_frames.push(ArchiveBodyFrame {
                entry_index: actual_index,
                body,
            });
        }

        let offset =
            usize::try_from(reader.position()).expect("cursor position for in-memory payload fits");
        if offset != bytes.len() {
            return Err(PayloadError::TrailingBytes(bytes.len().saturating_sub(offset)));
        }

        Self::new(manifest, body_frames)
    }
}

fn map_payload_io_error(error: io::Error) -> PayloadError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        PayloadError::TruncatedManifest
    } else {
        PayloadError::Io(error)
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

#[expect(
    clippy::expect_used,
    reason = "File entries always carry a validated body length and the manifest entry count is bounded below MAX_MANIFEST_ENTRY_COUNT (< u32::MAX), so these unwraps/conversions cannot fail"
)]
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

fn read_u8_from(reader: &mut impl Read) -> Result<u8, PayloadError> {
    Ok(read_array_from::<1>(reader)?[0])
}

fn read_u16_from(reader: &mut impl Read) -> Result<u16, PayloadError> {
    Ok(u16::from_le_bytes(read_array_from(reader)?))
}

fn read_u32_from(reader: &mut impl Read) -> Result<u32, PayloadError> {
    Ok(u32::from_le_bytes(read_array_from(reader)?))
}

fn read_u64_from(reader: &mut impl Read) -> Result<u64, PayloadError> {
    Ok(u64::from_le_bytes(read_array_from(reader)?))
}

fn read_array_from<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], PayloadError> {
    let mut bytes = [0u8; N];
    reader
        .read_exact(&mut bytes)
        .map_err(map_payload_io_error)?;
    Ok(bytes)
}

fn read_vec_from(reader: &mut impl Read, len: usize) -> Result<Vec<u8>, PayloadError> {
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(map_payload_io_error)?;
    Ok(bytes)
}

//! This module contains all Dexios header-related functions, such as dumping the header, restoring a dumped header, or stripping it entirely.

pub mod dump;
pub mod restore;
pub mod strip;

use core::header::common::HeaderReadError;

use crate::storage::identity::IdentityError;
use crate::storage::transaction::TransactionError;
use crate::workflow_error::WorkflowErrorClass;
use crate::workflow_error::{classify_identity_error, classify_transaction_error};

#[derive(Debug)]
pub enum Error {
    UnsupportedRestore,
    InvalidFile,
    InvalidMagic([u8; 4]),
    UnsupportedFormat([u8; 2]),
    UnsupportedVersion([u8; 2]),
    RetiredV1Layout,
    MalformedV1Header(HeaderReadError),
    Write,
    Read,
    WriteIo,
    ReadIo,
    ReadIoWithSource(std::io::Error),
    HeaderSizeParse,
    Rewind,
    ShortDetachedHeader { actual_len: usize },
    TrailingDetachedHeader { actual_len: usize },
    MissingPayload { actual_len: usize },
    TargetTooShort { actual_len: usize },
    TargetNotStripped,
    PathIdentity(IdentityError),
    Transaction(TransactionError),
}

impl Error {
    #[must_use]
    pub fn workflow_class(&self) -> WorkflowErrorClass {
        match self {
            Self::InvalidFile
            | Self::MalformedV1Header(_)
            | Self::HeaderSizeParse
            | Self::ShortDetachedHeader { .. }
            | Self::TrailingDetachedHeader { .. }
            | Self::MissingPayload { .. }
            | Self::TargetTooShort { .. }
            | Self::TargetNotStripped => WorkflowErrorClass::MalformedFormat,
            Self::InvalidMagic(_)
            | Self::UnsupportedFormat(_)
            | Self::UnsupportedVersion(_)
            | Self::RetiredV1Layout => WorkflowErrorClass::UnsupportedFormat,
            Self::UnsupportedRestore => WorkflowErrorClass::UnsupportedWorkflow,
            Self::Write
            | Self::Read
            | Self::WriteIo
            | Self::ReadIo
            | Self::ReadIoWithSource(_)
            | Self::Rewind => WorkflowErrorClass::IoFailure,
            Self::PathIdentity(error) => classify_identity_error(error),
            Self::Transaction(error) => classify_transaction_error(error),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::{
            HeaderSizeParse, InvalidFile, InvalidMagic, MalformedV1Header, MissingPayload,
            PathIdentity, Read, ReadIo, ReadIoWithSource, RetiredV1Layout, Rewind,
            ShortDetachedHeader, TargetNotStripped, TargetTooShort, TrailingDetachedHeader,
            Transaction, UnsupportedFormat, UnsupportedRestore, UnsupportedVersion, Write, WriteIo,
        };
        match self {
            UnsupportedRestore => f.write_str("The provided request is unsupported with this file. It maybe isn't an encrypted file, or it was encrypted in detached mode."),
            InvalidFile => f.write_str("The file does not contain a valid Dexios header."),
            InvalidMagic(magic) => write!(f, "Invalid Dexios header magic: {magic:02X?}"),
            UnsupportedFormat(prefix) => {
                write!(f, "Unsupported Dexios format: {prefix:02X?}")
            }
            UnsupportedVersion(version) => {
                write!(f, "Unsupported Dexios format: {version:02X?}")
            }
            RetiredV1Layout => f.write_str("Retired Dexios V1 header layout"),
            MalformedV1Header(error) => write!(f, "Malformed Dexios V1 header: {error}"),
            Write => f.write_str("Unable to write the data."),
            Read => f.write_str("Unable to read the data."),
            WriteIo => f.write_str("Unable to write header data."),
            ReadIo | ReadIoWithSource(_) => f.write_str("Unable to read header data."),
            Rewind => f.write_str("Unable to rewind the stream."),
            HeaderSizeParse => f.write_str("Unable to parse the size of the header."),
            ShortDetachedHeader { actual_len } => {
                write!(f, "Detached header is too short: {actual_len} bytes")
            }
            TrailingDetachedHeader { actual_len } => {
                write!(f, "Detached header has trailing bytes: {actual_len} bytes")
            }
            MissingPayload { actual_len } => {
                write!(f, "Encrypted artifact has no payload: {actual_len} bytes")
            }
            TargetTooShort { actual_len } => {
                write!(f, "Header restore target is too short: {actual_len} bytes")
            }
            TargetNotStripped => f.write_str("Header restore target is not stripped"),
            PathIdentity(error) => write!(f, "{error}"),
            Transaction(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedV1Header(error) => Some(error),
            Self::ReadIoWithSource(error) => Some(error),
            Self::PathIdentity(error) => Some(error),
            Self::Transaction(error) => Some(error),
            Self::UnsupportedRestore
            | Self::InvalidFile
            | Self::InvalidMagic(_)
            | Self::UnsupportedFormat(_)
            | Self::UnsupportedVersion(_)
            | Self::RetiredV1Layout
            | Self::Write
            | Self::Read
            | Self::WriteIo
            | Self::ReadIo
            | Self::HeaderSizeParse
            | Self::Rewind
            | Self::ShortDetachedHeader { .. }
            | Self::TrailingDetachedHeader { .. }
            | Self::MissingPayload { .. }
            | Self::TargetTooShort { .. }
            | Self::TargetNotStripped => None,
        }
    }
}

impl From<HeaderReadError> for Error {
    fn from(error: HeaderReadError) -> Self {
        match error {
            HeaderReadError::Io(error) => Self::ReadIoWithSource(error),
            HeaderReadError::InvalidMagic(magic) => Self::InvalidMagic(magic),
            HeaderReadError::UnsupportedFormat(prefix) => Self::UnsupportedFormat(prefix),
            HeaderReadError::UnsupportedVersion(version) => Self::UnsupportedVersion(version),
            HeaderReadError::RetiredV1Layout => Self::RetiredV1Layout,
            error => Self::MalformedV1Header(error),
        }
    }
}

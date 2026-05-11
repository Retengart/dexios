//! This module contains all Dexios header-related functions, such as dumping the header, restoring a dumped header, or stripping it entirely.

pub mod dump;
pub mod restore;
pub mod strip;

use core::header::common::HeaderReadError;

use crate::workflow_error::WorkflowErrorClass;

#[derive(Debug)]
pub enum Error {
    UnsupportedRestore,
    InvalidFile,
    InvalidMagic([u8; 4]),
    UnsupportedFormat([u8; 2]),
    UnsupportedVersion([u8; 2]),
    MalformedV1Header(HeaderReadError),
    Write,
    Read,
    HeaderSizeParse,
    Rewind,
}

impl Error {
    #[must_use]
    pub fn workflow_class(&self) -> WorkflowErrorClass {
        match self {
            Self::InvalidFile | Self::MalformedV1Header(_) | Self::HeaderSizeParse => {
                WorkflowErrorClass::MalformedFormat
            }
            Self::InvalidMagic(_) | Self::UnsupportedFormat(_) | Self::UnsupportedVersion(_) => {
                WorkflowErrorClass::UnsupportedFormat
            }
            Self::UnsupportedRestore => WorkflowErrorClass::UnsupportedWorkflow,
            Self::Write | Self::Read | Self::Rewind => WorkflowErrorClass::IoFailure,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::{
            HeaderSizeParse, InvalidFile, InvalidMagic, MalformedV1Header, Read, Rewind,
            UnsupportedFormat, UnsupportedRestore, UnsupportedVersion, Write,
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
            MalformedV1Header(error) => write!(f, "Malformed Dexios V1 header: {error}"),
            Write => f.write_str("Unable to write the data."),
            Read => f.write_str("Unable to read the data."),
            Rewind => f.write_str("Unable to rewind the stream."),
            HeaderSizeParse => f.write_str("Unable to parse the size of the header."),
        }
    }
}

impl std::error::Error for Error {}

impl From<HeaderReadError> for Error {
    fn from(error: HeaderReadError) -> Self {
        match error {
            HeaderReadError::Io(_) => Self::Read,
            HeaderReadError::InvalidMagic(magic) => Self::InvalidMagic(magic),
            HeaderReadError::UnsupportedFormat(prefix) => Self::UnsupportedFormat(prefix),
            HeaderReadError::UnsupportedVersion(version) => Self::UnsupportedVersion(version),
            error => Self::MalformedV1Header(error),
        }
    }
}

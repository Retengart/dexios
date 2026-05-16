use anyhow::anyhow;
use domain::workflow_error::WorkflowErrorClass;

pub fn map_encrypt_error(error: domain::encrypt::Error) -> anyhow::Error {
    match error.workflow_class() {
        WorkflowErrorClass::KdfFailure => anyhow!("Unable to derive encryption key"),
        WorkflowErrorClass::UnsafePath => anyhow!("Unsafe path: {error}"),
        WorkflowErrorClass::IoFailure => anyhow!("I/O failure while encrypting data"),
        WorkflowErrorClass::OverwriteDenied => anyhow!("Output already exists"),
        WorkflowErrorClass::TransactionCommitFailure => {
            anyhow!("Unable to commit encrypted output")
        }
        WorkflowErrorClass::CleanupFailure => anyhow!("Cleanup failed after output commit"),
        WorkflowErrorClass::ResourcePressure => {
            anyhow!("Not enough temporary or output storage while encrypting data")
        }
        WorkflowErrorClass::MalformedFormat
        | WorkflowErrorClass::UnsupportedFormat
        | WorkflowErrorClass::AuthenticationFailure
        | WorkflowErrorClass::UnsupportedWorkflow
        | WorkflowErrorClass::IncorrectKey
        | WorkflowErrorClass::Other => anyhow!("Encryption failed"),
    }
}

pub fn map_decrypt_error(error: domain::decrypt::Error) -> anyhow::Error {
    match error.workflow_class() {
        WorkflowErrorClass::MalformedFormat => anyhow!("Malformed Dexios encrypted data"),
        WorkflowErrorClass::UnsupportedFormat => anyhow!("Unsupported Dexios format"),
        WorkflowErrorClass::KdfFailure => match error {
            domain::decrypt::Error::UnsupportedKdf(tag) => {
                anyhow!("Unsupported keyslot KDF tag: {tag:02X?}")
            }
            _ => anyhow!("Unable to derive decryption key"),
        },
        WorkflowErrorClass::AuthenticationFailure | WorkflowErrorClass::IncorrectKey => {
            anyhow!("Authentication failed")
        }
        WorkflowErrorClass::UnsafePath => anyhow!("Unsafe path: {error}"),
        WorkflowErrorClass::IoFailure => anyhow!("I/O failure while decrypting data"),
        WorkflowErrorClass::OverwriteDenied => anyhow!("Output already exists"),
        WorkflowErrorClass::TransactionCommitFailure => {
            anyhow!("Unable to commit decrypted output")
        }
        WorkflowErrorClass::CleanupFailure => anyhow!("Cleanup failed after output commit"),
        WorkflowErrorClass::ResourcePressure => {
            anyhow!("Not enough temporary or output storage while decrypting data")
        }
        WorkflowErrorClass::UnsupportedWorkflow | WorkflowErrorClass::Other => {
            anyhow!("Decryption failed")
        }
    }
}

pub fn map_pack_error(error: domain::pack::Error) -> anyhow::Error {
    match error.workflow_class() {
        WorkflowErrorClass::ResourcePressure => {
            debug_assert!(error.is_resource_pressure());
            anyhow!("Not enough temporary or output storage while packing archive")
        }
        WorkflowErrorClass::UnsafePath => match error {
            domain::pack::Error::ArchiveLimit(_) => anyhow!("Archive limit error: {error}"),
            _ => anyhow!("Unsafe path: {error}"),
        },
        WorkflowErrorClass::IoFailure => anyhow!("I/O failure while packing archive"),
        WorkflowErrorClass::TransactionCommitFailure => {
            anyhow!("Unable to commit packed archive")
        }
        WorkflowErrorClass::AuthenticationFailure | WorkflowErrorClass::IncorrectKey => {
            anyhow!("Authentication failed")
        }
        WorkflowErrorClass::MalformedFormat => anyhow!("Malformed archive data"),
        WorkflowErrorClass::UnsupportedFormat => anyhow!("Unsupported archive format"),
        WorkflowErrorClass::KdfFailure => anyhow!("Unable to derive archive encryption key"),
        WorkflowErrorClass::OverwriteDenied => anyhow!("Output already exists"),
        WorkflowErrorClass::CleanupFailure => anyhow!("Cleanup failed after output commit"),
        WorkflowErrorClass::UnsupportedWorkflow | WorkflowErrorClass::Other => {
            anyhow!("Archive packing failed")
        }
    }
}

pub fn map_unpack_error(error: domain::unpack::Error) -> anyhow::Error {
    match error.workflow_class() {
        WorkflowErrorClass::ResourcePressure => {
            debug_assert!(error.is_resource_pressure());
            anyhow!("Not enough temporary or output storage while unpacking archive")
        }
        WorkflowErrorClass::UnsafePath => anyhow!("Unsafe archive path: {error}"),
        WorkflowErrorClass::MalformedFormat => anyhow!("Malformed archive data"),
        WorkflowErrorClass::UnsupportedFormat => anyhow!("Unsupported archive format"),
        WorkflowErrorClass::AuthenticationFailure | WorkflowErrorClass::IncorrectKey => {
            anyhow!("Authentication failed")
        }
        WorkflowErrorClass::KdfFailure => anyhow!("Unable to derive archive decryption key"),
        WorkflowErrorClass::IoFailure => anyhow!("I/O failure while unpacking archive"),
        WorkflowErrorClass::TransactionCommitFailure => {
            anyhow!("Unable to commit unpacked output")
        }
        WorkflowErrorClass::OverwriteDenied => anyhow!("Output already exists"),
        WorkflowErrorClass::CleanupFailure => anyhow!("Cleanup failed after output commit"),
        WorkflowErrorClass::UnsupportedWorkflow | WorkflowErrorClass::Other => {
            anyhow!("Archive unpacking failed")
        }
    }
}

#[derive(Clone, Copy)]
enum HeaderDisclosure {
    Terse,
    Details,
}

pub fn map_header_error(error: domain::header::Error) -> anyhow::Error {
    map_header_error_with_disclosure(error, HeaderDisclosure::Terse)
}

pub fn map_header_details_error(error: domain::header::Error) -> anyhow::Error {
    map_header_error_with_disclosure(error, HeaderDisclosure::Details)
}

fn map_header_error_with_disclosure(
    error: domain::header::Error,
    disclosure: HeaderDisclosure,
) -> anyhow::Error {
    match error.workflow_class() {
        WorkflowErrorClass::MalformedFormat => match (error, disclosure) {
            (domain::header::Error::MalformedV1Header(error), HeaderDisclosure::Details) => {
                anyhow!("Malformed Dexios V1 header: {error}")
            }
            (domain::header::Error::MalformedV1Header(_), HeaderDisclosure::Terse) => {
                anyhow!("Malformed Dexios V1 header")
            }
            (domain::header::Error::ShortDetachedHeader { actual_len }, _) => {
                anyhow!("Detached header is too short: {actual_len} bytes")
            }
            (domain::header::Error::TrailingDetachedHeader { actual_len }, _) => {
                anyhow!("Detached header has trailing bytes: {actual_len} bytes")
            }
            (domain::header::Error::MissingPayload { actual_len }, _) => {
                anyhow!("Encrypted artifact is missing payload bytes: {actual_len} bytes")
            }
            (domain::header::Error::TargetTooShort { actual_len }, _) => {
                anyhow!("Header restore target is too short: {actual_len} bytes")
            }
            (domain::header::Error::TargetNotStripped, _) => {
                anyhow!("Header restore target is not stripped")
            }
            (domain::header::Error::InvalidFile | domain::header::Error::HeaderSizeParse, _) => {
                anyhow!("Malformed Dexios header or payload")
            }
            _ => anyhow!("Malformed Dexios header or payload"),
        },
        WorkflowErrorClass::UnsupportedFormat => match error {
            domain::header::Error::InvalidMagic(_) => anyhow!("Invalid Dexios header magic"),
            domain::header::Error::UnsupportedFormat(_)
            | domain::header::Error::UnsupportedVersion(_)
            | domain::header::Error::RetiredV1Layout => anyhow!("Unsupported Dexios format"),
            _ => anyhow!("Unsupported Dexios format"),
        },
        WorkflowErrorClass::UnsupportedWorkflow => {
            anyhow!("Unsupported header workflow for this file")
        }
        WorkflowErrorClass::UnsafePath => match error {
            domain::header::Error::PathIdentity(error) => anyhow!("Unsafe path: {error}"),
            _ => anyhow!("Unsafe path"),
        },
        WorkflowErrorClass::IoFailure => match error {
            domain::header::Error::PathIdentity(_) => {
                anyhow!("I/O failure while checking header paths")
            }
            domain::header::Error::Transaction(_) => {
                anyhow!("I/O failure while writing header data")
            }
            domain::header::Error::Read
            | domain::header::Error::ReadIo
            | domain::header::Error::ReadIoWithSource(_) => {
                anyhow!("I/O failure while reading header data")
            }
            domain::header::Error::Write | domain::header::Error::WriteIo => {
                anyhow!("I/O failure while writing header data")
            }
            domain::header::Error::Rewind => anyhow!("I/O failure while rewinding header data"),
            _ => anyhow!("I/O failure while handling header data"),
        },
        WorkflowErrorClass::TransactionCommitFailure => {
            anyhow!("Unable to commit header update")
        }
        WorkflowErrorClass::ResourcePressure => {
            anyhow!("Not enough temporary or output storage while updating header data")
        }
        WorkflowErrorClass::CleanupFailure => anyhow!("Cleanup failed after output commit"),
        WorkflowErrorClass::KdfFailure
        | WorkflowErrorClass::AuthenticationFailure
        | WorkflowErrorClass::OverwriteDenied
        | WorkflowErrorClass::IncorrectKey
        | WorkflowErrorClass::Other => anyhow!("Header workflow failed"),
    }
}

pub fn map_key_error(error: domain::key::Error) -> anyhow::Error {
    match error.workflow_class() {
        WorkflowErrorClass::MalformedFormat => match error {
            domain::key::Error::MalformedV1Header(_)
            | domain::key::Error::HeaderSizeParse
            | domain::key::Error::HeaderDeserialize => anyhow!("Malformed Dexios V1 header"),
            _ => anyhow!("Malformed Dexios V1 header"),
        },
        WorkflowErrorClass::UnsupportedFormat => match error {
            domain::key::Error::InvalidMagic(_) => anyhow!("Invalid Dexios header magic"),
            domain::key::Error::Unsupported => {
                anyhow!("Unsupported key workflow for this header version")
            }
            domain::key::Error::UnsupportedFormat(_)
            | domain::key::Error::UnsupportedVersion(_)
            | domain::key::Error::RetiredV1Layout => anyhow!("Unsupported Dexios format"),
            _ => anyhow!("Unsupported Dexios format"),
        },
        WorkflowErrorClass::KdfFailure => match error {
            domain::key::Error::UnsupportedKdf(tag) => {
                anyhow!("Unsupported keyslot KDF tag: {tag:02X?}")
            }
            domain::key::Error::KeyHash => anyhow!("Unable to derive key"),
            _ => anyhow!("Unable to derive key"),
        },
        WorkflowErrorClass::IncorrectKey => anyhow!("Incorrect key"),
        WorkflowErrorClass::UnsupportedWorkflow => match error {
            domain::key::Error::CannotAddV1KeyslotWithoutReencrypt => {
                anyhow!("Cannot add a V1 keyslot without re-encrypting the payload")
            }
            domain::key::Error::CannotRemoveFinalV1Keyslot => {
                anyhow!("Cannot remove the final V1 keyslot")
            }
            domain::key::Error::TooManyKeyslots => {
                anyhow!("There are already too many populated keyslots within this file")
            }
            _ => anyhow!("Unsupported key workflow for this header version"),
        },
        WorkflowErrorClass::UnsafePath => match error {
            domain::key::Error::PathIdentity(error) => anyhow!("Unsafe path: {error}"),
            _ => anyhow!("Unsafe path"),
        },
        WorkflowErrorClass::IoFailure => match error {
            domain::key::Error::ReadIo | domain::key::Error::ReadIoWithSource(_) => {
                anyhow!("I/O failure while reading key workflow target")
            }
            domain::key::Error::PathIdentity(_) => {
                anyhow!("I/O failure while checking key workflow target")
            }
            domain::key::Error::Transaction(_)
            | domain::key::Error::HeaderWrite
            | domain::key::Error::Seek => anyhow!("I/O failure while updating keyslots"),
            _ => anyhow!("I/O failure while updating keyslots"),
        },
        WorkflowErrorClass::TransactionCommitFailure => {
            anyhow!("Unable to commit keyslot update")
        }
        WorkflowErrorClass::ResourcePressure => {
            anyhow!("Not enough temporary or output storage while updating keyslots")
        }
        WorkflowErrorClass::CleanupFailure => anyhow!("Cleanup failed after output commit"),
        WorkflowErrorClass::AuthenticationFailure
        | WorkflowErrorClass::OverwriteDenied
        | WorkflowErrorClass::Other => anyhow!("Key workflow failed"),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use domain::storage::transaction::TransactionError;

    use super::*;

    fn storage_full() -> io::Error {
        io::Error::from(io::ErrorKind::StorageFull)
    }

    fn path(name: &str) -> PathBuf {
        PathBuf::from(name)
    }

    #[test]
    fn pack_resource_pressure_uses_capacity_message() {
        let mapped = map_pack_error(domain::pack::Error::Transaction(TransactionError::Write {
            path: path("packed.enc"),
            source: Some(storage_full()),
        }));

        assert_eq!(
            format!("{mapped}"),
            "Not enough temporary or output storage while packing archive"
        );
    }

    #[test]
    fn unpack_resource_pressure_uses_capacity_message() {
        let mapped = map_unpack_error(domain::unpack::Error::Transaction(
            TransactionError::Write {
                path: path("unpacked.txt"),
                source: Some(storage_full()),
            },
        ));

        assert_eq!(
            format!("{mapped}"),
            "Not enough temporary or output storage while unpacking archive"
        );
    }

    #[test]
    fn unpack_format_and_authentication_errors_stay_distinct() {
        let malformed = map_unpack_error(domain::unpack::Error::OpenArchive);
        assert_eq!(format!("{malformed}"), "Malformed archive data");

        let authentication = map_unpack_error(domain::unpack::Error::Decrypt(
            domain::decrypt::Error::DecryptData,
        ));
        assert_eq!(format!("{authentication}"), "Authentication failed");
    }
}

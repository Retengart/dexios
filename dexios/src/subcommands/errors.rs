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
        WorkflowErrorClass::UnsupportedWorkflow | WorkflowErrorClass::Other => {
            anyhow!("Decryption failed")
        }
    }
}

pub fn map_header_error(error: domain::header::Error) -> anyhow::Error {
    match error {
        domain::header::Error::InvalidMagic(magic) => {
            anyhow!("Invalid Dexios header magic: {magic:02X?}")
        }
        domain::header::Error::UnsupportedFormat(_)
        | domain::header::Error::UnsupportedVersion(_) => anyhow!("Unsupported Dexios format"),
        domain::header::Error::MalformedV1Header(error) => {
            anyhow!("Malformed Dexios V1 header: {error}")
        }
        domain::header::Error::UnsupportedRestore => {
            anyhow!("Unsupported header workflow for this file")
        }
        domain::header::Error::InvalidFile | domain::header::Error::HeaderSizeParse => {
            anyhow!("Malformed Dexios header or payload")
        }
        domain::header::Error::Read => anyhow!("I/O failure while reading header data"),
        domain::header::Error::Write => anyhow!("I/O failure while writing header data"),
        domain::header::Error::Rewind => anyhow!("I/O failure while rewinding header data"),
    }
}

pub fn map_key_error(error: domain::key::Error) -> anyhow::Error {
    match error {
        domain::key::Error::UnsupportedKdf(tag) => {
            anyhow!("Unsupported keyslot KDF tag: {tag:02X?}")
        }
        domain::key::Error::IncorrectKey => anyhow!("Incorrect key"),
        domain::key::Error::CannotAddV1KeyslotWithoutReencrypt => {
            anyhow!("Cannot add a V1 keyslot without re-encrypting the payload")
        }
        domain::key::Error::CannotRemoveFinalV1Keyslot => {
            anyhow!("Cannot remove the final V1 keyslot")
        }
        domain::key::Error::TooManyKeyslots => {
            anyhow!("There are already too many populated keyslots within this file")
        }
        domain::key::Error::Unsupported => {
            anyhow!("Unsupported key workflow for this header version")
        }
        domain::key::Error::HeaderSizeParse | domain::key::Error::HeaderDeserialize => {
            anyhow!("Malformed Dexios V1 header")
        }
        domain::key::Error::KeyHash => anyhow!("Unable to derive key"),
        domain::key::Error::HeaderWrite | domain::key::Error::Seek => {
            anyhow!("I/O failure while updating keyslots")
        }
        domain::key::Error::MasterKeyEncrypt | domain::key::Error::CipherInit => {
            anyhow!("Key workflow failed")
        }
    }
}

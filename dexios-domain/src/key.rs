use core::cipher::{unwrap_v1_master_key, wrap_v1_master_key};
use core::header::common::{HEADER_LEN, KeyslotNonce, Salt};
use core::header::v1::{
    EncryptedMasterKey, KeyslotKdf, V1Header, V1Keyslot, V1KeyslotIndex, V1Keyslots,
};
use core::header::{HeaderReadError, ParsedHeader, read_header};
use core::kdf::Kdf;
use core::primitives::{
    ENCRYPTED_MASTER_KEY_LEN, MasterKey, WrappingKey, gen_keyslot_nonce, gen_salt,
};
use core::protected::Protected;
use std::io::Cursor;
use std::path::Path;

use crate::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
use crate::storage::mutation::{MutationFreshnessError, MutationSnapshot};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction, TransactionError};
use crate::workflow_error::WorkflowErrorClass;

pub mod add;
pub mod change;
pub mod delete;
pub mod verify;

#[derive(Debug)]
pub enum Error {
    HeaderSizeParse,
    Unsupported,
    UnsupportedKdf([u8; 2]),
    IncorrectKey,
    MasterKeyEncrypt,
    TooManyKeyslots,
    KeyHash,
    CipherInit,
    HeaderDeserialize,
    InvalidMagic([u8; 4]),
    UnsupportedFormat([u8; 2]),
    UnsupportedVersion([u8; 2]),
    RetiredV1Layout,
    MalformedV1Header(HeaderReadError),
    ReadIo,
    ReadIoWithSource(std::io::Error),
    HeaderWrite,
    Seek,
    PathIdentity(IdentityError),
    Transaction(TransactionError),
    TargetChanged,
    CannotRemoveFinalV1Keyslot,
    CannotAddV1KeyslotWithoutReencrypt,
}

impl Error {
    #[must_use]
    pub fn workflow_class(&self) -> WorkflowErrorClass {
        match self {
            Self::HeaderSizeParse | Self::HeaderDeserialize | Self::MalformedV1Header(_) => {
                WorkflowErrorClass::MalformedFormat
            }
            Self::InvalidMagic(_)
            | Self::UnsupportedFormat(_)
            | Self::UnsupportedVersion(_)
            | Self::RetiredV1Layout
            | Self::Unsupported => WorkflowErrorClass::UnsupportedFormat,
            Self::UnsupportedKdf(_) | Self::KeyHash => WorkflowErrorClass::KdfFailure,
            Self::IncorrectKey => WorkflowErrorClass::IncorrectKey,
            Self::HeaderWrite
            | Self::Seek
            | Self::ReadIo
            | Self::ReadIoWithSource(_)
            | Self::TargetChanged => WorkflowErrorClass::IoFailure,
            Self::PathIdentity(error) => crate::workflow_error::classify_identity_error(error),
            Self::Transaction(error) => crate::workflow_error::classify_transaction_error(error),
            Self::TooManyKeyslots
            | Self::CannotRemoveFinalV1Keyslot
            | Self::CannotAddV1KeyslotWithoutReencrypt => WorkflowErrorClass::UnsupportedWorkflow,
            Self::MasterKeyEncrypt | Self::CipherInit => WorkflowErrorClass::Other,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderSizeParse => f.write_str("Cannot parse header size"),
            Self::Seek => f.write_str("Unable to seek the data's cursor"),
            Self::HeaderWrite => f.write_str("Unable to write the header"),
            Self::HeaderDeserialize => f.write_str("Unable to deserialize the header"),
            Self::InvalidMagic(magic) => write!(f, "Invalid Dexios header magic: {magic:02X?}"),
            Self::UnsupportedFormat(prefix) => {
                write!(f, "Unsupported Dexios header format: {prefix:02X?}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "Unsupported Dexios header version: {version:02X?}")
            }
            Self::RetiredV1Layout => f.write_str("Retired Dexios V1 header layout"),
            Self::MalformedV1Header(error) => write!(f, "Malformed Dexios V1 header: {error}"),
            Self::ReadIo | Self::ReadIoWithSource(_) => {
                f.write_str("Unable to read key workflow target")
            }
            Self::PathIdentity(error) => write!(f, "{error}"),
            Self::Transaction(error) => write!(f, "{error}"),
            Self::TargetChanged => f.write_str("Key workflow target changed before commit"),
            Self::CannotRemoveFinalV1Keyslot => f.write_str("Cannot remove the final V1 keyslot"),
            Self::CannotAddV1KeyslotWithoutReencrypt => {
                f.write_str("Cannot add a V1 keyslot without re-encrypting the payload")
            }
            Self::CipherInit => f.write_str("Unable to initialize a cipher"),
            Self::KeyHash => f.write_str("Unable to hash your key"),
            Self::TooManyKeyslots => {
                f.write_str("There are already too many populated keyslots within this file")
            }
            Self::MasterKeyEncrypt => f.write_str("Unable to encrypt master key"),
            Self::Unsupported => {
                f.write_str("The provided request is unsupported with this header version")
            }
            Self::UnsupportedKdf(tag) => {
                write!(f, "Unsupported keyslot KDF tag: {tag:02X?}")
            }
            Self::IncorrectKey => f.write_str("The provided key is incorrect"),
        }
    }
}

pub fn decrypt_v1_master_key_with_index(
    header: &V1Header,
    raw_key_old: Protected<Vec<u8>>,
) -> Result<(MasterKey, V1KeyslotIndex), Error> {
    let keyslots = header.keyslots_collection();
    let mut index = None;
    let mut master_key = None;
    let mut saw_unsupported_kdf = None;

    // we need the index, so we can't use `decrypt_master_key()`
    for keyslot in keyslots.as_slice() {
        let physical_index = keyslot.physical_index();
        let kdf = match keyslot.kdf() {
            KeyslotKdf::Argon2id => Kdf::Argon2id,
            KeyslotKdf::UnsupportedArgon2id => {
                saw_unsupported_kdf = Some([0xDF, 0x02]);
                continue;
            }
        };
        let salt = keyslot.salt().to_kdf_salt();
        let key_old = kdf
            .derive(&raw_key_old, &salt)
            .map_err(|_| Error::KeyHash)?;

        let slot_index = V1KeyslotIndex::try_from_physical_index(physical_index)
            .map_err(|_| Error::HeaderDeserialize)?;
        let encrypted_master_key = EncryptedMasterKey::new(*keyslot.encrypted_master_key());
        let slot_wrapping_aad = header
            .slot_wrapping_aad_for_physical_slot(slot_index)
            .map_err(|_| Error::HeaderDeserialize)?;
        let master_key_result = unwrap_v1_master_key(
            WrappingKey::from(key_old),
            &encrypted_master_key,
            keyslot.nonce(),
            &slot_wrapping_aad,
        );

        let Ok(decrypted_master_key) = master_key_result else {
            continue;
        };

        master_key = Some(decrypted_master_key);
        index = Some(slot_index);

        break;
    }

    drop(raw_key_old);

    let Some(index) = index else {
        if let Some(tag) = saw_unsupported_kdf {
            return Err(Error::UnsupportedKdf(tag));
        }
        return Err(Error::IncorrectKey);
    };

    let Some(master_key) = master_key else {
        return Err(Error::IncorrectKey);
    };

    Ok((master_key, index))
}

pub(crate) fn decrypt_v1_master_key_at_index(
    header: &V1Header,
    index: V1KeyslotIndex,
    raw_key: Protected<Vec<u8>>,
) -> Result<MasterKey, Error> {
    let keyslot = header
        .keyslots_collection()
        .get_physical(index.get())
        .ok_or(Error::IncorrectKey)?;
    let kdf = match keyslot.kdf() {
        KeyslotKdf::Argon2id => Kdf::Argon2id,
        KeyslotKdf::UnsupportedArgon2id => return Err(Error::UnsupportedKdf([0xDF, 0x02])),
    };
    let salt = keyslot.salt().to_kdf_salt();
    let key = kdf.derive(&raw_key, &salt).map_err(|_| Error::KeyHash)?;
    let encrypted_master_key = EncryptedMasterKey::new(*keyslot.encrypted_master_key());
    let slot_wrapping_aad = header
        .slot_wrapping_aad_for_physical_slot(index)
        .map_err(|_| Error::HeaderDeserialize)?;

    unwrap_v1_master_key(
        WrappingKey::from(key),
        &encrypted_master_key,
        keyslot.nonce(),
        &slot_wrapping_aad,
    )
    .map_err(|_| Error::IncorrectKey)
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedV1Header(error) => Some(error),
            Self::ReadIoWithSource(error) => Some(error),
            Self::PathIdentity(error) => Some(error),
            Self::Transaction(error) => Some(error),
            Self::HeaderSizeParse
            | Self::Unsupported
            | Self::UnsupportedKdf(_)
            | Self::IncorrectKey
            | Self::MasterKeyEncrypt
            | Self::TooManyKeyslots
            | Self::KeyHash
            | Self::CipherInit
            | Self::HeaderDeserialize
            | Self::InvalidMagic(_)
            | Self::UnsupportedFormat(_)
            | Self::UnsupportedVersion(_)
            | Self::RetiredV1Layout
            | Self::ReadIo
            | Self::HeaderWrite
            | Self::Seek
            | Self::TargetChanged
            | Self::CannotRemoveFinalV1Keyslot
            | Self::CannotAddV1KeyslotWithoutReencrypt => None,
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

pub(in crate::key) struct V1MutationIntent {
    target: ResolvedTarget,
    original: Vec<u8>,
    header: V1Header,
}

impl V1MutationIntent {
    pub(in crate::key) fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut graph = PathIdentityGraph::new();
        let target = graph
            .add_output(
                target_path,
                PathRole::MutationTarget,
                OverwritePolicy::ReplaceAtCommit,
            )
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        let (target, original) = read_mutation_target(target)?;
        let header = parse_v1_header(&original)?;

        Ok(Self {
            target,
            original,
            header,
        })
    }

    pub(in crate::key) fn header(&self) -> &V1Header {
        &self.header
    }

    pub(in crate::key) fn commit_replacement_header(
        self,
        replacement_header: &V1Header,
    ) -> Result<CommitReceipt, Error> {
        let Self {
            target,
            mut original,
            header: _,
        } = self;

        let header_bytes = validated_v1_header_bytes(replacement_header)?;
        ensure_target_unchanged(&target, &original)?;
        let target_header = original
            .get_mut(..HEADER_LEN)
            .ok_or(Error::HeaderDeserialize)?;
        target_header.copy_from_slice(&header_bytes);

        let mut transaction = StagedOutputTransaction::new(target).map_err(Error::Transaction)?;
        transaction
            .write_all(&original)
            .map_err(Error::Transaction)?;
        transaction.commit().map_err(Error::Transaction)
    }
}

pub(in crate::key) fn read_v1_header_from_reader(
    reader: &mut impl std::io::Read,
) -> Result<V1Header, Error> {
    let parsed = read_header(reader)?;
    let ParsedHeader::V1(payload) = parsed;
    Ok(payload.header().clone())
}

pub(in crate::key) fn parse_v1_header(bytes: &[u8]) -> Result<V1Header, Error> {
    let mut reader = Cursor::new(bytes);
    read_v1_header_from_reader(&mut reader)
}

pub(in crate::key) fn validated_v1_header_bytes(header: &V1Header) -> Result<Vec<u8>, Error> {
    let header_bytes = header.serialize().map_err(|_| Error::HeaderWrite)?;
    if header_bytes.len() != HEADER_LEN {
        return Err(Error::HeaderWrite);
    }

    parse_v1_header(&header_bytes)?;
    Ok(header_bytes)
}

pub(crate) fn ensure_target_unchanged(
    target: &ResolvedTarget,
    original: &[u8],
) -> Result<(), Error> {
    crate::storage::mutation::ensure_fresh(target, original).map_err(map_mutation_freshness_error)
}

pub(crate) fn read_mutation_target(
    target: ResolvedTarget,
) -> Result<(ResolvedTarget, Vec<u8>), Error> {
    MutationSnapshot::read(target)
        .map(MutationSnapshot::into_parts)
        .map_err(map_mutation_freshness_error)
}

fn map_mutation_freshness_error(error: MutationFreshnessError) -> Error {
    match error {
        MutationFreshnessError::Read { source, .. } => Error::ReadIoWithSource(source),
        MutationFreshnessError::IdentityChanged { .. }
        | MutationFreshnessError::ContentChanged { .. } => Error::TargetChanged,
    }
}

pub(crate) fn unsupported_keyslot_kdf_tag(keyslots: &V1Keyslots) -> Option<[u8; 2]> {
    keyslots
        .as_slice()
        .iter()
        .find(|keyslot| matches!(keyslot.kdf(), KeyslotKdf::UnsupportedArgon2id))
        .map(|_| [0xDF, 0x02])
}

pub(crate) fn all_keyslots_have_unsupported_kdf(keyslots: &V1Keyslots) -> Option<[u8; 2]> {
    keyslots
        .as_slice()
        .iter()
        .all(|keyslot| matches!(keyslot.kdf(), KeyslotKdf::UnsupportedArgon2id))
        .then_some([0xDF, 0x02])
}

#[derive(Clone, Copy)]
pub(in crate::key) enum V1KeyslotWrite {
    Insert,
    Replace,
}

pub(in crate::key) fn build_v1_rewrapped_keyslot_header(
    header: &V1Header,
    master_key: &MasterKey,
    index: V1KeyslotIndex,
    raw_key_new: &Protected<Vec<u8>>,
    kdf: Kdf,
    write: V1KeyslotWrite,
) -> Result<V1Header, Error> {
    let mut keyslots = header.keyslots_collection().clone();
    let salt = Salt::new(gen_salt());
    let key_new = kdf
        .derive(raw_key_new, &salt.to_kdf_salt())
        .map_err(|_| Error::KeyHash)?;
    let fresh_wrapping_nonce = gen_keyslot_nonce();
    let placeholder_keyslot = V1Keyslot::new(
        kdf,
        [0u8; ENCRYPTED_MASTER_KEY_LEN],
        fresh_wrapping_nonce,
        salt,
    );

    match write {
        V1KeyslotWrite::Insert => {
            keyslots
                .insert_physical_slot(index, placeholder_keyslot)
                .map_err(|_| Error::HeaderWrite)?;
        }
        V1KeyslotWrite::Replace => {
            keyslots
                .replace(index, placeholder_keyslot)
                .map_err(|_| Error::HeaderWrite)?;
        }
    }

    let replacement_context_header = header
        .with_keyslots(keyslots.clone())
        .map_err(|_| Error::HeaderWrite)?;
    let encrypted_master_key = encrypt_master_key(
        &replacement_context_header,
        index,
        master_key,
        key_new,
        &fresh_wrapping_nonce,
        &salt,
        kdf,
    )?;

    keyslots
        .replace(
            index,
            V1Keyslot::new(kdf, encrypted_master_key, fresh_wrapping_nonce, salt),
        )
        .map_err(|_| Error::HeaderWrite)?;

    header
        .with_keyslots(keyslots)
        .map_err(|_| Error::HeaderWrite)
}

// Crate-private: external callers must not be able to supply a reused keyslot nonce.
// The public, contract-bearing wrap API is `dexios_core::cipher::wrap_v1_master_key`.
pub(crate) fn encrypt_master_key(
    header: &V1Header,
    index: V1KeyslotIndex,
    master_key: &MasterKey,
    key_new: Protected<[u8; 32]>,
    nonce: &KeyslotNonce,
    salt: &Salt,
    kdf: Kdf,
) -> Result<[u8; ENCRYPTED_MASTER_KEY_LEN], Error> {
    let placeholder_keyslot = V1Keyslot::new(kdf, [0u8; ENCRYPTED_MASTER_KEY_LEN], *nonce, *salt);
    let mut placeholder_keyslots = header.keyslots_collection().clone();
    if placeholder_keyslots.get_physical(index.get()).is_some() {
        placeholder_keyslots
            .replace(index, placeholder_keyslot)
            .map_err(|_| Error::HeaderDeserialize)?;
    } else {
        placeholder_keyslots
            .insert_physical_slot(index, placeholder_keyslot)
            .map_err(|_| Error::HeaderDeserialize)?;
    }
    let placeholder_header = header
        .with_keyslots(placeholder_keyslots)
        .map_err(|_| Error::HeaderDeserialize)?;
    let slot_wrapping_aad = placeholder_header
        .slot_wrapping_aad_for_physical_slot(index)
        .map_err(|_| Error::HeaderDeserialize)?;
    let encrypted_master_key = wrap_v1_master_key(
        WrappingKey::from(key_new),
        master_key,
        nonce,
        &slot_wrapping_aad,
    )
    .map_err(|_| Error::MasterKeyEncrypt)?;
    Ok(*encrypted_master_key.as_bytes())
}

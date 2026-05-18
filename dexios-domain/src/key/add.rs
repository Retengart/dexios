//! This provides functionality for adding a key to a header that adheres to the
//! Dexios V1 format.

use super::Error;
use core::header::common::{HEADER_LEN, Salt};
use core::header::v1::{V1Header, V1Keyslot, V1KeyslotIndex};
use core::header::{ParsedHeader, read_header};
use core::kdf::Kdf;
use core::primitives::{MasterKey, gen_keyslot_nonce, gen_salt};
use core::protected::Protected;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use crate::storage::identity::ResolvedTarget;
use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction};

pub struct AddIntent {
    target: ResolvedTarget,
    original: Vec<u8>,
    header: V1Header,
    empty_index: V1KeyslotIndex,
}

impl AddIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
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

        let original = fs::read(target.target_path()).map_err(|_| Error::ReadIo)?;
        let header = parse_v1_header(&original)?;
        let keyslots = header.keyslots_collection();

        if let Some(tag) = super::unsupported_keyslot_kdf_tag(keyslots) {
            return Err(Error::UnsupportedKdf(tag));
        }

        let empty_index = keyslots
            .first_empty_physical_slot()
            .ok_or(Error::TooManyKeyslots)?;

        Ok(Self {
            target,
            original,
            header,
            empty_index,
        })
    }

    pub fn verify_old_key(self, raw_key_old: Protected<Vec<u8>>) -> Result<ProvenAddIntent, Error> {
        let (master_key, _index) =
            super::decrypt_v1_master_key_with_index(&self.header, raw_key_old)?;

        Ok(ProvenAddIntent {
            target: self.target,
            original: self.original,
            header: self.header,
            master_key,
            empty_index: self.empty_index,
        })
    }
}

pub struct ProvenAddIntent {
    target: ResolvedTarget,
    original: Vec<u8>,
    header: V1Header,
    master_key: MasterKey,
    empty_index: V1KeyslotIndex,
}

pub fn execute(
    intent: ProvenAddIntent,
    new_key_secret: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<CommitReceipt, Error> {
    let ProvenAddIntent {
        target,
        mut original,
        header,
        master_key,
        empty_index,
    } = intent;

    let replacement_header = added_header(&header, &master_key, empty_index, new_key_secret, kdf)?;
    let header_bytes = validated_header_bytes(&replacement_header)?;
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

fn added_header(
    header: &V1Header,
    master_key: &MasterKey,
    index: V1KeyslotIndex,
    new_key_secret: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<V1Header, Error> {
    let mut keyslots = header.keyslots_collection().clone();

    let salt = Salt::new(gen_salt());
    let key_new = kdf
        .derive(&new_key_secret, &salt.to_kdf_salt())
        .map_err(|_| Error::KeyHash)?;
    let fresh_wrapping_nonce = gen_keyslot_nonce();

    let placeholder_keyslot = V1Keyslot::new(kdf, [0u8; 48], fresh_wrapping_nonce, salt);
    keyslots
        .insert_physical_slot(index, placeholder_keyslot)
        .map_err(|_| Error::HeaderWrite)?;
    let replacement_context_header =
        header.with_keyslots(keyslots.clone()).map_err(|_| Error::HeaderWrite)?;

    let encrypted_master_key = super::encrypt_master_key(
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

    let replacement_header =
        header.with_keyslots(keyslots).map_err(|_| Error::HeaderWrite)?;
    let replacement_master_key =
        super::decrypt_v1_master_key_at_index(&replacement_header, index, new_key_secret)?;

    if !master_key.same_secret_as(&replacement_master_key) {
        return Err(Error::MasterKeyEncrypt);
    }

    Ok(replacement_header)
}

fn parse_v1_header(bytes: &[u8]) -> Result<V1Header, Error> {
    let mut reader = Cursor::new(bytes);
    let parsed = read_header(&mut reader).map_err(super::map_header_read_error)?;
    let ParsedHeader::V1(payload) = parsed;
    Ok(payload.header().clone())
}

fn validated_header_bytes(header: &V1Header) -> Result<Vec<u8>, Error> {
    let header_bytes = header.serialize().map_err(|_| Error::HeaderWrite)?;
    if header_bytes.len() != HEADER_LEN {
        return Err(Error::HeaderWrite);
    }

    parse_v1_header(&header_bytes)?;
    Ok(header_bytes)
}

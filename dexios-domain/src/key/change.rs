//! This provides functionality for changing an existing key in a header that
//! adheres to the Dexios V1 format.

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

pub struct ChangeIntent {
    target: ResolvedTarget,
    original: Vec<u8>,
    header: V1Header,
}

impl ChangeIntent {
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

        if let Some(tag) = super::unsupported_keyslot_kdf_tag(header.keyslots_collection()) {
            return Err(Error::UnsupportedKdf(tag));
        }

        Ok(Self {
            target,
            original,
            header,
        })
    }

    pub fn verify_old_key(
        self,
        raw_key_old: Protected<Vec<u8>>,
    ) -> Result<ProvenChangeIntent, Error> {
        let (master_key, index) = super::decrypt_v1_master_key_with_index(
            self.header.keyslots_collection(),
            raw_key_old,
        )?;

        Ok(ProvenChangeIntent {
            target: self.target,
            original: self.original,
            header: self.header,
            master_key,
            index,
        })
    }
}

pub struct ProvenChangeIntent {
    target: ResolvedTarget,
    original: Vec<u8>,
    header: V1Header,
    master_key: MasterKey,
    index: V1KeyslotIndex,
}

pub fn execute(
    intent: ProvenChangeIntent,
    raw_key_new: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<CommitReceipt, Error> {
    let ProvenChangeIntent {
        target,
        mut original,
        header,
        master_key,
        index,
    } = intent;

    let replacement_header = changed_header(&header, &master_key, index, raw_key_new, kdf)?;
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

fn changed_header(
    header: &V1Header,
    master_key: &MasterKey,
    index: V1KeyslotIndex,
    raw_key_new: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<V1Header, Error> {
    let mut keyslots = header.keyslots_collection().clone();

    let salt_bytes = gen_salt();
    let salt = Salt::new(salt_bytes);
    let key_new = kdf
        .derive(&raw_key_new, &salt.to_kdf_salt())
        .map_err(|_| Error::KeyHash)?;

    let master_key_nonce = gen_keyslot_nonce();

    let encrypted_master_key = super::encrypt_master_key(master_key, key_new, &master_key_nonce)?;

    keyslots
        .replace(
            index,
            V1Keyslot::new(kdf, encrypted_master_key, master_key_nonce, salt),
        )
        .map_err(|_| Error::HeaderWrite)?;

    let replacement_header =
        V1Header::new(*header.payload_nonce(), keyslots).map_err(|_| Error::HeaderWrite)?;
    let replacement_keyslots = replacement_header.keyslots_collection().clone();
    let (replacement_master_key, replacement_index) =
        super::decrypt_v1_master_key_with_index(&replacement_keyslots, raw_key_new)?;

    if replacement_index.get() != index.get() || !master_key.same_secret_as(&replacement_master_key)
    {
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

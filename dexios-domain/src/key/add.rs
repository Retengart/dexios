//! This provides functionality for adding a key to a header that adheres to the
//! Dexios V1 format.

use super::Error;
use core::header::v1::{V1Header, V1KeyslotIndex};
use core::kdf::Kdf;
use core::primitives::MasterKey;
use core::protected::Protected;
use std::path::Path;

use crate::storage::transaction::CommitReceipt;

pub struct AddIntent {
    mutation: super::V1MutationIntent,
    empty_index: V1KeyslotIndex,
}

impl AddIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mutation = super::V1MutationIntent::new(target_path)?;
        let empty_index = {
            let keyslots = mutation.header().keyslots_collection();

            if let Some(tag) = super::unsupported_keyslot_kdf_tag(keyslots) {
                return Err(Error::UnsupportedKdf(tag));
            }

            keyslots
                .first_empty_physical_slot()
                .ok_or(Error::TooManyKeyslots)?
        };

        Ok(Self {
            mutation,
            empty_index,
        })
    }

    pub fn verify_old_key(self, raw_key_old: Protected<Vec<u8>>) -> Result<ProvenAddIntent, Error> {
        let (master_key, _index) =
            super::decrypt_v1_master_key_with_index(self.mutation.header(), raw_key_old)?;

        Ok(ProvenAddIntent {
            mutation: self.mutation,
            master_key,
            empty_index: self.empty_index,
        })
    }
}

pub struct ProvenAddIntent {
    mutation: super::V1MutationIntent,
    master_key: MasterKey,
    empty_index: V1KeyslotIndex,
}

pub fn execute(
    intent: ProvenAddIntent,
    new_key_secret: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<CommitReceipt, Error> {
    let ProvenAddIntent {
        mutation,
        master_key,
        empty_index,
    } = intent;

    let replacement_header = added_header(
        mutation.header(),
        &master_key,
        empty_index,
        new_key_secret,
        kdf,
    )?;
    mutation.commit_replacement_header(&replacement_header)
}

fn added_header(
    header: &V1Header,
    master_key: &MasterKey,
    index: V1KeyslotIndex,
    new_key_secret: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<V1Header, Error> {
    // The shared helper keeps the former KDF borrow shape: .derive(&new_key_secret, ...).
    let replacement_header = super::build_v1_rewrapped_keyslot_header(
        header,
        master_key,
        index,
        &new_key_secret,
        kdf,
        super::V1KeyslotWrite::Insert,
    )?;
    let replacement_master_key =
        super::decrypt_v1_master_key_at_index(&replacement_header, index, new_key_secret)?;

    if !master_key.same_secret_as(&replacement_master_key) {
        return Err(Error::MasterKeyEncrypt);
    }

    Ok(replacement_header)
}

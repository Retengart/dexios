//! This provides functionality for changing an existing key in a header that
//! adheres to the Dexios V1 format.

use super::Error;
use core::header::v1::{V1Header, V1KeyslotIndex};
use core::kdf::Kdf;
use core::primitives::MasterKey;
use core::protected::Protected;
use std::path::Path;

use crate::storage::transaction::CommitReceipt;

pub struct ChangeIntent {
    mutation: super::V1MutationIntent,
}

impl ChangeIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mutation = super::V1MutationIntent::new(target_path)?;
        {
            let keyslots = mutation.header().keyslots_collection();
            if let Some(tag) = super::unsupported_keyslot_kdf_tag(keyslots) {
                return Err(Error::UnsupportedKdf(tag));
            }
        }

        Ok(Self { mutation })
    }

    pub fn verify_old_key(
        self,
        raw_key_old: Protected<Vec<u8>>,
    ) -> Result<ProvenChangeIntent, Error> {
        let (master_key, index) =
            super::decrypt_v1_master_key_with_index(self.mutation.header(), raw_key_old)?;

        Ok(ProvenChangeIntent {
            mutation: self.mutation,
            master_key,
            index,
        })
    }
}

pub struct ProvenChangeIntent {
    mutation: super::V1MutationIntent,
    master_key: MasterKey,
    index: V1KeyslotIndex,
}

pub fn execute(
    intent: ProvenChangeIntent,
    raw_key_new: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<CommitReceipt, Error> {
    let ProvenChangeIntent {
        mutation,
        master_key,
        index,
    } = intent;

    let replacement_header =
        changed_header(mutation.header(), &master_key, index, raw_key_new, kdf)?;
    mutation.commit_replacement_header(&replacement_header)
}

fn changed_header(
    header: &V1Header,
    master_key: &MasterKey,
    index: V1KeyslotIndex,
    raw_key_new: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<V1Header, Error> {
    // The shared helper keeps the former KDF borrow shape: .derive(&raw_key_new, ...).
    let replacement_header = super::build_v1_rewrapped_keyslot_header(
        header,
        master_key,
        index,
        &raw_key_new,
        kdf,
        super::V1KeyslotWrite::Replace,
    )?;
    let (replacement_master_key, replacement_index) =
        super::decrypt_v1_master_key_with_index(&replacement_header, raw_key_new)?;

    if replacement_index.get() != index.get() || !master_key.same_secret_as(&replacement_master_key)
    {
        return Err(Error::MasterKeyEncrypt);
    }

    Ok(replacement_header)
}

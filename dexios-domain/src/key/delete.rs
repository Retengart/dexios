//! This provides functionality for deleting a key from a Dexios V1 header.

use super::Error;
use core::header::v1::V1Header;
use core::protected::Protected;
use std::path::Path;

use crate::storage::transaction::CommitReceipt;

pub struct DeleteIntent {
    mutation: super::V1MutationIntent,
}

impl DeleteIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mutation = super::V1MutationIntent::new(target_path)?;
        {
            let keyslots = mutation.header().keyslots_collection();
            if let Some(tag) = super::all_keyslots_have_unsupported_kdf(keyslots) {
                return Err(Error::UnsupportedKdf(tag));
            }
        }

        Ok(Self { mutation })
    }
}

pub fn execute(
    intent: DeleteIntent,
    raw_key_old: Protected<Vec<u8>>,
) -> Result<CommitReceipt, Error> {
    let DeleteIntent { mutation } = intent;

    let replacement_header = deleted_header(mutation.header(), raw_key_old)?;
    mutation.commit_replacement_header(&replacement_header)
}

fn deleted_header(header: &V1Header, raw_key_old: Protected<Vec<u8>>) -> Result<V1Header, Error> {
    let mut keyslots = header.keyslots_collection().clone();

    // all of these functions need either the master key, or the index
    let (master_key, index) = super::decrypt_v1_master_key_with_index(header, raw_key_old)?;
    drop(master_key);

    if keyslots.supported_slot_count() <= 1 {
        return Err(Error::CannotRemoveFinalV1Keyslot);
    }

    keyslots
        .clear_physical_slot(index)
        .map_err(|_| Error::HeaderWrite)?;

    header
        .with_keyslots(keyslots)
        .map_err(|_| Error::HeaderWrite)
}

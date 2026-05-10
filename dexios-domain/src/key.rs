use core::cipher::{unwrap_v1_master_key, wrap_v1_master_key};
use core::header::common::KeyslotNonce;
use core::header::v1::{EncryptedMasterKey, KeyslotKdf, V1KeyslotIndex, V1Keyslots};
use core::kdf::Kdf;
use core::primitives::ENCRYPTED_MASTER_KEY_LEN;
use core::primitives::{MasterKey, WrappingKey};
use core::protected::Protected;

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
    HeaderWrite,
    Seek,
    CannotRemoveFinalV1Keyslot,
    CannotAddV1KeyslotWithoutReencrypt,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::HeaderSizeParse => f.write_str("Cannot parse header size"),
            Error::Seek => f.write_str("Unable to seek the data's cursor"),
            Error::HeaderWrite => f.write_str("Unable to write the header"),
            Error::HeaderDeserialize => f.write_str("Unable to deserialize the header"),
            Error::CannotRemoveFinalV1Keyslot => f.write_str("Cannot remove the final V1 keyslot"),
            Error::CannotAddV1KeyslotWithoutReencrypt => {
                f.write_str("Cannot add a V1 keyslot without re-encrypting the payload")
            }
            Error::CipherInit => f.write_str("Unable to initialize a cipher"),
            Error::KeyHash => f.write_str("Unable to hash your key"),
            Error::TooManyKeyslots => {
                f.write_str("There are already too many populated keyslots within this file")
            }
            Error::MasterKeyEncrypt => f.write_str("Unable to encrypt master key"),
            Error::Unsupported => {
                f.write_str("The provided request is unsupported with this header version")
            }
            Error::UnsupportedKdf(tag) => {
                write!(f, "Unsupported keyslot KDF tag: {tag:02X?}")
            }
            Error::IncorrectKey => f.write_str("The provided key is incorrect"),
        }
    }
}

pub fn decrypt_v1_master_key_with_index(
    keyslots: &V1Keyslots,
    raw_key_old: Protected<Vec<u8>>,
) -> Result<(MasterKey, V1KeyslotIndex), Error> {
    let mut index = None;
    let mut master_key = None;
    let mut saw_unsupported_kdf = None;

    // we need the index, so we can't use `decrypt_master_key()`
    for (i, keyslot) in keyslots.as_slice().iter().enumerate() {
        let kdf = match keyslot.kdf() {
            KeyslotKdf::Blake3Balloon => Kdf::Blake3Balloon,
            KeyslotKdf::UnsupportedArgon2id => {
                saw_unsupported_kdf = Some([0xDF, 0x02]);
                continue;
            }
        };
        let salt = keyslot.salt().to_kdf_salt();
        let key_old = kdf
            .derive(&raw_key_old, &salt)
            .map_err(|_| Error::KeyHash)?;

        let encrypted_master_key = EncryptedMasterKey::new(*keyslot.encrypted_master_key());
        let master_key_result = unwrap_v1_master_key(
            WrappingKey::from(key_old),
            &encrypted_master_key,
            keyslot.nonce(),
        );

        let Ok(decrypted_master_key) = master_key_result else {
            continue;
        };

        master_key = Some(decrypted_master_key);
        index = Some(
            V1KeyslotIndex::try_from_usize(i, keyslots.count())
                .map_err(|_| Error::HeaderDeserialize)?,
        );

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

impl std::error::Error for Error {}

// TODO(brxken128): make this available in the core
pub fn encrypt_master_key(
    master_key: MasterKey,
    key_new: Protected<[u8; 32]>,
    nonce: &KeyslotNonce,
) -> Result<[u8; ENCRYPTED_MASTER_KEY_LEN], Error> {
    let encrypted_master_key = wrap_v1_master_key(WrappingKey::from(key_new), &master_key, nonce)
        .map_err(|_| Error::MasterKeyEncrypt)?;
    Ok(*encrypted_master_key.as_bytes())
}

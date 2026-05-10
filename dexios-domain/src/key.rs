use core::Zeroize;
use core::cipher::Ciphers;
use core::header::v1::{KeyslotKdf, V1KeyslotIndex, V1Keyslots};
use core::kdf::Kdf;
use core::key::vec_to_arr;
use core::primitives::ENCRYPTED_MASTER_KEY_LEN;
use core::primitives::MASTER_KEY_LEN;
use core::protected::Protected;

pub mod add;
pub mod change;
pub mod delete;
pub mod verify;

#[derive(Debug)]
pub enum Error {
    HeaderSizeParse,
    Unsupported,
    IncorrectKey,
    MasterKeyEncrypt,
    TooManyKeyslots,
    KeyHash,
    CipherInit,
    HeaderDeserialize,
    HeaderWrite,
    Seek,
    CannotRemoveFinalV1Keyslot,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::HeaderSizeParse => f.write_str("Cannot parse header size"),
            Error::Seek => f.write_str("Unable to seek the data's cursor"),
            Error::HeaderWrite => f.write_str("Unable to write the header"),
            Error::HeaderDeserialize => f.write_str("Unable to deserialize the header"),
            Error::CannotRemoveFinalV1Keyslot => f.write_str("Cannot remove the final V1 keyslot"),
            Error::CipherInit => f.write_str("Unable to initialize a cipher"),
            Error::KeyHash => f.write_str("Unable to hash your key"),
            Error::TooManyKeyslots => {
                f.write_str("There are already too many populated keyslots within this file")
            }
            Error::MasterKeyEncrypt => f.write_str("Unable to encrypt master key"),
            Error::Unsupported => {
                f.write_str("The provided request is unsupported with this header version")
            }
            Error::IncorrectKey => f.write_str("The provided key is incorrect"),
        }
    }
}

pub fn decrypt_v1_master_key_with_index(
    keyslots: &V1Keyslots,
    raw_key_old: Protected<Vec<u8>>,
) -> Result<(Protected<[u8; MASTER_KEY_LEN]>, V1KeyslotIndex), Error> {
    let mut index = None;
    let mut master_key = [0u8; MASTER_KEY_LEN];

    // we need the index, so we can't use `decrypt_master_key()`
    for (i, keyslot) in keyslots.as_slice().iter().enumerate() {
        let kdf = match keyslot.kdf() {
            KeyslotKdf::Blake3Balloon => Kdf::Blake3Balloon,
            KeyslotKdf::UnsupportedArgon2id => continue,
        };
        let salt = core::kdf::Salt::new(*keyslot.salt().as_bytes());
        let key_old = kdf
            .derive(raw_key_old.clone(), &salt)
            .map_err(|_| Error::KeyHash)?;
        let cipher = Ciphers::initialize(key_old).map_err(|_| Error::CipherInit)?;

        let master_key_result = cipher.decrypt(
            keyslot.nonce().as_bytes(),
            keyslot.encrypted_master_key().as_slice(),
        );

        if master_key_result.is_err() {
            continue;
        }

        let mut master_key_decrypted = master_key_result.unwrap();
        let len = MASTER_KEY_LEN.min(master_key_decrypted.len());
        master_key[..len].copy_from_slice(&master_key_decrypted[..len]);
        master_key_decrypted.zeroize();

        index = Some(
            V1KeyslotIndex::try_from_usize(i, keyslots.count())
                .map_err(|_| Error::HeaderDeserialize)?,
        );

        drop(cipher);
        break;
    }

    drop(raw_key_old);

    let Some(index) = index else {
        return Err(Error::IncorrectKey);
    };

    Ok((Protected::new(master_key), index))
}

impl std::error::Error for Error {}

// TODO(brxken128): make this available in the core
pub fn encrypt_master_key(
    master_key: Protected<[u8; MASTER_KEY_LEN]>,
    key_new: Protected<[u8; 32]>,
    nonce: &[u8],
) -> Result<[u8; ENCRYPTED_MASTER_KEY_LEN], Error> {
    let cipher = Ciphers::initialize(key_new).map_err(|_| Error::CipherInit)?;

    let master_key_result = cipher.encrypt(nonce, master_key.expose().as_slice());

    drop(master_key);

    let master_key_encrypted = master_key_result.map_err(|_| Error::MasterKeyEncrypt)?;

    Ok(vec_to_arr(master_key_encrypted))
}

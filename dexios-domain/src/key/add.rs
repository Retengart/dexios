//! This provides functionality for adding a key to a header that adheres to the
//! Dexios V1 format.

use std::io::Seek;

use super::Error;
use core::header::common::{HEADER_LEN, Salt};
use core::header::v1::V1Keyslot;
use core::header::{ParsedHeader, read_header};
use core::kdf::Kdf;
use core::primitives::{gen_keyslot_nonce, gen_salt};
use core::protected::Protected;
use std::cell::RefCell;
use std::io::{Read, Write};

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>, // header read+write+seek
    pub raw_key_old: Protected<Vec<u8>>,
    pub raw_key_new: Protected<Vec<u8>>,
    pub kdf: Kdf,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let (parsed, _) =
        read_header(&mut *req.handle.borrow_mut()).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(header) = parsed;

    req.handle
        .borrow_mut()
        .seek(std::io::SeekFrom::Current(
            -i64::try_from(HEADER_LEN).map_err(|_| Error::HeaderSizeParse)?,
        ))
        .map_err(|_| Error::Seek)?;

    let mut keyslots = header.keyslots_collection().clone();

    // all of these functions need either the master key, or the index
    let (master_key, _) = super::decrypt_v1_master_key_with_index(&keyslots, req.raw_key_old)?;

    if keyslots.is_full() {
        return Err(Error::TooManyKeyslots);
    }

    let salt_bytes = gen_salt();
    let salt = Salt::new(salt_bytes);
    let master_key_nonce = gen_keyslot_nonce();

    let key_new = req
        .kdf
        .derive(req.raw_key_new, &core::kdf::Salt::new(salt_bytes));
    let key_new = key_new.map_err(|_| Error::KeyHash)?;

    let encrypted_master_key =
        super::encrypt_master_key(master_key, key_new, master_key_nonce.as_bytes())?;

    let keyslot = V1Keyslot::new(req.kdf.into(), encrypted_master_key, master_key_nonce, salt);

    keyslots.push(keyslot).map_err(|_| Error::HeaderWrite)?;

    let header_new = core::header::v1::V1Header::new(*header.payload_nonce(), keyslots)
        .map_err(|_| Error::HeaderWrite)?;

    // write the header to the handle
    header_new
        .write(&mut *req.handle.borrow_mut())
        .map_err(|_| Error::HeaderWrite)?;

    Ok(())
}

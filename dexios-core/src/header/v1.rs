use std::io::{Read, Write};

use super::common::{
    Aad, HEADER_LEN, HEADER_STATIC_LEN, HeaderReadError, HeaderWriteError, KEYSLOT_LEN,
    KeyslotNonce, MAGIC, MAX_KEYSLOTS, PayloadNonce, Salt, VERSION_V1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyslotKdf {
    Blake3Balloon,
    Argon2id,
}

impl KeyslotKdf {
    fn serialize(self) -> [u8; 2] {
        match self {
            Self::Blake3Balloon => [0xDF, 0x01],
            Self::Argon2id => [0xDF, 0x02],
        }
    }

    fn deserialize(tag: [u8; 2]) -> Result<Self, HeaderReadError> {
        match tag {
            [0xDF, 0x01] => Ok(Self::Blake3Balloon),
            [0xDF, 0x02] => Ok(Self::Argon2id),
            _ => Err(HeaderReadError::InvalidKeyslotTag(tag)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V1Keyslot {
    kdf: KeyslotKdf,
    encrypted_master_key: [u8; 48],
    nonce: KeyslotNonce,
    salt: Salt,
}

impl V1Keyslot {
    #[must_use]
    pub const fn new(
        kdf: KeyslotKdf,
        encrypted_master_key: [u8; 48],
        nonce: KeyslotNonce,
        salt: Salt,
    ) -> Self {
        Self {
            kdf,
            encrypted_master_key,
            nonce,
            salt,
        }
    }

    fn serialize_into(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.kdf.serialize());
        bytes.extend_from_slice(&self.encrypted_master_key);
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(self.salt.as_bytes());
        bytes.extend_from_slice(&[0u8; 6]);
    }

    fn deserialize(slot_bytes: &[u8]) -> Result<Self, HeaderReadError> {
        let kdf = KeyslotKdf::deserialize([slot_bytes[0], slot_bytes[1]])?;

        let mut encrypted_master_key = [0u8; 48];
        encrypted_master_key.copy_from_slice(&slot_bytes[2..50]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&slot_bytes[50..74]);

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&slot_bytes[74..90]);

        Ok(Self::new(
            kdf,
            encrypted_master_key,
            KeyslotNonce::new(nonce),
            Salt::new(salt),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1Header {
    payload_nonce: PayloadNonce,
    keyslots: Vec<V1Keyslot>,
}

impl V1Header {
    pub fn new(
        payload_nonce: PayloadNonce,
        keyslots: Vec<V1Keyslot>,
    ) -> Result<Self, HeaderWriteError> {
        if keyslots.len() > MAX_KEYSLOTS {
            return Err(HeaderWriteError::TooManyKeyslots(keyslots.len()));
        }

        Ok(Self {
            payload_nonce,
            keyslots,
        })
    }

    #[must_use]
    pub const fn payload_nonce(&self) -> &PayloadNonce {
        &self.payload_nonce
    }

    #[must_use]
    pub fn keyslots(&self) -> &[V1Keyslot] {
        &self.keyslots
    }

    #[must_use]
    pub fn create_aad(&self) -> Aad {
        let mut aad = [0u8; HEADER_STATIC_LEN];
        aad[..4].copy_from_slice(&MAGIC);
        aad[4..6].copy_from_slice(&VERSION_V1);
        aad[6] = self.keyslots.len() as u8;
        aad[8..28].copy_from_slice(self.payload_nonce.as_bytes());
        Aad::new(aad)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, HeaderWriteError> {
        if self.keyslots.len() > MAX_KEYSLOTS {
            return Err(HeaderWriteError::TooManyKeyslots(self.keyslots.len()));
        }

        let mut bytes = Vec::with_capacity(HEADER_LEN);
        bytes.extend_from_slice(self.create_aad().as_bytes());

        for keyslot in &self.keyslots {
            keyslot.serialize_into(&mut bytes);
        }

        for _ in self.keyslots.len()..MAX_KEYSLOTS {
            bytes.extend_from_slice(&[0u8; KEYSLOT_LEN]);
        }

        Ok(bytes)
    }

    pub fn write(&self, writer: &mut impl Write) -> Result<(), HeaderWriteError> {
        let serialized = self.serialize()?;
        writer
            .write_all(&serialized)
            .map_err(|_| HeaderWriteError::Io)
    }

    pub fn deserialize(reader: &mut impl Read) -> Result<Self, HeaderReadError> {
        let mut bytes = [0u8; HEADER_LEN];
        reader.read_exact(&mut bytes)?;

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[..4]);
        if magic != MAGIC {
            return Err(HeaderReadError::InvalidMagic(magic));
        }

        let mut version = [0u8; 2];
        version.copy_from_slice(&bytes[4..6]);
        if version != VERSION_V1 {
            return Err(HeaderReadError::UnsupportedVersion(version));
        }

        let keyslot_count = bytes[6] as usize;
        if keyslot_count > MAX_KEYSLOTS {
            return Err(HeaderReadError::InvalidKeyslotCount(bytes[6]));
        }

        let mut payload_nonce = [0u8; 20];
        payload_nonce.copy_from_slice(&bytes[8..28]);

        let mut keyslots = Vec::with_capacity(keyslot_count);
        for index in 0..keyslot_count {
            let start = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
            let end = start + KEYSLOT_LEN;
            keyslots.push(V1Keyslot::deserialize(&bytes[start..end])?);
        }

        Self::new(PayloadNonce::new(payload_nonce), keyslots)
            .map_err(|_| HeaderReadError::InvalidKeyslotCount(bytes[6]))
    }
}

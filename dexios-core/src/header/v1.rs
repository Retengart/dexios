use std::io::{Read, Write};

use crate::kdf::Kdf;

use super::common::{
    HEADER_LEN, HEADER_STATIC_LEN, HeaderReadError, HeaderWriteError, KEYSLOT_LEN, KeyslotNonce,
    MAGIC, MAX_KEYSLOTS, PayloadNonce, Salt, V1HeaderAad, VERSION_V1,
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

impl From<Kdf> for KeyslotKdf {
    fn from(value: Kdf) -> Self {
        match value {
            Kdf::Blake3Balloon => Self::Blake3Balloon,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V1KeyslotCount(u8);

impl V1KeyslotCount {
    pub const MIN: u8 = 1;
    pub const MAX: u8 = MAX_KEYSLOTS as u8;

    pub fn try_from_u8(count: u8) -> Result<Self, HeaderReadError> {
        if !(Self::MIN..=Self::MAX).contains(&count) {
            return Err(HeaderReadError::InvalidKeyslotCount(count));
        }
        Ok(Self(count))
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V1KeyslotIndex(u8);

impl V1KeyslotIndex {
    pub fn try_from_usize(index: usize, count: V1KeyslotCount) -> Result<Self, HeaderReadError> {
        if index >= usize::from(count.get()) {
            return Err(HeaderReadError::InvalidKeyslotCount(count.get()));
        }
        Ok(Self(index as u8))
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedMasterKey([u8; 48]);

impl EncryptedMasterKey {
    #[must_use]
    pub const fn new(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, HeaderReadError> {
        if bytes.len() != 48 {
            return Err(HeaderReadError::InvalidEncryptedMasterKeyLength(
                bytes.len(),
            ));
        }

        let mut encrypted_master_key = [0u8; 48];
        encrypted_master_key.copy_from_slice(bytes);
        Ok(Self(encrypted_master_key))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V1Keyslot {
    kdf: KeyslotKdf,
    encrypted_master_key: EncryptedMasterKey,
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
            encrypted_master_key: EncryptedMasterKey::new(encrypted_master_key),
            nonce,
            salt,
        }
    }

    #[must_use]
    pub const fn kdf(&self) -> KeyslotKdf {
        self.kdf
    }

    #[must_use]
    pub const fn encrypted_master_key(&self) -> &[u8; 48] {
        self.encrypted_master_key.as_bytes()
    }

    #[must_use]
    pub const fn nonce(&self) -> &KeyslotNonce {
        &self.nonce
    }

    #[must_use]
    pub const fn salt(&self) -> &Salt {
        &self.salt
    }

    fn serialize_into(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.kdf.serialize());
        bytes.extend_from_slice(self.encrypted_master_key.as_bytes());
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(self.salt.as_bytes());
        bytes.extend_from_slice(&[0u8; 6]);
    }

    fn deserialize(slot_bytes: &[u8]) -> Result<Self, HeaderReadError> {
        let kdf = KeyslotKdf::deserialize([slot_bytes[0], slot_bytes[1]])?;

        Ok(Self {
            kdf,
            encrypted_master_key: EncryptedMasterKey::try_from_slice(&slot_bytes[2..50])?,
            nonce: KeyslotNonce::try_from_slice(&slot_bytes[50..74])?,
            salt: Salt::try_from_slice(&slot_bytes[74..90])?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1Keyslots {
    inner: Vec<V1Keyslot>,
}

impl V1Keyslots {
    #[must_use]
    pub fn single(keyslot: V1Keyslot) -> Self {
        Self {
            inner: vec![keyslot],
        }
    }

    pub fn try_from_vec(keyslots: Vec<V1Keyslot>) -> Result<Self, HeaderWriteError> {
        match keyslots.len() {
            0 => Err(HeaderWriteError::NoKeyslots),
            len if len > MAX_KEYSLOTS => Err(HeaderWriteError::TooManyKeyslots(len)),
            _ => Ok(Self { inner: keyslots }),
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[V1Keyslot] {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.inner.len() == MAX_KEYSLOTS
    }

    #[must_use]
    pub fn count(&self) -> V1KeyslotCount {
        V1KeyslotCount::try_from_u8(self.inner.len() as u8)
            .expect("V1Keyslots invariant keeps count in 1..=4")
    }

    pub fn push(&mut self, keyslot: V1Keyslot) -> Result<(), HeaderWriteError> {
        if self.is_full() {
            return Err(HeaderWriteError::TooManyKeyslots(self.inner.len() + 1));
        }
        self.inner.push(keyslot);
        Ok(())
    }

    pub fn replace(
        &mut self,
        index: V1KeyslotIndex,
        keyslot: V1Keyslot,
    ) -> Result<V1Keyslot, HeaderWriteError> {
        let slot = self
            .inner
            .get_mut(index.get())
            .ok_or_else(|| HeaderWriteError::InvalidKeyslotIndex(index.get()))?;
        Ok(std::mem::replace(slot, keyslot))
    }

    pub fn remove(&mut self, index: V1KeyslotIndex) -> Result<V1Keyslot, HeaderWriteError> {
        if self.inner.len() == 1 {
            return Err(HeaderWriteError::NoKeyslots);
        }
        if index.get() >= self.inner.len() {
            return Err(HeaderWriteError::InvalidKeyslotIndex(index.get()));
        }
        Ok(self.inner.remove(index.get()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1Header {
    payload_nonce: PayloadNonce,
    keyslots: V1Keyslots,
}

impl V1Header {
    pub fn new(
        payload_nonce: PayloadNonce,
        keyslots: V1Keyslots,
    ) -> Result<Self, HeaderWriteError> {
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
        self.keyslots.as_slice()
    }

    #[must_use]
    pub const fn keyslots_collection(&self) -> &V1Keyslots {
        &self.keyslots
    }

    #[must_use]
    pub fn aad(&self) -> V1HeaderAad {
        let mut aad = [0u8; HEADER_STATIC_LEN];
        aad[..4].copy_from_slice(&MAGIC);
        aad[4..6].copy_from_slice(&VERSION_V1);
        aad[6] = self.keyslots.count().get();
        aad[8..28].copy_from_slice(self.payload_nonce.as_bytes());
        V1HeaderAad::from_static_header_bytes(aad)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, HeaderWriteError> {
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        bytes.extend_from_slice(self.aad().as_bytes());

        for keyslot in self.keyslots.as_slice() {
            keyslot.serialize_into(&mut bytes);
        }

        for _ in self.keyslots.len()..MAX_KEYSLOTS {
            bytes.extend_from_slice(&[0u8; KEYSLOT_LEN]);
        }

        Ok(bytes)
    }

    pub fn write(&self, writer: &mut impl Write) -> Result<(), HeaderWriteError> {
        let serialized = self.serialize()?;
        writer.write_all(&serialized).map_err(HeaderWriteError::Io)
    }

    pub fn deserialize(reader: &mut impl Read) -> Result<Self, HeaderReadError> {
        let mut bytes = [0u8; HEADER_LEN];
        reader.read_exact(&mut bytes)?;

        Self::deserialize_bytes(bytes)
    }

    pub(crate) fn deserialize_bytes(bytes: [u8; HEADER_LEN]) -> Result<Self, HeaderReadError> {
        if bytes[7] != 0 || bytes[28..32] != [0u8; 4] {
            return Err(HeaderReadError::NonZeroReservedBytes);
        }

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

        let keyslot_count = V1KeyslotCount::try_from_u8(bytes[6])?;

        let payload_nonce = PayloadNonce::try_from_slice(&bytes[8..28])?;

        let mut keyslots = Vec::with_capacity(usize::from(keyslot_count.get()));
        for index in 0..usize::from(keyslot_count.get()) {
            let start = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
            let end = start + KEYSLOT_LEN;
            let keyslot = V1Keyslot::deserialize(&bytes[start..end])?;
            if bytes[(start + 90)..end] != [0u8; 6] {
                return Err(HeaderReadError::NonZeroActiveKeyslotPadding(index));
            }
            keyslots.push(keyslot);
        }

        for index in usize::from(keyslot_count.get())..MAX_KEYSLOTS {
            let start = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
            let end = start + KEYSLOT_LEN;
            if bytes[start..end] != [0u8; KEYSLOT_LEN] {
                return Err(HeaderReadError::NonZeroInactiveKeyslotPadding(index));
            }
        }

        V1Keyslots::try_from_vec(keyslots)
            .map_err(|_| HeaderReadError::InvalidKeyslotCount(bytes[6]))
            .and_then(|keyslots| {
                Self::new(payload_nonce, keyslots)
                    .map_err(|_| HeaderReadError::InvalidKeyslotCount(bytes[6]))
            })
    }
}

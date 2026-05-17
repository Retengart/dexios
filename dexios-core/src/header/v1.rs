use std::io::{Read, Write};

use crate::kdf::{BLAKE3_BALLOON_KDF_PARAM_PROFILE_ID, BLAKE3_BALLOON_KDF_PROFILE_ID, Kdf};
use crate::payload::{PayloadFramingProfile, PayloadKind};

use super::common::{
    CANONICAL_V1_DISCRIMINATOR, HEADER_LEN, HEADER_STATIC_LEN, HeaderReadError, HeaderWriteError,
    KEYSLOT_LEN, KeyslotNonce, MAGIC, MAX_KEYSLOTS, PayloadNonce, Salt, V1HeaderAad, VERSION_V1,
};

const CANONICAL_SCHEMA_PROFILE: u8 = 0x01;
const SLOT_STATE_EMPTY: u8 = 0x00;
const SLOT_STATE_ACTIVE: u8 = 0x01;
const KDF_PROFILE_HISTORICAL_ARGON2ID: u8 = 0xDF;
const KDF_PARAM_PROFILE_HISTORICAL_ARGON2ID: u8 = 0x02;
const SLOT_WRAPPING_AAD_LEN: usize = HEADER_STATIC_LEN + 1 + 1 + 1 + 16 + 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyslotKdf {
    Blake3Balloon,
    UnsupportedArgon2id,
}

impl KeyslotKdf {
    fn serialize_profile(self) -> u8 {
        match self {
            Self::Blake3Balloon => BLAKE3_BALLOON_KDF_PROFILE_ID,
            Self::UnsupportedArgon2id => KDF_PROFILE_HISTORICAL_ARGON2ID,
        }
    }

    fn serialize_param_profile(self) -> u8 {
        match self {
            Self::Blake3Balloon => BLAKE3_BALLOON_KDF_PARAM_PROFILE_ID,
            Self::UnsupportedArgon2id => KDF_PARAM_PROFILE_HISTORICAL_ARGON2ID,
        }
    }

    fn deserialize(profile: u8, param_profile: u8) -> Result<Self, HeaderReadError> {
        match (profile, param_profile) {
            (BLAKE3_BALLOON_KDF_PROFILE_ID, BLAKE3_BALLOON_KDF_PARAM_PROFILE_ID) => {
                Ok(Self::Blake3Balloon)
            }
            (KDF_PROFILE_HISTORICAL_ARGON2ID, KDF_PARAM_PROFILE_HISTORICAL_ARGON2ID) => {
                Ok(Self::UnsupportedArgon2id)
            }
            (BLAKE3_BALLOON_KDF_PROFILE_ID, param_profile) => {
                Err(HeaderReadError::InvalidKdfParamProfile(param_profile))
            }
            (profile, _) => Err(HeaderReadError::InvalidKdfProfile(profile)),
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

    pub fn try_from_physical_index(index: usize) -> Result<Self, HeaderReadError> {
        if index >= MAX_KEYSLOTS {
            return Err(HeaderReadError::InvalidPhysicalSlotIndex {
                expected: MAX_KEYSLOTS - 1,
                actual: u8::try_from(index).unwrap_or(u8::MAX),
            });
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
    physical_index: u8,
    kdf: KeyslotKdf,
    encrypted_master_key: EncryptedMasterKey,
    nonce: KeyslotNonce,
    salt: Salt,
}

impl V1Keyslot {
    #[must_use]
    pub const fn new(
        kdf: Kdf,
        encrypted_master_key: [u8; 48],
        nonce: KeyslotNonce,
        salt: Salt,
    ) -> Self {
        let kdf = match kdf {
            Kdf::Blake3Balloon => KeyslotKdf::Blake3Balloon,
        };

        Self {
            physical_index: 0,
            kdf,
            encrypted_master_key: EncryptedMasterKey::new(encrypted_master_key),
            nonce,
            salt,
        }
    }

    fn with_physical_index(mut self, physical_index: usize) -> Self {
        self.physical_index =
            u8::try_from(physical_index).expect("physical V1 slot index fits in u8");
        self
    }

    #[must_use]
    pub const fn physical_index(&self) -> usize {
        self.physical_index as usize
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
        bytes.push(SLOT_STATE_ACTIVE);
        bytes.push(self.physical_index);
        bytes.push(self.kdf.serialize_profile());
        bytes.push(self.kdf.serialize_param_profile());
        bytes.extend_from_slice(self.salt.as_bytes());
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(self.encrypted_master_key.as_bytes());
        bytes.extend_from_slice(&[0u8; KEYSLOT_LEN - 92]);
    }

    fn deserialize(slot_bytes: &[u8], physical_index: usize) -> Result<Self, HeaderReadError> {
        if slot_bytes[0] != SLOT_STATE_ACTIVE {
            return Err(HeaderReadError::InvalidSlotState {
                index: physical_index,
                state: slot_bytes[0],
            });
        }

        let actual_index = slot_bytes[1];
        if usize::from(actual_index) != physical_index {
            return Err(HeaderReadError::InvalidPhysicalSlotIndex {
                expected: physical_index,
                actual: actual_index,
            });
        }

        let kdf = KeyslotKdf::deserialize(slot_bytes[2], slot_bytes[3])?;

        Ok(Self {
            physical_index: u8::try_from(physical_index)
                .expect("physical V1 slot index fits in u8"),
            kdf,
            salt: Salt::try_from_slice(&slot_bytes[4..20])?,
            nonce: KeyslotNonce::try_from_slice(&slot_bytes[20..44])?,
            encrypted_master_key: EncryptedMasterKey::try_from_slice(&slot_bytes[44..92])?,
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
            inner: vec![keyslot.with_physical_index(0)],
        }
    }

    pub fn try_from_vec(keyslots: Vec<V1Keyslot>) -> Result<Self, HeaderWriteError> {
        match keyslots.len() {
            0 => Err(HeaderWriteError::NoKeyslots),
            len if len > MAX_KEYSLOTS => Err(HeaderWriteError::TooManyKeyslots(len)),
            _ => Ok(Self {
                inner: keyslots
                    .into_iter()
                    .enumerate()
                    .map(|(index, keyslot)| keyslot.with_physical_index(index))
                    .collect(),
            }),
        }
    }

    fn try_from_parsed_vec(keyslots: Vec<V1Keyslot>) -> Result<Self, HeaderWriteError> {
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

    pub fn iter_physical_slots(&self) -> impl Iterator<Item = (usize, Option<&V1Keyslot>)> + '_ {
        (0..MAX_KEYSLOTS)
            .map(move |physical_index| (physical_index, self.get_physical(physical_index)))
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
    pub fn supported_slot_count(&self) -> usize {
        self.inner
            .iter()
            .filter(|keyslot| matches!(keyslot.kdf(), KeyslotKdf::Blake3Balloon))
            .count()
    }

    pub fn first_empty_physical_slot(&self) -> Option<V1KeyslotIndex> {
        (0..MAX_KEYSLOTS)
            .find(|index| self.get_physical(*index).is_none())
            .and_then(|index| V1KeyslotIndex::try_from_physical_index(index).ok())
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
        let physical_index = self
            .first_empty_physical_slot()
            .ok_or_else(|| HeaderWriteError::TooManyKeyslots(self.inner.len() + 1))?;
        self.insert_physical_slot(physical_index, keyslot)
    }

    pub fn insert_physical_slot(
        &mut self,
        index: V1KeyslotIndex,
        keyslot: V1Keyslot,
    ) -> Result<(), HeaderWriteError> {
        if self.is_full() {
            return Err(HeaderWriteError::TooManyKeyslots(self.inner.len() + 1));
        }
        if self.get_physical(index.get()).is_some() {
            return Err(HeaderWriteError::InvalidKeyslotIndex(index.get()));
        }
        self.inner.push(keyslot.with_physical_index(index.get()));
        Ok(())
    }

    pub fn replace(
        &mut self,
        index: V1KeyslotIndex,
        keyslot: V1Keyslot,
    ) -> Result<V1Keyslot, HeaderWriteError> {
        let slot = self
            .inner
            .iter_mut()
            .find(|keyslot| keyslot.physical_index() == index.get())
            .ok_or_else(|| HeaderWriteError::InvalidKeyslotIndex(index.get()))?;
        Ok(std::mem::replace(
            slot,
            keyslot.with_physical_index(index.get()),
        ))
    }

    pub fn clear_physical_slot(
        &mut self,
        index: V1KeyslotIndex,
    ) -> Result<V1Keyslot, HeaderWriteError> {
        if self.inner.len() == 1 {
            return Err(HeaderWriteError::NoKeyslots);
        }
        let mut cleared = None;
        self.inner.retain(|keyslot| {
            if keyslot.physical_index() == index.get() {
                cleared = Some(*keyslot);
                false
            } else {
                true
            }
        });
        cleared.ok_or_else(|| HeaderWriteError::InvalidKeyslotIndex(index.get()))
    }

    pub fn get_physical(&self, physical_index: usize) -> Option<&V1Keyslot> {
        self.inner
            .iter()
            .find(|keyslot| keyslot.physical_index() == physical_index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1Header {
    payload_nonce: PayloadNonce,
    payload_kind: PayloadKind,
    payload_framing: PayloadFramingProfile,
    keyslots: V1Keyslots,
}

impl V1Header {
    pub fn new(
        payload_nonce: PayloadNonce,
        keyslots: V1Keyslots,
    ) -> Result<Self, HeaderWriteError> {
        Ok(Self {
            payload_nonce,
            payload_kind: PayloadKind::RawFile,
            payload_framing: PayloadFramingProfile::RawLe31,
            keyslots,
        })
    }

    pub fn new_manifest_archive(
        payload_nonce: PayloadNonce,
        keyslots: V1Keyslots,
    ) -> Result<Self, HeaderWriteError> {
        Ok(Self {
            payload_nonce,
            payload_kind: PayloadKind::ManifestArchive,
            payload_framing: PayloadFramingProfile::ManifestFirst,
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
    pub const fn payload_kind(&self) -> PayloadKind {
        self.payload_kind
    }

    #[must_use]
    pub const fn payload_framing(&self) -> PayloadFramingProfile {
        self.payload_framing
    }

    #[must_use]
    pub fn aad(&self) -> V1HeaderAad {
        let mut aad = [0u8; HEADER_STATIC_LEN];
        aad[..4].copy_from_slice(&MAGIC);
        aad[4..6].copy_from_slice(&VERSION_V1);
        aad[6..10].copy_from_slice(&CANONICAL_V1_DISCRIMINATOR);
        aad[10] = CANONICAL_SCHEMA_PROFILE;
        aad[11] = self.payload_kind.to_byte();
        aad[12] = self.payload_framing.to_byte();
        aad[13] = BLAKE3_BALLOON_KDF_PARAM_PROFILE_ID;
        aad[14] = MAX_KEYSLOTS as u8;
        aad[16..36].copy_from_slice(self.payload_nonce.as_bytes());
        V1HeaderAad::from_static_header_bytes(aad)
    }

    pub fn slot_wrapping_aad(
        &self,
        physical_index: usize,
        keyslot: &V1Keyslot,
    ) -> Result<Vec<u8>, HeaderWriteError> {
        if physical_index >= MAX_KEYSLOTS {
            return Err(HeaderWriteError::InvalidKeyslotIndex(physical_index));
        }

        let mut aad = Vec::with_capacity(SLOT_WRAPPING_AAD_LEN);
        aad.extend_from_slice(self.aad().as_bytes());
        aad.push(u8::try_from(physical_index).expect("physical V1 slot index fits in u8"));
        aad.push(keyslot.kdf.serialize_profile());
        aad.push(keyslot.kdf.serialize_param_profile());
        aad.extend_from_slice(keyslot.salt.as_bytes());
        aad.extend_from_slice(keyslot.nonce.as_bytes());
        Ok(aad)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, HeaderWriteError> {
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        bytes.extend_from_slice(self.aad().as_bytes());

        for (_physical_index, keyslot) in self.keyslots.iter_physical_slots() {
            match keyslot {
                Some(keyslot) => keyslot.serialize_into(&mut bytes),
                None => bytes.extend_from_slice(&[0u8; KEYSLOT_LEN]),
            }
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

        let mut discriminator = [0u8; 4];
        discriminator.copy_from_slice(&bytes[6..10]);
        if discriminator != CANONICAL_V1_DISCRIMINATOR {
            return Err(HeaderReadError::InvalidCanonicalDiscriminator(
                discriminator,
            ));
        }

        if bytes[10] != CANONICAL_SCHEMA_PROFILE {
            return Err(HeaderReadError::UnsupportedVersion([0x00, bytes[10]]));
        }
        let payload_kind = PayloadKind::try_from_byte(bytes[11])
            .map_err(|_| HeaderReadError::InvalidPayloadKind(bytes[11]))?;
        let payload_framing = PayloadFramingProfile::try_from_byte(bytes[12])
            .map_err(|_| HeaderReadError::InvalidPayloadFraming(bytes[12]))?;
        match (payload_kind, payload_framing) {
            (PayloadKind::RawFile, PayloadFramingProfile::RawLe31)
            | (PayloadKind::ManifestArchive, PayloadFramingProfile::ManifestFirst) => {}
            _ => return Err(HeaderReadError::InvalidPayloadFraming(bytes[12])),
        }
        if bytes[13] != BLAKE3_BALLOON_KDF_PARAM_PROFILE_ID {
            return Err(HeaderReadError::InvalidKdfParamProfile(bytes[13]));
        }
        if bytes[14] != MAX_KEYSLOTS as u8 {
            return Err(HeaderReadError::InvalidKeyslotCount(bytes[14]));
        }
        if bytes[15] != 0 || bytes[36..HEADER_STATIC_LEN] != [0u8; HEADER_STATIC_LEN - 36] {
            return Err(HeaderReadError::NonZeroReservedBytes);
        }

        let payload_nonce = PayloadNonce::try_from_slice(&bytes[16..36])?;

        let mut keyslots = Vec::with_capacity(MAX_KEYSLOTS);
        for index in 0..MAX_KEYSLOTS {
            let start = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
            let end = start + KEYSLOT_LEN;
            let slot_bytes = &bytes[start..end];
            match slot_bytes[0] {
                SLOT_STATE_EMPTY => {
                    if slot_bytes != [0u8; KEYSLOT_LEN] {
                        return Err(HeaderReadError::NonZeroInactiveKeyslotPadding(index));
                    }
                }
                SLOT_STATE_ACTIVE => {
                    let keyslot = V1Keyslot::deserialize(slot_bytes, index)?;
                    if slot_bytes[92..] != [0u8; KEYSLOT_LEN - 92] {
                        return Err(HeaderReadError::NonZeroActiveKeyslotPadding(index));
                    }
                    keyslots.push(keyslot);
                }
                state => return Err(HeaderReadError::InvalidSlotState { index, state }),
            }
        }

        let keyslots = V1Keyslots::try_from_parsed_vec(keyslots)
            .map_err(|_| HeaderReadError::InvalidKeyslotCount(0))?;
        Ok(Self {
            payload_nonce,
            payload_kind,
            payload_framing,
            keyslots,
        })
    }
}

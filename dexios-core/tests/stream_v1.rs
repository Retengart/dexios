use std::io::Cursor;

use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt as HeaderSalt};
use dexios_core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use dexios_core::header::{ParsedHeader, ParsedV1Payload};
use dexios_core::kdf::Kdf;
use dexios_core::primitives::{BLOCK_SIZE, MasterKey};
use dexios_core::stream::{StreamError, V1PayloadDecryptor, V1PayloadEncryptor, V1PayloadStream};

const STREAM_TAG_LEN: usize = 16;

mod support {
    use super::*;

    pub fn sample_v1_header() -> V1Header {
        V1Header::new(
            PayloadNonce::new([7u8; 20]),
            V1Keyslots::single(sample_keyslot(11)),
        )
        .expect("sample v1 header")
    }

    pub fn parsed_payload_for(header: &V1Header) -> ParsedV1Payload {
        let bytes = header.serialize().expect("serialize header");
        let ParsedHeader::V1(payload) =
            dexios_core::header::read_header(&mut Cursor::new(bytes)).expect("parse header");
        payload
    }

    pub fn master_key() -> MasterKey {
        MasterKey::new([31u8; 32])
    }

    fn sample_keyslot(seed: u8) -> V1Keyslot {
        V1Keyslot::new(
            Kdf::Blake3Balloon,
            [seed; 48],
            KeyslotNonce::new([seed.wrapping_add(2); 24]),
            HeaderSalt::new([seed.wrapping_add(6); 16]),
        )
    }
}

#[test]
fn v1_stream_roundtrips_with_header_derived_aad() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = b"typed v1 stream binds payload chunks to header-derived aad";

    let mut encrypted = Vec::new();
    V1PayloadStream::encrypt_file(
        support::master_key(),
        &header,
        &mut Cursor::new(plaintext),
        &mut encrypted,
    )
    .expect("encrypt v1 stream");

    let mut decrypted = Vec::new();
    V1PayloadStream::decrypt_file(
        support::master_key(),
        &payload,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    )
    .expect("decrypt v1 stream");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn exact_block_plaintext_emits_empty_authenticated_final_chunk() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = vec![0xA5; BLOCK_SIZE];

    let mut encryptor =
        V1PayloadEncryptor::new(support::master_key(), &header).expect("create encryptor");
    let normal_chunk = encryptor
        .encrypt_next(&plaintext)
        .expect("encrypt exact normal chunk");
    let final_chunk = encryptor
        .encrypt_last(&[])
        .expect("encrypt empty final chunk");

    assert_eq!(normal_chunk.len(), BLOCK_SIZE + STREAM_TAG_LEN);
    assert_eq!(final_chunk.len(), STREAM_TAG_LEN);

    let mut decryptor =
        V1PayloadDecryptor::new(support::master_key(), &payload).expect("create decryptor");
    let decrypted_normal = decryptor
        .decrypt_next(&normal_chunk)
        .expect("decrypt normal chunk");
    let decrypted_final = decryptor
        .decrypt_last(&final_chunk)
        .expect("decrypt empty final chunk");

    assert_eq!(decrypted_normal, plaintext);
    assert!(
        decrypted_final.is_empty(),
        "exact-block streams must authenticate an empty final marker"
    );
}

#[test]
fn exact_block_ciphertext_without_final_marker_fails() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = vec![0xC3; BLOCK_SIZE];

    let mut encryptor =
        V1PayloadEncryptor::new(support::master_key(), &header).expect("create encryptor");
    let ciphertext_without_final_marker = encryptor
        .encrypt_next(&plaintext)
        .expect("encrypt exact normal chunk");

    let mut scratch = Vec::new();
    let result = V1PayloadStream::decrypt_file(
        support::master_key(),
        &payload,
        &mut Cursor::new(ciphertext_without_final_marker),
        &mut scratch,
    );

    assert!(matches!(result, Err(StreamError::MissingFinalBlock)));
    assert_eq!(
        scratch, plaintext,
        "plaintext written before final authentication is uncommitted scratch"
    );
}

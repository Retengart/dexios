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
        sample_v1_header_with_nonce_and_keyslot_count([7u8; 20], 1)
    }

    pub fn sample_v1_header_with_nonce_and_keyslot_count(
        payload_nonce: [u8; 20],
        keyslot_count: usize,
    ) -> V1Header {
        let keyslots = (0..keyslot_count)
            .map(|index| sample_keyslot(11 + index as u8))
            .collect();
        V1Header::new(
            PayloadNonce::new(payload_nonce),
            V1Keyslots::try_from_vec(keyslots).expect("sample keyslot count"),
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

fn plaintext_spanning_normal_chunks() -> Vec<u8> {
    (0..(BLOCK_SIZE * 3 + 37))
        .map(|index| (index % 251) as u8)
        .collect()
}

fn exact_two_block_plaintext() -> Vec<u8> {
    vec![0x42; BLOCK_SIZE * 2]
}

fn encrypt_chunks(header: &V1Header, plaintext: &[u8]) -> Vec<Vec<u8>> {
    let mut encryptor =
        V1PayloadEncryptor::new(support::master_key(), header).expect("create encryptor");
    let mut chunks = Vec::new();
    let mut offset = 0;

    while offset + BLOCK_SIZE <= plaintext.len() {
        chunks.push(
            encryptor
                .encrypt_next(&plaintext[offset..offset + BLOCK_SIZE])
                .expect("encrypt normal chunk"),
        );
        offset += BLOCK_SIZE;
    }

    chunks.push(
        encryptor
            .encrypt_last(&plaintext[offset..])
            .expect("encrypt final chunk"),
    );
    chunks
}

fn flatten_chunks(chunks: &[Vec<u8>]) -> Vec<u8> {
    chunks
        .iter()
        .flat_map(|chunk| chunk.iter().copied())
        .collect()
}

fn decrypt_file_with(
    master_key: MasterKey,
    payload: &ParsedV1Payload,
    ciphertext: Vec<u8>,
) -> (Result<(), StreamError>, Vec<u8>) {
    let mut scratch = Vec::new();
    let result = V1PayloadStream::decrypt_file(
        master_key,
        payload,
        &mut Cursor::new(ciphertext),
        &mut scratch,
    );
    (result, scratch)
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

#[test]
fn decrypt_rejects_wrong_master_key() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let ciphertext = flatten_chunks(&encrypt_chunks(&header, &plaintext));

    let (result, scratch) = decrypt_file_with(MasterKey::new([99u8; 32]), &payload, ciphertext);

    assert!(matches!(result, Err(StreamError::Authentication)));
    assert!(
        scratch.is_empty(),
        "wrong-key failure must not be reported as committed plaintext"
    );
}

#[test]
fn decrypt_rejects_mismatched_header_aad() {
    let header = support::sample_v1_header();
    let wrong_aad_header = support::sample_v1_header_with_nonce_and_keyslot_count([7u8; 20], 2);
    let wrong_aad_payload = support::parsed_payload_for(&wrong_aad_header);
    let plaintext = plaintext_spanning_normal_chunks();
    let ciphertext = flatten_chunks(&encrypt_chunks(&header, &plaintext));

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &wrong_aad_payload, ciphertext);

    assert!(matches!(result, Err(StreamError::Authentication)));
    assert!(
        scratch.is_empty(),
        "wrong-AAD failure must not be reported as committed plaintext"
    );
}

#[test]
fn decrypt_rejects_wrong_payload_nonce() {
    let header = support::sample_v1_header();
    let wrong_nonce_header = support::sample_v1_header_with_nonce_and_keyslot_count([8u8; 20], 1);
    let wrong_nonce_payload = support::parsed_payload_for(&wrong_nonce_header);
    let plaintext = plaintext_spanning_normal_chunks();
    let ciphertext = flatten_chunks(&encrypt_chunks(&header, &plaintext));

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &wrong_nonce_payload, ciphertext);

    assert!(matches!(result, Err(StreamError::Authentication)));
    assert!(
        scratch.is_empty(),
        "wrong-payload-nonce failure must not be reported as committed plaintext"
    );
}

#[test]
fn decrypt_rejects_truncated_ciphertext() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = exact_two_block_plaintext();
    let mut ciphertext = flatten_chunks(&encrypt_chunks(&header, &plaintext));
    ciphertext.pop().expect("ciphertext has a final tag byte");

    let (result, scratch) = decrypt_file_with(support::master_key(), &payload, ciphertext);

    assert!(matches!(result, Err(StreamError::TruncatedCiphertext)));
    assert_eq!(
        scratch, plaintext,
        "plaintext written before final authentication is uncommitted scratch"
    );
}

#[test]
fn decrypt_rejects_reordered_chunks() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let mut chunks = encrypt_chunks(&header, &plaintext);
    chunks.swap(0, 1);

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &payload, flatten_chunks(&chunks));

    assert!(matches!(result, Err(StreamError::Authentication)));
    assert!(
        scratch.is_empty(),
        "reordered chunks must fail before committed plaintext success is claimed"
    );
}

#[test]
fn decrypt_rejects_tampered_middle_chunk() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let mut chunks = encrypt_chunks(&header, &plaintext);
    chunks[1][0] ^= 0x80;

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &payload, flatten_chunks(&chunks));

    assert!(matches!(result, Err(StreamError::Authentication)));
    assert_eq!(
        scratch,
        plaintext[..BLOCK_SIZE],
        "plaintext written before tamper detection is uncommitted scratch"
    );
}

#[test]
fn decrypt_rejects_tampered_final_chunk() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let mut chunks = encrypt_chunks(&header, &plaintext);
    let final_chunk = chunks.last_mut().expect("final chunk exists");
    final_chunk[0] ^= 0x40;

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &payload, flatten_chunks(&chunks));

    assert!(matches!(result, Err(StreamError::FinalBlockAuthentication)));
    assert_eq!(
        scratch,
        plaintext[..BLOCK_SIZE * 3],
        "normal chunks before a final-block failure are uncommitted scratch"
    );
}

#[test]
fn decrypt_rejects_missing_final_block() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = exact_two_block_plaintext();
    let mut chunks = encrypt_chunks(&header, &plaintext);
    let final_marker = chunks.pop().expect("final marker exists");

    assert_eq!(final_marker.len(), STREAM_TAG_LEN);

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &payload, flatten_chunks(&chunks));

    assert!(matches!(result, Err(StreamError::MissingFinalBlock)));
    assert_eq!(
        scratch, plaintext,
        "plaintext written before final marker validation is uncommitted scratch"
    );
}

#[test]
fn decrypt_failure_output_is_uncommitted_scratch() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let mut chunks = encrypt_chunks(&header, &plaintext);
    chunks.last_mut().expect("final chunk exists")[0] ^= 0x20;

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &payload, flatten_chunks(&chunks));

    assert!(
        result.is_err(),
        "a failed decrypt must not return committed plaintext success"
    );
    assert_eq!(
        scratch,
        plaintext[..BLOCK_SIZE * 3],
        "failed decrypt output is only uncommitted scratch until final authentication succeeds"
    );
}

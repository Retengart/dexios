use std::io::{Cursor, Read, Write};

use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt as HeaderSalt};
use dexios_core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use dexios_core::header::{ParsedHeader, ParsedV1Payload};
use dexios_core::kdf::Kdf;
use dexios_core::primitives::{BLOCK_SIZE, MasterKey};
use dexios_core::stream::{
    StreamError, V1PayloadDecryptor, V1PayloadEncryptingWriter, V1PayloadEncryptor, V1PayloadStream,
};

const STREAM_TAG_LEN: usize = 16;
const FIXTURE_MANIFEST: &str = include_str!("testdata/fixture_manifest.toml");

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

    pub fn parsed_payload_with_payload_metadata(
        header: &V1Header,
        payload_kind: u8,
        payload_framing: u8,
    ) -> ParsedV1Payload {
        let mut bytes = header.serialize().expect("serialize header");
        bytes[11] = payload_kind;
        bytes[12] = payload_framing;
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

fn payload_boundary_cases() -> Vec<(&'static str, Vec<u8>)> {
    [
        ("empty", 0),
        ("one-byte", 1),
        ("block-minus-one", BLOCK_SIZE - 1),
        ("exact-block", BLOCK_SIZE),
        ("block-plus-one", BLOCK_SIZE + 1),
        ("exact-two-blocks", BLOCK_SIZE * 2),
        ("multi-block-plus-tail", BLOCK_SIZE * 3 + 37),
    ]
    .into_iter()
    .map(|(label, len)| {
        let payload = (0..len).map(|index| (index % 251) as u8).collect();
        (label, payload)
    })
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

struct ShortRead<R> {
    inner: R,
    max_chunk: usize,
}

impl<R> ShortRead<R> {
    fn new(inner: R, max_chunk: usize) -> Self {
        assert!(max_chunk > 0, "short-read chunk size must be nonzero");
        Self { inner, max_chunk }
    }
}

impl<R: Read> Read for ShortRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let limit = buf.len().min(self.max_chunk);
        self.inner.read(&mut buf[..limit])
    }
}

struct ShortWrite<W> {
    inner: W,
    max_chunk: usize,
}

impl<W> ShortWrite<W> {
    fn new(inner: W, max_chunk: usize) -> Self {
        assert!(max_chunk > 0, "short-write chunk size must be nonzero");
        Self { inner, max_chunk }
    }
}

impl<W: Write> Write for ShortWrite<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let limit = buf.len().min(self.max_chunk);
        self.inner.write(&buf[..limit])
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
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
fn stream_payload_boundary_matrix_roundtrips_with_file_api() {
    for (label, plaintext) in payload_boundary_cases() {
        let header = support::sample_v1_header();
        let payload = support::parsed_payload_for(&header);

        let mut encrypted = Vec::new();
        V1PayloadStream::encrypt_file(
            support::master_key(),
            &header,
            &mut Cursor::new(plaintext.as_slice()),
            &mut encrypted,
        )
        .unwrap_or_else(|error| panic!("{label}: encrypt v1 stream failed: {error}"));

        let mut decrypted = Vec::new();
        V1PayloadStream::decrypt_file(
            support::master_key(),
            &payload,
            &mut Cursor::new(encrypted),
            &mut decrypted,
        )
        .unwrap_or_else(|error| panic!("{label}: decrypt v1 stream failed: {error}"));

        assert_eq!(
            decrypted, plaintext,
            "{label}: file API roundtrip must preserve boundary payload"
        );
    }
}

#[test]
fn encrypt_file_fills_plaintext_block_before_finalizing_on_short_reads() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();

    let mut encrypted = Vec::new();
    let mut reader = ShortRead::new(Cursor::new(plaintext.as_slice()), 257);
    V1PayloadStream::encrypt_file(support::master_key(), &header, &mut reader, &mut encrypted)
        .expect("encrypt v1 stream from short-reading source");

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
fn stream_file_api_handles_short_output_writes_at_boundaries() {
    for (label, plaintext) in payload_boundary_cases() {
        let header = support::sample_v1_header();
        let payload = support::parsed_payload_for(&header);

        let mut encrypted = Vec::new();
        let mut plaintext_reader = ShortRead::new(Cursor::new(plaintext.as_slice()), 257);
        {
            let mut encrypted_writer = ShortWrite::new(&mut encrypted, 7);
            V1PayloadStream::encrypt_file(
                support::master_key(),
                &header,
                &mut plaintext_reader,
                &mut encrypted_writer,
            )
            .unwrap_or_else(|error| {
                panic!("{label}: encrypt with short output writes failed: {error}")
            });
        }

        let mut decrypted = Vec::new();
        let mut encrypted_reader = ShortRead::new(Cursor::new(encrypted.as_slice()), 11);
        {
            let mut decrypted_writer = ShortWrite::new(&mut decrypted, 5);
            V1PayloadStream::decrypt_file(
                support::master_key(),
                &payload,
                &mut encrypted_reader,
                &mut decrypted_writer,
            )
            .unwrap_or_else(|error| {
                panic!("{label}: decrypt with short output writes failed: {error}")
            });
        }

        assert_eq!(
            decrypted, plaintext,
            "{label}: short output writes must preserve boundary payload"
        );
    }
}

#[test]
fn decrypt_file_fills_ciphertext_block_before_finalizing_on_short_reads() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();

    let mut encrypted = Vec::new();
    V1PayloadStream::encrypt_file(
        support::master_key(),
        &header,
        &mut Cursor::new(plaintext.as_slice()),
        &mut encrypted,
    )
    .expect("encrypt v1 stream");

    let mut decrypted = Vec::new();
    let mut reader = ShortRead::new(Cursor::new(encrypted.as_slice()), 257);
    V1PayloadStream::decrypt_file(support::master_key(), &payload, &mut reader, &mut decrypted)
        .expect("decrypt v1 stream from short-reading source");

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
fn encrypting_writer_roundtrips_fragmented_writes() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();

    let mut writer = V1PayloadEncryptingWriter::new(support::master_key(), &header, Vec::new())
        .expect("create encrypting writer");
    for chunk in plaintext.chunks(257) {
        writer
            .write_all(chunk)
            .expect("write fragmented plaintext into encrypting writer");
    }
    let encrypted = writer.finish().expect("finish encrypting writer");

    let mut decrypted = Vec::new();
    V1PayloadStream::decrypt_file(
        support::master_key(),
        &payload,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    )
    .expect("decrypt writer output");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypting_writer_exact_block_payload_emits_final_marker() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = vec![0x5A; BLOCK_SIZE];

    let mut writer = V1PayloadEncryptingWriter::new(support::master_key(), &header, Vec::new())
        .expect("create encrypting writer");
    writer
        .write_all(&plaintext)
        .expect("write exact block plaintext");
    let encrypted = writer.finish().expect("finish encrypting writer");

    assert_eq!(
        encrypted.len(),
        BLOCK_SIZE + STREAM_TAG_LEN + STREAM_TAG_LEN
    );

    let mut decrypted = Vec::new();
    V1PayloadStream::decrypt_file(
        support::master_key(),
        &payload,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    )
    .expect("decrypt exact block writer output");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn dropping_encrypting_writer_without_finish_does_not_finalize_payload() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = vec![0x7B; BLOCK_SIZE];
    let mut encrypted = Vec::new();

    {
        let mut writer =
            V1PayloadEncryptingWriter::new(support::master_key(), &header, &mut encrypted)
                .expect("create encrypting writer");
        writer
            .write_all(&plaintext)
            .expect("write exact block plaintext");
    }

    let mut decrypted = Vec::new();
    let result = V1PayloadStream::decrypt_file(
        support::master_key(),
        &payload,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    );

    assert!(matches!(result, Err(StreamError::MissingFinalBlock)));
    assert_eq!(
        decrypted, plaintext,
        "dropped writer output is uncommitted scratch because finish was explicit"
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
    let wrong_aad_payload = support::parsed_payload_with_payload_metadata(&header, 0x02, 0x02);
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
fn decrypt_rejects_each_truncated_stream_chunk() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let original_chunks = encrypt_chunks(&header, &plaintext);
    let final_chunk_index = original_chunks.len() - 1;

    for chunk_index in 0..original_chunks.len() {
        let mut chunks = original_chunks.clone();
        chunks[chunk_index]
            .pop()
            .unwrap_or_else(|| panic!("chunk {chunk_index} should have at least one byte"));

        let (result, scratch) =
            decrypt_file_with(support::master_key(), &payload, flatten_chunks(&chunks));

        assert!(
            result.is_err(),
            "chunk {chunk_index}: truncated stream chunk must fail"
        );
        let expected_scratch_len = chunk_index.min(final_chunk_index) * BLOCK_SIZE;
        assert_eq!(
            scratch,
            plaintext[..expected_scratch_len],
            "chunk {chunk_index}: truncated stream output is only uncommitted scratch before the failed chunk"
        );
    }
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
fn decrypt_rejects_duplicated_chunk() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let mut chunks = encrypt_chunks(&header, &plaintext);
    let duplicated_normal_chunk = chunks[0].clone();
    chunks.insert(1, duplicated_normal_chunk);

    let (result, scratch) =
        decrypt_file_with(support::master_key(), &payload, flatten_chunks(&chunks));

    assert!(matches!(result, Err(StreamError::Authentication)));
    assert_eq!(
        scratch,
        plaintext[..BLOCK_SIZE],
        "duplicated non-final chunk failure may expose only uncommitted scratch before the duplicate"
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

#[test]
fn phase01_core_fixture_manifest_links_stream_assurance_rows() {
    let manifest: toml::Value =
        toml::from_str(FIXTURE_MANIFEST).expect("fixture manifest must parse as TOML");
    let fixtures = manifest
        .get("fixture")
        .and_then(|value| value.as_array())
        .expect("fixture manifest must expose [[fixture]] rows");
    let expected_rows = [
        ("phase01-stream-payload-boundary-matrix", "STRM-01"),
        ("phase01-stream-fragmented-io-short-output", "STRM-01"),
        ("phase01-stream-wrong-aad", "STRM-02"),
        ("phase01-stream-wrong-nonce", "STRM-02"),
        ("phase01-stream-wrong-key", "STRM-02"),
        ("phase01-stream-reordered-chunks", "STRM-02"),
        ("phase01-stream-duplicated-chunk", "STRM-02"),
        ("phase01-stream-truncated-chunks", "STRM-02"),
        ("phase01-stream-missing-final-block", "STRM-02"),
        ("phase01-stream-middle-tamper", "STRM-02"),
        ("phase01-stream-final-tamper", "STRM-02"),
        ("phase01-header-malformed-evidence", "ASSR-02"),
        ("phase01-keyslot-corruption-evidence", "ASSR-02"),
    ];

    for (row_id, requirement) in expected_rows {
        let row = fixtures
            .iter()
            .find(|fixture| fixture.get("id").and_then(|value| value.as_str()) == Some(row_id))
            .unwrap_or_else(|| panic!("fixture manifest must include Phase 01 row {row_id}"));

        for field in [
            "id",
            "group",
            "path",
            "purpose",
            "invariant",
            "requirement",
            "source",
            "expected",
            "owner_phase",
        ] {
            let value = row
                .get(field)
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| panic!("{row_id}: field {field} must be present"));
            assert!(
                !value.trim().is_empty(),
                "{row_id}: field {field} must not be empty"
            );
        }

        assert_eq!(
            row.get("requirement").and_then(|value| value.as_str()),
            Some(requirement),
            "{row_id}: requirement must link to {requirement}"
        );
        assert_eq!(
            row.get("owner_phase").and_then(|value| value.as_str()),
            Some("Phase 1"),
            "{row_id}: owner phase must remain Phase 1"
        );
    }
}

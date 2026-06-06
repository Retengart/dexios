#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::string_slice,
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::match_same_arms,
        clippy::items_after_statements,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_collect,
        clippy::manual_let_else,
        clippy::format_collect,
        clippy::case_sensitive_file_extension_comparisons,
        clippy::struct_excessive_bools,
        reason = "integration tests assert exact behavior and may panic on failure"
    )
)]
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt as HeaderSalt};
use dexios_core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use dexios_core::header::{ParsedHeader, ParsedV1Payload};
use dexios_core::kdf::Kdf;
use dexios_core::payload::{
    ArchiveBodyFrame, ArchiveBodyFrameHeader, ArchiveManifest, MANIFEST_MAGIC, MAX_BODY_FRAME_LEN,
    MAX_MANIFEST_ENTRY_COUNT, MAX_NORMALIZED_PATH_BYTES, ManifestEntry, ManifestFirstPayload,
    PayloadError, PayloadFramingProfile, PayloadKind,
};
use dexios_core::primitives::{BLOCK_SIZE, MasterKey};
use dexios_core::stream::{
    StreamError, V1FinalAuth, V1PayloadDecryptingReader, V1PayloadDecryptor,
    V1PayloadEncryptingWriter, V1PayloadEncryptor, V1PayloadStream,
};

const STREAM_TAG_LEN: usize = 16;
const FIXTURE_MANIFEST: &str = include_str!("testdata/fixture_manifest.toml");
const PHASE01_HEADER_MALFORMED_ROW_ID: &str = "phase01-header-malformed-evidence";

fn keyslot_nonce(bytes: [u8; 24]) -> KeyslotNonce {
    KeyslotNonce::try_from_slice(&bytes).expect("valid keyslot nonce")
}

fn payload_nonce(bytes: [u8; 20]) -> PayloadNonce {
    PayloadNonce::try_from_slice(&bytes).expect("valid payload nonce")
}

mod support {
    use super::*;

    pub(crate) fn sample_v1_header() -> V1Header {
        sample_v1_header_with_nonce_and_keyslot_count([7u8; 20], 1)
    }

    pub(crate) fn sample_v1_header_with_nonce_and_keyslot_count(
        payload_nonce_bytes: [u8; 20],
        keyslot_count: usize,
    ) -> V1Header {
        let keyslots = (0..keyslot_count)
            .map(|index| sample_keyslot(11 + index as u8))
            .collect();
        V1Header::new(
            payload_nonce(payload_nonce_bytes),
            V1Keyslots::try_from_vec(keyslots).expect("sample keyslot count"),
        )
        .expect("sample v1 header")
    }

    pub(crate) fn parsed_payload_for(header: &V1Header) -> ParsedV1Payload {
        let bytes = header.serialize().expect("serialize header");
        let ParsedHeader::V1(payload) =
            dexios_core::header::read_header(&mut Cursor::new(bytes)).expect("parse header");
        payload
    }

    pub(crate) fn parsed_payload_with_payload_metadata(
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

    pub(crate) fn master_key() -> MasterKey {
        MasterKey::new([31u8; 32])
    }

    fn sample_keyslot(seed: u8) -> V1Keyslot {
        V1Keyslot::new(
            Kdf::Argon2id,
            [seed; 48],
            keyslot_nonce([seed.wrapping_add(2); 24]),
            HeaderSalt::new([seed.wrapping_add(6); 16]),
        )
    }
}

fn read_uncommitted_exact<R: Read>(
    reader: &mut V1PayloadDecryptingReader<R>,
    mut buf: &mut [u8],
) -> Result<(), StreamError> {
    while !buf.is_empty() {
        let read = reader.read_uncommitted(buf)?;
        if read == 0 {
            return Err(StreamError::MissingFinalBlock);
        }
        let tmp = buf;
        buf = &mut tmp[read..];
    }
    Ok(())
}

fn read_uncommitted_to_end<R: Read>(
    reader: &mut V1PayloadDecryptingReader<R>,
    output: &mut Vec<u8>,
) -> Result<(), StreamError> {
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read_uncommitted(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        output.extend_from_slice(&buffer[..read]);
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

fn sample_manifest_first_payload() -> ManifestFirstPayload {
    let manifest = ArchiveManifest::new(vec![
        ManifestEntry::directory(b"docs".to_vec()).expect("directory entry"),
        ManifestEntry::file(b"docs/readme.txt".to_vec(), 5).expect("file entry"),
        ManifestEntry::file(b"data.bin".to_vec(), 3).expect("file entry"),
    ])
    .expect("manifest");
    let bodies = vec![
        ArchiveBodyFrame::new(1, b"hello".to_vec()).expect("first body"),
        ArchiveBodyFrame::new(2, b"bin".to_vec()).expect("second body"),
    ];
    ManifestFirstPayload::new(manifest, bodies).expect("manifest-first payload")
}

#[test]
fn archive_payload_debug_does_not_disclose_body_bytes() {
    let frame = ArchiveBodyFrame::new(0, b"secret-body-bytes".to_vec()).expect("body frame");
    let frame_debug = format!("{frame:?}");

    assert!(frame_debug.contains("body_len"));
    assert!(!frame_debug.contains("body:"));
    assert!(!frame_debug.contains("secret-body-bytes"));

    let manifest = ArchiveManifest::new(vec![
        ManifestEntry::file(b"secret.txt".to_vec(), frame.body_len()).expect("file entry"),
    ])
    .expect("manifest");
    let payload = ManifestFirstPayload::new(manifest, vec![frame]).expect("manifest-first payload");
    let payload_debug = format!("{payload:?}");

    assert!(payload_debug.contains("body_frame_count"));
    assert!(!payload_debug.contains("body_frames"));
    assert!(!payload_debug.contains("secret-body-bytes"));
}

fn decrypt_file_with(
    master_key: MasterKey,
    payload: &ParsedV1Payload,
    ciphertext: Vec<u8>,
) -> (Result<V1FinalAuth, StreamError>, Vec<u8>) {
    let mut scratch = Vec::new();
    let result = V1PayloadStream::decrypt_file_uncommitted(
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
    V1PayloadStream::decrypt_file_uncommitted(
        support::master_key(),
        &payload,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    )
    .expect("decrypt v1 stream");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn v1_decrypt_file_returns_v1_final_auth_receipt() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = b"final auth receipt proves successful stream completion";

    let mut encrypted = Vec::new();
    V1PayloadStream::encrypt_file(
        support::master_key(),
        &header,
        &mut Cursor::new(plaintext),
        &mut encrypted,
    )
    .expect("encrypt v1 stream");

    let mut decrypted = Vec::new();
    let _final_auth: V1FinalAuth = V1PayloadStream::decrypt_file_uncommitted(
        support::master_key(),
        &payload,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    )
    .expect("decrypt v1 stream returns final auth receipt");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypting_reader_returns_final_auth_only_after_authenticated_eof() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let ciphertext = flatten_chunks(&encrypt_chunks(&header, &plaintext));

    let mut reader =
        V1PayloadDecryptingReader::new(support::master_key(), &payload, Cursor::new(ciphertext))
            .expect("create decrypting reader");
    let mut prefix = [0u8; 31];
    read_uncommitted_exact(&mut reader, &mut prefix).expect("read plaintext prefix");

    let early_finish = reader
        .finish()
        .expect_err("final auth before EOF must fail");
    assert!(matches!(early_finish, StreamError::MissingFinalBlock));
}

#[test]
fn decrypting_reader_roundtrips_to_same_plaintext_as_file_api() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let ciphertext = flatten_chunks(&encrypt_chunks(&header, &plaintext));

    let mut reader = V1PayloadDecryptingReader::new(
        support::master_key(),
        &payload,
        ShortRead::new(Cursor::new(ciphertext), 257),
    )
    .expect("create decrypting reader");
    let mut decrypted = Vec::new();
    read_uncommitted_to_end(&mut reader, &mut decrypted).expect("read decrypting reader to EOF");
    let _final_auth: V1FinalAuth = reader.finish().expect("finish after authenticated EOF");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypting_reader_rejects_tampered_final_chunk_without_receipt() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = plaintext_spanning_normal_chunks();
    let mut chunks = encrypt_chunks(&header, &plaintext);
    chunks.last_mut().expect("final chunk")[0] ^= 0x11;
    let mut reader = V1PayloadDecryptingReader::new(
        support::master_key(),
        &payload,
        Cursor::new(flatten_chunks(&chunks)),
    )
    .expect("create decrypting reader");

    let mut scratch = Vec::new();
    assert!(matches!(
        read_uncommitted_to_end(&mut reader, &mut scratch)
            .expect_err("tampered final chunk must fail"),
        StreamError::FinalBlockAuthentication
    ));
}

#[test]
fn decrypting_reader_rejects_truncation_without_receipt() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let plaintext = exact_two_block_plaintext();
    let mut ciphertext = flatten_chunks(&encrypt_chunks(&header, &plaintext));
    ciphertext.pop().expect("ciphertext has a byte to truncate");
    let mut reader =
        V1PayloadDecryptingReader::new(support::master_key(), &payload, Cursor::new(ciphertext))
            .expect("create decrypting reader");

    let mut scratch = Vec::new();
    assert!(matches!(
        read_uncommitted_to_end(&mut reader, &mut scratch)
            .expect_err("truncated ciphertext must fail"),
        StreamError::TruncatedCiphertext
    ));
}

#[test]
fn manifest_first_frames_serialize_and_parse_deterministically() {
    let payload = sample_manifest_first_payload();
    let encoded = payload
        .serialize()
        .expect("serialize manifest-first payload");

    assert_eq!(&encoded[..4], &MANIFEST_MAGIC);
    assert!(
        encoded.windows(4).any(|window| window == b"DXAR"),
        "manifest-first bytes must carry the DXAR magic"
    );

    let parsed = ManifestFirstPayload::parse(&encoded).expect("parse manifest-first payload");
    assert_eq!(parsed, payload);
    assert_eq!(parsed.manifest().entries()[0].normalized_path(), b"docs");
    assert_eq!(parsed.body_frames()[0].body(), b"hello");
    assert_eq!(
        parsed.body_frames()[1].entry_index(),
        2,
        "manifest-first body frames remain tied to manifest entry indexes"
    );
}

#[test]
fn manifest_first_streaming_helpers_roundtrip_manifest_and_body_headers() {
    let payload = sample_manifest_first_payload();
    let mut manifest_bytes = Vec::new();
    payload
        .manifest()
        .write_to(&mut manifest_bytes)
        .expect("write manifest");

    let parsed_manifest =
        ArchiveManifest::read_from(&mut Cursor::new(&manifest_bytes)).expect("read manifest");
    assert_eq!(&parsed_manifest, payload.manifest());

    let frame_header = ArchiveBodyFrameHeader::new(1, 5).expect("bounded body frame header");
    let mut frame_bytes = Vec::new();
    frame_header
        .write_to(&mut frame_bytes)
        .expect("write body frame header");
    let parsed_header =
        ArchiveBodyFrameHeader::read_from(&mut Cursor::new(frame_bytes)).expect("read header");

    assert_eq!(parsed_header.entry_index(), 1);
    assert_eq!(parsed_header.body_len(), 5);
}

#[test]
fn manifest_first_streaming_helpers_reject_invalid_body_magic_and_limits() {
    let mut invalid_magic = Vec::new();
    invalid_magic.extend_from_slice(b"BAD!");
    invalid_magic.extend_from_slice(&0u32.to_le_bytes());
    invalid_magic.extend_from_slice(&0u64.to_le_bytes());

    let error = ArchiveBodyFrameHeader::read_from(&mut Cursor::new(invalid_magic))
        .expect_err("invalid body frame magic must fail");
    assert!(matches!(error, PayloadError::InvalidBodyFrameMagic(_)));

    let error = ArchiveBodyFrameHeader::new(0, MAX_BODY_FRAME_LEN + 1)
        .expect_err("over-limit body frame header must fail");
    assert!(matches!(error, PayloadError::BodyFrameLimitExceeded { .. }));
}

#[test]
fn manifest_first_rejects_malformed_lengths() {
    let payload = sample_manifest_first_payload();
    let mut encoded = payload
        .serialize()
        .expect("serialize manifest-first payload");
    let body_frame_offset = encoded
        .windows(4)
        .position(|window| window == b"DXBF")
        .expect("body frame magic");
    let body_len_start = body_frame_offset + 8;
    encoded[body_len_start..body_len_start + 8].copy_from_slice(&6u64.to_le_bytes());

    let error = ManifestFirstPayload::parse(&encoded)
        .expect_err("body frame length must match manifest entry length");
    assert!(matches!(
        error,
        PayloadError::BodyFrameLengthMismatch {
            expected: 5,
            actual: 6
        }
    ));
}

#[test]
fn manifest_first_rejects_unsupported_payload_kind_and_framing_profile() {
    assert_eq!(
        PayloadKind::ManifestArchive.to_byte(),
        0x02,
        "ManifestArchive payload kind byte is canonical"
    );
    assert_eq!(
        PayloadFramingProfile::ManifestFirst.to_byte(),
        0x02,
        "ManifestFirst payload framing byte is canonical"
    );
    assert!(matches!(
        PayloadKind::try_from_byte(0xFE),
        Err(PayloadError::UnsupportedPayloadKind(0xFE))
    ));
    assert!(matches!(
        PayloadFramingProfile::try_from_byte(0xFD),
        Err(PayloadError::UnsupportedPayloadFramingProfile(0xFD))
    ));
}

#[test]
fn manifest_first_rejects_over_limit_entry_count_path_and_body() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&MANIFEST_MAGIC);
    encoded.extend_from_slice(&1u16.to_le_bytes());
    encoded.extend_from_slice(&(MAX_MANIFEST_ENTRY_COUNT + 1).to_le_bytes());

    let error = ManifestFirstPayload::parse(&encoded)
        .expect_err("over-limit manifest entry count must fail before allocation");
    assert!(matches!(
        error,
        PayloadError::ManifestEntryCountLimitExceeded { .. }
    ));

    let over_limit_path = vec![b'a'; MAX_NORMALIZED_PATH_BYTES + 1];
    let error = ManifestEntry::file(over_limit_path, 0)
        .expect_err("over-limit normalized path bytes must fail");
    assert!(matches!(
        error,
        PayloadError::NormalizedPathLimitExceeded { .. }
    ));

    let error = ManifestEntry::file(b"too-large.bin".to_vec(), MAX_BODY_FRAME_LEN + 1)
        .expect_err("over-limit body frame length must fail");
    assert!(matches!(error, PayloadError::BodyFrameLimitExceeded { .. }));
}

#[test]
fn manifest_first_requires_ordered_body_frames_to_match_manifest_entries() {
    let manifest = ArchiveManifest::new(vec![
        ManifestEntry::file(b"first.bin".to_vec(), 1).expect("first file"),
        ManifestEntry::file(b"second.bin".to_vec(), 1).expect("second file"),
    ])
    .expect("manifest");
    let payload = ManifestFirstPayload::new(
        manifest,
        vec![
            ArchiveBodyFrame::new(0, b"a".to_vec()).expect("first body"),
            ArchiveBodyFrame::new(1, b"b".to_vec()).expect("second body"),
        ],
    )
    .expect("manifest-first payload");
    let mut encoded = payload
        .serialize()
        .expect("serialize manifest-first payload");
    let first_frame_offset = encoded
        .windows(4)
        .position(|window| window == b"DXBF")
        .expect("first body frame");
    encoded[first_frame_offset + 4..first_frame_offset + 8].copy_from_slice(&1u32.to_le_bytes());

    let error = ManifestFirstPayload::parse(&encoded)
        .expect_err("ordered body frames must match manifest entry order");
    assert!(matches!(
        error,
        PayloadError::BodyFrameOrderMismatch {
            expected: 0,
            actual: 1
        }
    ));
}

#[test]
fn manifest_first_core_module_keeps_archive_framing_free_of_zip_surface() {
    let payload_source = include_str!("../src/payload.rs");

    for forbidden in ["zip::", "ZipArchive", "ZipWriter", "CompressionMethod"] {
        assert!(
            !payload_source.contains(forbidden),
            "core manifest-first payload framing must not expose {forbidden}"
        );
    }
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
        V1PayloadStream::decrypt_file_uncommitted(
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
    V1PayloadStream::decrypt_file_uncommitted(
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
            V1PayloadStream::decrypt_file_uncommitted(
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
    V1PayloadStream::decrypt_file_uncommitted(
        support::master_key(),
        &payload,
        &mut reader,
        &mut decrypted,
    )
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
fn segment_api_rejects_ambiguous_flat_file_chunk_sizes() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let exact_block = vec![0xA5; BLOCK_SIZE];

    let mut encryptor =
        V1PayloadEncryptor::new(support::master_key(), &header).expect("create encryptor");
    assert!(matches!(
        encryptor.encrypt_next(&exact_block[..BLOCK_SIZE - 1]),
        Err(StreamError::InvalidChunkSize(len)) if len == BLOCK_SIZE - 1
    ));

    let mut encryptor =
        V1PayloadEncryptor::new(support::master_key(), &header).expect("create encryptor");
    let normal_chunk = encryptor
        .encrypt_next(&exact_block)
        .expect("encrypt exact normal chunk");
    assert!(matches!(
        encryptor.encrypt_last(&exact_block),
        Err(StreamError::InvalidChunkSize(len)) if len == BLOCK_SIZE
    ));

    let mut decryptor =
        V1PayloadDecryptor::new(support::master_key(), &payload).expect("create decryptor");
    assert!(matches!(
        decryptor.decrypt_next(&normal_chunk[..normal_chunk.len() - 1]),
        Err(StreamError::InvalidChunkSize(len)) if len == BLOCK_SIZE + STREAM_TAG_LEN - 1
    ));

    let decryptor =
        V1PayloadDecryptor::new(support::master_key(), &payload).expect("create decryptor");
    assert!(matches!(
        decryptor.decrypt_last(&normal_chunk),
        Err(StreamError::InvalidChunkSize(len)) if len == BLOCK_SIZE + STREAM_TAG_LEN
    ));
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
    V1PayloadStream::decrypt_file_uncommitted(
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
    V1PayloadStream::decrypt_file_uncommitted(
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
    let result = V1PayloadStream::decrypt_file_uncommitted(
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
    let result = V1PayloadStream::decrypt_file_uncommitted(
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
    validate_phase01_fixture_manifest(FIXTURE_MANIFEST);
}

#[test]
fn phase01_fixture_manifest_validation_rejects_missing_test_target() {
    let manifest = FIXTURE_MANIFEST.replace(
        "retired_current_v1_malformed_reserved_byte_is_rejection_evidence",
        "missing_retired_layout_evidence",
    );

    assert_phase01_manifest_validation_fails(
        &manifest,
        "phase01-header-malformed-evidence: evidence target missing_retired_layout_evidence",
    );
}

#[test]
fn phase01_fixture_manifest_validation_rejects_prefix_only_test_target() {
    let manifest = FIXTURE_MANIFEST.replace(
        "retired_current_v1_malformed_reserved_byte_is_rejection_evidence",
        "retired_current_v1_malformed_reserved_byte_is_rejection",
    );

    assert_phase01_manifest_validation_fails(
        &manifest,
        "phase01-header-malformed-evidence: evidence target retired_current_v1_malformed_reserved_byte_is_rejection",
    );
}

#[test]
fn phase01_fixture_manifest_validation_rejects_missing_retired_fixture() {
    let manifest = FIXTURE_MANIFEST.replace(
        "v1_malformed_reserved_byte.hex",
        "v1_missing_reserved_byte.hex",
    );

    assert_phase01_manifest_validation_fails(
        &manifest,
        "phase01-header-malformed-evidence: source must reference v1_malformed_reserved_byte.hex",
    );
}

#[test]
fn phase01_fixture_manifest_validation_rejects_stale_retired_layout_expectation() {
    let manifest = FIXTURE_MANIFEST.replace(
        "HeaderReadError::RetiredV1Layout",
        "HeaderReadError::NonZeroReservedBytes",
    );

    assert_phase01_manifest_validation_fails(
        &manifest,
        "phase01-header-malformed-evidence: expected diagnostic must name HeaderReadError::RetiredV1Layout",
    );
}

fn validate_phase01_fixture_manifest(manifest_src: &str) {
    let manifest: toml::Value =
        toml::from_str(manifest_src).expect("fixture manifest must parse as TOML");
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

        validate_phase01_fixture_manifest_evidence(row, row_id);
    }
}

fn fixture_manifest_field<'a>(row: &'a toml::Value, row_id: &str, field: &str) -> &'a str {
    row.get(field)
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("{row_id}: field {field} must be present"))
}

fn validate_phase01_fixture_manifest_evidence(row: &toml::Value, row_id: &str) {
    let path = fixture_manifest_field(row, row_id, "path");
    assert_manifest_evidence_path_resolves(row_id, path);

    if row_id == PHASE01_HEADER_MALFORMED_ROW_ID {
        let source = fixture_manifest_field(row, row_id, "source");
        assert!(
            source.contains("v1_malformed_reserved_byte.hex"),
            "{row_id}: source must reference v1_malformed_reserved_byte.hex"
        );
        assert!(
            workspace_root()
                .join("dexios-core/tests/testdata/v1_malformed_reserved_byte.hex")
                .is_file(),
            "{row_id}: referenced fixture dexios-core/tests/testdata/v1_malformed_reserved_byte.hex must exist"
        );

        let expected = fixture_manifest_field(row, row_id, "expected");
        assert!(
            expected.contains("HeaderReadError::RetiredV1Layout"),
            "{row_id}: expected diagnostic must name HeaderReadError::RetiredV1Layout"
        );
        assert!(
            !expected.contains("HeaderReadError::NonZeroReservedBytes"),
            "{row_id}: expected diagnostic must not name stale HeaderReadError::NonZeroReservedBytes"
        );
    }
}

fn assert_manifest_evidence_path_resolves(row_id: &str, manifest_path: &str) {
    let (file_path, target) = manifest_path
        .split_once("::")
        .map_or((manifest_path, None), |(file_path, target)| {
            (file_path, Some(target))
        });
    let evidence_path = workspace_root().join(file_path);

    assert!(
        evidence_path.is_file(),
        "{row_id}: evidence path {file_path} must resolve to a checked-in file"
    );

    if let Some(target) = target {
        let file_source = std::fs::read_to_string(&evidence_path).unwrap_or_else(|error| {
            panic!("{row_id}: evidence path {file_path} unreadable: {error}")
        });
        assert!(
            rust_function_target_exists(&file_source, target),
            "{row_id}: evidence target {target} must exist in {file_path}"
        );
    }
}

fn rust_function_target_exists(file_source: &str, target: &str) -> bool {
    file_source.contains(&format!("fn {target}(")) || file_source.contains(&format!("fn {target}<"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dexios-core crate must have a workspace root")
        .to_path_buf()
}

fn assert_phase01_manifest_validation_fails(manifest_src: &str, expected_message: &str) {
    let result = std::panic::catch_unwind(|| validate_phase01_fixture_manifest(manifest_src));
    let Err(panic_payload) = result else {
        panic!("expected validation failure containing {expected_message}");
    };
    let panic_message = panic_payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic_payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic>");

    assert!(
        panic_message.contains(expected_message),
        "unexpected validation panic: {panic_message}"
    );
}

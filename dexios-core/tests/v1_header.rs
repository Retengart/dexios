use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt};
use dexios_core::header::v1::{KeyslotKdf, V1Header, V1Keyslot};

mod support {
    use super::*;

    pub fn sample_v1_header() -> V1Header {
        V1Header::new(
            PayloadNonce::new([7u8; 20]),
            vec![V1Keyslot::new(
                KeyslotKdf::Blake3Balloon,
                [11u8; 48],
                KeyslotNonce::new([13u8; 24]),
                Salt::new([17u8; 16]),
            )],
        )
        .expect("sample v1 header")
    }
}

#[test]
fn serializes_v1_header_to_416_bytes() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    assert_eq!(bytes.len(), 416);
}

#[test]
fn deserialize_roundtrip_preserves_payload_nonce_and_keyslots() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();
    let (parsed, aad) = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes)).unwrap();

    let dexios_core::header::ParsedHeader::V1(parsed) = parsed;
    assert_eq!(
        parsed.payload_nonce().as_bytes(),
        header.payload_nonce().as_bytes()
    );
    assert_eq!(parsed.keyslots().len(), 1);
    assert_eq!(aad.as_bytes().len(), 32);
}

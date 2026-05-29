// Source-level guard: the master-key wrap helper must stay crate-private so external
// callers cannot supply a reused keyslot nonce (crypto-3). The public, contract-bearing
// wrap/unwrap API lives in dexios-core (crypto-2).
const KEY_RS: &str = include_str!("../src/key.rs");

#[test]
fn encrypt_master_key_is_crate_private() {
    assert!(
        KEY_RS.contains("pub(crate) fn encrypt_master_key("),
        "encrypt_master_key must be pub(crate), never bare pub"
    );
    assert!(
        !KEY_RS.contains("\npub fn encrypt_master_key("),
        "encrypt_master_key must not be a bare pub fn"
    );
}

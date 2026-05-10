// TODO(pleshevskiy): dedup these utils

use std::fmt::Write as _;

#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
pub use test::gen_master_key;
#[cfg(test)]
pub use test::gen_salt;

#[cfg(not(test))]
pub use core::primitives::gen_master_key;
#[cfg(not(test))]
pub use core::primitives::gen_salt;

#[cfg(test)]
mod test {
    use core::primitives::{MASTER_KEY_LEN, MasterKey, SALT_LEN};
    use rand::{Rng, SeedableRng, rngs::StdRng};

    const SALT_SEED: u64 = 123_456;
    const MASTER_KEY_SEED: u64 = SALT_SEED + 1;

    #[must_use]
    pub fn gen_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        StdRng::seed_from_u64(SALT_SEED).fill_bytes(&mut salt);
        salt
    }

    #[must_use]
    pub fn gen_master_key() -> MasterKey {
        let mut master_key = [0u8; MASTER_KEY_LEN];
        StdRng::seed_from_u64(MASTER_KEY_SEED).fill_bytes(&mut master_key);
        MasterKey::new(master_key)
    }
}

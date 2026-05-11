use core::kdf::Kdf;

use crate::global::states::{ForceMode, HashMode};

use super::states::{DeleteInput, DeleteSource, DirectoryMode, HeaderLocation, Key, PrintMode};

pub struct CryptoParams {
    pub hash_mode: HashMode,
    pub force: ForceMode,
    pub delete_input: DeleteInput,
    pub key: Key,
    pub header_location: HeaderLocation,
    pub kdf: Kdf,
}

#[allow(dead_code)]
pub struct PackParams {
    pub dir_mode: DirectoryMode,
    pub print_mode: PrintMode,
    pub delete_source: DeleteSource,
}

pub struct KeyManipulationParams {
    pub key_old: Key,
    pub key_new: Key,
    pub kdf: Kdf,
}

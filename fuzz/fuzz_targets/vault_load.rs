#![no_main]

use libfuzzer_sys::fuzz_target;
use std::fs;
use std::path::PathBuf;

use your_crate::storage::Vault;

fuzz_target!(|data: &[u8]| {
    let path = PathBuf::from("/tmp/fuzz_vault");

    let _ = fs::write(&path, data);

    let _ = Vault::load(&path);
});

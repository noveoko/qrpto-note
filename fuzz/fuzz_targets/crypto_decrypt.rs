#![no_main]

use libfuzzer_sys::fuzz_target;
use your_crate::crypto::CryptoEngine;
use your_crate::secure_buf::SecureBuffer;

fuzz_target!(|data: (Vec<u8>, [u8;12])| {

    let key = [0u8;32];
    let engine = CryptoEngine::from_key(&key);

    let (ciphertext, nonce) = data;

    let mut buf = SecureBuffer::new();

    let _ = engine.decrypt_into(&ciphertext, &nonce, &mut buf);
});

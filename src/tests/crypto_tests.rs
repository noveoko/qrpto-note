#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_buf::SecureBuffer;

    fn setup_engine() -> CryptoEngine {
        let key = [42u8; 32];
        CryptoEngine::from_key(&key)
    }

    // ─────────────────────────────────────────────────────────────
    // Round-trip: encrypt then decrypt returns original plaintext
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn round_trip_encrypt_decrypt() {
        let engine = setup_engine();
        let plaintext = b"correct horse battery staple";

        let (ciphertext, nonce) = engine.encrypt(plaintext).expect("TODO: verify this is safe");

        let mut buf = SecureBuffer::new();
        engine.decrypt_into(&ciphertext, &nonce, &mut buf).expect("TODO: verify this is safe");

        assert_eq!(&buf[..plaintext.len()], plaintext);
    }

    // ─────────────────────────────────────────────────────────────
    // Wrong key: authentication should fail
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn decrypt_with_wrong_key_fails() {
        let engine1 = setup_engine();
        let plaintext = b"top secret";

        let (ciphertext, nonce) = engine1.encrypt(plaintext).expect("TODO: verify this is safe");

        let wrong_key = [99u8; 32];
        let engine2 = CryptoEngine::from_key(&wrong_key);

        let mut buf = SecureBuffer::new();
        let result = engine2.decrypt_into(&ciphertext, &nonce, &mut buf);

        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────
    // Tampered ciphertext: flipping one byte must fail
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn tampered_ciphertext_fails() {
        let engine = setup_engine();
        let plaintext = b"attack at dawn";

        let (mut ciphertext, nonce) = engine.encrypt(plaintext).expect("TODO: verify this is safe");

        ciphertext[0] ^= 0x01;

        let mut buf = SecureBuffer::new();
        let result = engine.decrypt_into(&ciphertext, &nonce, &mut buf);

        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────
    // Nonce uniqueness
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn nonce_uniqueness() {
        let engine = setup_engine();
        let plaintext = b"same plaintext";

        let (_, nonce1) = engine.encrypt(plaintext).expect("TODO: verify this is safe");
        let (_, nonce2) = engine.encrypt(plaintext).expect("TODO: verify this is safe");

        assert_ne!(nonce1, nonce2);
    }

    // ─────────────────────────────────────────────────────────────
    // Empty plaintext round-trip
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn empty_plaintext_round_trip() {
        let engine = setup_engine();

        let (ciphertext, nonce) = engine.encrypt(b"").expect("TODO: verify this is safe");

        let mut buf = SecureBuffer::new();
        engine.decrypt_into(&ciphertext, &nonce, &mut buf).expect("TODO: verify this is safe");

        assert_eq!(buf.len, 0);
    }

    // ─────────────────────────────────────────────────────────────
    // Additional tests worth having
    // ─────────────────────────────────────────────────────────────

    // Tampered nonce must fail authentication
    #[test]
    fn tampered_nonce_fails() {
        let engine = setup_engine();
        let plaintext = b"nonce test";

        let (ciphertext, mut nonce) = engine.encrypt(plaintext).expect("TODO: verify this is safe");
        nonce[0] ^= 0xFF;

        let mut buf = SecureBuffer::new();
        let result = engine.decrypt_into(&ciphertext, &nonce, &mut buf);

        assert!(result.is_err());
    }

    // Ciphertext must differ even with same plaintext (due to nonce)
    #[test]
    fn ciphertext_differs_for_same_plaintext() {
        let engine = setup_engine();
        let plaintext = b"identical input";

        let (ct1, _) = engine.encrypt(plaintext).expect("TODO: verify this is safe");
        let (ct2, _) = engine.encrypt(plaintext).expect("TODO: verify this is safe");

        assert_ne!(ct1, ct2);
    }

    // Large plaintext (near buffer capacity)
    #[test]
    fn large_plaintext_round_trip() {
        let engine = setup_engine();

        let plaintext = vec![7u8; 3000];

        let (ciphertext, nonce) = engine.encrypt(&plaintext).expect("TODO: verify this is safe");

        let mut buf = SecureBuffer::new();
        engine.decrypt_into(&ciphertext, &nonce, &mut buf).expect("TODO: verify this is safe");

        assert_eq!(&buf[..plaintext.len()], &plaintext[..]);
    }

    // Ciphertext exceeding buffer should error
    #[test]
    fn decrypt_rejects_oversized_ciphertext() {
        let engine = setup_engine();

        let huge = vec![1u8; 10_000];
        let nonce = [0u8; 12];

        let mut buf = SecureBuffer::new();
        let result = engine.decrypt_into(&huge, &nonce, &mut buf);

        assert!(result.is_err());
    }
}

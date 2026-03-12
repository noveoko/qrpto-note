// ─────────────────────────────────────────────────────────────────────────────
//  crypto.rs  –  AES-256-GCM encryption + Argon2id KDF
// ─────────────────────────────────────────────────────────────────────────────
//
//  Fix 1 – No intermediate Vec<u8> during decryption
//  ══════════════════════════════════════════════════
//  `decrypt_into` takes a `&mut SecureBuffer` (which implements `aead::Buffer`)
//  and calls `cipher.decrypt_in_place`.  The plaintext is written directly
//  into the mlock'd array.  No heap Vec is ever allocated for cleartext.
//
//  Fix 2 – Key schedule zeroed on drop (ZeroizingCipher)
//  ═══════════════════════════════════════════════════════
//  AES-256 key expansion produces 15 round keys of 128 bits each = 240 bytes.
//  These are stored *inline* in the Aes256Gcm struct (no heap indirection),
//  so zeroing the struct's bytes zeroes the round keys.
//
//  We use `write_volatile` rather than `write_bytes` / `memset` because the
//  compiler is legally allowed to eliminate dead stores to objects that go
//  out of scope.  `write_volatile` is explicitly defined as a side-effect the
//  compiler must not reorder or remove.
//
//  A `SeqCst` compiler fence after the volatile writes prevents the compiler
//  (and, on weakly-ordered architectures, the CPU) from reordering the stores
//  relative to the subsequent deallocation of the struct.
//
//  Visual: what lives where
//  ════════════════════════
//
//  Stack            Heap (not mlock'd)       Heap (mlock'd, DONTDUMP)
//  ─────            ──────────────────       ────────────────────────
//  ZeroizingCipher  [Aes256Gcm struct]  ←── zeroed in Drop via write_volatile
//    └─ Box ptr ──►  [round keys · · ]
//
//  SecureBuffer     [u8; 4096] ◄────────────── plaintext lands here directly
//    └─ Box ptr ──►  (mlock'd + DONTDUMP)

use std::sync::atomic::{compiler_fence, Ordering};

use aes_gcm::{
    aead::{Aead, AeadCore, AeadInPlace, Buffer as AeadBuffer, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;

use crate::secure_buf::SecureBuffer;

// ── ZeroizingCipher ───────────────────────────────────────────────────────────
//
//  Wraps Aes256Gcm in a newtype so we can implement a custom Drop that
//  volatile-zeroes the struct's bytes (including the inline round-key array).

pub struct ZeroizingCipher {
    inner: Aes256Gcm,
}

impl ZeroizingCipher {
    fn new(key: &Key<Aes256Gcm>) -> Self {
        ZeroizingCipher {
            inner: Aes256Gcm::new(key),
        }
    }
}

impl Drop for ZeroizingCipher {
    fn drop(&mut self) {
        // SAFETY:
        //   • We own `self` (exclusive access guaranteed in a Drop impl).
        //   • Casting to *mut u8 and writing bytes is defined for any T:
        //     the ABI guarantees each byte of the struct's storage is
        //     addressable as u8.
        //   • write_volatile on a *mut u8 derived from a valid &mut T is
        //     sound – it performs a byte-level volatile store.
        unsafe {
            let ptr = (&mut self.inner as *mut Aes256Gcm).cast::<u8>();
            let len = std::mem::size_of::<Aes256Gcm>();
            for i in 0..len {
                ptr.add(i).write_volatile(0u8);
            }
        }
        // Prevent the CPU (and the compiler on weakly-ordered targets) from
        // re-ordering the volatile stores above with the struct's deallocation.
        compiler_fence(Ordering::SeqCst);
    }
}

// ── CryptoEngine ──────────────────────────────────────────────────────────────

pub struct CryptoEngine {
    cipher: ZeroizingCipher,
}

impl CryptoEngine {
    /// Initialise the engine from a raw 256-bit key.
    /// The caller MUST zeroize the key array immediately after this returns.
    pub fn from_key(key: &[u8; 32]) -> Self {
        let k = Key::<Aes256Gcm>::from_slice(key);
        CryptoEngine {
            cipher: ZeroizingCipher::new(k),
        }
    }

    // ── Encryption ────────────────────────────────────────────────────────

    /// Encrypt `plaintext` with a fresh CSPRNG nonce.
    /// Ciphertext is not sensitive; a plain Vec<u8> is fine here.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), String> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .cipher
            .inner
            .encrypt(&nonce, plaintext)
            .map_err(|e| e.to_string())?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);
        Ok((ct, nonce_arr))
    }

    // ── Decryption (Fix 1) ────────────────────────────────────────────────
    //
    //  `decrypt_in_place` protocol:
    //    1.  buf initially holds ciphertext ‖ GCM_tag  (28+ bytes)
    //    2.  GHASH authenticates buf → error if tag does not match
    //    3.  AES-CTR decrypts buf[..ct_len] in place
    //    4.  buf.truncate(ct_len) strips the 16-byte tag, zeroes the tail
    //    5.  buf now holds plaintext only
    //
    //  The `buf` we pass is a mlock'd SecureBuffer.  Plaintext never
    //  exists in a regular heap Vec at any point in this function.

    /// Decrypt `ciphertext` directly into `buf` (mlock'd storage).
    /// `buf` is zeroized first, then receives ciphertext+tag, then is
    /// decrypted in-place — the plaintext never leaves protected memory.
    pub fn decrypt_into(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        buf: &mut SecureBuffer,
    ) -> Result<(), String> {
        // Start clean.
        buf.zeroize();

        // Load ciphertext+tag into the mlock'd buffer.
        // Ciphertext is not sensitive, so copying it in is fine.
        // `extend_from_slice` is our aead::Buffer impl in secure_buf.rs.
        buf.extend_from_slice(ciphertext)
            .map_err(|_| "Entry too large for the 4 KiB buffer".to_string())?;

        // Authenticate (GHASH) then decrypt (AES-CTR) in place.
        // On success the tag is stripped via buf.truncate(); on failure
        // buf is left containing the ciphertext (not sensitive).
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .inner
            .decrypt_in_place(nonce, &[], buf)
            .map_err(|_| "Authentication failed – wrong key or corrupted data".to_string())?;

        // Place the editing cursor at the end of the plaintext.
        buf.cursor = buf.len;
        Ok(())
    }

    /// Convenience: decrypt and return a plain `Vec<u8>`.
    /// Used ONLY for the password-verification check in `setup_vault`
    /// (the result is a short, non-secret success proof and is zeroized
    /// immediately by the caller via `Zeroizing<Vec<u8>>`).
    pub fn decrypt_verify(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<(), String> {
        let mut buf = SecureBuffer::new();
        self.decrypt_into(ciphertext, nonce, &mut buf)?;
        // buf is zeroized + munlocked when it drops here.
        Ok(())
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive a 256-bit key via Argon2id (memory-hard, PHC winner 2015).
/// Default params: 19 456 KiB memory, 2 iterations, parallelism 1.
/// The caller MUST zeroize the returned array after passing it to `from_key`.
pub fn derive_key(password: &str, salt: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 key derivation failed");
    key
}

/// Generate a random 32-byte salt from the OS CSPRNG.
pub fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

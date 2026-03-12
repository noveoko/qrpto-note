// ─────────────────────────────────────────────────────────────────────────────
//  storage.rs  –  Vault file format (binary, little-endian)
// ─────────────────────────────────────────────────────────────────────────────
//
//  File layout
//  ═══════════
//  Offset  Size   Field
//  ──────  ─────  ──────────────────────────────────────────────────────────
//     0      4    Magic bytes  "SVT1"  (Qrpto:note vault, format version 1)
//     4     32    Argon2id salt  (random, one per vault, never changes)
//    36      4    Entry count  (u32 little-endian)
//    40      …    Entry records (repeated `count` times):
//                   12 bytes  AES-GCM nonce  (unique per encryption)
//                    4 bytes  Ciphertext length  (u32 LE, includes 16-byte tag)
//                    N bytes  Ciphertext  (= encrypted_plaintext ‖ GCM_tag)
//
//  The Argon2id salt is *not* secret; it is safe to store in plaintext.
//  Its only job is to ensure that two vaults with the same password produce
//  different keys, preventing cross-vault precomputation attacks.

use std::io;
use std::path::Path;

const MAGIC: &[u8; 4] = b"SVT1";

// ── Data types ────────────────────────────────────────────────────────────────

/// One encrypted line (nonce + ciphertext-with-tag).
#[derive(Clone, Debug)]
pub struct EncryptedLine {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// The full vault: salt + ordered list of encrypted lines.
pub struct Vault {
    pub salt: [u8; 32],
    pub lines: Vec<EncryptedLine>,
}

// ── Vault impl ────────────────────────────────────────────────────────────────

impl Vault {
    pub const fn new_empty(salt: [u8; 32]) -> Self {
        Self {
            salt,
            lines: Vec::new(),
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut buf: Vec<u8> = Vec::new();

        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(
            &u32::try_from(self.lines.len())
                .expect("Line count overflow")
                .to_le_bytes(),
        );

        for line in &self.lines {
            buf.extend_from_slice(&line.nonce);
            buf.extend_from_slice(
                &u32::try_from(line.ciphertext.len())
                    .expect("Ciphertext overflow")
                    .to_le_bytes(),
            );
            buf.extend_from_slice(&line.ciphertext);
        }

        std::fs::write(path, buf)
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        let mut p = 0usize; // read cursor

        // Magic
        if data.len() < 4 || &data[p..p + 4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not a Qrpto:note vault file (bad magic bytes)",
            ));
        }
        p += 4;

        // Salt
        if data.len() < p + 32 {
            return Err(short_file());
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[p..p + 32]);
        p += 32;

        // Entry count
        if data.len() < p + 4 {
            return Err(short_file());
        }
        let count = u32::from_le_bytes(
            data[p..p + 4]
                .try_into()
                .expect("TODO: verify this is safe"),
        ) as usize;
        p += 4;

        // Entries
        let mut lines = Vec::with_capacity(count);
        for i in 0..count {
            if data.len() < p + 12 + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Truncated entry header at index {i}"),
                ));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&data[p..p + 12]);
            p += 12;

            let ct_len = u32::from_le_bytes(
                data[p..p + 4]
                    .try_into()
                    .expect("TODO: verify this is safe"),
            ) as usize;
            p += 4;

            if data.len() < p + ct_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Truncated ciphertext at entry {i}"),
                ));
            }
            let ciphertext = data[p..p + ct_len].to_vec();
            p += ct_len;

            lines.push(EncryptedLine { nonce, ciphertext });
        }

        Ok(Self { salt, lines })
    }
}

fn short_file() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "File is too short to be a valid vault",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("TODO: verify this is safe")
            .as_nanos();
        p.push(format!("vault_test_{}_{}", name, ts));
        p
    }

    // ─────────────────────────────────────────────────────────────
    // Round-trip: save → load
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn vault_round_trip() {
        let path = temp_file("roundtrip");

        let salt = [7u8; 32];

        let mut vault = Vault::new_empty(salt);
        vault.lines.push(EncryptedLine {
            nonce: [1u8; 12],
            ciphertext: vec![10, 11, 12, 13],
        });

        vault.save(&path).expect("TODO: verify this is safe");

        let loaded = Vault::load(&path).expect("TODO: verify this is safe");

        assert_eq!(loaded.salt, salt);
        assert_eq!(loaded.lines.len(), 1);

        fs::remove_file(path).ok();
    }

    // ─────────────────────────────────────────────────────────────
    // Invalid magic
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn invalid_magic_fails() {
        let path = temp_file("bad_magic");

        fs::write(&path, b"XXXXbadvault").expect("TODO: verify this is safe");

        let result = Vault::load(&path);

        assert!(result.is_err());

        fs::remove_file(path).ok();
    }

    // ─────────────────────────────────────────────────────────────
    // Truncated file
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn truncated_file_rejected() {
        let path = temp_file("truncated");

        // valid magic but nothing else
        fs::write(&path, b"SVT1").expect("TODO: verify this is safe");

        let result = Vault::load(&path);

        assert!(result.is_err());

        fs::remove_file(path).ok();
    }

    // ─────────────────────────────────────────────────────────────
    // Large vault (1000 entries)
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn large_vault_round_trip() {
        let path = temp_file("large");

        let salt = [9u8; 32];
        let mut vault = Vault::new_empty(salt);

        for i in 0..1000 {
            vault.lines.push(EncryptedLine {
                nonce: [i as u8; 12],
                ciphertext: vec![i as u8; 32],
            });
        }

        vault.save(&path).expect("TODO: verify this is safe");

        let loaded = Vault::load(&path).expect("TODO: verify this is safe");

        assert_eq!(loaded.salt, salt);
        assert_eq!(loaded.lines.len(), 1000);

        for (i, line) in loaded.lines.iter().enumerate() {
            assert_eq!(line.nonce, [i as u8; 12]);
            assert_eq!(line.ciphertext, vec![i as u8; 32]);
        }

        fs::remove_file(path).ok();
    }

    // ─────────────────────────────────────────────────────────────
    // Extra useful tests
    // ─────────────────────────────────────────────────────────────

    // Entry header truncated
    #[test]
    fn truncated_entry_header_rejected() {
        let path = temp_file("entry_header");

        let mut data = Vec::new();
        data.extend_from_slice(b"SVT1");
        data.extend_from_slice(&[1u8; 32]); // salt
        data.extend_from_slice(&(1u32.to_le_bytes())); // count
        data.extend_from_slice(&[0u8; 5]); // incomplete header

        fs::write(&path, data).expect("TODO: verify this is safe");

        let result = Vault::load(&path);

        assert!(result.is_err());

        fs::remove_file(path).ok();
    }

    // Ciphertext truncated
    #[test]
    fn truncated_ciphertext_rejected() {
        let path = temp_file("ct_truncated");

        let mut data = Vec::new();
        data.extend_from_slice(b"SVT1");
        data.extend_from_slice(&[1u8; 32]); // salt
        data.extend_from_slice(&(1u32.to_le_bytes())); // count

        data.extend_from_slice(&[0u8; 12]); // nonce
        data.extend_from_slice(&(10u32.to_le_bytes())); // ciphertext len
        data.extend_from_slice(&[1u8; 3]); // truncated ciphertext

        fs::write(&path, data).expect("TODO: verify this is safe");

        let result = Vault::load(&path);

        assert!(result.is_err());

        fs::remove_file(path).ok();
    }

    // Zero-entry vault
    #[test]
    fn empty_vault_round_trip() {
        let path = temp_file("empty");

        let salt = [3u8; 32];
        let vault = Vault::new_empty(salt);

        vault.save(&path).expect("TODO: verify this is safe");

        let loaded = Vault::load(&path).expect("TODO: verify this is safe");

        assert_eq!(loaded.salt, salt);
        assert_eq!(loaded.lines.len(), 0);

        fs::remove_file(path).ok();
    }
}

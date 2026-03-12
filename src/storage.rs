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
    pub fn new_empty(salt: [u8; 32]) -> Self {
        Vault {
            salt,
            lines: Vec::new(),
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut buf: Vec<u8> = Vec::new();

        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&(self.lines.len() as u32).to_le_bytes());

        for line in &self.lines {
            buf.extend_from_slice(&line.nonce);
            buf.extend_from_slice(&(line.ciphertext.len() as u32).to_le_bytes());
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
        let count = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
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

            let ct_len = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
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

        Ok(Vault { salt, lines })
    }
}

fn short_file() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "File is too short to be a valid vault",
    )
}

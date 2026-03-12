// ─────────────────────────────────────────────────────────────────────────────
//  app.rs  –  Application state machine
// ─────────────────────────────────────────────────────────────────────────────
//
//  State transitions
//  ═════════════════
//
//         ┌──────────────────────────────────────────────┐
//         │                  LOCKED                      │
//         │  All lines displayed as ████████████         │
//         │  Cursor navigates freely                     │
//         └──────┬───────────────────────────────────────┘
//                │ [Space]  decrypt focused line into
//                │          transient SecureBuffer  (in-place, no Vec)
//                ▼
//         ┌──────────────────────────────────────────────┐
//         │                 REVEALED                     │
//         │  Focused line shown in cleartext (read-only) │
//         │  Transient buffer: mlock'd + DONTDUMP        │
//         └──────┬───────────────────────────────────────┘
//                │ [Enter]                         [↑↓ / Esc]
//                │ enter edit                       seal()
//                ▼                                 (zeroize → LOCKED)
//         ┌──────────────────────────────────────────────┐
//         │                  EDITING                     │
//         │  Focused line editable; cursor visible       │
//         └──────┬───────────────────────────────────────┘
//                │ [Esc]  re-encrypt → zeroize → LOCKED
//                └──────────────────────────────────────►
//
//  seal() is the single choke-point:
//    1. SecureBuffer::zeroize() – volatile-writes 0 over every byte.
//    2. drop(buf)               – munlock + DONTDUMP pages freed.
//    3. Mode → Locked.

use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::crypto::CryptoEngine;
use crate::secure_buf::{LockStatus, SecureBuffer};
use crate::storage::{EncryptedLine, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Locked,
    Revealed,
    Editing,
}

pub struct App {
    pub vault: Vault,
    pub cursor: usize,
    pub mode: Mode,
    /// Single transient cleartext buffer.  None in Locked mode.
    pub transient: Option<SecureBuffer>,
    pub status: String,
    pub path: PathBuf,
    /// Last observed lock status (shown in UI header).
    pub last_lock_status: Option<LockStatus>,
    crypto: CryptoEngine,
}

impl App {
    pub fn new(vault: Vault, crypto: CryptoEngine, path: PathBuf) -> Self {
        App {
            cursor: 0,
            mode: Mode::Locked,
            transient: None,
            status: String::from("Ready. [n] New  [Space] Reveal  [s] Save  [q] Quit"),
            last_lock_status: None,
            vault,
            path,
            crypto,
        }
    }

    // ── Navigation ────────────────────────────────────────────────────────

    pub fn move_up(&mut self) {
        self.seal();
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_down(&mut self) {
        self.seal();
        let last = self.vault.lines.len().saturating_sub(1);
        if self.cursor < last {
            self.cursor += 1;
        }
    }

    // ── Reveal / Edit lifecycle ───────────────────────────────────────────

    /// Decrypt the focused entry directly into a new SecureBuffer (Fix 1).
    /// No intermediate Vec<u8> is created; plaintext lands in mlock'd memory.
    pub fn reveal(&mut self) {
        if self.vault.lines.is_empty() {
            self.status = String::from("No entries. Press [n] to add one.");
            return;
        }
        self.seal();

        let line = &self.vault.lines[self.cursor];
        let mut buf = SecureBuffer::new();
        let ls = buf.lock_status;

        match self
            .crypto
            .decrypt_into(&line.ciphertext, &line.nonce, &mut buf)
        {
            Ok(()) => {
                self.last_lock_status = Some(ls);
                self.transient = Some(buf);
                self.mode = Mode::Revealed;
                self.status = if ls.fully_protected() {
                    String::from("Revealed. [Enter] edit  [Esc/↑↓] lock")
                } else {
                    format!(
                        "⚠ Revealed (pages {}{}). [Enter] edit  [Esc/↑↓] lock",
                        if ls.mlocked {
                            "mlock'd"
                        } else {
                            "NOT mlock'd – may swap!"
                        },
                        if !ls.dontdump {
                            " | core-dump NOT suppressed"
                        } else {
                            ""
                        },
                    )
                };
            }
            Err(e) => {
                // buf is dropped here → volatile-zeroed + munlock'd
                self.status = format!("Decryption failed: {e}");
            }
        }
    }

    pub fn begin_edit(&mut self) {
        if self.mode == Mode::Revealed {
            self.mode = Mode::Editing;
            self.status = String::from(
                "Editing. [Esc] save & lock  [←→] cursor  [Home/End]  [Del] fwd-delete",
            );
        }
    }

    /// Re-encrypt edited content, then seal.
    pub fn commit_edit(&mut self) {
        if self.mode != Mode::Editing {
            return;
        }

        // ── Step 1: snapshot plaintext into a Zeroizing<Vec<u8>>.
        //    Zeroizing overwrites the Vec's bytes when it drops, so this
        //    temporary copy is short-lived and self-cleaning.
        let snapshot: Option<Zeroizing<Vec<u8>>> = self
            .transient
            .as_ref()
            .map(|b| Zeroizing::new(b.as_str().as_bytes().to_vec()));

        // ── Step 2: seal NOW – zeroize mlock'd buffer before any further
        //    allocations that might interleave with the heap.
        self.seal();

        // ── Step 3: re-encrypt from the Zeroizing snapshot.
        if let Some(bytes) = snapshot {
            match self.crypto.encrypt(&bytes) {
                Ok((ct, nonce)) => {
                    if self.cursor < self.vault.lines.len() {
                        self.vault.lines[self.cursor] = EncryptedLine {
                            nonce,
                            ciphertext: ct,
                        };
                    }
                    self.status = String::from("Re-encrypted. [s] to save to disk.");
                }
                Err(e) => {
                    self.status = format!("Re-encryption failed: {e}");
                }
            }
            // `bytes` dropped here → Zeroizing zeroes the Vec backing store.
        }
    }

    pub fn discard(&mut self) {
        self.seal();
        self.status = String::from("Entry locked.");
    }

    // ── In-edit key handling ──────────────────────────────────────────────

    pub fn type_char(&mut self, ch: char) {
        if self.mode == Mode::Editing {
            if let Some(b) = &mut self.transient {
                b.insert_char(ch);
            }
        }
    }
    pub fn backspace(&mut self) {
        if self.mode == Mode::Editing {
            if let Some(b) = &mut self.transient {
                b.delete_before_cursor();
            }
        }
    }
    pub fn delete_fwd(&mut self) {
        if self.mode == Mode::Editing {
            if let Some(b) = &mut self.transient {
                b.delete_at_cursor();
            }
        }
    }
    pub fn cursor_left(&mut self) {
        if self.mode == Mode::Editing {
            if let Some(b) = &mut self.transient {
                b.move_left();
            }
        }
    }
    pub fn cursor_right(&mut self) {
        if self.mode == Mode::Editing {
            if let Some(b) = &mut self.transient {
                b.move_right();
            }
        }
    }
    pub fn cursor_home(&mut self) {
        if self.mode == Mode::Editing {
            if let Some(b) = &mut self.transient {
                b.move_home();
            }
        }
    }
    pub fn cursor_end(&mut self) {
        if self.mode == Mode::Editing {
            if let Some(b) = &mut self.transient {
                b.move_end();
            }
        }
    }

    // ── Vault-level ───────────────────────────────────────────────────────

    pub fn add_entry(&mut self) {
        match self.crypto.encrypt(b"") {
            Ok((ct, nonce)) => {
                self.vault.lines.push(EncryptedLine {
                    nonce,
                    ciphertext: ct,
                });
                self.cursor = self.vault.lines.len() - 1;
                self.status = String::from("New entry added. [Space] reveal, [Enter] edit.");
            }
            Err(e) => {
                self.status = format!("Failed to add entry: {e}");
            }
        }
    }

    pub fn delete_entry(&mut self) {
        if self.vault.lines.is_empty() {
            return;
        }
        self.seal();
        self.vault.lines.remove(self.cursor);
        if self.cursor > 0 && self.cursor >= self.vault.lines.len() {
            self.cursor -= 1;
        }
        self.status = String::from("Entry deleted.");
    }

    pub fn save(&mut self) {
        match self.vault.save(&self.path) {
            Ok(_) => self.status = String::from("Vault saved."),
            Err(e) => self.status = format!("Save failed: {e}"),
        }
    }

    pub fn clear_transient(&mut self) {
        self.seal();
    }

    // ── Internal ──────────────────────────────────────────────────────────

    /// Single choke-point: volatile-zeroize + munlock the transient, return
    /// to Locked.  Called before EVERY mode transition.
    fn seal(&mut self) {
        if let Some(mut buf) = self.transient.take() {
            buf.zeroize(); // volatile 0-fill
            drop(buf); // munlock + DONTDUMP pages freed
        }
        self.mode = Mode::Locked;
    }
}

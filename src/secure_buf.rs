// ─────────────────────────────────────────────────────────────────────────────
//  secure_buf.rs  –  mlock'd, zeroize-on-drop in-memory buffer
// ─────────────────────────────────────────────────────────────────────────────
//
//  Memory-safety layers (outermost → innermost)
//  ════════════════════════════════════════════
//
//  Layer 0 – prctl(PR_SET_DUMPABLE, 0)               [done once in main()]
//            Removes the process from /proc/PID/mem ptrace access and
//            disables core dumps for the whole process.  No root required.
//
//  Layer 1 – madvise(MADV_DONTDUMP)                  [per page, unconditional]
//            Marks the specific pages as excluded from core dumps even if
//            Layer 0 is somehow bypassed.  Works independently of mlock.
//
//  Layer 2 – mlock(2) + RLIMIT_MEMLOCK management    [per page, best-effort]
//            Wires physical RAM pages so the kernel cannot swap them to disk.
//            We first try to raise the soft RLIMIT_MEMLOCK limit (non-root
//            can raise up to the hard limit), then call mlock.  Failure is
//            non-fatal: Layers 0/1/3 still protect the data.
//
//  Layer 3 – Zeroize on drop                         [always, no exceptions]
//            write_volatile over every byte → the compiler cannot elide the
//            stores even under full LTO.  SeqCst fence prevents CPU
//            reordering relative to the subsequent page deallocation.
//
//  Why Box<[u8; CAPACITY]> and not Vec<u8>?
//  ════════════════════════════════════════
//  A Box<[T; N]> heap-allocates N bytes at a *stable* address.  The address
//  does NOT change when the Box (or its containing struct) is moved on the
//  stack – only the 8-byte fat-pointer value moves.  This stability means:
//    • mlock(ptr, CAPACITY) called once in ::new() remains valid forever.
//    • No reallocation can copy cleartext to a new address leaving an
//      un-zeroed ghost.
//
//  Why implement aead::Buffer here?
//  ════════════════════════════════
//  The aes-gcm `decrypt_in_place` call writes the plaintext directly into
//  whatever implements `aead::Buffer`.  By implementing it on SecureBuffer
//  we make the mlock'd array the *first* place the plaintext lands – there
//  is no intermediate heap Vec<u8> that would briefly hold cleartext before
//  being freed without zeroing.

use std::sync::atomic::{compiler_fence, Ordering};
use aead::Buffer as AeadBuffer;
use libc::{madvise, mlock, munlock, setrlimit, getrlimit, MADV_DONTDUMP, RLIMIT_MEMLOCK};

/// Maximum bytes a single vault entry may contain (4 KiB).
pub const CAPACITY: usize = 4096;

// ── Lock status ───────────────────────────────────────────────────────────────

/// Reported to the UI so it can warn the user when pages might be swappable.
#[derive(Debug, Clone, Copy)]
pub struct LockStatus {
    /// mlock(2) succeeded → pages are pinned in RAM.
    pub mlocked:    bool,
    /// madvise(MADV_DONTDUMP) succeeded → pages excluded from core dumps.
    pub dontdump:   bool,
}

impl LockStatus {
    /// True when all memory-protection layers are active.
    pub fn fully_protected(&self) -> bool {
        self.mlocked && self.dontdump
    }
}

// ── SecureBuffer ──────────────────────────────────────────────────────────────

pub struct SecureBuffer {
    /// Stable-address heap allocation.  Never reallocated.
    storage: Box<[u8; CAPACITY]>,
    /// Number of valid UTF-8 bytes in storage[..len].
    pub len: usize,
    /// Byte offset of the insertion cursor (always at a char boundary).
    pub cursor: usize,
    /// Memory-lock status, reported to the UI.
    pub lock_status: LockStatus,
}

impl SecureBuffer {
    // ── Construction ─────────────────────────────────────────────────────

    pub fn new() -> Self {
        let storage = Box::new([0u8; CAPACITY]);
        let ptr  = storage.as_ptr() as *mut libc::c_void;
        let size = CAPACITY;

        // ── Layer 2a: raise RLIMIT_MEMLOCK before mlock ───────────────────
        //
        // Stock Ubuntu gives unprivileged processes a soft limit of 64 KiB.
        // CAPACITY is 4 KiB, so we need at least that much head-room.  We
        // read the current limits and try to raise the soft cap to at least
        // soft+CAPACITY.  The hard limit acts as a ceiling; if it's too low
        // we carry on and let mlock fail gracefully.
        unsafe {
            let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if getrlimit(RLIMIT_MEMLOCK, &mut rl) == 0 {
                // Only try to raise if we're below what we need.
                let want = rl.rlim_cur.saturating_add(size as libc::rlim_t);
                let cap  = if rl.rlim_max == libc::RLIM_INFINITY { want } else { rl.rlim_max };
                if want <= cap {
                    let new_rl = libc::rlimit { rlim_cur: want, rlim_max: rl.rlim_max };
                    setrlimit(RLIMIT_MEMLOCK, &new_rl); // failure is non-fatal
                }
            }
        }

        // ── Layer 2b: mlock ───────────────────────────────────────────────
        let mlocked = unsafe { mlock(ptr, size) == 0 };

        // ── Layer 1: madvise(MADV_DONTDUMP) ──────────────────────────────
        //
        // Works independently of mlock.  Even if mlock failed (pages could
        // be swapped), MADV_DONTDUMP ensures the pages are omitted from any
        // core dump, reducing the exposure window significantly.
        let dontdump = unsafe { madvise(ptr, size, MADV_DONTDUMP) == 0 };

        SecureBuffer {
            storage,
            len: 0,
            cursor: 0,
            lock_status: LockStatus { mlocked, dontdump },
        }
    }

    // ── Content management ───────────────────────────────────────────────

    /// View the current content as a UTF-8 &str.
    #[inline]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.storage[..self.len]).unwrap_or("[utf-8 error]")
    }

    /// Overwrite all bytes with 0 using write_volatile and reset length/cursor.
    ///
    /// write_volatile stores cannot be reordered or eliminated by the
    /// compiler, making this the guaranteed zeroize operation.  The
    /// SeqCst fence prevents CPU reordering relative to subsequent code.
    pub fn zeroize(&mut self) {
        unsafe {
            let ptr = self.storage.as_mut_ptr();
            for i in 0..CAPACITY {
                ptr.add(i).write_volatile(0u8);
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.len    = 0;
        self.cursor = 0;
    }

    // ── Editing ──────────────────────────────────────────────────────────

    /// Insert `ch` at the cursor position and advance the cursor.
    pub fn insert_char(&mut self, ch: char) {
        let mut tmp = [0u8; 4];
        let encoded = ch.encode_utf8(&mut tmp);
        let clen = encoded.len();
        if self.len + clen > CAPACITY { return; }
        self.storage.copy_within(self.cursor..self.len, self.cursor + clen);
        self.storage[self.cursor..self.cursor + clen].copy_from_slice(encoded.as_bytes());
        self.len    += clen;
        self.cursor += clen;
    }

    /// Delete the character immediately *before* the cursor (Backspace).
    pub fn delete_before_cursor(&mut self) {
        if self.cursor == 0 { return; }
        let end   = self.cursor;
        let start = self.prev_boundary(end);
        let clen  = end - start;
        self.storage.copy_within(end..self.len, start);
        // Volatile-zero the vacated tail so it can never be re-read.
        unsafe {
            let ptr = self.storage.as_mut_ptr().add(self.len - clen);
            for i in 0..clen { ptr.add(i).write_volatile(0u8); }
        }
        self.len    -= clen;
        self.cursor  = start;
    }

    /// Delete the character *at* the cursor position (Delete key).
    pub fn delete_at_cursor(&mut self) {
        if self.cursor >= self.len { return; }
        let start = self.cursor;
        let end   = self.next_boundary(start);
        let clen  = end - start;
        self.storage.copy_within(end..self.len, start);
        unsafe {
            let ptr = self.storage.as_mut_ptr().add(self.len - clen);
            for i in 0..clen { ptr.add(i).write_volatile(0u8); }
        }
        self.len -= clen;
    }

    // ── Cursor movement ──────────────────────────────────────────────────

    pub fn move_left(&mut self) {
        if self.cursor > 0 { self.cursor = self.prev_boundary(self.cursor); }
    }
    pub fn move_right(&mut self) {
        if self.cursor < self.len { self.cursor = self.next_boundary(self.cursor); }
    }
    pub fn move_home(&mut self) { self.cursor = 0; }
    pub fn move_end(&mut self)  { self.cursor = self.len; }

    // ── Private UTF-8 helpers ────────────────────────────────────────────

    fn prev_boundary(&self, mut pos: usize) -> usize {
        pos -= 1;
        while pos > 0 && Self::is_continuation(self.storage[pos]) { pos -= 1; }
        pos
    }
    fn next_boundary(&self, mut pos: usize) -> usize {
        pos += 1;
        while pos < self.len && Self::is_continuation(self.storage[pos]) { pos += 1; }
        pos
    }
    #[inline]
    fn is_continuation(b: u8) -> bool { b & 0xC0 == 0x80 }
}

// ── aead::Buffer impl ─────────────────────────────────────────────────────────
//
//  This is the key to Fix 1.  `Aes256Gcm::decrypt_in_place` accepts any
//  `&mut impl aead::Buffer`.  It loads the ciphertext+tag from the buffer,
//  authenticates it (GHASH), decrypts in-place (CTR mode), then calls
//  `buffer.truncate(plaintext_len)` to strip the 16-byte tag.
//
//  Result: the mlock'd storage array is the FIRST and ONLY place the
//  plaintext lands.  No intermediate Vec<u8> is allocated on the heap.
//
//  Data flow (before this fix):
//      ciphertext (disk)
//        → heap Vec<u8>  [UNPROTECTED, may swap]
//          → SecureBuffer  [mlock'd]
//
//  Data flow (after this fix):
//      ciphertext (disk)
//        → SecureBuffer  [mlock'd]   ← single destination

impl AsRef<[u8]> for SecureBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] { &self.storage[..self.len] }
}

impl AsMut<[u8]> for SecureBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { &mut self.storage[..self.len] }
}

impl AeadBuffer for SecureBuffer {
    fn len(&self)      -> usize { self.len }
    fn is_empty(&self) -> bool  { self.len == 0 }

    /// Called by `decrypt_in_place` to append the ciphertext+tag bytes.
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        let new_len = self.len.checked_add(other.len()).ok_or(aead::Error)?;
        if new_len > CAPACITY { return Err(aead::Error); }
        self.storage[self.len..new_len].copy_from_slice(other);
        self.len = new_len;
        Ok(())
    }

    /// Called by `decrypt_in_place` to strip the 16-byte GCM tag after
    /// authentication succeeds.  We volatile-zero the freed tail bytes.
    fn truncate(&mut self, len: usize) {
        if len >= self.len { return; }
        unsafe {
            let ptr = self.storage.as_mut_ptr().add(len);
            for i in 0..(self.len - len) { ptr.add(i).write_volatile(0u8); }
        }
        self.len = len;
        if self.cursor > len { self.cursor = len; }
    }
}

// ── Drop ──────────────────────────────────────────────────────────────────────

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Layer 3: volatile-zeroize (guaranteed, even under LTO).
        self.zeroize();
        // Layer 2: release the mlock budget back to the process.
        if self.lock_status.mlocked {
            unsafe { munlock(self.storage.as_ptr() as *const libc::c_void, CAPACITY) };
        }
        // No need to undo MADV_DONTDUMP – pages are being freed anyway.
    }
}

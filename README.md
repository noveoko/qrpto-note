# 🔐 Secure Vault – TUI-based AES-256-GCM Encrypted Notepad

A terminal-based encrypted vault written in Rust.  Every line is stored as an
independent AES-256-GCM ciphertext.  Cleartext only ever exists in a
**mlock'd, zeroize-on-drop** buffer while the entry is focused and revealed.

---

## Build

```bash
# Requires Rust 1.75+ (tested with rustc 1.75 / cargo 1.75)
cargo build --release
# Binary: ./target/release/secure-vault
```

---

## 🔍 First-Run Security Audit (Linux)

qrptonote relies on OS-level features — `mlock`, `prctl`, ASLR, and ptrace
restrictions — that must be correctly configured to work as intended.

Run the one-time audit to verify your system before trusting it with secrets:
```bash
python3 tools/audit/qrptonote_audit.py
# then open qrptonote_security_report.html
```

The script checks 21 security controls and generates a colour-coded HTML report
with a fix command for every issue found. No root required, nothing is written
to your system.

> **Note for CI/server users:** run the audit on every new host you deploy to.
> A misconfigured `ptrace_scope = 0` silently defeats process hardening.

---

## Usage

```bash
# Create a new vault
./secure-vault my-secrets.sv

# Open an existing vault
./secure-vault my-secrets.sv
```

---

## Key bindings

### Locked mode  (all lines shown as ████)

| Key | Action |
|-----|--------|
| `↑` / `k`  | Move cursor up |
| `↓` / `j`  | Move cursor down |
| `Space`     | **Reveal** focused entry (decrypt into transient buffer) |
| `n`         | Add new empty entry |
| `d`         | Delete focused entry |
| `s`         | Save vault to disk |
| `q`         | Quit |

### Revealed mode  (cleartext visible, read-only)

| Key | Action |
|-----|--------|
| `Enter`    | Enter **edit mode** |
| `Esc`      | Lock entry (zeroize buffer) |
| `↑` / `↓` | Navigate – **immediately** zeroizes buffer (spec requirement) |
| `s`        | Save vault |

### Editing mode  (cleartext editable)

| Key | Action |
|-----|--------|
| `Esc`        | Save edits → re-encrypt → return to Locked |
| `↑` / `↓`   | Discard edits, move cursor, return to Locked |
| `←` / `→`   | Move cursor within line |
| `Home` / `End` | Jump to start / end of line |
| `Backspace` | Delete character before cursor |
| `Delete`    | Delete character at cursor |

---

## File format  (`SVT1` binary)

```
Offset   Size   Field
──────   ────   ──────────────────────────────────────────────────
0        4      Magic bytes "SVT1"
4        32     Argon2id salt  (random, stored plaintext)
36       4      Entry count (u32 LE)
40       …      Entries (repeated):
                  12  AES-GCM nonce  (per-encryption random)
                   4  Ciphertext length (u32 LE)
                   N  Ciphertext  =  encrypted_bytes ‖ GCM_tag_128
```

---

## Security architecture

### Encryption – AES-256-GCM

AES-256-GCM is an **AEAD** (Authenticated Encryption with Associated Data)
scheme combining:

- **Confidentiality** via AES in CTR mode (256-bit key → 14 rounds).
- **Integrity + Authentication** via GHASH, a 128-bit polynomial MAC.

Each line is encrypted **independently** with a fresh 96-bit nonce from the OS
CSPRNG.  This means:

1. Entries can be edited, deleted, or reordered without decrypting the rest.
2. There is no cross-entry nonce re-use risk.

### Key derivation – Argon2id

The master key is derived from the user's password using **Argon2id**
(PHC winner, 2015) with default parameters:

- Memory  = 19 456 KiB (≈ 19 MB — fills L3 cache, memory-hard)
- Iterations = 2
- Parallelism = 1
- Output = 32 bytes (→ AES-256 key)

The 32-byte random salt is stored in the vault header (not secret).

### Transient cleartext buffer – `SecureBuffer`

The transient (revealed/editing) buffer uses a `Box<[u8; 4096]>`:

```
Box<[u8; 4096]>
│
├── Fixed-size heap allocation  → stable address, never reallocated
├── mlock(2) on construction    → OS wires pages into RAM; excluded from swap
│                                  (requires CAP_IPC_LOCK or RLIMIT_MEMLOCK)
└── Drop impl:
      1. Overwrite all 4096 bytes with 0x00  (zeroize)
      2. munlock(2) to release the kernel lock
```

**Zeroize is triggered** any time the cursor leaves the focused entry:
- `↑` / `↓` navigation
- `Esc` (discard)
- `Esc` in edit mode (after re-encrypting)
- Program exit (`q` / Ctrl-C)

### Known limitations

1. The intermediate `Vec<u8>` produced by the AES-GCM decrypt call lives
   briefly on the heap before being loaded into `SecureBuffer`.  A custom
   allocator (e.g. `memsec`) would eliminate this window.
2. The AES key schedule inside `Aes256Gcm` is not explicitly zeroed on drop
   (the crate does not expose a `Zeroize` impl on the cipher).
3. `mlock` is best-effort: it can fail silently if `RLIMIT_MEMLOCK` is
   exhausted.  Zeroize still runs regardless.

---

## Project structure

```
src/
  main.rs        Entry point, password prompt, TUI event loop
  app.rs         State machine (Locked → Revealed → Editing)
  ui.rs          ratatui rendering (header, list, footer)
  crypto.rs      AES-256-GCM engine + Argon2id key derivation
  secure_buf.rs  mlock'd, zeroize-on-drop cleartext buffer
  storage.rs     Binary vault file format (SVT1)
```
# qrpto-note

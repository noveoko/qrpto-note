// ─────────────────────────────────────────────────────────────────────────────
//  main.rs  –  Entry point: prctl hardening → password → vault → TUI loop
// ─────────────────────────────────────────────────────────────────────────────

mod app;
mod crypto;
mod secure_buf;
mod storage;
mod ui;

use std::{
    io::{self, stdout, Write},
    path::PathBuf,
    time::Duration,
};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture,
        Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    app::{App, Mode},
    crypto::{derive_key, random_salt, CryptoEngine},
    storage::Vault,
};

// ─────────────────────────────────────────────────────────────────────────────
//  Process-level hardening (Fix 3 – Layer 0)
// ─────────────────────────────────────────────────────────────────────────────
//
//  prctl(PR_SET_DUMPABLE, 0)
//  ═════════════════════════
//  Marks this process as non-dumpable.  Effects:
//    • Core dumps are suppressed process-wide (SIGABRT, SIGSEGV, etc.).
//    • /proc/PID/mem cannot be read by another process (even same UID)
//      without CAP_SYS_PTRACE.
//    • ptrace(PTRACE_ATTACH) from non-root is refused.
//
//  This is our outermost layer – it limits what an attacker who has already
//  gained local code execution can extract from our address space.
//
//  Note: execve() in a child process resets dumpability to 1 for the child,
//  so this setting does NOT propagate to sub-processes.  That is desirable
//  (we don't want to break shell tools we might exec).

fn harden_process() {
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0,   // not dumpable
            0, 0, 0,
        )
    };
    if ret != 0 {
        // Non-fatal: continue with remaining protections.
        eprintln!("  [warn] prctl(PR_SET_DUMPABLE, 0) failed (errno {})", ret);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Password input (raw mode, masked echo)
// ─────────────────────────────────────────────────────────────────────────────

fn read_password(prompt: &str) -> Zeroizing<String> {
    print!("{prompt}");
    stdout().flush().unwrap();

    let mut pw = Zeroizing::new(String::new());

    enable_raw_mode().expect("Could not enable raw mode");
    loop {
        match event::read().expect("Could not read key") {
            Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break,
                KeyCode::Char(c) => {
                    pw.push(c);
                    print!("•");
                    stdout().flush().unwrap();
                }
                KeyCode::Backspace => {
                    if !pw.is_empty() {
                        pw.pop();
                        print!("\x08 \x08");
                        stdout().flush().unwrap();
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    disable_raw_mode().expect("Could not restore terminal");
    println!();
    pw
}



// ─────────────────────────────────────────────────────────────────────────────
//  Vault setup (load-or-create)
// ─────────────────────────────────────────────────────────────────────────────

fn setup_vault(path: &Path) -> Result<(Vault, CryptoEngine), String> {
    if path.exists() {
        let vault = Vault::load(path).map_err(|e| format!("Cannot read vault: {e}"))?;

        let pw = read_password("Password: ");
        let mut key = derive_key(&pw, &vault.salt);
        let crypto = CryptoEngine::from_key(&key);
        // Volatile-zero the raw key bytes now that the cipher's key schedule
        // is set inside ZeroizingCipher.
        key.zeroize();

        // Verify password: try to decrypt the first entry (if present).
        // `decrypt_verify` uses a temporary SecureBuffer; no Vec<u8> created.
        if let Some(first) = vault.lines.first() {
            crypto.decrypt_verify(&first.ciphertext, &first.nonce)
                .map_err(|_| "Wrong password or corrupted vault.".to_string())?;
        }

        Ok((vault, crypto))
    } else {
        println!("  Creating new vault at '{}'", path.display());

        let pw1 = read_password("New password:     ");
        let pw2 = read_password("Confirm password: ");
        if *pw1 != *pw2 {
            return Err("Passwords do not match.".to_string());
        }

        let salt = random_salt();
        let mut key = derive_key(&pw1, &salt);
        let crypto = CryptoEngine::from_key(&key);
        key.zeroize();

        Ok((Vault::new_empty(salt), crypto))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  TUI event loop
// ─────────────────────────────────────────────────────────────────────────────

fn run(mut app: App) -> io::Result<()> {
    // Restore terminal on panic.
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        orig_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    'main: loop {
        term.draw(|f| ui::draw(f, &app))?;

        if !event::poll(Duration::from_millis(100))? { continue; }

        let key = match event::read()? {
            Event::Key(k) if k.kind == KeyEventKind::Press => k,
            _ => continue,
        };

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            break 'main;
        }

        match app.mode {
            Mode::Locked => match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') => break 'main,
                KeyCode::Up              => app.move_up(),
                KeyCode::Down            => app.move_down(),
                KeyCode::Char(' ')       => app.reveal(),
                KeyCode::Char('n')                 => app.add_entry(),
                KeyCode::Char('d') if key.modifiers.is_empty() => app.delete_entry(),
                KeyCode::Char('s')                 => app.save(),
                _ => {}
            },
            Mode::Revealed => match key.code {
                KeyCode::Up              => app.move_up(),
                KeyCode::Down            => app.move_down(),
                KeyCode::Esc             => app.discard(),
                KeyCode::Enter                     => app.begin_edit(),
                KeyCode::Char('s')                 => app.save(),
                _ => {}
            },
            Mode::Editing => match key.code {
                KeyCode::Esc   => app.commit_edit(),
                KeyCode::Up    => app.move_up(),
                KeyCode::Down  => app.move_down(),
                KeyCode::Left      => app.cursor_left(),
                KeyCode::Right     => app.cursor_right(),
                KeyCode::Home      => app.cursor_home(),
                KeyCode::End       => app.cursor_end(),
                KeyCode::Backspace => app.backspace(),
                KeyCode::Delete    => app.delete_fwd(),
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.type_char(c);
                }
                _ => {}
            },
        }
    }

    app.clear_transient();

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    term.show_cursor()?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    // ── Layer 0: process-level hardening ─────────────────────────────────
    //  Called before any user input, vault access, or TUI init.
    harden_process();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("\n  Usage: secure-vault <vault-file>\n");
        std::process::exit(1);
    }

    let path = PathBuf::from(&args[1]);

    // In main(), after the banner, before setup_vault():
    if !path.exists() {
        println!("  💡  New vault detected. If you haven't already, run the");
        println!("      OS security audit to verify your system is hardened:");
        println!("      python3 tools/audit/qrptonote_audit.py");
        println!();
    }

    println!();
    println!("  ╔════════════════════════════════════════════════╗");
    println!("  ║           🔐  Secure Vault  v0.2               ║");
    println!("  ║  AES-256-GCM · Argon2id · mlock · MADV_DONTDUMP║");
    println!("  ╚════════════════════════════════════════════════╝");
    println!();

    if path.exists() {
        println!("  Opening vault:  {}", path.display());
    }
    println!("  Deriving key via Argon2id…");
    println!();

    match setup_vault(&path) {
        Ok((vault, crypto)) => {
            let app = App::new(vault, crypto, path);
            if let Err(e) = run(app) {
                eprintln!("TUI error: {e}");
                std::process::exit(1);
            }
            println!();
            println!("  ✓  Vault closed. All cleartext volatile-zeroed.");
            println!();
        }
        Err(e) => {
            eprintln!("\n  Error: {e}\n");
            std::process::exit(1);
        }
    }
}

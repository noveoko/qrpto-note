// ─────────────────────────────────────────────────────────────────────────────
//  ui.rs  –  ratatui TUI rendering
// ─────────────────────────────────────────────────────────────────────────────
//
//  Layout (three horizontal bands)
//  ═════════════════════════════════
//
//  ┌──────────────────────────────────────────────────────────┐  ← 3 rows
//  │  🔐  Qrpto:note  │  vault.sv  │  3 entries    [MODE]  │
//  └──────────────────────────────────────────────────────────┘
//  ┌──────────────────────────────────────────────────────────┐  ← fills
//  │  Entries                                                 │
//  │   1   ████████████████████████████████████████          │
//  │ ▶ 2   My cleartext line│  (cursor bar shown in editing)  │
//  │   3   ████████████████████████████████████████          │
//  └──────────────────────────────────────────────────────────┘
//  ┌──────────────────────────────────────────────────────────┐  ← 3 rows
//  │  <status message>  │  <context-sensitive key hints>      │
//  └──────────────────────────────────────────────────────────┘
//
//  Masking
//  ═══════
//  All lines are rendered as a fixed-width block of ████ characters.
//  Using a *fixed* width prevents the length of the entry from being
//  inferred by the attacker observing the screen.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::{App, Mode};

// ── Fixed mask used for every locked entry ────────────────────────────────────
const MASK: &str = "████████████████████████████████████";

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.size();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(3),    // entry list
            Constraint::Length(3), // status / help footer
        ])
        .split(area);

    render_header(frame, app, chunks[0]);
    render_list(frame, app, chunks[1]);
    render_footer(frame, app, chunks[2]);
}

// ── Header ────────────────────────────────────────────────────────────────────

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let (mode_str, mode_color) = match app.mode {
        Mode::Locked => (" LOCKED ", Color::Red),
        Mode::Revealed => (" REVEALED ", Color::Yellow),
        Mode::Editing => (" EDITING ", Color::Green),
    };

    let fname = app
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| app.path.to_string_lossy().into_owned());

    // Memory-lock indicator: shown whenever a buffer has been opened this session.
    let mem_indicator = match app.last_lock_status {
        Some(ls) => {
            let mlock_sym = if ls.mlocked { "🔒" } else { "⚠ " };
            let dump_sym = if ls.dontdump { "🛡" } else { "⚠ " };
            format!("  {mlock_sym}mlock {dump_sym}DONTDUMP")
        }
        None => String::new(),
    };

    let title = format!(
        "  🔐  Qrpto:note  │  {}  │  {} entr{}{}",
        fname,
        app.vault.lines.len(),
        if app.vault.lines.len() == 1 {
            "y"
        } else {
            "ies"
        },
        mem_indicator,
    );

    let content = Line::from(vec![
        Span::styled(title, Style::default().fg(Color::Cyan)),
        Span::raw("    "),
        Span::styled(
            mode_str,
            Style::default()
                .fg(Color::Black)
                .bg(mode_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let header = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Left);
    frame.render_widget(header, area);
}

// ── Entry list ────────────────────────────────────────────────────────────────

fn render_list(frame: &mut Frame, app: &App, area: Rect) {
    let n = app.vault.lines.len();

    if n == 0 {
        let empty = Paragraph::new("\n  No entries yet.\n  Press [n] to create your first entry.")
            .block(Block::default().borders(Borders::ALL).title(" Entries "))
            .style(
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            );
        frame.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = (0..n).map(|i| ListItem::new(build_line(app, i))).collect();

    let block = Block::default().borders(Borders::ALL).title(" Entries ");

    let list = List::new(items).block(block);

    // Use ListState so ratatui scrolls the viewport to keep `cursor` visible.
    let mut state = ListState::default();
    state.select(Some(app.cursor));
    frame.render_stateful_widget(list, area, &mut state);
}

/// Build the rendered `Line` for entry `idx`.
fn build_line(app: &App, idx: usize) -> Line<'static> {
    let focused = idx == app.cursor;

    // Line number label (right-aligned in 3 chars, then a space).
    let num_label = format!("{:>3} ", idx + 1);

    // ── Focused + Revealed or Editing ────────────────────────────────────
    if focused && matches!(app.mode, Mode::Revealed | Mode::Editing) {
        if let Some(buf) = &app.transient {
            let text = buf.as_str();
            let cur = buf.cursor;

            // Clamp cursor to valid byte positions (safety guard).
            let cur = cur.min(text.len());

            if app.mode == Mode::Editing {
                // Split the text at the cursor and insert a visual bar.
                let before = text[..cur].to_owned();
                let after = text[cur..].to_owned();

                return Line::from(vec![
                    Span::styled(
                        "▶ ",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(num_label, Style::default().fg(Color::Green)),
                    Span::styled(before, Style::default().fg(Color::White)),
                    Span::styled(
                        "│",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::SLOW_BLINK),
                    ),
                    Span::styled(after, Style::default().fg(Color::White)),
                ]);
            } else {
                // Revealed but not yet editing.
                return Line::from(vec![
                    Span::styled(
                        "▶ ",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(num_label, Style::default().fg(Color::Yellow)),
                    Span::styled(
                        text.to_owned(),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]);
            }
        }
    }

    // ── Masked (Locked, or not the focused line) ──────────────────────────
    let (prefix, label_color, mask_color) = if focused {
        ("▶ ", Color::Yellow, Color::Yellow)
    } else {
        // ciphertext for an empty entry is exactly 16 bytes (bare GCM tag).
        // Anything longer means the entry actually has content.
        let has_content = app.vault.lines[idx].ciphertext.len() > 16;
        let num_color = if has_content {
            Color::LightBlue
        } else {
            Color::DarkGray
        };
        ("  ", num_color, Color::DarkGray)
    };

    Line::from(vec![
        Span::styled(
            prefix,
            Style::default().fg(label_color).add_modifier(if focused {
                Modifier::BOLD
            } else {
                Modifier::empty()
            }),
        ),
        Span::styled(num_label, Style::default().fg(label_color)),
        Span::styled(MASK, Style::default().fg(mask_color)),
    ])
}

// ── Footer / status bar ───────────────────────────────────────────────────────

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let hints = match app.mode {
        Mode::Locked => {
            " [↑↓]  Navigate    [Space]  Reveal    \
             [n]  New    [d]  Delete    [s]  Save    [q]  Quit "
        }
        Mode::Revealed => " [Enter]  Edit    [Esc / ↑↓]  Lock & navigate ",
        Mode::Editing => {
            " [Esc]  Save & lock    [↑↓]  Discard & navigate    \
             [← →]  Cursor    [Home / End]    [Backspace]  Del-back    [Del]  Del-fwd "
        }
    };

    let line = Line::from(vec![
        Span::styled(
            format!("  {}  ", app.status),
            Style::default().fg(Color::White),
        ),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled(hints, Style::default().fg(Color::DarkGray)),
    ]);

    let footer = Paragraph::new(line).block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, area);
}

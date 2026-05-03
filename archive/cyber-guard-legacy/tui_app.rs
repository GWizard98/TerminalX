use anyhow::Result;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use std::io;
use std::time::{Duration, Instant};

struct AppState {
    snap: crate::health::HealthSnapshot,
    sa_line: String,
    refresh_every: Duration,
    next_tick: Instant,
    message: Option<String>,
}

pub fn run_tui() -> Result<()> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState {
        snap: crate::health::quick_self_check(),
        sa_line: crate::health::read_self_awareness_summary::<&str>(None)
            .unwrap_or_else(|| "no recent self-awareness logs".into()),
        refresh_every: Duration::from_secs(2),
        next_tick: Instant::now(),
        message: None,
    };

    loop {
        // Periodic refresh of health snapshot and SA line
        if Instant::now() >= state.next_tick {
            state.snap = crate::health::quick_self_check();
            state.sa_line = crate::health::read_self_awareness_summary::<&str>(None)
                .unwrap_or_else(|| "no recent self-awareness logs".into());
            state.next_tick = Instant::now() + state.refresh_every;
        }

        terminal.draw(|f| {
            let size = f.size();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),  // header
                    Constraint::Min(0),     // body
                    Constraint::Length(1),  // footer
                ])
                .split(size);

            // Header with title
            let header = Paragraph::new(Line::from(vec![
                Span::styled(" Cyber-Guard ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(" — Interactive Dashboard"),
            ]))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

            // Body content
            let body = Paragraph::new(format!(
                "{}\nSelf-awareness: {}\n\nShortcuts:\n  q: quit\n  r: redraw\n  +/-: adjust refresh interval ({}s)\n  c: self-check now\n  h: help",
                state.snap.format_summary(),
                state.sa_line,
                state.refresh_every.as_secs()
            ))
            .block(Block::default().borders(Borders::ALL).title("Overview"));
            f.render_widget(body, chunks[1]);

            // Footer
            let footer_text = state
                .message
                .as_deref()
                .unwrap_or("Press q to quit • Cyber-Guard TUI");
            let footer = Paragraph::new(footer_text);
            f.render_widget(footer, chunks[2]);
        })?;

        // Handle input
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => { /* redraw on next loop */ }
                    KeyCode::Char('+') => {
                        let secs = (state.refresh_every.as_secs().saturating_add(1)).min(10);
                        state.refresh_every = Duration::from_secs(secs);
                        state.message = Some(format!("Refresh interval: {}s", secs));
                    }
                    KeyCode::Char('-') => {
                        let secs = state.refresh_every.as_secs().saturating_sub(1).max(1);
                        state.refresh_every = Duration::from_secs(secs);
                        state.message = Some(format!("Refresh interval: {}s", secs));
                    }
                    KeyCode::Char('c') => {
                        // Trigger immediate self-check (quick snapshot)
                        state.snap = crate::health::quick_self_check();
                        if let Ok(out) = crate::health::trigger_local_self_check() {
                            let head = out.lines().take(2).collect::<Vec<_>>().join(" | ");
                            state.message = Some(format!("Self-check: {}", head));
                        } else {
                            state.message = Some("Self-check triggered".into());
                        }
                    }
                    KeyCode::Char('h') => {
                        state.message = Some("Help: q quit • r redraw • +/- interval • c self-check".into());
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    disable_raw_mode()?;
    crossterm::execute!(io::stdout(), DisableMouseCapture)?;
    Ok(())
}

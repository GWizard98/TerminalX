use anyhow::Result;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::cursor::{Hide, Show};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use serde::{Deserialize, Serialize};
use std::{fs, io};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

struct ChatState {
    messages: Vec<String>,
    input: String,
    sandbox_root: PathBuf,
    plan_original: Option<PathBuf>,
    plan_sandbox: Option<PathBuf>,
    // Alert subscription state
    alerts_on: bool,
    alert_path: PathBuf,
    alert_offset: usize,
    // Notification subscription state
    notify_on: bool,
    notify_path: PathBuf,
    notify_offset: usize,
    // Theme
    theme_dark: bool,
    accent: Color,
    // Async self-check state
    is_checking: bool,
    check_started: Option<Instant>,
    tx: Sender<String>,
    rx: Receiver<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatConfig {
    theme: String,     // "dark" | "light"
    accent: String,    // color name
}

impl ChatConfig {
    fn default() -> Self {
        Self { theme: "dark".into(), accent: "cyan".into() }
    }
}

fn config_path() -> PathBuf {
    let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push(".cyber_guardian");
    let _ = fs::create_dir_all(&p);
    p.push("chat_config.json");
    p
}

fn load_config() -> ChatConfig {
    let p = config_path();
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str::<ChatConfig>(&s).ok())
        .unwrap_or_else(ChatConfig::default)
}

fn save_config(cfg: &ChatConfig) -> Result<()> {
    let p = config_path();
    let s = serde_json::to_string_pretty(cfg)?;
    fs::write(p, s)?;
    Ok(())
}

fn color_from_name(name: &str) -> Color {
    match name.to_lowercase().as_str() {
        "cyan" => Color::Cyan,
        "blue" => Color::Blue,
        "green" => Color::Green,
        "magenta" => Color::Magenta,
        "yellow" => Color::Yellow,
        "red" => Color::Red,
        _ => Color::Cyan,
    }
}

fn color_to_name(c: Color) -> &'static str {
    match c {
        Color::Cyan => "cyan",
        Color::Blue => "blue",
        Color::Green => "green",
        Color::Magenta => "magenta",
        Color::Yellow => "yellow",
        Color::Red => "red",
        _ => "cyan",
    }
}

impl ChatState {
    fn new() -> Self {
        let root = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".cyber_guardian/sandbox");
        // Default alert log path (local Cyber-Guard self-awareness log)
        let default_alert = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Projects/cyber-guard/self_awareness.log");
        // Load theme config
        let cfg = load_config();
        // Start reading from end by default
        let offset = fs::read_to_string(&default_alert).map(|s| s.len()).unwrap_or(0);
        // Default notification log path (local CG stdout log)
        let default_notify = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library/Logs/cyber-guard.out.log");
        let notify_offset = fs::read_to_string(&default_notify).map(|s| s.len()).unwrap_or(0);
        let (tx, rx) = mpsc::channel();
        let mut s = Self {
            messages: Vec::new(),
            input: String::new(),
            sandbox_root: root,
            plan_original: None,
            plan_sandbox: None,
            alerts_on: false,
            alert_path: default_alert,
            alert_offset: offset,
            notify_on: false,
            notify_path: default_notify,
            notify_offset,
            theme_dark: cfg.theme.to_lowercase() != "light",
            accent: color_from_name(&cfg.accent),
            is_checking: false,
            check_started: None,
            tx,
            rx,
        };
        s.messages.push("CG: Hello. Type 'help' to see what I can do.".into());
        s
    }

    fn push_user(&mut self, msg: &str) {
        self.messages.push(format!("You: {}", msg));
    }

    fn push_bot(&mut self, msg: &str) {
        self.messages.push(format!("CG: {}", msg));
    }
}

pub fn run_chat() -> Result<()> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen, EnableMouseCapture, Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = ChatState::new();

    let redraw = || {};

    loop {
        // Poll alerts when subscribed
        if state.alerts_on {
            poll_alerts(&mut state);
        }
        if state.notify_on {
            poll_notify(&mut state);
        }
        // Drain async messages
        while let Ok(msg) = state.rx.try_recv() {
            state.push_bot(&msg);
            state.is_checking = false;
            state.check_started = None;
        }
        // Notify if long-running check crosses timeout
        if state.is_checking {
            if let Some(started) = state.check_started {
                if started.elapsed() > Duration::from_secs(3) {
                    state.push_bot("Self-check is still running in background...");
                    // prevent spamming: clear timestamp so we only notify once
                    state.check_started = None;
                }
            }
        }

        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(3),
                    Constraint::Length(3),
                ])
                .split(size);

            // Header
            let header = Paragraph::new(Line::from(vec![
                Span::styled(" Cyber-Guard ", Style::default().fg(state.accent).add_modifier(Modifier::BOLD)),
                Span::raw(" — Chat Terminal"),
            ]))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

            // Messages
            let msgs = state.messages.join("\n");
            let messages = Paragraph::new(msgs)
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title("Activity"));
            f.render_widget(messages, chunks[1]);

            // Input
            let input = Paragraph::new(state.input.as_str())
                .block(Block::default().borders(Borders::ALL).title("Type a command... (help)"));
            f.render_widget(input, chunks[2]);
            // Put cursor at input end
            let cursor_x = chunks[2].x + 1 + state.input.len() as u16;
            let cursor_y = chunks[2].y + 1;
            f.set_cursor(cursor_x, cursor_y);
        })?;

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => break,
                    KeyCode::Esc => break,
                    KeyCode::Enter => {
                        let line = state.input.trim().to_string();
                        state.input.clear();
                        if !line.is_empty() {
                            handle_command(&mut state, &line);
                        }
                    }
                    KeyCode::Backspace | KeyCode::Delete => { state.input.pop(); }
                    KeyCode::Char(ch) => { state.input.push(ch); }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    // Cleanup
    disable_raw_mode()?;
    crossterm::execute!(io::stdout(), Show, DisableMouseCapture, LeaveAlternateScreen)?;
    Ok(())
}

fn handle_command(state: &mut ChatState, line: &str) {
    state.push_user(line);
    match line {
        "help" => state.push_bot("Commands: status, selfcheck, tail, license, clear, quit,\n  subscribe [alerts|notify] — stream new alerts (default alerts) or notifications\n  unsubscribe [alerts|notify] — stop streaming\n  theme              — show current theme\n  theme light|dark   — set theme\n  theme homebrew     — dark + green accent\n  theme accent <c>   — set accent (cyan|blue|green|magenta|yellow|red)\n  theme save|load|reset\n  edit start <file>  — copy to sandbox\n  edit open          — open sandbox copy\n  edit diff          — show unified diff\n  edit apply         — overwrite original with sandbox copy\n  edit cancel        — abandon current plan"),
        "quit" | "exit" => state.push_bot("Press Esc to exit."),
        "clear" => { state.messages.clear(); state.push_bot("Cleared."); },
        "status" => {
            let snap = crate::health::quick_self_check();
            state.push_bot(&format!("{}", snap.format_summary()));
            if let Some(line) = crate::health::read_self_awareness_summary::<&str>(None) {
                state.push_bot(&format!("Self-awareness: {}", line));
            }
        }
        "selfcheck" => {
            let snap = crate::health::quick_self_check();
            state.push_bot(&format!("{}", snap.format_summary()));
            if state.is_checking {
                state.push_bot("Self-check already in progress; please wait...");
            } else {
                state.is_checking = true;
                state.check_started = Some(Instant::now());
                let tx = state.tx.clone();
                thread::spawn(move || {
                    let msg = match crate::health::trigger_local_self_check() {
                        Ok(output) => {
                            let head = output.lines().take(3).collect::<Vec<_>>().join(" | ");
                            format!("Triggered local CG: {}", head)
                        }
                        Err(e) => format!("Could not trigger local CG: {}", e),
                    };
                    let _ = tx.send(msg);
                });
            }
        }
        "tail" => {
            if let Some(line) = crate::health::read_self_awareness_summary::<&str>(None) {
                state.push_bot(&format!("Last log: {}", line));
            } else {
                state.push_bot("No logs found.");
            }
        }
        "license" => {
            let mut lm = crate::license::LicenseManager::new();
            if lm.initialize().is_ok() {
                if let Some(info) = lm.get_license_info() {
                    state.push_bot(&format!("License: {} ({})", info.tier, info.email));
                } else { state.push_bot("No license info."); }
            } else { state.push_bot("License init failed."); }
        }
        "theme" => {
            state.push_bot(&format!("Theme: {} | Accent: {}", if state.theme_dark {"dark"} else {"light"}, color_to_name(state.accent)));
        }
        other if other.starts_with("theme ") => {
            let parts: Vec<&str> = other.split_whitespace().collect();
            if parts.len() >= 2 {
                match parts[1] {
                    "light" => { state.theme_dark = false; state.push_bot("Theme set to light (save to persist)"); }
                    "dark" => { state.theme_dark = true; state.push_bot("Theme set to dark (save to persist)"); }
                    "homebrew" => { state.theme_dark = true; state.accent = Color::Green; state.push_bot("Theme set to homebrew (dark + green). Use 'theme save' to persist."); }
                    "accent" => {
                        if parts.len() >= 3 { state.accent = color_from_name(parts[2]); state.push_bot(&format!("Accent set to {} (save to persist)", parts[2])); }
                        else { state.push_bot("Usage: theme accent <color>"); }
                    }
                    "save" => {
                        let cfg = ChatConfig { theme: if state.theme_dark {"dark".into()} else {"light".into()}, accent: color_to_name(state.accent).into() };
                        if let Err(e) = save_config(&cfg) { state.push_bot(&format!("Save failed: {}", e)); } else { state.push_bot("Theme saved."); }
                    }
                    "load" => {
                        let cfg = load_config();
                        state.theme_dark = cfg.theme.to_lowercase() != "light";
                        state.accent = color_from_name(&cfg.accent);
                        state.push_bot("Theme loaded.");
                    }
                    "reset" => {
                        let cfg = ChatConfig::default();
                        state.theme_dark = true; state.accent = color_from_name(&cfg.accent);
                        let _ = save_config(&cfg);
                        state.push_bot("Theme reset to defaults.");
                    }
                    _ => state.push_bot("Unknown theme command"),
                }
            }
        }
        "subscribe" => {
            // Default: alerts
            // Reset offset to end to only stream new lines
            state.alert_offset = fs::read_to_string(&state.alert_path).map(|s| s.len()).unwrap_or(0);
            state.alerts_on = true;
            state.push_bot(&format!("Subscribed to alerts: {}", state.alert_path.display()));
        }
        other if other == "subscribe alerts" => {
            state.alert_offset = fs::read_to_string(&state.alert_path).map(|s| s.len()).unwrap_or(0);
            state.alerts_on = true;
            state.push_bot(&format!("Subscribed to alerts: {}", state.alert_path.display()));
        }
        other if other == "subscribe notify" => {
            state.notify_offset = fs::read_to_string(&state.notify_path).map(|s| s.len()).unwrap_or(0);
            state.notify_on = true;
            state.push_bot(&format!("Subscribed to notifications: {}", state.notify_path.display()));
        }
        "unsubscribe" => {
            state.alerts_on = false;
            state.notify_on = false;
            state.push_bot("Unsubscribed from all streams");
        }
        other if other == "unsubscribe alerts" => {
            state.alerts_on = false;
            state.push_bot("Unsubscribed from alerts");
        }
        other if other == "unsubscribe notify" => {
            state.notify_on = false;
            state.push_bot("Unsubscribed from notifications");
        }
        other => {
            if other.starts_with("edit ") {
                handle_edit_command(state, other);
            } else {
                state.push_bot(&format!("Unknown: {}. Try 'help'", other));
            }
        }
    }
}

fn poll_notify(state: &mut ChatState) {
    if let Ok(content) = fs::read_to_string(&state.notify_path) {
        let len = content.len();
        if state.notify_offset > len { state.notify_offset = 0; }
        if len > state.notify_offset {
            let new = &content[state.notify_offset..];
            for line in new.lines() {
                let l = line.trim();
                if l.contains("Notification sent:") {
                    state.push_bot(&format!("NOTIFY: {}", l));
                }
            }
            state.notify_offset = len;
            if state.messages.len() > 500 {
                let drain = state.messages.len() - 500;
                state.messages.drain(0..drain);
            }
        }
    } else if state.notify_on {
        state.push_bot(&format!("Notification log not found: {}", state.notify_path.display()));
        state.notify_on = false;
    }
}

fn handle_edit_command(state: &mut ChatState, line: &str) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 { state.push_bot("Usage: edit start <file> | edit open | edit diff | edit apply | edit cancel"); return; }
    let sub = parts[1];

    // Ensure sandbox root exists
    let _ = fs::create_dir_all(&state.sandbox_root);

    match sub {
        "start" => {
            if parts.len() < 3 { state.push_bot("edit start <file>"); return; }
            let orig = PathBuf::from(parts[2]);
            if !orig.exists() { state.push_bot("Original file not found"); return; }
            let sand = state.sandbox_root.join(
                orig.file_name().unwrap_or_default()
            );
            match fs::copy(&orig, &sand) {
                Ok(_) => {
                    state.plan_original = Some(orig.clone());
                    state.plan_sandbox = Some(sand.clone());
                    state.push_bot(&format!("Planned edit: {} → {}", orig.display(), sand.display()));
                }
                Err(e) => state.push_bot(&format!("Copy failed: {}", e)),
            }
        }
        "open" => {
            if let Some(sand) = &state.plan_sandbox {
                let _ = Command::new("open").arg(sand).output();
                state.push_bot(&format!("Opened {}", sand.display()));
            } else { state.push_bot("No active plan. Use 'edit start <file>'"); }
        }
        "diff" => {
            if let (Some(orig), Some(sand)) = (&state.plan_original, &state.plan_sandbox) {
                match Command::new("diff").arg("-u").arg(orig).arg(sand).output() {
                    Ok(out) => {
                        if out.status.success() {
                            state.push_bot("No differences.");
                        } else {
                            let text = String::from_utf8_lossy(&out.stdout);
                            let preview = text.lines().take(40).collect::<Vec<_>>().join("\n");
                            state.push_bot(&format!("Diff:\n{}", preview));
                        }
                    }
                    Err(e) => state.push_bot(&format!("diff failed: {}", e)),
                }
            } else { state.push_bot("No active plan"); }
        }
        "apply" => {
            if let (Some(orig), Some(sand)) = (&state.plan_original, &state.plan_sandbox) {
                match fs::copy(sand, orig) {
                    Ok(_) => {
                        state.push_bot("Applied changes to original file.");
                        state.plan_original = None;
                        state.plan_sandbox = None;
                    }
                    Err(e) => state.push_bot(&format!("Apply failed: {}", e)),
                }
            } else { state.push_bot("No active plan"); }
        }
        "cancel" => {
            if let Some(sand) = &state.plan_sandbox { let _ = fs::remove_file(sand); }
            state.plan_original = None;
            state.plan_sandbox = None;
            state.push_bot("Canceled plan.");
        }
        _ => state.push_bot("Unknown edit command"),
    }
}

fn poll_alerts(state: &mut ChatState) {
    if let Ok(content) = fs::read_to_string(&state.alert_path) {
        let len = content.len();
        if state.alert_offset > len { // log rotated/truncated
            state.alert_offset = 0;
        }
        if len > state.alert_offset {
            let new = &content[state.alert_offset..];
            for line in new.lines() {
                let l = line.trim();
                if !l.is_empty() {
                    state.push_bot(&format!("ALERT: {}", l));
                }
            }
            state.alert_offset = len;
            // Keep message buffer from growing unbounded
            if state.messages.len() > 500 {
                let drain = state.messages.len() - 500;
                state.messages.drain(0..drain);
            }
        }
    } else if state.alerts_on {
        // If file missing, notify once
        state.push_bot(&format!("Alert file not found: {}", state.alert_path.display()));
        state.alerts_on = false;
    }
}

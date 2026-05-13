//! Cowrie Honeypot Monitor
//!
//! Tails cowrie.json and feeds events into CyberGuardian.
//!
//! Events handled:
//!   cowrie.login.success  → Critical alert + Active Response (OSINT + block)
//!   cowrie.login.failed   → Warning alert (tracked per IP)
//!   cowrie.command.input  → Critical alert (attacker is inside)
//!   cowrie.session.file_download → Critical alert (malware delivery)
//!
//! This closes the integration gap between Cowrie and CyberGuardian.
//! All honeypot intel flows through Active Response for automated blocking.

use crate::config::CowrieMonitorConfig;
use crate::notifycore::{alert::Alert, NotifyCore};
use crate::response::{
    ActiveResponse,
    incident::{Incident, IncidentSource, IncidentSeverity},
};
use anyhow::Result;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::info;

// ── Cowrie event structures ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CowrieEvent {
    eventid: String,
    src_ip: String,
    session: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    input: String,
    #[serde(default)]
    url: String,
    timestamp: String,
}

// ── Monitor entry point ───────────────────────────────────────────────────────

pub async fn run(
    config: CowrieMonitorConfig,
    notifycore: Arc<NotifyCore>,
    server_name: String,
    active_response: Arc<Mutex<ActiveResponse>>,
) -> Result<()> {
    if !config.enabled {
        info!("Cowrie monitor disabled");
        return Ok(());
    }

    info!("Cowrie monitor started — watching {:?}", config.log_path);

    let file = std::fs::File::open(&config.log_path)?;
    let mut reader = BufReader::new(file);

    // Seek to end — only process new events
    reader.seek(SeekFrom::End(0))?;

    loop {
        let mut line = String::new();

        while reader.read_line(&mut line)? > 0 {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                line.clear();
                continue;
            }

            if let Ok(event) = serde_json::from_str::<CowrieEvent>(trimmed) {
                handle_event(
                    event,
                    &notifycore,
                    &server_name,
                    &active_response,
                ).await?;
            }

            line.clear();
        }

        sleep(Duration::from_secs(1)).await;
    }
}

// ── Event handler ─────────────────────────────────────────────────────────────

async fn handle_event(
    event: CowrieEvent,
    notifycore: &Arc<NotifyCore>,
    server_name: &str,
    active_response: &Arc<Mutex<ActiveResponse>>,
) -> Result<()> {
    match event.eventid.as_str() {

        // Attacker successfully logged in — highest priority
        "cowrie.login.success" => {
            let alert = Alert::critical(
                "cowrie",
                server_name,
                &format!("🍯 HONEYPOT BREACH: {} logged in as '{}'", event.src_ip, event.username),
                &format!("Session: {} | Password: {} | Time: {}", event.session, event.password, event.timestamp),
            );
            notifycore.send(alert).await?;

            // Trigger Active Response — OSINT + auto-block
            let incident = Incident::new(
                IncidentSource::Honeypot,
                IncidentSeverity::Critical,
                Some(event.src_ip.clone()),
                format!("Honeypot breach: login as '{}' with '{}'", event.username, event.password),
                format!("Session: {} | Time: {}", event.session, event.timestamp),
            );
            let mut ar = active_response.lock().await;
            if let Err(e) = ar.respond(incident).await {
                tracing::error!("Active Response failed for honeypot breach: {}", e);
            }
        }

        // Failed login attempt
        "cowrie.login.failed" => {
            let alert = Alert::warning(
                "cowrie",
                server_name,
                &format!("Honeypot probe: {} tried '{}/{}'", event.src_ip, event.username, event.password),
                &format!("Session: {}", event.session),
            );
            notifycore.send(alert).await?;
        }

        // Attacker ran a command inside honeypot
        "cowrie.command.input" => {
            let alert = Alert::critical(
                "cowrie",
                server_name,
                &format!("🍯 HONEYPOT CMD: {} executed command", event.src_ip),
                &format!("Command: {} | Session: {}", event.input, event.session),
            );
            notifycore.send(alert).await?;
        }

        // Attacker downloaded malware
        "cowrie.session.file_download" => {
            let alert = Alert::critical(
                "cowrie",
                server_name,
                &format!("🍯 MALWARE DOWNLOAD: {} pulled file from {}", event.src_ip, event.url),
                &format!("Session: {} | Time: {}", event.session, event.timestamp),
            );
            notifycore.send(alert).await?;

            // Also trigger Active Response for malware delivery
            let incident = Incident::new(
                IncidentSource::Honeypot,
                IncidentSeverity::Critical,
                Some(event.src_ip.clone()),
                format!("Malware delivery from {}", event.url),
                format!("Session: {}", event.session),
            );
            let mut ar = active_response.lock().await;
            if let Err(e) = ar.respond(incident).await {
                tracing::error!("Active Response failed for malware download: {}", e);
            }
        }

        // Ignore everything else
        _ => {}
    }

    Ok(())
}

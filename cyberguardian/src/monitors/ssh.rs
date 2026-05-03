//! SSH Monitor
//!
//! Watches /var/log/auth.log for:
//!   - Failed login attempts (tracks per-IP count, alerts at threshold)
//!   - Successful root logins
//!   - Root login attempts
//!
//! When brute force threshold is hit, passes incident to Active Response
//! for automated OSINT investigation and IP blocking.

use crate::config::SshMonitorConfig;
use crate::notifycore::{alert::Alert, NotifyCore};
use crate::response::{ActiveResponse, incident::{Incident, IncidentSource, IncidentSeverity}};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{info};

pub async fn run(
    config: SshMonitorConfig,
    notifycore: Arc<NotifyCore>,
    server_name: String,
    active_response: Arc<Mutex<ActiveResponse>>,
) -> Result<()> {
    if !config.enabled {
        info!("SSH monitor disabled");
        return Ok(());
    }

    info!("SSH monitor started — watching {:?}", config.auth_log_path);

    let re_failed  = Regex::new(r"Failed password for (?:invalid user )?(\S+) from (\S+)")?;
    let re_success = Regex::new(r"Accepted \S+ for (\S+) from (\S+)")?;
    let re_invalid = Regex::new(r"Invalid user (\S+) from (\S+)")?;

    let mut fail_counts: HashMap<String, u32> = HashMap::new();

    let file = std::fs::File::open(&config.auth_log_path)?;
    let mut reader = BufReader::new(file);

    // Seek to end so we only process new lines
    reader.seek(SeekFrom::End(0))?;

    loop {
        let mut line = String::new();

        while reader.read_line(&mut line)? > 0 {
            let l = line.trim().to_string();

            // Failed password attempt
            if let Some(caps) = re_failed.captures(&l) {
                let user = caps[1].to_string();
                let ip   = caps[2].to_string();

                let count = fail_counts.entry(ip.clone()).or_insert(0);
                *count += 1;

                if *count >= config.fail_threshold {
                    // Fire critical alert
                    let alert = Alert::critical(
                        "ssh_monitor",
                        &server_name,
                        &format!("Brute force detected: {} failed attempts from {}", count, ip),
                        &format!("Last user attempted: {}", user),
                    );
                    notifycore.send(alert).await?;

                    // Pass to Active Response for automated OSINT + block
                    let incident = Incident::new(
                        IncidentSource::Ssh,
                        IncidentSeverity::Critical,
                        Some(ip.clone()),
                        format!("Brute force: {} failed attempts", count),
                        format!("IP: {} | User: {}", ip, user),
                    );
                    let mut ar = active_response.lock().await;
                    if let Err(e) = ar.respond(incident).await {
                        tracing::error!("Active Response failed: {}", e);
                    }
                    drop(ar);

                    // Reset after alert to avoid spam
                    fail_counts.insert(ip, 0);
                } else {
                    let alert = Alert::warning(
                        "ssh_monitor",
                        &server_name,
                        &format!("Invalid user '{}' attempted from {}", user, ip),
                        &format!("Attempt {} of {}", count, config.fail_threshold),
                    );
                    notifycore.send(alert).await?;
                }
            }

            // Successful login
            if let Some(caps) = re_success.captures(&l) {
                let user = &caps[1];
                let ip   = &caps[2];

                // Clear fail count on success (legitimate login)
                fail_counts.remove(*&ip);
                let alert = Alert::info(
                    "ssh_monitor",
                    &server_name,
                    &format!("SSH login: user '{}' from {}", user, ip),
                    "",
                );
                notifycore.send(alert).await?;
            }

            // Invalid user attempt
            if let Some(caps) = re_invalid.captures(&l) {
                let user = &caps[1];
                let ip   = &caps[2];

                let alert = Alert::warning(
                    "ssh_monitor",
                    &server_name,
                    &format!("Invalid user '{}' attempted from {}", user, ip),
                    "",
                );
                notifycore.send(alert).await?;
            }

            line.clear();
        }

        sleep(Duration::from_secs(1)).await;
    }
}
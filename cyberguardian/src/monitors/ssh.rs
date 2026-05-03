//! SSH monitor
//!
//! Tails /var/log/auth.log and parses for:
//!   - Failed login attempts (tracks per-IP count, alerts at threshold)
//!   - Successful logins from unknown IPs
//!   - Root login attempts

use crate::config::SshMonitorConfig;
use crate::notifycore::{alert::Alert, NotifyCore};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, Seek, SeekFrom};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::info;

pub async fn run(config: SshMonitorConfig, notifycore: Arc<NotifyCore>, server_name: String) -> Result<()> {
    if !config.enabled {
        info!("SSH monitor disabled");
        return Ok(());
    }

    info!("SSH monitor started — watching {:?}", config.auth_log_path);

    // Regex patterns for auth.log parsing
    let re_failed  = Regex::new(r"Failed password for (?:invalid user )?(\S+) from (\S+)")?;
    let re_success = Regex::new(r"Accepted (?:password|publickey) for (\S+) from (\S+)")?;
    let re_invalid = Regex::new(r"Invalid user (\S+) from (\S+)")?;

    let mut fail_counts: HashMap<String, u32> = HashMap::new();
    let mut file = std::fs::File::open(&config.auth_log_path)?;

    // Seek to end so we only process new lines
    file.seek(SeekFrom::End(0))?;

    loop {
        let mut reader = std::io::BufReader::new(&file);
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
                    let alert = Alert::critical(
                        "ssh_monitor",
                        &server_name,
                        &format!("Brute force detected: {} failed attempts from {}", count, ip),
                        &l,
                    );
                    notifycore.send(alert).await?;
                    // Reset after alert to avoid spam
                    fail_counts.insert(ip, 0);
                } else if *count == 1 {
                    let alert = Alert::warning(
                        "ssh_monitor",
                        &server_name,
                        &format!("Failed SSH login for user '{}' from {}", user, ip),
                        &l,
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
                    &l,
                );
                notifycore.send(alert).await?;
            }

            // Invalid user attempt — always at least warning
            if let Some(caps) = re_invalid.captures(&l) {
                let user = &caps[1];
                let ip   = &caps[2];
                let alert = Alert::warning(
                    "ssh_monitor",
                    &server_name,
                    &format!("Invalid user '{}' attempted from {}", user, ip),
                    &l,
                );
                notifycore.send(alert).await?;
            }

            line.clear();
        }

        sleep(Duration::from_secs(5)).await;
    }
}

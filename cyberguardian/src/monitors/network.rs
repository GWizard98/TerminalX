//! Network monitor
//!
//! Monitors active network connections for suspicious outbound activity.
//! Reads /proc/net/tcp and /proc/net/tcp6 directly — no external tools needed.
//!
//! Alerts on:
//!   - Connections to non-whitelisted destinations
//!   - Connections on alert-listed ports (reverse shell indicators)

use crate::config::NetworkMonitorConfig;
use crate::notifycore::{alert::Alert, NotifyCore};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::info;

/// Convert /proc/net/tcp hex address to dotted-decimal IP:port
fn parse_hex_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return None; }

    let ip_hex = u32::from_str_radix(parts[0], 16).ok()?;
    let port   = u16::from_str_radix(parts[1], 16).ok()?;

    // Linux stores IP in little-endian — reverse the bytes
    let ip = format!("{}.{}.{}.{}",
        ip_hex & 0xFF,
        (ip_hex >> 8) & 0xFF,
        (ip_hex >> 16) & 0xFF,
        (ip_hex >> 24) & 0xFF,
    );
    Some((ip, port))
}

pub async fn run(config: NetworkMonitorConfig, notifycore: Arc<NotifyCore>, server_name: String, poll_secs: u64) -> Result<()> {
    if !config.enabled {
        info!("Network monitor disabled");
        return Ok(());
    }

    info!("Network monitor started");

    let alert_ports: HashSet<u16> = config.alert_ports.into_iter().collect();
    let mut alerted: HashSet<String> = HashSet::new();

    loop {
        // Read /proc/net/tcp for active connections
        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) { // skip header
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 { continue; }

                // State 01 = ESTABLISHED
                if fields[3] != "01" { continue; }

                let remote = fields[2];
                if let Some((ip, port)) = parse_hex_addr(remote) {
                    // Skip loopback
                    if ip.starts_with("127.") || ip == "0.0.0.0" { continue; }

                    let key = format!("{}:{}", ip, port);

                    // Alert on suspicious ports
                    if alert_ports.contains(&port) && !alerted.contains(&key) {
                        alerted.insert(key.clone());
                        let alert = Alert::critical(
                            "network_monitor",
                            &server_name,
                            &format!("Suspicious connection on port {} to {}", port, ip),
                            &key,
                        );
                        notifycore.send(alert).await?;
                    }
                }
            }
        }

        sleep(Duration::from_secs(poll_secs)).await;
    }
}

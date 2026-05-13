//! Process monitor
//!
//! Polls running processes against a whitelist.
//! Any process not on the whitelist fires a warning.
//! Tracks process appearance over time — a new process that
//! wasn't running at startup is treated as higher priority.

use crate::config::ProcessMonitorConfig;
use crate::notifycore::{alert::Alert, NotifyCore};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use sysinfo::System;
use tokio::time::{sleep, Duration};
use tracing::info;

pub async fn run(config: ProcessMonitorConfig, notifycore: Arc<NotifyCore>, server_name: String, poll_secs: u64) -> Result<()> {
    if !config.enabled {
        info!("Process monitor disabled");
        return Ok(());
    }

    info!("Process monitor started — {} whitelisted processes", config.whitelist.len());

    let whitelist: HashSet<String> = config.whitelist.into_iter().collect();
    let mut known_unknown: HashSet<String> = HashSet::new();
    let mut sys = System::new_all();

    loop {
        sys.refresh_all();

    let running: HashSet<String> = sys.processes().values()
        .filter(|p| p.exe().is_some())
        .map(|p| p.name().to_string())
        .collect();

        for proc_name in &running {
            // Skip if whitelisted
           let whitelisted = whitelist.iter().any(|w: &String| proc_name.contains(w.as_str()));
            if whitelisted { continue; }

            // Already alerted on this one
            if known_unknown.contains(proc_name) { continue; }

            // New unknown process
            known_unknown.insert(proc_name.clone());

            let alert = Alert::warning(
                "process_monitor",
                &server_name,
                &format!("Unknown process detected: '{}'", proc_name),
                proc_name,
            );
            notifycore.send(alert).await?;
        }

        // Clean up processes that are no longer running
        known_unknown.retain(|p| running.contains(p));

        sleep(Duration::from_secs(poll_secs)).await;
    }
}
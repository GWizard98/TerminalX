//! Filesystem monitor
//!
//! Watches protected directories for unauthorized changes.
//! Uses the `notify` crate for inotify-based real-time events.
//!
//! Protects:
//!   /root/TradeEco      — trading system binary and config
//!   /etc/cyberguardian  — our own config

use crate::config::FilesystemMonitorConfig;
use crate::notifycore::{alert::Alert, NotifyCore};
use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher, recommended_watcher};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

pub async fn run(config: FilesystemMonitorConfig, notifycore: Arc<NotifyCore>, server_name: String) -> Result<()> {
    if !config.enabled {
        info!("Filesystem monitor disabled");
        return Ok(());
    }

    info!("Filesystem monitor started — watching {} paths", config.watch_paths.len());

    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(100);

    let mut watcher = recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;

    for path in &config.watch_paths {
        if path.exists() {
            watcher.watch(path, RecursiveMode::Recursive)?;
            info!("Watching: {:?}", path);
        } else {
            tracing::warn!("Watch path does not exist: {:?}", path);
        }
    }

    while let Some(res) = rx.recv().await {
        match res {
            Ok(event) => {
                // Skip ignored extensions
                let relevant = event.paths.iter().any(|p| {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    !config.ignore_extensions.contains(&ext.to_string())
                });

                if !relevant { continue; }

                let paths_str = event.paths.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                let (severity_fn, msg): (fn(&str,&str,&str,&str) -> Alert, &str) = match event.kind {
                    EventKind::Modify(_) => (Alert::warning, "File modified in protected directory"),
                    EventKind::Create(_) => (Alert::warning, "New file created in protected directory"),
                    EventKind::Remove(_) => (Alert::critical,"File deleted from protected directory"),
                    EventKind::Access(_) => continue, // access events are too noisy
                    _ => continue,
                };

                let alert = severity_fn(
                    "filesystem_monitor",
                    &server_name,
                    msg,
                    &paths_str,
                );
                notifycore.send(alert).await?;
            }
            Err(e) => {
                tracing::error!("Filesystem watcher error: {}", e);
            }
        }
    }

    Ok(())
}

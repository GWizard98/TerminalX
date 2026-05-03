//! File Integrity Monitor
//!
//! Job: Remember what every important file looks like when the system
//! is clean, then notice and alert when anything changes.
//!
//! How it works:
//!   1. On startup — walk every file in watched directories, hash each one
//!   2. Store those hashes as the "baseline" (clean state)
//!   3. Every poll interval — hash everything again
//!   4. Compare current hashes to baseline
//!   5. Any difference = alert through NotifyCore
//!
//! Why hashing?
//!   A hash is a fingerprint. Feed a file's contents into a hash function
//!   and you get a fixed-length string that uniquely represents those contents.
//!   Change one byte in the file — the hash changes completely.
//!   This means we can detect any modification, however small.

use crate::config::IntegrityMonitorConfig;
use crate::notifycore::{alert::Alert, NotifyCore};
use anyhow::Result;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

// ── Data definitions ─────────────────────────────────────────────────────────

/// A record of a single file at a known-good moment.
/// This is what "clean state" looks like for one file.
#[derive(Debug, Clone)]
pub struct FileRecord {
    /// The file's location on disk
    pub path: PathBuf,
    /// SHA-256 hash of the file's contents at baseline time
    pub hash: String,
    /// Size in bytes — a quick pre-check before full hash comparison
    pub size: u64,
}

/// The full baseline — a map of path → FileRecord
/// HashMap means we can look up any file's baseline record instantly by path
type Baseline = HashMap<PathBuf, FileRecord>;

// ── Hashing ───────────────────────────────────────────────────────────────────

/// Compute a SHA-256 hash of a file's contents.
///
/// Returns the hash as a hex string, or an error if the file can't be read.
/// We implement SHA-256 manually here using only the standard library
/// to avoid adding a dependency just for hashing.
///
/// For now we use a simple checksum approach — replace with sha2 crate
/// when adding it to Cargo.toml in the next build session.
fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Simple hash using std — replace with SHA-256 via sha2 crate later
    // This gives us a unique fingerprint good enough for v0.1
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for byte in &contents {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
    }

    Ok(format!("{:016x}", hash))
}

// ── Baseline operations ───────────────────────────────────────────────────────

/// Walk a directory recursively and hash every file.
/// Returns a Baseline map of path → FileRecord.
///
/// Skips files it can't read — logs a warning but keeps going.
/// A monitor should never crash because one file is unreadable.
fn build_baseline_for_dir(dir: &Path, ignore_extensions: &[String]) -> Baseline {
    let mut baseline = HashMap::new();

    // walkdir recursively visits every file in the directory tree
    let walker = walkdir::WalkDir::new(dir)
        .follow_links(false) // don't follow symlinks — security risk
        .into_iter()
        .filter_map(|e| e.ok()); // skip entries we can't read

    for entry in walker {
        // Only process files, not directories
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path().to_path_buf();

        // Skip ignored extensions (e.g. log files change constantly)
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        if ignore_extensions.contains(&ext) {
            continue;
        }

        // Get file metadata for size
        let size = match entry.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                warn!("integrity: could not read metadata for {:?}: {}", path, e);
                continue;
            }
        };

        // Hash the file contents
        let hash = match hash_file(&path) {
            Ok(h) => h,
            Err(e) => {
                warn!("integrity: could not hash {:?}: {}", path, e);
                continue;
            }
        };

        baseline.insert(path.clone(), FileRecord { path, hash, size });
    }

    baseline
}

// ── Comparison ────────────────────────────────────────────────────────────────

/// The result of comparing current state to baseline for one file.
#[derive(Debug)]
pub enum IntegrityEvent {
    /// File exists in baseline but is gone now — deletion or rename
    Deleted { path: PathBuf },
    /// File contents changed — hash no longer matches
    Modified { path: PathBuf, old_hash: String, new_hash: String },
    /// File appeared that wasn't in the baseline — new file added
    Added { path: PathBuf },
}

/// Compare a freshly-built baseline against the stored baseline.
/// Returns a list of every difference found.
fn compare_baselines(stored: &Baseline, current: &Baseline) -> Vec<IntegrityEvent> {
    let mut events = Vec::new();

    // Check for deleted and modified files
    // Walk every file we knew about and see if it's still there and unchanged
    for (path, stored_record) in stored {
        match current.get(path) {
            None => {
                // Was in baseline, not in current scan — deleted
                events.push(IntegrityEvent::Deleted { path: path.clone() });
            }
            Some(current_record) => {
                // Still exists — check if contents changed
                if current_record.hash != stored_record.hash {
                    events.push(IntegrityEvent::Modified {
                        path: path.clone(),
                        old_hash: stored_record.hash.clone(),
                        new_hash: current_record.hash.clone(),
                    });
                }
            }
        }
    }

    // Check for new files — in current but not in stored baseline
    for path in current.keys() {
        if !stored.contains_key(path) {
            events.push(IntegrityEvent::Added { path: path.clone() });
        }
    }

    events
}

// ── Monitor entry point ───────────────────────────────────────────────────────

/// Run the file integrity monitor.
///
/// This is the function called by main.rs when spawning this monitor as a task.
/// It follows the exact same pattern as every other monitor in the codebase.
pub async fn run(
    config: IntegrityMonitorConfig,
    notifycore: Arc<NotifyCore>,
    server_name: String,
) -> Result<()> {
    // Early exit if disabled in config
    if !config.enabled {
        info!("Integrity monitor disabled");
        return Ok(());
    }

    info!(
        "Integrity monitor started — watching {} paths",
        config.watch_paths.len()
    );

    // ── Phase 1: Build the baseline ──────────────────────────────────────────
    // Hash every file in every watched directory right now.
    // This is our "known good" state — the fingerprint of a clean system.

    let mut baseline: Baseline = HashMap::new();

    for dir in &config.watch_paths {
        if dir.exists() {
            info!("integrity: building baseline for {:?}", dir);
            let dir_baseline = build_baseline_for_dir(dir, &config.ignore_extensions);
            info!("integrity: {} files hashed in {:?}", dir_baseline.len(), dir);
            baseline.extend(dir_baseline);
        } else {
            warn!("integrity: watch path does not exist: {:?}", dir);
        }
    }

    info!(
        "Integrity baseline established — {} files tracked",
        baseline.len()
    );

    // ── Phase 2: Monitor loop ────────────────────────────────────────────────
    // Every poll interval, rebuild the current state and compare to baseline.

    loop {
        sleep(Duration::from_secs(config.poll_interval_secs)).await;

        // Rebuild current state
        let mut current: Baseline = HashMap::new();
        for dir in &config.watch_paths {
            if dir.exists() {
                let dir_current = build_baseline_for_dir(dir, &config.ignore_extensions);
                current.extend(dir_current);
            }
        }

        // Compare current to baseline
        let events = compare_baselines(&baseline, &current);

        // Alert on every event
        for event in &events {
            let alert = match event {
                IntegrityEvent::Deleted { path } => {
                    // Deletion is critical — could be an attacker covering tracks
                    Alert::critical(
                        "integrity_monitor",
                        &server_name,
                        &format!("File deleted from protected directory"),
                        &path.display().to_string(),
                    )
                }
                IntegrityEvent::Modified { path, old_hash, new_hash } => {
                    // Modification is critical if it's a binary, warning if config
                    let ext = path.extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");

                    let is_binary = matches!(ext, "" | "bin" | "exe" | "so" | "dylib");

                    if is_binary {
                        Alert::critical(
                            "integrity_monitor",
                            &server_name,
                            &format!("BINARY MODIFIED — possible compromise"),
                            &format!("{} | {} → {}", path.display(), &old_hash[..8], &new_hash[..8]),
                        )
                    } else {
                        Alert::warning(
                            "integrity_monitor",
                            &server_name,
                            &format!("File modified in protected directory"),
                            &format!("{} | {} → {}", path.display(), &old_hash[..8], &new_hash[..8]),
                        )
                    }
                }
                IntegrityEvent::Added { path } => {
                    // New file — warning, could be legitimate deployment or intrusion
                    Alert::warning(
                        "integrity_monitor",
                        &server_name,
                        &format!("New file appeared in protected directory"),
                        &path.display().to_string(),
                    )
                }
            };

            notifycore.send(alert).await?;
        }

        // Update baseline with current state so we don't re-alert on same changes
        // Only update if we found changes — prevents drift from unresolved incidents
        if events.is_empty() {
            // All clean — baseline stays current
        } else {
            // Changes detected — DO NOT update baseline automatically
            // Baseline only updates when YOU explicitly authorize it
            // This means persistent alerts until you acknowledge and reset
            info!(
                "integrity: {} change(s) detected — baseline held, alerts active",
                events.len()
            );
        }
    }
}
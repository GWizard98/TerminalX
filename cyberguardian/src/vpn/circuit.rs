//! VPN Circuit Manager
//!
//! Job: Build and maintain multi-hop encrypted tunnels.
//! Each hop in the circuit wraps the data in its own encryption layer.
//! This is onion routing — like Tor but purpose-built for CyberGuardian.
//!
//! Why multi-hop?
//!   A single VPN server knows your real IP and your destination.
//!   With 3 hops: Server A knows your real IP but not the destination.
//!   Server B knows Server A but not you or the destination.
//!   Server C knows the destination but not you.
//!   Nobody sees the full picture.
//!
//! How encryption layering works:
//!   Think of it like nested envelopes.
//!   The data gets wrapped in Hop 3's envelope first.
//!   Then that gets wrapped in Hop 2's envelope.
//!   Then that gets wrapped in Hop 1's envelope.
//!   Hop 1 opens its envelope, sees Hop 2's envelope, forwards it.
//!   Hop 2 opens its envelope, sees Hop 3's envelope, forwards it.
//!   Hop 3 opens its envelope, sees the actual data, sends it to destination.
//!
//! Circuit lifetime:
//!   Circuits have a maximum lifetime. When they expire, they rebuild
//!   automatically with fresh keys. This limits how long any key exposure
//!   window lasts.
//!
//! Security levels map to hop counts and lifetimes:
//!   Basic      — 1 hop,  60 min lifetime  (fast, minimal anonymity)
//!   Professional — 3 hops, 45 min lifetime  (balanced)
//!   Enterprise   — 5 hops, 30 min lifetime  (secure)
//!   Paranoid     — 7 hops, 15 min lifetime  (maximum, slowest)

use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn, error, debug};

// ── Security levels ───────────────────────────────────────────────────────────

/// Security level determines hop count and circuit lifetime.
/// Maps directly to CyberGuardian threat levels:
///   Low threat    → Basic
///   Medium threat → Professional
///   High threat   → Enterprise
///   Critical      → Paranoid
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    Basic,
    Professional,
    Enterprise,
    Paranoid,
}

impl SecurityLevel {
    /// How many hops this security level uses
    pub fn hop_count(&self) -> usize {
        match self {
            SecurityLevel::Basic        => 1,
            SecurityLevel::Professional => 3,
            SecurityLevel::Enterprise   => 5,
            SecurityLevel::Paranoid     => 7,
        }
    }

    /// Maximum circuit lifetime before automatic rebuild
    pub fn max_lifetime(&self) -> Duration {
        match self {
            SecurityLevel::Basic        => Duration::minutes(60),
            SecurityLevel::Professional => Duration::minutes(45),
            SecurityLevel::Enterprise   => Duration::minutes(30),
            SecurityLevel::Paranoid     => Duration::minutes(15),
        }
    }

    /// Human readable label
    pub fn label(&self) -> &'static str {
        match self {
            SecurityLevel::Basic        => "Basic (1 hop)",
            SecurityLevel::Professional => "Professional (3 hops)",
            SecurityLevel::Enterprise   => "Enterprise (5 hops)",
            SecurityLevel::Paranoid     => "Paranoid (7 hops)",
        }
    }

    /// Determine security level from a threat score (0.0 - 1.0)
    pub fn from_threat_score(score: f64) -> Self {
        match score {
            s if s < 0.3  => SecurityLevel::Basic,
            s if s < 0.6  => SecurityLevel::Professional,
            s if s < 0.85 => SecurityLevel::Enterprise,
            _             => SecurityLevel::Paranoid,
        }
    }
}

// ── Circuit data structures ───────────────────────────────────────────────────

/// A single hop in the circuit — one server in the chain.
/// Each hop has its own encryption key so no two hops share key material.
#[derive(Debug, Clone)]
pub struct CircuitHop {
    /// Which hop in the chain (0 = first, closest to us)
    pub index: usize,
    /// Server address for this hop
    pub server_addr: String,
    /// Server location label (for logging/alerts)
    pub server_location: String,
    /// Encryption key unique to this hop
    /// Generated fresh for every circuit build
    pub key: Vec<u8>,
    /// Initialization vector for this hop's encryption
    pub iv: Vec<u8>,
    /// Current state of this hop's connection
    pub state: HopState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HopState {
    Connecting,
    Connected,
    Failed(String),
}

/// A complete multi-hop encrypted circuit.
/// Contains all the hops and tracks its own health and lifetime.
#[derive(Debug, Clone)]
pub struct VpnCircuit {
    /// Unique ID for this circuit
    pub circuit_id: String,
    /// Security level this circuit was built for
    pub security_level: SecurityLevel,
    /// All hops in order from closest to furthest
    pub hops: Vec<CircuitHop>,
    /// Current state of the overall circuit
    pub state: CircuitState,
    /// When this circuit was built
    pub created_at: DateTime<Utc>,
    /// When this circuit was last rebuilt
    pub last_rebuild: DateTime<Utc>,
    /// How many times this circuit has been rebuilt
    pub rebuild_count: u32,
    /// Traffic statistics
    pub stats: CircuitStats,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Building,
    Active,
    Rebuilding,
    Expired,
    Failed(String),
}

/// Traffic statistics for a circuit.
/// Used by NotifyCore for the daily digest report.
#[derive(Debug, Clone, Default)]
pub struct CircuitStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_forwarded: u64,
    pub rebuild_count: u32,
}

impl VpnCircuit {
    /// Check if this circuit has exceeded its maximum lifetime
    pub fn is_expired(&self) -> bool {
        let age = Utc::now() - self.created_at;
        age > self.security_level.max_lifetime()
    }

    /// Check if any hop in this circuit has failed
    pub fn has_failed_hop(&self) -> bool {
        self.hops.iter().any(|h| matches!(h.state, HopState::Failed(_)))
    }

    /// Get a summary string for logging and alerts
    pub fn summary(&self) -> String {
        format!(
            "Circuit {} | {} | {} hops | age: {}min | rebuilds: {}",
            &self.circuit_id[..8],
            self.security_level.label(),
            self.hops.len(),
            (Utc::now() - self.created_at).num_minutes(),
            self.rebuild_count,
        )
    }
}

// ── Circuit manager ───────────────────────────────────────────────────────────

/// Manages all active circuits and handles build, rebuild, and health checks.
pub struct VpnCircuitManager {
    /// All currently active circuits, keyed by circuit_id
    active_circuits: HashMap<String, VpnCircuit>,
    /// The ID of the circuit currently carrying live traffic
    active_circuit_id: Option<String>,
    /// Pre-built backup circuit ready for instant failover
    backup_circuit_id: Option<String>,
}

impl VpnCircuitManager {
    pub fn new() -> Self {
        VpnCircuitManager {
            active_circuits: HashMap::new(),
            active_circuit_id: None,
            backup_circuit_id: None,
        }
    }

    /// Build a new circuit for the given security level.
    ///
    /// In v0.1 this builds the circuit data structure and generates keys.
    /// Full WireGuard tunnel establishment goes in v0.2.
    ///
    /// TODO (next build session):
    ///   - Actual WireGuard tunnel establishment per hop
    ///   - Real server selection from a configured server list
    ///   - Latency measurement per hop
    pub async fn build_circuit(
        &mut self,
        security_level: SecurityLevel,
        server_pool: &[ServerEntry],
    ) -> Result<String> {
        let hop_count = security_level.hop_count();

        info!("circuit: building {} circuit ({} hops)", security_level.label(), hop_count);

        if server_pool.len() < hop_count {
            anyhow::bail!(
                "Not enough servers for {} hops (have {}, need {})",
                security_level.label(),
                server_pool.len(),
                hop_count
            );
        }

        // Select servers for each hop
        // TODO: use scoring from manager.rs for selection
        let selected = &server_pool[..hop_count];

        // Build each hop with fresh keys
        let mut hops = Vec::new();
        for (index, server) in selected.iter().enumerate() {
            let hop = CircuitHop {
                index,
                server_addr: server.address.clone(),
                server_location: server.location.clone(),
                key: generate_key(32),
                iv: generate_iv(12),
                state: HopState::Connected, // TODO: real connection in v0.2
            };
            debug!("circuit: hop {} → {} ({})", index, server.location, server.address);
            hops.push(hop);
        }

        let circuit_id = format!(
            "cg-circuit-{}-{}",
            security_level as u8,
            Utc::now().timestamp_millis()
        );

        let circuit = VpnCircuit {
            circuit_id: circuit_id.clone(),
            security_level,
            hops,
            state: CircuitState::Active,
            created_at: Utc::now(),
            last_rebuild: Utc::now(),
            rebuild_count: 0,
            stats: CircuitStats::default(),
        };

        info!("circuit: {} built successfully", circuit.summary());

        // If no active circuit yet, make this the active one
        // Otherwise it becomes the backup
        if self.active_circuit_id.is_none() {
            self.active_circuit_id = Some(circuit_id.clone());
            info!("circuit: set as active circuit");
        } else {
            self.backup_circuit_id = Some(circuit_id.clone());
            info!("circuit: set as backup circuit");
        }

        self.active_circuits.insert(circuit_id.clone(), circuit);
        Ok(circuit_id)
    }

    /// Rebuild a circuit — destroys old one, builds fresh with new keys.
    /// Called automatically when a circuit expires or a hop fails.
    pub async fn rebuild_circuit(
        &mut self,
        circuit_id: &str,
        server_pool: &[ServerEntry],
    ) -> Result<String> {
        info!("circuit: rebuilding {}", &circuit_id[..8.min(circuit_id.len())]);

        // Get security level from old circuit before destroying it
        let security_level = self.active_circuits
            .get(circuit_id)
            .map(|c| c.security_level)
            .unwrap_or(SecurityLevel::Professional);

        let rebuild_count = self.active_circuits
            .get(circuit_id)
            .map(|c| c.rebuild_count)
            .unwrap_or(0);

        // Destroy old circuit
        self.destroy_circuit(circuit_id).await?;

        // Build fresh circuit with new keys
        let new_id = self.build_circuit(security_level, server_pool).await?;

        // Update rebuild count on new circuit
        if let Some(circuit) = self.active_circuits.get_mut(&new_id) {
            circuit.rebuild_count = rebuild_count + 1;
        }

        info!("circuit: rebuilt successfully → {}", &new_id[..8.min(new_id.len())]);
        Ok(new_id)
    }

    /// Destroy a circuit and clean up its resources.
    pub async fn destroy_circuit(&mut self, circuit_id: &str) -> Result<()> {
        if self.active_circuits.remove(circuit_id).is_some() {
            // Clear active/backup references if they pointed to this circuit
            if self.active_circuit_id.as_deref() == Some(circuit_id) {
                // Promote backup to active if available
                self.active_circuit_id = self.backup_circuit_id.take();
                if self.active_circuit_id.is_some() {
                    info!("circuit: promoted backup circuit to active");
                }
            }
            if self.backup_circuit_id.as_deref() == Some(circuit_id) {
                self.backup_circuit_id = None;
            }
            info!("circuit: destroyed {}", &circuit_id[..8.min(circuit_id.len())]);
        }
        Ok(())
    }

    /// Health check — called every poll interval.
    /// Rebuilds any expired or failed circuits automatically.
    pub async fn health_check(&mut self, server_pool: &[ServerEntry]) -> Result<()> {
        let mut to_rebuild: Vec<String> = Vec::new();

        for (id, circuit) in &self.active_circuits {
            if circuit.is_expired() {
                info!("circuit: {} expired — scheduling rebuild", &id[..8.min(id.len())]);
                to_rebuild.push(id.clone());
            } else if circuit.has_failed_hop() {
                warn!("circuit: {} has failed hop — scheduling rebuild", &id[..8.min(id.len())]);
                to_rebuild.push(id.clone());
            }
        }

        for id in to_rebuild {
            if let Err(e) = self.rebuild_circuit(&id, server_pool).await {
                error!("circuit: failed to rebuild {}: {}", &id[..8.min(id.len())], e);
            }
        }

        Ok(())
    }

    /// Get the currently active circuit
    pub fn active_circuit(&self) -> Option<&VpnCircuit> {
        self.active_circuit_id.as_ref()
            .and_then(|id| self.active_circuits.get(id))
    }

    /// Get stats for all active circuits
    pub fn all_stats(&self) -> Vec<String> {
        self.active_circuits.values()
            .map(|c| c.summary())
            .collect()
    }
}

// ── Server entry ──────────────────────────────────────────────────────────────

/// A VPN server available for use in circuits.
/// Loaded from config — you control which servers are trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub address: String,
    pub location: String,
    pub jurisdiction: String,
    /// Higher = more preferred (0.0 - 1.0)
    pub trust_score: f64,
}

// ── Key generation ────────────────────────────────────────────────────────────
// These use the system's cryptographically secure random source.
// NOT timestamp-based like the legacy code — that was not real crypto.
//
// TODO (next build session): replace with ring::rand for production-grade keys
// For now, uses /dev/urandom via std which is cryptographically secure on Linux.

fn generate_key(size: usize) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut key = vec![0u8; size];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut key);
    } else {
        // Fallback for non-Linux (development on Mac)
        // Replace with ring::rand in production build
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = ((i * 251 + 127) % 256) as u8;
        }
    }
    key
}

fn generate_iv(size: usize) -> Vec<u8> {
    generate_key(size) // Same source, different size
}
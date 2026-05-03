//! VPN Manager
//!
//! Job: Sit between CyberGuardian's threat detection and the VPN system.
//! When a threat score comes in, decide what security level is needed,
//! coordinate the circuit manager to build or upgrade, and tell the
//! kill switch what to do.
//!
//! This is the brain. It doesn't build tunnels (circuit.rs does that).
//! It doesn't manage firewall rules (killswitch.rs does that).
//! It decides WHEN and WHY those things happen.
//!
//! The threat feedback loop:
//!
//!   CyberGuardian monitor detects threat
//!           ↓
//!   Calls vpn_manager.on_threat_detected(score)
//!           ↓
//!   Manager converts score → SecurityLevel
//!           ↓
//!   If level upgrade needed → rebuild circuit at higher security
//!           ↓
//!   Kill switch stays active throughout
//!           ↓
//!   NotifyCore alert fired with VPN status
//!
//! SurfShark architecture influence:
//!   The manager follows the privileged helper pattern from SurfShark's DMG.
//!   It owns the connection state and coordinates between components,
//!   but each component (circuit, killswitch) is independently responsible
//!   for its own domain. No component reaches into another's state directly.

use crate::vpn::circuit::{SecurityLevel, VpnCircuitManager, ServerEntry};
use crate::vpn::killswitch::{KillSwitch, KillSwitchConfig};
use crate::notifycore::{NotifyCore, alert::Alert};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn, error};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Full VPN configuration — loaded from config.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    /// Whether VPN is enabled at all
    pub enabled: bool,
    /// Starting security level on boot
    pub default_security_level: String,
    /// Threat score threshold to auto-upgrade security level
    /// e.g. 0.6 means upgrade from Basic to Professional when score hits 0.6
    pub auto_upgrade_threshold: f64,
    /// Kill switch configuration
    pub kill_switch: KillSwitchSettings,
    /// VPN servers available for circuit building
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchSettings {
    pub enabled: bool,
    pub tunnel_interface: String,
    /// Your own IP — bypass so you don't lock yourself out of SSH
    pub bypass_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub location: String,
    pub jurisdiction: String,
    pub trust_score: f64,
}

impl Default for VpnConfig {
    fn default() -> Self {
        VpnConfig {
            enabled: true,
            default_security_level: "professional".to_string(),
            auto_upgrade_threshold: 0.6,
            kill_switch: KillSwitchSettings {
                enabled: true,
                tunnel_interface: "wg0".to_string(),
                bypass_ips: Vec::new(),
            },
            servers: Vec::new(),
        }
    }
}

// ── Connection state ──────────────────────────────────────────────────────────

/// The current state of the VPN connection.
/// This is what NotifyCore reports in alerts and daily digest.
#[derive(Debug, Clone, PartialEq)]
pub enum VpnState {
    /// VPN is not running
    Disconnected,
    /// Building the initial circuit
    Connecting,
    /// Connected and protecting traffic
    Connected {
        security_level: SecurityLevel,
        circuit_id: String,
    },
    /// Upgrading to a higher security level due to threat detection
    Upgrading {
        from: SecurityLevel,
        to: SecurityLevel,
    },
    /// VPN dropped — kill switch is blocking all traffic
    KillSwitchActive,
    /// Rebuilding after a drop or circuit expiry
    Reconnecting,
}

impl VpnState {
    pub fn label(&self) -> String {
        match self {
            VpnState::Disconnected      => "Disconnected".to_string(),
            VpnState::Connecting        => "Connecting...".to_string(),
            VpnState::Connected { security_level, .. } => {
                format!("Connected — {}", security_level.label())
            }
            VpnState::Upgrading { from, to } => {
                format!("Upgrading {} → {}", from.label(), to.label())
            }
            VpnState::KillSwitchActive  => "KILL SWITCH ACTIVE — traffic blocked".to_string(),
            VpnState::Reconnecting      => "Reconnecting...".to_string(),
        }
    }
}

// ── VPN Manager ───────────────────────────────────────────────────────────────

pub struct VpnManager {
    config: VpnConfig,
    state: VpnState,
    circuit_manager: VpnCircuitManager,
    kill_switch: KillSwitch,
    server_pool: Vec<ServerEntry>,
    /// Current threat score — updated by CyberGuardian monitors
    current_threat_score: f64,
}

impl VpnManager {
    /// Create a new VPN manager from config
    pub fn new(config: VpnConfig) -> Self {
        // Convert ServerConfig → ServerEntry for the circuit manager
        let server_pool: Vec<ServerEntry> = config.servers.iter().map(|s| ServerEntry {
            address: s.address.clone(),
            location: s.location.clone(),
            jurisdiction: s.jurisdiction.clone(),
            trust_score: s.trust_score,
        }).collect();

        // Build kill switch config from VPN config
        let ks_config = KillSwitchConfig {
            tunnel_interface: config.kill_switch.tunnel_interface.clone(),
            bypass_ips: config.kill_switch.bypass_ips.clone(),
            allow_lan: false,
        };

        VpnManager {
            config,
            state: VpnState::Disconnected,
            circuit_manager: VpnCircuitManager::new(),
            kill_switch: KillSwitch::new(ks_config),
            server_pool,
            current_threat_score: 0.3, // Start at low threat
        }
    }

    /// Start the VPN — build initial circuit and activate kill switch.
    /// Called by main.rs when CyberGuardian starts up.
    pub async fn start(&mut self, notifycore: Arc<NotifyCore>, server_name: &str) -> Result<()> {
        if !self.config.enabled {
            info!("vpn: disabled in config — skipping");
            return Ok(());
        }

        info!("vpn: starting up");
        self.state = VpnState::Connecting;

        // Determine starting security level from config
        let security_level = match self.config.default_security_level.as_str() {
            "basic"        => SecurityLevel::Basic,
            "enterprise"   => SecurityLevel::Enterprise,
            "paranoid"     => SecurityLevel::Paranoid,
            _              => SecurityLevel::Professional, // default
        };

        // Check we have enough servers
        if self.server_pool.len() < security_level.hop_count() {
            let alert = Alert::critical(
                "vpn_manager",
                server_name,
                &format!("Not enough VPN servers configured for {} security level — {} needed, {} available",
                    security_level.label(),
                    security_level.hop_count(),
                    self.server_pool.len()
                ),
                "Check [vpn.servers] in config.toml",
            );
            notifycore.send(alert).await?;
            anyhow::bail!("Insufficient VPN servers in config");
        }

        // Build the initial circuit
        let circuit_id = self.circuit_manager
            .build_circuit(security_level, &self.server_pool)
            .await?;

        // Activate kill switch
        if self.config.kill_switch.enabled {
            self.kill_switch
                .activate(&self.config.kill_switch.tunnel_interface)
                .await?;
        }

        self.state = VpnState::Connected { security_level, circuit_id: circuit_id.clone() };

        let alert = Alert::info(
            "vpn_manager",
            server_name,
            &format!("VPN connected — {}", security_level.label()),
            &circuit_id,
        );
        notifycore.send(alert).await?;

        info!("vpn: connected at {}", security_level.label());
        Ok(())
    }

    /// Called by CyberGuardian monitors when a threat is detected.
    ///
    /// This is the core of the adaptive VPN system:
    ///   - SSH brute force fires this with score 0.8 → upgrades to Enterprise
    ///   - Critical alert fires this with score 0.95 → upgrades to Paranoid
    ///   - Threat resolves → can downgrade back to Professional
    pub async fn on_threat_detected(
        &mut self,
        threat_score: f64,
        notifycore: Arc<NotifyCore>,
        server_name: &str,
    ) -> Result<()> {
        self.current_threat_score = threat_score;

        let needed_level = SecurityLevel::from_threat_score(threat_score);

        // Check if we need to upgrade
        if let VpnState::Connected { security_level: current_level, .. } = &self.state.clone() {
            if self.should_upgrade(current_level, &needed_level) {
                info!("vpn: threat score {:.2} — upgrading {} → {}",
                    threat_score,
                    current_level.label(),
                    needed_level.label()
                );

                self.upgrade_security(
                    *current_level,
                    needed_level,
                    notifycore,
                    server_name
                ).await?;
            }
        }

        Ok(())
    }

    /// Upgrade to a higher security level by rebuilding the circuit.
    async fn upgrade_security(
        &mut self,
        from: SecurityLevel,
        to: SecurityLevel,
        notifycore: Arc<NotifyCore>,
        server_name: &str,
    ) -> Result<()> {
        self.state = VpnState::Upgrading { from, to };

        let alert = Alert::warning(
            "vpn_manager",
            server_name,
            &format!("VPN upgrading security: {} → {}", from.label(), to.label()),
            &format!("Threat score: {:.2}", self.current_threat_score),
        );
        notifycore.send(alert).await?;

        // Build new circuit at higher security level
        let new_circuit_id = self.circuit_manager
            .build_circuit(to, &self.server_pool)
            .await?;

        self.state = VpnState::Connected {
            security_level: to,
            circuit_id: new_circuit_id.clone(),
        };

        let alert = Alert::info(
            "vpn_manager",
            server_name,
            &format!("VPN upgraded to {}", to.label()),
            &new_circuit_id,
        );
        notifycore.send(alert).await?;

        info!("vpn: upgraded to {}", to.label());
        Ok(())
    }

    /// Called when the VPN tunnel drops unexpectedly.
    /// Activates kill switch blocking and fires critical alert.
    pub async fn on_tunnel_drop(
        &mut self,
        notifycore: Arc<NotifyCore>,
        server_name: &str,
    ) -> Result<()> {
        error!("vpn: tunnel dropped unexpectedly");

        self.kill_switch.on_tunnel_drop().await?;
        self.state = VpnState::KillSwitchActive;

        let alert = Alert::critical(
            "vpn_manager",
            server_name,
            "VPN tunnel dropped — kill switch active, all traffic blocked",
            "Attempting automatic reconnection",
        );
        notifycore.send(alert).await?;

        // Attempt automatic reconnection
        self.reconnect(notifycore, server_name).await?;

        Ok(())
    }

    /// Attempt to reconnect after a tunnel drop.
    async fn reconnect(
        &mut self,
        notifycore: Arc<NotifyCore>,
        server_name: &str,
    ) -> Result<()> {
        self.state = VpnState::Reconnecting;
        info!("vpn: attempting reconnection");

        let security_level = SecurityLevel::from_threat_score(self.current_threat_score);

        match self.circuit_manager.build_circuit(security_level, &self.server_pool).await {
            Ok(circuit_id) => {
                // Restore tunnel through kill switch
                self.kill_switch
                    .on_tunnel_restore(&self.config.kill_switch.tunnel_interface)
                    .await?;

                self.state = VpnState::Connected { security_level, circuit_id: circuit_id.clone() };

                let alert = Alert::info(
                    "vpn_manager",
                    server_name,
                    &format!("VPN reconnected — {}", security_level.label()),
                    &circuit_id,
                );
                notifycore.send(alert).await?;

                info!("vpn: reconnected at {}", security_level.label());
            }
            Err(e) => {
                error!("vpn: reconnection failed: {}", e);

                let alert = Alert::critical(
                    "vpn_manager",
                    server_name,
                    "VPN reconnection failed — server remains protected by kill switch",
                    &e.to_string(),
                );
                notifycore.send(alert).await?;
            }
        }

        Ok(())
    }

    /// Health check — runs every poll interval.
    /// Verifies kill switch rules and checks circuit health.
    pub async fn health_check(
        &mut self,
        notifycore: Arc<NotifyCore>,
        server_name: &str,
    ) -> Result<()> {
        // Verify kill switch rules haven't been tampered with
        if self.config.kill_switch.enabled {
            match self.kill_switch.verify_rules().await {
                Ok(false) => {
                    let alert = Alert::critical(
                        "vpn_manager",
                        server_name,
                        "Kill switch rules missing — possible firewall tampering",
                        "Re-applying kill switch rules",
                    );
                    notifycore.send(alert).await?;

                    // Re-apply rules
                    if let Err(e) = self.kill_switch
                        .activate(&self.config.kill_switch.tunnel_interface)
                        .await
                    {
                        error!("vpn: failed to re-apply kill switch rules: {}", e);
                    }
                }
                Err(e) => {
                    warn!("vpn: kill switch verification error: {}", e);
                }
                Ok(true) => {} // All good
            }
        }

        // Run circuit health check
        self.circuit_manager.health_check(&self.server_pool).await?;

        Ok(())
    }

    /// Clean shutdown — deactivate kill switch and destroy circuits.
    /// ALWAYS call this on graceful shutdown.
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("vpn: shutting down cleanly");

        // Deactivate kill switch first — restores normal routing
        if let Err(e) = self.kill_switch.deactivate().await {
            error!("vpn: error deactivating kill switch on shutdown: {}", e);
        }

        self.state = VpnState::Disconnected;
        info!("vpn: shutdown complete");
        Ok(())
    }

    /// Get current VPN state for dashboard/reporting
    pub fn state(&self) -> &VpnState {
        &self.state
    }

    /// Get current threat score
    pub fn threat_score(&self) -> f64 {
        self.current_threat_score
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Determine if we need to upgrade security level
    fn should_upgrade(&self, current: &SecurityLevel, needed: &SecurityLevel) -> bool {
        use SecurityLevel::*;
        matches!(
            (current, needed),
            (Basic, Professional | Enterprise | Paranoid)
            | (Professional, Enterprise | Paranoid)
            | (Enterprise, Paranoid)
        )
    }
}
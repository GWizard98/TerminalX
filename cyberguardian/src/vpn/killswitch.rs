//! VPN Kill Switch
//!
//! Job: If the VPN tunnel drops for ANY reason, immediately block all
//! outbound traffic until the tunnel is restored.
//!
//! Why this matters for TradeEco:
//!   If the VPN drops without a kill switch, the server continues
//!   operating with its real IP exposed. For a live trading system
//!   that means OANDA API keys, trade data, and server location
//!   are suddenly visible. The kill switch prevents this entirely.
//!
//! How it works:
//!   - On VPN connect: install firewall rules that ALLOW traffic only
//!     through the VPN tunnel interface
//!   - On VPN disconnect: those rules remain — traffic is blocked
//!   - On VPN restore: re-allow traffic through the new tunnel
//!   - On CyberGuardian shutdown: clean up rules, restore normal routing
//!
//! Implementation:
//!   Uses `iptables` on Linux (the droplet) via shell commands.
//!   This is intentional — iptables is the standard Linux firewall tool
//!   and is always available on Ubuntu without extra dependencies.

use anyhow::Result;
use std::process::Command;
use tracing::{info, warn, error};

// ── Data definitions ──────────────────────────────────────────────────────────

/// The current state of the kill switch
#[derive(Debug, Clone, PartialEq)]
pub enum KillSwitchState {
    /// Kill switch is inactive — normal traffic flows
    Inactive,
    /// VPN is connected — traffic allowed through tunnel only
    Active { tunnel_interface: String },
    /// VPN dropped — all outbound traffic blocked
    Blocking,
    /// Kill switch rules failed to apply — alert immediately
    Failed(String),
}

/// Configuration for the kill switch
#[derive(Debug, Clone)]
pub struct KillSwitchConfig {
    /// Network interface for the VPN tunnel (e.g. "wg0" for WireGuard)
    pub tunnel_interface: String,
    /// Always-allowed destinations regardless of VPN state
    /// These bypass the kill switch — use sparingly
    /// Example: your own IP for SSH access so you don't lock yourself out
    pub bypass_ips: Vec<String>,
    /// Whether to allow LAN traffic when VPN is down
    pub allow_lan: bool,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        KillSwitchConfig {
            tunnel_interface: "wg0".to_string(), // WireGuard default
            bypass_ips: Vec::new(),
            allow_lan: false, // Default: block everything on VPN drop
        }
    }
}

// ── Kill switch implementation ─────────────────────────────────────────────────

pub struct KillSwitch {
    config: KillSwitchConfig,
    state: KillSwitchState,
}

impl KillSwitch {
    pub fn new(config: KillSwitchConfig) -> Self {
        KillSwitch {
            config,
            state: KillSwitchState::Inactive,
        }
    }

    /// Activate the kill switch when VPN connects.
    /// Installs firewall rules that only allow traffic through the tunnel.
    pub async fn activate(&mut self, tunnel_interface: &str) -> Result<()> {
        info!("killswitch: activating on interface {}", tunnel_interface);

        // Allow traffic on the tunnel interface
        run_iptables(&["-A", "OUTPUT", "-o", tunnel_interface, "-j", "ACCEPT"])?;

        // Allow loopback (localhost traffic must always work)
        run_iptables(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;

        // Allow bypass IPs (e.g. your SSH IP so you don't lock yourself out)
        for ip in &self.config.bypass_ips.clone() {
            run_iptables(&["-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"])?;
            info!("killswitch: bypass allowed for {}", ip);
        }

        // Allow established connections to continue
        run_iptables(&["-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;

        // Block everything else outbound
        // This is the kill switch rule — if VPN drops, this remains and blocks all traffic
        run_iptables(&["-A", "OUTPUT", "-j", "DROP"])?;

        self.state = KillSwitchState::Active {
            tunnel_interface: tunnel_interface.to_string(),
        };

        info!("killswitch: active — traffic locked to VPN tunnel");
        Ok(())
    }

    /// Called when the VPN tunnel drops unexpectedly.
    /// The blocking rules are already in place — this just updates state
    /// and fires an alert through NotifyCore.
    pub async fn on_tunnel_drop(&mut self) -> Result<()> {
        warn!("killswitch: VPN tunnel dropped — all outbound traffic is now BLOCKED");

        self.state = KillSwitchState::Blocking;

        // The iptables DROP rule is already in place from activate()
        // Traffic is already blocked — no additional action needed
        // NotifyCore alert is fired by the caller (vpn/manager.rs)

        Ok(())
    }

    /// Called when the VPN tunnel restores after a drop.
    /// Re-allows traffic through the new tunnel interface.
    pub async fn on_tunnel_restore(&mut self, new_interface: &str) -> Result<()> {
        info!("killswitch: VPN tunnel restored on {} — re-allowing traffic", new_interface);

        // Remove the old tunnel allow rule if interface changed
        if let KillSwitchState::Active { tunnel_interface } = &self.state.clone() {
            if tunnel_interface != new_interface {
                let _ = run_iptables(&["-D", "OUTPUT", "-o", tunnel_interface, "-j", "ACCEPT"]);
            }
        }

        // Allow traffic on the new tunnel interface
        run_iptables(&["-A", "OUTPUT", "-o", new_interface, "-j", "ACCEPT"])?;

        self.state = KillSwitchState::Active {
            tunnel_interface: new_interface.to_string(),
        };

        info!("killswitch: traffic restored through VPN tunnel");
        Ok(())
    }

    /// Deactivate the kill switch completely.
    /// Called when CyberGuardian shuts down cleanly.
    /// IMPORTANT: Always call this on shutdown or the server stays locked down.
    pub async fn deactivate(&mut self) -> Result<()> {
        info!("killswitch: deactivating — restoring normal routing");

        // Flush all OUTPUT rules we added
        // -F flushes all rules in the OUTPUT chain
        // This removes both the ACCEPT and DROP rules we installed
        if let Err(e) = run_iptables(&["-F", "OUTPUT"]) {
            error!("killswitch: failed to flush OUTPUT rules: {}", e);
            // Don't return error — try to continue cleanup
        }

        // Restore default ACCEPT policy on OUTPUT chain
        // Without this, after flushing rules, no traffic would flow
        run_iptables(&["-P", "OUTPUT", "ACCEPT"])?;

        self.state = KillSwitchState::Inactive;
        info!("killswitch: deactivated — normal routing restored");
        Ok(())
    }

    /// Check if kill switch is currently blocking traffic
    pub fn is_blocking(&self) -> bool {
        matches!(self.state, KillSwitchState::Blocking)
    }

    /// Get current state
    pub fn state(&self) -> &KillSwitchState {
        &self.state
    }

    /// Verify kill switch rules are actually in place
    /// Used by health check to confirm the firewall rules weren't tampered with
    pub async fn verify_rules(&self) -> Result<bool> {
        // Check if our DROP rule exists in OUTPUT chain
        let output = Command::new("iptables")
            .args(["-L", "OUTPUT", "-n"])
            .output()?;

        let rules = String::from_utf8_lossy(&output.stdout);
        let drop_rule_present = rules.contains("DROP");

        if matches!(self.state, KillSwitchState::Active { .. }) && !drop_rule_present {
            warn!("killswitch: DROP rule missing from OUTPUT chain — possible tampering");
            return Ok(false);
        }

        Ok(true)
    }
}

// ── Helper function ───────────────────────────────────────────────────────────

/// Run an iptables command with the given arguments.
/// Returns an error if iptables is not available or the command fails.
fn run_iptables(args: &[&str]) -> Result<()> {
    let output = Command::new("iptables")
        .args(args)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("iptables command failed: {}", stderr);
    }

    Ok(())
}
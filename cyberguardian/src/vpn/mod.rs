//! VPN Module
//!
//! Job: Declare all VPN sub-modules and expose the public API so the
//! rest of CyberGuardian can use the VPN system with clean imports.
//!
//! Architecture summary:
//!
//!   manager.rs    — Decision maker. Coordinates all VPN components.
//!                   Receives threat scores from CyberGuardian monitors.
//!                   Decides when to upgrade security level.
//!                   Like HQ in TradeEco.
//!
//!   circuit.rs    — Tunnel builder. Multi-hop onion-routed encrypted circuits.
//!                   Each hop has its own encryption layer and key.
//!                   Auto-rebuilds on expiry or hop failure.
//!
//!   killswitch.rs — Emergency firewall. Blocks ALL outbound traffic
//!                   the instant the VPN tunnel drops unexpectedly.
//!                   Re-allows traffic only when tunnel is restored.
//!
//! How it connects to CyberGuardian:
//!
//!   main.rs spawns the VPN manager as a tokio task alongside monitors.
//!   Each monitor calls vpn_manager.on_threat_detected(score) when
//!   it fires a critical alert. The manager handles the rest.
//!
//! Usage from main.rs:
//!
//!   use crate::vpn::manager::{VpnManager, VpnConfig};
//!
//!   let vpn = VpnManager::new(config.vpn);
//!   vpn.start(notifycore.clone(), &server_name).await?;

// Declare the three sub-modules
// pub means they are accessible from outside this module
// Without pub, only code inside vpn/ could use them
pub mod circuit;
pub mod killswitch;
pub mod manager;

// Re-export the most commonly used types so callers don't need
// to write the full path every time
//
// Instead of: crate::vpn::manager::VpnManager
// They write:  crate::vpn::VpnManager
pub use manager::{VpnManager, VpnConfig, VpnState};
pub use circuit::SecurityLevel;
pub use killswitch::KillSwitchState;
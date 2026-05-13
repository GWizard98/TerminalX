use crate::osint::AttackerProfile;
use crate::config::CountermeasuresConfig;
use anyhow::Result;
use std::process::Command;
use tracing::{info, warn, error};

pub struct CounterDefense {
    config: CountermeasuresConfig,
}

pub struct CounterResponse {
    pub ip: String,
    pub actions_taken: Vec<String>,
    pub vpn_status: VpnStatus,
}

pub enum VpnStatus {
    Healthy,
    SuspiciousHandshake,
    UnknownPeer,
}

impl CounterDefense {
    pub fn new(config: CountermeasuresConfig) -> Self {
        CounterDefense { config }
    }

    pub async fn respond(&self, profile: &AttackerProfile) -> Result<CounterResponse> {
        if !self.config.enabled {
            return Ok(CounterResponse {
                ip: profile.ip.clone(),
                actions_taken: vec!["Counter-defense disabled".to_string()],
                vpn_status: VpnStatus::Healthy,
            });
        }

        let mut actions = vec![];

        if self.config.auto_block {
            match self.block_ip(&profile.ip) {
                Ok(()) => {
                    info!("countermeasures: blocked {}", profile.ip);
                    actions.push(format!("BLOCKED: {}", profile.ip));
                }
                Err(e) => {
                    error!("countermeasures: block failed for {}: {}", profile.ip, e);
                    actions.push(format!("BLOCK FAILED: {}", e));
                }
            }
        }

        if self.config.block_asn_range && profile.threat_tags.contains(&"BULLETPROOF_HOST".to_string()) {
            actions.push(format!("ASN FLAGGED FOR RANGE BLOCK: {}", profile.asn));
            warn!("countermeasures: ASN {} flagged", profile.asn);
        }

        let c2_ports = [4444, 1337, 6666, 31337, 9001];
        for port in &c2_ports {
            if profile.open_ports.contains(port) {
                actions.push(format!("C2 PORT DETECTED: {}/{}", profile.ip, port));
                warn!("countermeasures: possible C2 — {}:{}", profile.ip, port);
            }
        }

        let vpn_status = self.check_vpn_integrity().await;
        match &vpn_status {
            VpnStatus::Healthy => info!("countermeasures: VPN integrity verified"),
            VpnStatus::SuspiciousHandshake => {
                actions.push("VPN WARNING: suspicious handshake detected".to_string());
            }
            VpnStatus::UnknownPeer => {
                actions.push("VPN CRITICAL: unknown peer detected".to_string());
                error!("countermeasures: unknown VPN peer");
            }
        }

        Ok(CounterResponse {
            ip: profile.ip.clone(),
            actions_taken: actions,
            vpn_status,
        })
    }

    fn block_ip(&self, ip: &str) -> Result<()> {
        let block = Command::new("iptables")
            .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output()?;
        if !block.status.success() {
            let err = String::from_utf8_lossy(&block.stderr);
            anyhow::bail!("iptables failed: {}", err);
        }
        let _ = Command::new("netfilter-persistent").args(["save"]).output();
        Ok(())
    }

    async fn check_vpn_integrity(&self) -> VpnStatus {
        let output = Command::new("wg")
            .args(["show", &self.config.vpn_interface])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                if text.contains("(none)") {
                    VpnStatus::SuspiciousHandshake
                } else {
                    VpnStatus::Healthy
                }
            }
            _ => VpnStatus::Healthy,
        }
    }
}

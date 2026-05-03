//! Active Response Engine
//!
//! Job: Receive an incident, investigate the IP, score the threat,
//! decide the response, execute it, record the evidence.
//!
//! This is the brain of Active Response. It coordinates:
//!   - OSINT investigation (ipinfo.io queries)
//!   - Threat scoring (ASN reputation classification)
//!   - Response execution (iptables, process kill, file lock)
//!   - Evidence logging (permanent audit trail)
//!   - Telegram reporting (full OSINT report in the alert)
//!
//! The response decision tree:
//!   Score 0.00 (whitelisted)  → ignore completely
//!   Score 0.10 (legitimate)   → log only
//!   Score 0.40 (residential)  → alert only
//!   Score 0.60 (generic VPS)  → alert + add to watchlist
//!   Score 0.80 (abuse host)   → auto-block + alert
//!   Score 0.95 (bulletproof)  → auto-block + alert + evidence log
//!   Score 1.00 (active)       → auto-block + critical alert + escalate to CyberRecon

pub mod incident;

use incident::{
    EvidenceRecord, Incident, IncidentSource,
    ResponseAction, ThreatClassification, ThreatScore,
};
use crate::notifycore::{NotifyCore, alert::{Alert, Severity}};
use crate::config::ActiveResponseConfig;
use anyhow::Result;
use serde_json::Value;
use std::collections::HashSet;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use tracing::{info, warn, error};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Active Response configuration

// ── Response Engine ───────────────────────────────────────────────────────────

pub struct ActiveResponse {
    config: ActiveResponseConfig,
    notifycore: Arc<NotifyCore>,
    server_name: String,
    http_client: reqwest::Client,
    /// Track which IPs we've already blocked this session
    /// Prevents duplicate blocks and duplicate alerts
    blocked_ips: HashSet<String>,
    /// Track IPs currently being watched (score 0.60)
    watchlist: HashSet<String>,
}

impl ActiveResponse {
    pub fn new(
        config: ActiveResponseConfig,
        notifycore: Arc<NotifyCore>,
        server_name: String,
    ) -> Self {
        ActiveResponse {
            config,
            notifycore,
            server_name,
            http_client: reqwest::Client::new(),
            blocked_ips: HashSet::new(),
            watchlist: HashSet::new(),
        }
    }

    /// Main entry point — receive an incident and respond to it.
    /// Called by monitors when they detect something suspicious.
    pub async fn respond(&mut self, incident: Incident) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        info!(
            "response: received incident from {} — {}",
            incident.source.label(),
            incident.description
        );

        // If no IP involved — handle non-network incidents separately
        if incident.ip.is_none() {
            return self.respond_non_network(&incident).await;
        }

        let ip = incident.ip.clone().unwrap();

        // Check whitelist first — whitelisted IPs are never touched
        if self.config.ip_whitelist.contains(&ip) {
            info!("response: {} is whitelisted — ignoring", ip);
            return Ok(());
        }

        // Check if already blocked this session
        if self.blocked_ips.contains(&ip) {
            info!("response: {} already blocked this session", ip);
            return Ok(());
        }

        // ── Step 1: OSINT Investigation ───────────────────────────────────────
        let threat_score = self.investigate_ip(&ip).await?;

        info!(
            "response: {} scored {:.2} — {}",
            ip,
            threat_score.score,
            threat_score.classification.label()
        );

        // ── Step 2: Decide Response ───────────────────────────────────────────
        let action = self.decide_response(&threat_score, &incident).await?;

        // ── Step 3: Execute Response ──────────────────────────────────────────
        let alerted = self.execute_response(&action, &incident, &threat_score).await?;

        // ── Step 4: Record Evidence ───────────────────────────────────────────
        let record = EvidenceRecord::new(
            incident,
            Some(threat_score),
            action,
            alerted,
        );

        self.write_evidence(&record).await?;

        Ok(())
    }

    // ── OSINT Investigation ───────────────────────────────────────────────────

    /// Query ipinfo.io for intelligence on an IP address.
    /// Returns a ThreatScore with classification and raw data.
    async fn investigate_ip(&self, ip: &str) -> Result<ThreatScore> {
        info!("response: investigating {}", ip);

        let url = format!("https://ipinfo.io/{}/json", ip);

        let response = self.http_client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;

        match response {
            Ok(r) if r.status().is_success() => {
                let raw = r.text().await.unwrap_or_default();
                let json: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);

                let country = json["country"].as_str().unwrap_or("Unknown").to_string();
                let org = json["org"].as_str().unwrap_or("Unknown").to_string();

                // Extract ASN from org field — format is "AS12345 Org Name"
                let asn = org.split_whitespace()
                    .next()
                    .unwrap_or("Unknown")
                    .to_string();

                // Classify the threat based on org and ASN
                let classification = self.classify_ip(&org, &asn, ip);
                let score = classification.score();

                Ok(ThreatScore {
                    ip: ip.to_string(),
                    score,
                    classification,
                    country,
                    org,
                    asn,
                    whitelisted: false,
                    raw_ipinfo: raw,
                })
            }
            _ => {
                // If ipinfo.io is unreachable, default to GenericVps
                // Better to over-respond than under-respond
                warn!("response: ipinfo.io unreachable for {} — defaulting to GenericVps", ip);
                Ok(ThreatScore {
                    ip: ip.to_string(),
                    score: 0.60,
                    classification: ThreatClassification::GenericVps,
                    country: "Unknown".to_string(),
                    org: "Unknown".to_string(),
                    asn: "Unknown".to_string(),
                    whitelisted: false,
                    raw_ipinfo: String::new(),
                })
            }
        }
    }

    /// Classify an IP based on its org, ASN, and known bad actor lists.
    fn classify_ip(&self, org: &str, asn: &str, _ip: &str) -> ThreatClassification {
        let org_upper = org.to_uppercase();

        // Check bulletproof hosting keywords
        for keyword in &self.config.bulletproof_keywords {
            if org_upper.contains(&keyword.to_uppercase()) {
                return ThreatClassification::BulletproofHost;
            }
        }

        // Check known abuse ASNs
        for known_asn in &self.config.known_abuse_asns {
            if asn.to_uppercase().contains(&known_asn.to_uppercase()) {
                return ThreatClassification::KnownAbuseHost;
            }
        }

        // Generic cloud/VPS providers — frequently abused
        let generic_vps_keywords = ["DIGITALOCEAN", "LINODE", "VULTR", "HETZNER", "OVH",
                                     "AMAZON", "GOOGLE", "AZURE", "CLOUDFLARE"];
        for keyword in &generic_vps_keywords {
            if org_upper.contains(keyword) {
                return ThreatClassification::GenericVps;
            }
        }

        // Check if it looks like a residential ISP
        let residential_keywords = ["COMCAST", "AT&T", "VERIZON", "SPECTRUM", "COX",
                                     "TMOBILE", "T-MOBILE", "HELIUM", "RESIDENTIAL"];
        for keyword in &residential_keywords {
            if org_upper.contains(keyword) {
                return ThreatClassification::Residential;
            }
        }

        // Default to GenericVps for anything unknown
        ThreatClassification::GenericVps
    }

    // ── Response Decision ─────────────────────────────────────────────────────

    /// Decide what response action to take based on threat score.
    async fn decide_response(
        &self,
        threat: &ThreatScore,
        incident: &Incident,
    ) -> Result<ResponseAction> {
        // Active incident — escalate to CyberRecon
        if threat.score >= self.config.escalate_threshold {
            return Ok(ResponseAction::EscalatedToCyberRecon {
                ip: threat.ip.clone(),
                reason: format!(
                    "Score {:.2} — {} — {}",
                    threat.score,
                    threat.classification.label(),
                    incident.description
                ),
            });
        }

        // Auto-block threshold reached
        if threat.score >= self.config.auto_block_threshold {
            return Ok(ResponseAction::AutoBlocked { ip: threat.ip.clone() });
        }

        // Generic VPS — alert and add to watchlist
        if threat.score >= 0.60 {
            return Ok(ResponseAction::AlertAndMonitor);
        }

        // Residential — alert only
        if threat.score >= 0.40 {
            return Ok(ResponseAction::AlertOnly);
        }

        // Everything else — log only
        Ok(ResponseAction::LogOnly)
    }

    // ── Response Execution ────────────────────────────────────────────────────

    /// Execute the decided response action.
    /// Returns true if a Telegram alert was sent.
    async fn execute_response(
        &mut self,
        action: &ResponseAction,
        incident: &Incident,
        threat: &ThreatScore,
    ) -> Result<bool> {
        match action {
            ResponseAction::LogOnly => {
                info!("response: log only — {}", threat.ip);
                Ok(false)
            }

            ResponseAction::AlertOnly => {
                let alert = Alert::warning(
                    "active_response",
                    &self.server_name,
                    &format!("Suspicious IP detected: {} ({})", threat.ip, threat.classification.label()),
                    &format!("Country: {} | Org: {}", threat.country, threat.org),
                );
                self.notifycore.send(alert).await?;
                Ok(true)
            }

            ResponseAction::AlertAndMonitor => {
                self.watchlist.insert(threat.ip.clone());
                let alert = Alert::warning(
                    "active_response",
                    &self.server_name,
                    &format!("IP added to watchlist: {} ({})", threat.ip, threat.classification.label()),
                    &format!("Country: {} | Org: {}", threat.country, threat.org),
                );
                self.notifycore.send(alert).await?;
                Ok(true)
            }

            ResponseAction::AutoBlocked { ip } => {
                // Execute iptables block
                match self.block_ip(ip) {
                    Ok(()) => {
                        self.blocked_ips.insert(ip.clone());
                        info!("response: AUTO-BLOCKED {}", ip);

                        // Build full OSINT report for Telegram
                        let record = EvidenceRecord::new(
                            incident.clone(),
                            Some(threat.clone()),
                            action.clone(),
                            false,
                        );

                        let alert = Alert {
                            severity: Severity::Critical,
                            source: "active_response".to_string(),
                            server_name: self.server_name.clone(),
                            message: format!("AUTO-BLOCKED: {} — {}", ip, threat.classification.label()),
                            evidence: record.telegram_summary(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        };
                        self.notifycore.send(alert).await?;
                        Ok(true)
                    }
                    Err(e) => {
                        error!("response: failed to block {}: {}", ip, e);
                        // Still alert even if block failed
                        let alert = Alert::critical(
                            "active_response",
                            &self.server_name,
                            &format!("BLOCK FAILED for {} — manual action required", ip),
                            &e.to_string(),
                        );
                        self.notifycore.send(alert).await?;
                        Ok(true)
                    }
                }
            }

            ResponseAction::EscalatedToCyberRecon { ip, reason } => {
                // Block first
                let _ = self.block_ip(ip);
                self.blocked_ips.insert(ip.clone());

                // Critical alert
                let alert = Alert::critical(
                    "active_response",
                    &self.server_name,
                    &format!("ACTIVE INCIDENT — ESCALATED TO CYBERRECON: {}", ip),
                    reason,
                );
                self.notifycore.send(alert).await?;

                // TODO: send incident report to CyberRecon API when built
                error!("response: ACTIVE INCIDENT — {} — {}", ip, reason);
                Ok(true)
            }

            ResponseAction::ProcessKilled { process_name } => {
                warn!("response: process kill not yet implemented for {}", process_name);
                Ok(false)
            }

            ResponseAction::FileLocked { path } => {
                warn!("response: file lock not yet implemented for {}", path);
                Ok(false)
            }
        }
    }

    // ── Non-network incidents ─────────────────────────────────────────────────

    /// Handle incidents that don't involve an IP address.
    /// Process detections, file integrity violations, etc.
    async fn respond_non_network(&self, incident: &Incident) -> Result<()> {
        match incident.source {
            IncidentSource::Integrity => {
                // File integrity violation — always critical
                let alert = Alert::critical(
                    "active_response",
                    &self.server_name,
                    &format!("FILE INTEGRITY VIOLATION: {}", incident.description),
                    &incident.evidence,
                );
                self.notifycore.send(alert).await?;
            }
            IncidentSource::Process => {
                // Unknown process — warning for now
                // TODO: implement process kill when process_name is in evidence
                let alert = Alert::warning(
                    "active_response",
                    &self.server_name,
                    &format!("Unknown process: {}", incident.description),
                    &incident.evidence,
                );
                self.notifycore.send(alert).await?;
            }
            _ => {
                info!("response: non-network incident logged — {}", incident.description);
            }
        }
        Ok(())
    }

    // ── iptables execution ────────────────────────────────────────────────────

    /// Block an IP using iptables and make it permanent.
    fn block_ip(&self, ip: &str) -> Result<()> {
        // Add the block rule
        let block = Command::new("iptables")
            .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output()?;

        if !block.status.success() {
            let err = String::from_utf8_lossy(&block.stderr);
            anyhow::bail!("iptables block failed: {}", err);
        }

        // Make permanent
        let save = Command::new("netfilter-persistent")
            .args(["save"])
            .output()?;

        if !save.status.success() {
            warn!("response: netfilter-persistent save failed — block may not survive reboot");
        }

        info!("response: {} blocked and persisted", ip);
        Ok(())
    }

    // ── Evidence logging ──────────────────────────────────────────────────────

    /// Write an evidence record to the local log file.
    /// Uses JSONL format — one JSON object per line.
    /// Easy to parse, easy to grep, easy to feed into reports.
    async fn write_evidence(&self, record: &EvidenceRecord) -> Result<()> {
        // Ensure log directory exists
        if let Some(parent) = std::path::Path::new(&self.config.evidence_log_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string(record)?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.evidence_log_path)?;

        writeln!(file, "{}", json)?;

        info!("response: evidence written to {}", self.config.evidence_log_path);
        Ok(())
    }
}
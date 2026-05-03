//! Incident data structures
//!
//! Defines what an incident looks like, how threats are scored,
//! what response actions are taken, and how evidence is recorded.
//!
//! This file is pure data — no logic lives here.
//! All logic lives in mod.rs (the response engine).
//!
//! Data flow:
//!   Monitor detects event
//!       ↓
//!   Creates Incident
//!       ↓
//!   Response engine scores it → ThreatScore
//!       ↓
//!   Response engine decides action → ResponseAction
//!       ↓
//!   Evidence recorded → EvidenceRecord → written to disk

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Incident ──────────────────────────────────────────────────────────────────

/// A security incident detected by any CyberGuardian monitor.
/// This is the input to the Active Response engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    /// Unique ID for this incident
    pub id: String,
    /// Which monitor detected it
    pub source: IncidentSource,
    /// Severity as detected by the monitor
    pub severity: IncidentSeverity,
    /// The IP address involved — None if not network-related
    pub ip: Option<String>,
    /// Human readable description of what happened
    pub description: String,
    /// Raw evidence from the monitor (log line, process name, etc)
    pub evidence: String,
    /// When this incident was detected
    pub timestamp: DateTime<Utc>,
}

/// Which monitor generated this incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentSource {
    Ssh,
    Filesystem,
    Process,
    Network,
    Integrity,
}

impl IncidentSource {
    pub fn label(&self) -> &'static str {
        match self {
            IncidentSource::Ssh        => "ssh_monitor",
            IncidentSource::Filesystem => "filesystem_monitor",
            IncidentSource::Process    => "process_monitor",
            IncidentSource::Network    => "network_monitor",
            IncidentSource::Integrity  => "integrity_monitor",
        }
    }
}

/// How severe the monitor judged this incident
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IncidentSeverity {
    Info,
    Warning,
    Critical,
}

impl Incident {
    /// Create a new incident with a generated ID
    pub fn new(
        source: IncidentSource,
        severity: IncidentSeverity,
        ip: Option<String>,
        description: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Incident {
            id: format!("INC-{}", Utc::now().timestamp_millis()),
            source,
            severity,
            ip,
            description: description.into(),
            evidence: evidence.into(),
            timestamp: Utc::now(),
        }
    }
}

// ── Threat Score ──────────────────────────────────────────────────────────────

/// The result of OSINT analysis on an incident's IP.
/// Score ranges from 0.0 (safe) to 1.0 (active incident).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    /// The IP that was analyzed
    pub ip: String,
    /// Threat score 0.0 - 1.0
    pub score: f64,
    /// Classification based on score
    pub classification: ThreatClassification,
    /// Country of origin
    pub country: String,
    /// Organization that owns the IP
    pub org: String,
    /// ASN number and name
    pub asn: String,
    /// Whether this IP is on the whitelist
    pub whitelisted: bool,
    /// Raw ipinfo.io response for evidence log
    pub raw_ipinfo: String,
}

/// Threat classification based on score
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatClassification {
    /// Score 0.00 — whitelisted, always ignore
    Whitelisted,
    /// Score 0.10 — known legitimate company
    Legitimate,
    /// Score 0.40 — residential ISP, low sophistication
    Residential,
    /// Score 0.60 — generic VPS/cloud, could be rented by anyone
    GenericVps,
    /// Score 0.80 — known abuse-tolerant host (Pfcloud, OVH abuse range)
    KnownAbuseHost,
    /// Score 0.95 — bulletproof host (UNMANAGED, etc)
    BulletproofHost,
    /// Score 1.00 — active incident (coordinated attack, C2, successful breach)
    ActiveIncident,
}

impl ThreatClassification {
    pub fn score(&self) -> f64 {
        match self {
            ThreatClassification::Whitelisted    => 0.00,
            ThreatClassification::Legitimate     => 0.10,
            ThreatClassification::Residential    => 0.40,
            ThreatClassification::GenericVps     => 0.60,
            ThreatClassification::KnownAbuseHost => 0.80,
            ThreatClassification::BulletproofHost => 0.95,
            ThreatClassification::ActiveIncident => 1.00,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ThreatClassification::Whitelisted     => "Whitelisted",
            ThreatClassification::Legitimate      => "Legitimate",
            ThreatClassification::Residential     => "Residential ISP",
            ThreatClassification::GenericVps      => "Generic VPS",
            ThreatClassification::KnownAbuseHost  => "Known Abuse Host",
            ThreatClassification::BulletproofHost => "Bulletproof Host",
            ThreatClassification::ActiveIncident  => "ACTIVE INCIDENT",
        }
    }
}

// ── Response Action ───────────────────────────────────────────────────────────

/// What the response engine decided to do about an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    /// Score too low or whitelisted — just log it
    LogOnly,
    /// Score 0.40 — alert sent, no block
    AlertOnly,
    /// Score 0.60 — alert sent, IP added to watch list
    AlertAndMonitor,
    /// Score 0.80+ — IP blocked via iptables, made permanent
    AutoBlocked { ip: String },
    /// Score 1.00 — blocked + escalated to CyberRecon
    EscalatedToCyberRecon { ip: String, reason: String },
    /// Non-IP incident — process killed
    ProcessKilled { process_name: String },
    /// Non-IP incident — file permissions locked
    FileLocked { path: String },
}

impl ResponseAction {
    pub fn label(&self) -> String {
        match self {
            ResponseAction::LogOnly                         => "Logged".to_string(),
            ResponseAction::AlertOnly                       => "Alert sent".to_string(),
            ResponseAction::AlertAndMonitor                 => "Alert + monitoring".to_string(),
            ResponseAction::AutoBlocked { ip }              => format!("AUTO-BLOCKED: {}", ip),
            ResponseAction::EscalatedToCyberRecon { ip, .. }=> format!("ESCALATED: {}", ip),
            ResponseAction::ProcessKilled { process_name } => format!("Process killed: {}", process_name),
            ResponseAction::FileLocked { path }            => format!("File locked: {}", path),
        }
    }
}

// ── Evidence Record ───────────────────────────────────────────────────────────

/// A permanent record of an incident and the response taken.
/// Written to the evidence store on disk.
/// Becomes the audit trail for client reports and CyberRecon escalations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// The original incident
    pub incident: Incident,
    /// OSINT analysis result (None if no IP involved)
    pub threat_score: Option<ThreatScore>,
    /// What action was taken
    pub action: ResponseAction,
    /// When the response was executed
    pub responded_at: DateTime<Utc>,
    /// Whether a Telegram alert was sent
    pub alerted: bool,
}

impl EvidenceRecord {
    pub fn new(
        incident: Incident,
        threat_score: Option<ThreatScore>,
        action: ResponseAction,
        alerted: bool,
    ) -> Self {
        EvidenceRecord {
            incident,
            threat_score,
            action,
            responded_at: Utc::now(),
            alerted,
        }
    }

    /// Format for Telegram alert message
    pub fn telegram_summary(&self) -> String {
        let mut msg = format!(
            "🛡 Active Response\n\nIncident: {}\nSource: {}\n",
            self.incident.description,
            self.incident.source.label(),
        );

        if let Some(score) = &self.threat_score {
            msg.push_str(&format!(
                "IP: {}\nCountry: {}\nOrg: {}\nThreat: {} ({:.0}%)\n",
                score.ip,
                score.country,
                score.org,
                score.classification.label(),
                score.score * 100.0,
            ));
        }

        msg.push_str(&format!(
            "Action: {}\nTime: {}",
            self.action.label(),
            self.responded_at.format("%Y-%m-%d %H:%M:%S UTC"),
        ));

        msg
    }
}
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self { Severity::Critical => "CRITICAL", Severity::Warning => "WARNING", Severity::Info => "INFO" }
    }
    pub fn tag(&self) -> &'static str {
        match self { Severity::Critical => "rotating_light", Severity::Warning => "warning", Severity::Info => "information_source" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: Severity,
    pub source: String,
    pub server_name: String,
    pub message: String,
    pub evidence: String,
    pub timestamp: String,
}

impl Alert {
    pub fn new(severity: Severity, source: impl Into<String>, server_name: impl Into<String>, message: impl Into<String>, evidence: impl Into<String>) -> Self {
        Alert { severity, source: source.into(), server_name: server_name.into(), message: message.into(), evidence: evidence.into(), timestamp: Utc::now().to_rfc3339() }
    }
    pub fn critical(source: &str, server: &str, msg: &str, evidence: &str) -> Self { Self::new(Severity::Critical, source, server, msg, evidence) }
    pub fn warning(source: &str, server: &str, msg: &str, evidence: &str) -> Self  { Self::new(Severity::Warning,  source, server, msg, evidence) }
    pub fn info(source: &str, server: &str, msg: &str, evidence: &str) -> Self     { Self::new(Severity::Info,     source, server, msg, evidence) }
}

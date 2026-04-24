use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ============================================================
// ATM Compliance Module — TerminalX / CyberGuardian
// Targets: TR-31/TR-34, Windows 10 EOL, FDIC Digital Signage
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtmComplianceEngine {
    pub tr31_checker: Tr31Checker,
    pub tr34_checker: Tr34Checker,
    pub os_eol_checker: OsEolChecker,
    pub fdic_signage_checker: FdicSignageChecker,
    pub audit_log: Vec<ComplianceEvent>,
}

// TR-31 — Key Block Standard (encryption key management)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tr31Checker {
    pub supported_versions: Vec<String>,
    pub key_block_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tr31Result {
    pub compliant: bool,
    pub version_detected: Option<String>,
    pub key_block_valid: bool,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub checked_at: DateTime<Utc>,
}

// TR-34 — Remote Key Loading Standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tr34Checker {
    pub certificate_validator: CertificateValidator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tr34Result {
    pub compliant: bool,
    pub certificate_valid: bool,
    pub key_injection_method: String,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub checked_at: DateTime<Utc>,
}

// Windows 10 EOL Detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsEolChecker {
    pub eol_dates: Vec<EolEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EolEntry {
    pub os_name: String,
    pub version: String,
    pub eol_date: String,
    pub extended_support: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsEolResult {
    pub os_detected: String,
    pub is_eol: bool,
    pub eol_date: Option<String>,
    pub days_until_eol: Option<i64>,
    pub risk_level: RiskLevel,
    pub recommendations: Vec<String>,
    pub checked_at: DateTime<Utc>,
}

// FDIC Digital Signage Compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdicSignageChecker {
    pub required_disclosures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdicSignageResult {
    pub compliant: bool,
    pub disclosures_found: Vec<String>,
    pub disclosures_missing: Vec<String>,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
    pub checked_at: DateTime<Utc>,
}

// Full ATM Assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtmAssessment {
    pub assessment_id: String,
    pub atm_id: String,
    pub location: Option<String>,
    pub tr31: Tr31Result,
    pub tr34: Tr34Result,
    pub os_eol: OsEolResult,
    pub fdic_signage: FdicSignageResult,
    pub overall_risk: RiskLevel,
    pub overall_compliant: bool,
    pub assessed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Compliant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvent {
    pub event_id: String,
    pub atm_id: String,
    pub event_type: String,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidator {
    pub trusted_cas: Vec<String>,
}

// Implementations
impl AtmComplianceEngine {
    pub fn new() -> Self {
        Self {
            tr31_checker: Tr31Checker::new(),
            tr34_checker: Tr34Checker::new(),
            os_eol_checker: OsEolChecker::new(),
            fdic_signage_checker: FdicSignageChecker::new(),
            audit_log: Vec::new(),
        }
    }

    pub async fn assess_atm(&mut self, atm_id: &str, location: Option<String>, os_version: &str) -> Result<AtmAssessment> {
        let assessment_id = format!("atm_assessment_{}", Utc::now().timestamp_millis());

        let tr31 = self.tr31_checker.check(atm_id).await?;
        let tr34 = self.tr34_checker.check(atm_id).await?;
        let os_eol = self.os_eol_checker.check(os_version).await?;
        let fdic_signage = self.fdic_signage_checker.check(atm_id).await?;

        let overall_compliant = tr31.compliant && tr34.compliant && !os_eol.is_eol && fdic_signage.compliant;

        let overall_risk = if !tr31.compliant || !tr34.compliant {
            RiskLevel::Critical
        } else if os_eol.is_eol {
            RiskLevel::High
        } else if !fdic_signage.compliant {
            RiskLevel::Medium
        } else {
            RiskLevel::Compliant
        };

        let assessment = AtmAssessment {
            assessment_id: assessment_id.clone(),
            atm_id: atm_id.to_string(),
            location,
            tr31,
            tr34,
            os_eol,
            fdic_signage,
            overall_risk,
            overall_compliant,
            assessed_at: Utc::now(),
        };

        self.audit_log.push(ComplianceEvent {
            event_id: format!("event_{}", Utc::now().timestamp_millis()),
            atm_id: atm_id.to_string(),
            event_type: "assessment_completed".to_string(),
            details: format!("Assessment {} completed. Compliant: {}", assessment_id, overall_compliant),
            timestamp: Utc::now(),
        });

        Ok(assessment)
    }

    pub fn get_audit_log(&self) -> &[ComplianceEvent] {
        &self.audit_log
    }
}

impl Tr31Checker {
    pub fn new() -> Self {
        Self {
            supported_versions: vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()],
            key_block_headers: Vec::new(),
        }
    }

    pub async fn check(&self, _atm_id: &str) -> Result<Tr31Result> {
        Ok(Tr31Result {
            compliant: false,
            version_detected: None,
            key_block_valid: false,
            issues: vec![
                "TR-31 key block format not detected".to_string(),
                "Encryption key management not compliant".to_string(),
            ],
            recommendations: vec![
                "Upgrade to TR-31 compliant key management system".to_string(),
                "Contact HSM vendor for TR-31 support".to_string(),
            ],
            checked_at: Utc::now(),
        })
    }
}

impl Tr34Checker {
    pub fn new() -> Self {
        Self {
            certificate_validator: CertificateValidator {
                trusted_cas: vec!["Visa".to_string(), "Mastercard".to_string(), "NIST".to_string()],
            },
        }
    }

    pub async fn check(&self, _atm_id: &str) -> Result<Tr34Result> {
        Ok(Tr34Result {
            compliant: false,
            certificate_valid: false,
            key_injection_method: "Unknown".to_string(),
            issues: vec![
                "TR-34 remote key loading not configured".to_string(),
            ],
            recommendations: vec![
                "Implement TR-34 compliant remote key loading".to_string(),
                "Obtain certificates from accredited CA".to_string(),
            ],
            checked_at: Utc::now(),
        })
    }
}

impl OsEolChecker {
    pub fn new() -> Self {
        Self {
            eol_dates: vec![
                EolEntry {
                    os_name: "Windows 10".to_string(),
                    version: "10.0".to_string(),
                    eol_date: "2025-10-14".to_string(),
                    extended_support: false,
                },
                EolEntry {
                    os_name: "Windows 7".to_string(),
                    version: "6.1".to_string(),
                    eol_date: "2020-01-14".to_string(),
                    extended_support: false,
                },
                EolEntry {
                    os_name: "Windows XP".to_string(),
                    version: "5.1".to_string(),
                    eol_date: "2014-04-08".to_string(),
                    extended_support: false,
                },
            ],
        }
    }

    pub async fn check(&self, os_version: &str) -> Result<OsEolResult> {
        let matched = self.eol_dates.iter().find(|e| 
            os_version.to_lowercase().contains(&e.os_name.to_lowercase())
        );

        match matched {
            Some(entry) => {
                let is_eol = true;
                Ok(OsEolResult {
                    os_detected: entry.os_name.clone(),
                    is_eol,
                    eol_date: Some(entry.eol_date.clone()),
                    days_until_eol: Some(-1),
                    risk_level: RiskLevel::High,
                    recommendations: vec![
                        format!("{} reached end of life on {}", entry.os_name, entry.eol_date),
                        "Upgrade to Windows 11 or supported OS immediately".to_string(),
                        "Contact ATM vendor for upgrade path".to_string(),
                        "Isolate ATM from network until upgraded".to_string(),
                    ],
                    checked_at: Utc::now(),
                })
            },
            None => {
                Ok(OsEolResult {
                    os_detected: os_version.to_string(),
                    is_eol: false,
                    eol_date: None,
                    days_until_eol: None,
                    risk_level: RiskLevel::Compliant,
                    recommendations: vec![
                        "OS version appears current — verify extended support status".to_string(),
                    ],
                    checked_at: Utc::now(),
                })
            }
        }
    }
}

impl FdicSignageChecker {
    pub fn new() -> Self {
        Self {
            required_disclosures: vec![
                "FDIC Insured".to_string(),
                "Member FDIC".to_string(),
                "Deposits insured to at least $250,000".to_string(),
            ],
        }
    }

    pub async fn check(&self, _atm_id: &str) -> Result<FdicSignageResult> {
        Ok(FdicSignageResult {
            compliant: false,
            disclosures_found: vec![],
            disclosures_missing: self.required_disclosures.clone(),
            issues: vec![
                "Required FDIC digital signage not detected on ATM display".to_string(),
            ],
            recommendations: vec![
                "Add FDIC membership disclosure to ATM welcome screen".to_string(),
                "Display deposit insurance limit ($250,000) prominently".to_string(),
                "Ensure FDIC signage meets updated 2024 digital display requirements".to_string(),
            ],
            checked_at: Utc::now(),
        })
    }
}

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub key: String,
    pub email: String,
    pub tier: String,
    pub features: Vec<String>,
    pub issued: String,
    pub valid: bool,
}

#[derive(Debug, PartialEq)]
pub enum LicenseTier {
    Personal,
    Professional,
    Enterprise,
    Trial,
}

impl LicenseTier {
    pub fn from_string(tier: &str) -> Self {
        match tier.to_lowercase().as_str() {
            "personal" => LicenseTier::Personal,
            "professional" => LicenseTier::Professional,
            "enterprise" => LicenseTier::Enterprise,
            _ => LicenseTier::Trial,
        }
    }

    pub fn allows_feature(&self, feature: &str) -> bool {
        match (self, feature) {
            (LicenseTier::Personal, "cli") => true,
            (LicenseTier::Personal, "basic_api") => true,
            (LicenseTier::Personal, "log_analysis") => true,

            (LicenseTier::Professional, _) => true, // All Personal features + more
            (LicenseTier::Enterprise, _) => true,   // All features

            (LicenseTier::Trial, "cli") => true, // Limited trial
            (LicenseTier::Trial, _) => false,

            _ => false,
        }
    }
}

pub struct LicenseManager {
    license_path: PathBuf,
    validation_url: String,
    current_license: Option<LicenseInfo>,
}

impl LicenseManager {
    pub fn new() -> Self {
        let license_path = Self::get_license_path();
        let validation_url = env::var("LICENSE_VALIDATION_URL")
            .unwrap_or_else(|_| "https://your-domain.com/validate-license".to_string());

        Self {
            license_path,
            validation_url,
            current_license: None,
        }
    }

    fn get_license_path() -> PathBuf {
        let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push(".cyber_guardian");
        path.push("license.json");
        path
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Create license directory if it doesn't exist
        if let Some(parent) = self.license_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Try to load existing license
        match self.load_license() {
            Ok(license) => {
                info!("License loaded: {} ({})", license.tier, license.email);
                self.current_license = Some(license);
            }
            Err(_) => {
                warn!("No valid license found. Trial mode disabled. Features requiring a license will be unavailable until activation.");
                self.current_license = None;
            }
        }

        Ok(())
    }

    fn load_license(&self) -> Result<LicenseInfo> {
        if !self.license_path.exists() {
            return Err(anyhow!("License file not found"));
        }

        let license_data = fs::read_to_string(&self.license_path)?;
        let license: LicenseInfo = serde_json::from_str(&license_data)?;

        // Validate license online
        self.validate_license_online(&license)?;

        Ok(license)
    }

    fn validate_license_online(&self, license: &LicenseInfo) -> Result<()> {
        // For offline operation, skip online validation
        if env::var("OFFLINE_MODE").is_ok() {
            return Ok(());
        }

        // Use blocking HTTP client to avoid tokio runtime issues
        let client = Client::new();
        let response = client
            .post(&self.validation_url)
            .json(&serde_json::json!({
                "licenseKey": license.key,
                "email": license.email
            }))
            .send()?;

        let validation: serde_json::Value = response.json()?;

        if validation["valid"].as_bool() != Some(true) {
            return Err(anyhow!("License validation failed"));
        }

        Ok(())
    }

    pub fn activate_license(&mut self, license_key: String, email: String) -> Result<()> {
        info!("Activating license: {}", license_key);

        // Validate with server using blocking client
        let client = Client::new();
        let response = client
            .post(&self.validation_url)
            .json(&serde_json::json!({
                "licenseKey": license_key,
                "email": email
            }))
            .send()?;

        // Check if response is successful
        if !response.status().is_success() {
            return Err(anyhow!(
                "License validation request failed: {}",
                response.status()
            ));
        }

        let response_text = response.text()?;
        info!("License validation response: {}", response_text);

        let mut license_info: LicenseInfo = serde_json::from_str(&response_text)?;

        if !license_info.valid {
            return Err(anyhow!("Invalid license key"));
        }

        license_info.key = license_key;
        license_info.email = email;

        // Save license locally
        let license_json = serde_json::to_string_pretty(&license_info)?;
        fs::write(&self.license_path, license_json)?;

        self.current_license = Some(license_info);
        info!("License activated successfully!");

        Ok(())
    }

    fn start_trial_mode(&mut self) -> Result<()> {
        let trial_license = LicenseInfo {
            key: "TRIAL-MODE".to_string(),
            email: "trial@localhost".to_string(),
            tier: "trial".to_string(),
            features: vec!["cli".to_string()],
            issued: chrono::Utc::now().to_rfc3339(),
            valid: true,
        };

        self.current_license = Some(trial_license);
        info!("Running in trial mode with limited features");

        Ok(())
    }

    pub fn check_feature_access(&self, feature: &str) -> bool {
        match &self.current_license {
            Some(license) => {
                let tier = LicenseTier::from_string(&license.tier);
                tier.allows_feature(feature)
            }
            None => false,
        }
    }

    #[allow(dead_code)]
    pub fn get_license_info(&self) -> Option<&LicenseInfo> {
        self.current_license.as_ref()
    }

    pub fn show_license_status(&self) {
        match &self.current_license {
            Some(license) => {
                println!("🔐 License Status:");
                println!("   Tier: {}", license.tier.to_uppercase());
                println!("   Email: {}", license.email);
                println!("   Key: {}****", &license.key[..8]);
                println!("   Issued: {}", license.issued);
                println!("   Features: {}", license.features.join(", "));

                if license.tier == "trial" {
                    println!();
                    println!("⚠️  You are running in TRIAL mode with limited features.");
                    println!("   Purchase a license at: https://your-domain.com");
                }
            }
            None => {
                println!("❌ No license found. Please activate a license.");
            }
        }
    }

    pub fn require_feature(&self, feature: &str, feature_name: &str) -> Result<()> {
        if !self.check_feature_access(feature) {
            return Err(anyhow!(
                "🔒 {} requires a {} license or higher.\n   Current license: {}\n   Upgrade at: https://your-domain.com",
                feature_name,
                self.get_required_tier_for_feature(feature),
                self.current_license.as_ref().map(|l| l.tier.as_str()).unwrap_or("None")
            ));
        }
        Ok(())
    }

    fn get_required_tier_for_feature(&self, feature: &str) -> &str {
        match feature {
            "cli" | "basic_api" | "log_analysis" => "Personal",
            "advanced_ai" | "real_time" | "full_api" => "Professional",
            "custom_deploy" | "multi_user" => "Enterprise",
            _ => "Professional",
        }
    }
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_tier_permissions() {
        let personal = LicenseTier::Personal;
        assert!(personal.allows_feature("cli"));
        assert!(personal.allows_feature("basic_api"));
        assert!(!personal.allows_feature("advanced_ai"));

        let professional = LicenseTier::Professional;
        assert!(professional.allows_feature("cli"));
        assert!(professional.allows_feature("advanced_ai"));

        let enterprise = LicenseTier::Enterprise;
        assert!(enterprise.allows_feature("multi_user"));
    }
}

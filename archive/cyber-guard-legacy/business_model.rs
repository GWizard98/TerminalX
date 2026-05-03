use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// License types for the open-core business model
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LicenseType {
    /// Free open-source edition with basic features
    OpenSource,
    /// Professional edition with advanced ML and enterprise features
    Professional,
    /// Enterprise edition with full feature set, SLA, and support
    Enterprise,
    /// Custom enterprise license with specific terms
    Custom,
}

/// Feature flags based on license type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSet {
    // Core anomaly detection (always available)
    pub basic_statistical_detection: bool,
    pub simple_rule_engine: bool,
    pub json_log_ingestion: bool,
    pub basic_alerting: bool,
    
    // ML features (Professional+)
    pub isolation_forest: bool,
    pub ensemble_models: bool,
    pub model_training: bool,
    pub custom_features: bool,
    
    // Advanced ML (Professional+)
    pub autoencoder_models: bool,
    pub time_series_analysis: bool,
    pub drift_detection: bool,
    pub online_learning: bool,
    
    // Explainability (Professional+)
    pub shap_explanations: bool,
    pub feature_importance: bool,
    pub anomaly_explanations: bool,
    
    // Enterprise features (Enterprise+)
    pub threat_intelligence: bool,
    pub advanced_analytics: bool,
    pub session_analysis: bool,
    pub graph_analysis: bool,
    pub custom_integrations: bool,
    
    // Infrastructure (Enterprise+)
    pub high_availability: bool,
    pub clustering: bool,
    pub distributed_training: bool,
    pub priority_support: bool,
    pub sla_guarantees: bool,
    
    // Limits based on license
    pub max_logs_per_day: Option<u64>,
    pub max_models: Option<u32>,
    pub max_users: Option<u32>,
    pub retention_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessLicense {
    pub license_type: LicenseType,
    pub organization: String,
    pub contact_email: String,
    pub issued_date: u64,
    pub expires_date: Option<u64>,
    pub features: FeatureSet,
    pub usage_limits: UsageLimits,
    pub support_tier: SupportTier,
    pub license_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLimits {
    pub logs_processed_today: u64,
    pub models_created: u32,
    pub active_users: u32,
    pub data_retention_days: u32,
    pub api_requests_per_hour: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupportTier {
    Community,      // Forum support only
    Professional,   // Email support, 48h response
    Enterprise,     // Phone + email, 24h response, dedicated support
    Premium,        // 24/7 support, dedicated customer success manager
}

pub struct BusinessLicenseManager {
    current_license: Option<BusinessLicense>,
    usage_tracker: UsageTracker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTracker {
    pub daily_log_count: HashMap<String, u64>,
    pub model_count: u32,
    pub user_sessions: HashMap<String, u64>,
    pub api_requests: HashMap<String, u64>,
}

impl FeatureSet {
    pub fn open_source() -> Self {
        Self {
            // Basic features (always available)
            basic_statistical_detection: true,
            simple_rule_engine: true,
            json_log_ingestion: true,
            basic_alerting: true,
            
            // ML features (disabled in open source)
            isolation_forest: false,
            ensemble_models: false,
            model_training: false,
            custom_features: false,
            
            // Advanced ML (disabled)
            autoencoder_models: false,
            time_series_analysis: false,
            drift_detection: false,
            online_learning: false,
            
            // Explainability (disabled)
            shap_explanations: false,
            feature_importance: false,
            anomaly_explanations: false,
            
            // Enterprise features (disabled)
            threat_intelligence: false,
            advanced_analytics: false,
            session_analysis: false,
            graph_analysis: false,
            custom_integrations: false,
            
            // Infrastructure (disabled)
            high_availability: false,
            clustering: false,
            distributed_training: false,
            priority_support: false,
            sla_guarantees: false,
            
            // Limits for open source
            max_logs_per_day: Some(10_000),
            max_models: Some(1),
            max_users: Some(5),
            retention_days: Some(7),
        }
    }

    pub fn professional() -> Self {
        Self {
            // Basic features
            basic_statistical_detection: true,
            simple_rule_engine: true,
            json_log_ingestion: true,
            basic_alerting: true,
            
            // ML features (enabled)
            isolation_forest: true,
            ensemble_models: true,
            model_training: true,
            custom_features: true,
            
            // Advanced ML (enabled)
            autoencoder_models: true,
            time_series_analysis: true,
            drift_detection: true,
            online_learning: true,
            
            // Explainability (enabled)
            shap_explanations: true,
            feature_importance: true,
            anomaly_explanations: true,
            
            // Enterprise features (limited)
            threat_intelligence: false,
            advanced_analytics: true,
            session_analysis: true,
            graph_analysis: false,
            custom_integrations: false,
            
            // Infrastructure (limited)
            high_availability: false,
            clustering: false,
            distributed_training: false,
            priority_support: true,
            sla_guarantees: false,
            
            // Professional limits
            max_logs_per_day: Some(1_000_000),
            max_models: Some(10),
            max_users: Some(50),
            retention_days: Some(90),
        }
    }

    pub fn enterprise() -> Self {
        Self {
            // All features enabled
            basic_statistical_detection: true,
            simple_rule_engine: true,
            json_log_ingestion: true,
            basic_alerting: true,
            
            isolation_forest: true,
            ensemble_models: true,
            model_training: true,
            custom_features: true,
            
            autoencoder_models: true,
            time_series_analysis: true,
            drift_detection: true,
            online_learning: true,
            
            shap_explanations: true,
            feature_importance: true,
            anomaly_explanations: true,
            
            threat_intelligence: true,
            advanced_analytics: true,
            session_analysis: true,
            graph_analysis: true,
            custom_integrations: true,
            
            high_availability: true,
            clustering: true,
            distributed_training: true,
            priority_support: true,
            sla_guarantees: true,
            
            // No limits (or very high limits)
            max_logs_per_day: None,
            max_models: None,
            max_users: None,
            retention_days: None,
        }
    }
}

impl BusinessLicenseManager {
    pub fn new() -> Self {
        Self {
            current_license: None,
            usage_tracker: UsageTracker {
                daily_log_count: HashMap::new(),
                model_count: 0,
                user_sessions: HashMap::new(),
                api_requests: HashMap::new(),
            },
        }
    }

    /// Initialize with open-source license (default)
    pub fn init_open_source() -> Self {
        let license = BusinessLicense {
            license_type: LicenseType::OpenSource,
            organization: "Open Source User".to_string(),
            contact_email: "".to_string(),
            issued_date: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            expires_date: None,
            features: FeatureSet::open_source(),
            usage_limits: UsageLimits {
                logs_processed_today: 0,
                models_created: 0,
                active_users: 0,
                data_retention_days: 7,
                api_requests_per_hour: 1000,
            },
            support_tier: SupportTier::Community,
            license_key: "open-source".to_string(),
        };

        Self {
            current_license: Some(license),
            usage_tracker: UsageTracker {
                daily_log_count: HashMap::new(),
                model_count: 0,
                user_sessions: HashMap::new(),
                api_requests: HashMap::new(),
            },
        }
    }

    pub fn validate_license_key(key: &str) -> Result<BusinessLicense> {
        // In production, this would validate against a license server
        // For demo purposes, we'll parse some simple patterns
        
        match key {
            "open-source" => Ok(BusinessLicense {
                license_type: LicenseType::OpenSource,
                organization: "Open Source".to_string(),
                contact_email: "".to_string(),
                issued_date: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                expires_date: None,
                features: FeatureSet::open_source(),
                usage_limits: UsageLimits {
                    logs_processed_today: 0,
                    models_created: 0,
                    active_users: 0,
                    data_retention_days: 7,
                    api_requests_per_hour: 1000,
                },
                support_tier: SupportTier::Community,
                license_key: key.to_string(),
            }),
            key if key.starts_with("PRO-") => {
                // Parse professional license
                Ok(BusinessLicense {
                    license_type: LicenseType::Professional,
                    organization: "Professional User".to_string(),
                    contact_email: "pro@example.com".to_string(),
                    issued_date: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    expires_date: Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 365 * 24 * 3600),
                    features: FeatureSet::professional(),
                    usage_limits: UsageLimits {
                        logs_processed_today: 0,
                        models_created: 0,
                        active_users: 0,
                        data_retention_days: 90,
                        api_requests_per_hour: 10000,
                    },
                    support_tier: SupportTier::Professional,
                    license_key: key.to_string(),
                })
            },
            key if key.starts_with("ENT-") => {
                // Parse enterprise license
                Ok(BusinessLicense {
                    license_type: LicenseType::Enterprise,
                    organization: "Enterprise User".to_string(),
                    contact_email: "enterprise@example.com".to_string(),
                    issued_date: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    expires_date: Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 365 * 24 * 3600),
                    features: FeatureSet::enterprise(),
                    usage_limits: UsageLimits {
                        logs_processed_today: 0,
                        models_created: 0,
                        active_users: 0,
                        data_retention_days: 365,
                        api_requests_per_hour: 100000,
                    },
                    support_tier: SupportTier::Enterprise,
                    license_key: key.to_string(),
                })
            },
            _ => Err(anyhow::anyhow!("Invalid license key")),
        }
    }

    pub fn set_license(&mut self, license_key: &str) -> Result<()> {
        let license = Self::validate_license_key(license_key)?;
        self.current_license = Some(license);
        tracing::info!("License updated: {:?}", self.current_license.as_ref().unwrap().license_type);
        Ok(())
    }

    pub fn check_feature(&self, feature: &str) -> bool {
        if let Some(license) = &self.current_license {
            match feature {
                "basic_statistical_detection" => license.features.basic_statistical_detection,
                "isolation_forest" => license.features.isolation_forest,
                "ensemble_models" => license.features.ensemble_models,
                "autoencoder_models" => license.features.autoencoder_models,
                "shap_explanations" => license.features.shap_explanations,
                "threat_intelligence" => license.features.threat_intelligence,
                "high_availability" => license.features.high_availability,
                _ => false,
            }
        } else {
            // Default to open source features
            matches!(feature, "basic_statistical_detection" | "simple_rule_engine" | "json_log_ingestion" | "basic_alerting")
        }
    }

    pub fn check_usage_limit(&self, resource: &str, current_usage: u64) -> Result<bool> {
        if let Some(license) = &self.current_license {
            match resource {
                "logs_per_day" => {
                    if let Some(limit) = license.features.max_logs_per_day {
                        Ok(current_usage < limit)
                    } else {
                        Ok(true) // No limit
                    }
                },
                "models" => {
                    if let Some(limit) = license.features.max_models {
                        Ok(current_usage < limit as u64)
                    } else {
                        Ok(true) // No limit
                    }
                },
                "users" => {
                    if let Some(limit) = license.features.max_users {
                        Ok(current_usage < limit as u64)
                    } else {
                        Ok(true) // No limit
                    }
                },
                _ => Ok(true),
            }
        } else {
            Ok(false) // No license means no access
        }
    }

    pub fn record_usage(&mut self, resource: &str, amount: u64) {
        let today = self.get_today_string();
        
        match resource {
            "logs" => {
                *self.usage_tracker.daily_log_count.entry(today).or_insert(0) += amount;
            },
            "models" => {
                self.usage_tracker.model_count += amount as u32;
            },
            "api_requests" => {
                let hour = self.get_current_hour();
                *self.usage_tracker.api_requests.entry(hour).or_insert(0) += amount;
            },
            _ => {},
        }
    }

    pub fn get_usage_summary(&self) -> HashMap<String, u64> {
        let mut summary = HashMap::new();
        
        let today = self.get_today_string();
        summary.insert("logs_today".to_string(), 
                      self.usage_tracker.daily_log_count.get(&today).copied().unwrap_or(0));
        
        summary.insert("models_total".to_string(), self.usage_tracker.model_count as u64);
        
        let current_hour = self.get_current_hour();
        summary.insert("api_requests_current_hour".to_string(),
                      self.usage_tracker.api_requests.get(&current_hour).copied().unwrap_or(0));
        
        summary
    }

    pub fn get_license_info(&self) -> Option<&BusinessLicense> {
        self.current_license.as_ref()
    }

    pub fn is_license_valid(&self) -> bool {
        if let Some(license) = &self.current_license {
            if let Some(expires) = license.expires_date {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                now < expires
            } else {
                true // No expiration
            }
        } else {
            false
        }
    }

    pub fn get_pricing_info() -> Vec<PricingTier> {
        vec![
            PricingTier {
                name: "Open Source".to_string(),
                description: "Perfect for individuals and small teams getting started".to_string(),
                price_monthly: 0,
                features: vec![
                    "Basic statistical anomaly detection".to_string(),
                    "Simple rule engine".to_string(),
                    "JSON log ingestion".to_string(),
                    "Basic alerting".to_string(),
                    "Community support".to_string(),
                ],
                limits: vec![
                    "Up to 10K logs/day".to_string(),
                    "1 model".to_string(),
                    "5 users".to_string(),
                    "7 days retention".to_string(),
                ],
            },
            PricingTier {
                name: "Professional".to_string(),
                description: "Advanced ML detection for growing teams".to_string(),
                price_monthly: 99,
                features: vec![
                    "All Open Source features".to_string(),
                    "Isolation Forest & ensemble models".to_string(),
                    "Autoencoder neural networks".to_string(),
                    "SHAP explainability".to_string(),
                    "Time-series analysis".to_string(),
                    "Drift detection".to_string(),
                    "Email support".to_string(),
                ],
                limits: vec![
                    "Up to 1M logs/day".to_string(),
                    "10 models".to_string(),
                    "50 users".to_string(),
                    "90 days retention".to_string(),
                ],
            },
            PricingTier {
                name: "Enterprise".to_string(),
                description: "Full-featured solution with enterprise support".to_string(),
                price_monthly: 499,
                features: vec![
                    "All Professional features".to_string(),
                    "Threat intelligence integration".to_string(),
                    "Graph & session analysis".to_string(),
                    "High availability & clustering".to_string(),
                    "Custom integrations".to_string(),
                    "SLA guarantees".to_string(),
                    "24/7 phone support".to_string(),
                ],
                limits: vec![
                    "Unlimited logs".to_string(),
                    "Unlimited models".to_string(),
                    "Unlimited users".to_string(),
                    "Custom retention".to_string(),
                ],
            },
        ]
    }

    fn get_today_string(&self) -> String {
        // Simple date string - in production use proper date handling
        format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 86400)
    }

    fn get_current_hour(&self) -> String {
        // Simple hour string - in production use proper date handling
        format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 3600)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingTier {
    pub name: String,
    pub description: String,
    pub price_monthly: u32,
    pub features: Vec<String>,
    pub limits: Vec<String>,
}

impl Default for BusinessLicenseManager {
    fn default() -> Self {
        Self::init_open_source()
    }
}

/// Macro to check if a feature is available before using it
#[macro_export]
macro_rules! feature_guard {
    ($license_manager:expr, $feature:expr, $action:block) => {
        if $license_manager.check_feature($feature) {
            $action
        } else {
            tracing::warn!("Feature '{}' not available in current license", $feature);
            Err(anyhow::anyhow!("Feature '{}' requires {} license or higher", 
                $feature, 
                match $feature {
                    "isolation_forest" | "ensemble_models" | "autoencoder_models" | "shap_explanations" => "Professional",
                    "threat_intelligence" | "high_availability" => "Enterprise",
                    _ => "Professional"
                }
            ))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_source_license() {
        let manager = BusinessLicenseManager::init_open_source();
        
        assert!(manager.check_feature("basic_statistical_detection"));
        assert!(!manager.check_feature("isolation_forest"));
        assert!(!manager.check_feature("shap_explanations"));
    }

    #[test]
    fn test_professional_license() {
        let mut manager = BusinessLicenseManager::new();
        manager.set_license("PRO-TEST-KEY").unwrap();
        
        assert!(manager.check_feature("basic_statistical_detection"));
        assert!(manager.check_feature("isolation_forest"));
        assert!(manager.check_feature("shap_explanations"));
        assert!(!manager.check_feature("threat_intelligence"));
    }

    #[test]
    fn test_enterprise_license() {
        let mut manager = BusinessLicenseManager::new();
        manager.set_license("ENT-TEST-KEY").unwrap();
        
        assert!(manager.check_feature("basic_statistical_detection"));
        assert!(manager.check_feature("isolation_forest"));
        assert!(manager.check_feature("threat_intelligence"));
        assert!(manager.check_feature("high_availability"));
    }

    #[test]
    fn test_usage_limits() {
        let manager = BusinessLicenseManager::init_open_source();
        
        // Open source should have limits
        assert!(!manager.check_usage_limit("logs_per_day", 15000).unwrap());
        assert!(manager.check_usage_limit("logs_per_day", 5000).unwrap());
    }

    #[test]
    fn test_usage_tracking() {
        let mut manager = BusinessLicenseManager::init_open_source();
        
        manager.record_usage("logs", 1000);
        manager.record_usage("models", 1);
        
        let summary = manager.get_usage_summary();
        assert_eq!(summary.get("logs_today").copied().unwrap_or(0), 1000);
        assert_eq!(summary.get("models_total").copied().unwrap_or(0), 1);
    }
}
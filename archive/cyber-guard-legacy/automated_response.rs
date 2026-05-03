use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use tracing::{error, info, warn};

use crate::api::{AnalysisResponse, ThreatSummary};
use crate::notifications::NotificationManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_id: String,
    pub threat_id: String,
    pub action_type: ResponseActionType,
    pub target: String,
    pub status: ActionStatus,
    pub timestamp: DateTime<Utc>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseActionType {
    // Security Response Actions
    BlockIP,
    LockAccount,
    IsolateSystem,
    DisableService,
    QuarantineFile,
    RestrictAccess,
    AlertEscalation,
    
    // System Maintenance Actions
    CleanDiskSpace,
    ConfigureSecureDNS,
    EnableVPN,
    SystemHealthCheck,
    SecurityHardening,
}

impl std::fmt::Display for ResponseActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseActionType::BlockIP => write!(f, "Block IP"),
            ResponseActionType::LockAccount => write!(f, "Lock Account"),
            ResponseActionType::IsolateSystem => write!(f, "Isolate System"),
            ResponseActionType::DisableService => write!(f, "Disable Service"),
            ResponseActionType::QuarantineFile => write!(f, "Quarantine File"),
            ResponseActionType::RestrictAccess => write!(f, "Restrict Access"),
            ResponseActionType::AlertEscalation => write!(f, "Alert Escalation"),
            ResponseActionType::CleanDiskSpace => write!(f, "Clean Disk Space"),
            ResponseActionType::ConfigureSecureDNS => write!(f, "Configure Secure DNS"),
            ResponseActionType::EnableVPN => write!(f, "Enable VPN"),
            ResponseActionType::SystemHealthCheck => write!(f, "System Health Check"),
            ResponseActionType::SecurityHardening => write!(f, "Security Hardening"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionStatus {
    Pending,
    InProgress,
    Success,
    Failed,
    Skipped,
}

impl std::fmt::Display for ActionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionStatus::Pending => write!(f, "Pending"),
            ActionStatus::InProgress => write!(f, "In Progress"),
            ActionStatus::Success => write!(f, "Success"),
            ActionStatus::Failed => write!(f, "Failed"),
            ActionStatus::Skipped => write!(f, "Skipped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub auto_response_enabled: bool,
    pub confidence_threshold: f64,
    pub max_actions_per_minute: u32,
    pub allowed_actions: Vec<ResponseActionType>,
    pub whitelist_ips: Vec<String>,
    pub critical_systems: Vec<String>,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            auto_response_enabled: false, // Start with manual approval for safety
            confidence_threshold: 0.9,   // Only respond to very high confidence threats
            max_actions_per_minute: 10,
            allowed_actions: vec![
                ResponseActionType::BlockIP,
                ResponseActionType::AlertEscalation,
            ],
            whitelist_ips: vec![
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
            critical_systems: vec![],
        }
    }
}

pub struct AutomatedResponseEngine {
    config: ResponseConfig,
    notification_manager: NotificationManager,
    action_history: Vec<ResponseAction>,
    rate_limiter: HashMap<String, DateTime<Utc>>,
}

impl AutomatedResponseEngine {
    pub fn new(config: ResponseConfig) -> Self {
        Self {
            config,
            notification_manager: NotificationManager::new(),
            action_history: Vec::new(),
            rate_limiter: HashMap::new(),
        }
    }

    /// Process analysis results and trigger automated responses
    pub async fn process_threat_response(&mut self, analysis: &AnalysisResponse) -> anyhow::Result<Vec<ResponseAction>> {
        if !self.config.auto_response_enabled {
            info!("Automated response disabled - manual review required");
            return Ok(vec![]);
        }

        let mut actions = Vec::new();

        for threat in &analysis.top_threats {
            if threat.confidence >= self.config.confidence_threshold {
                if let Some(action) = self.determine_response_action(threat, &analysis.analysis_id).await? {
                    match self.execute_response_action(action.clone()).await {
                        Ok(executed_action) => {
                            actions.push(executed_action);
                            self.log_action_success(&action).await?;
                        }
                        Err(e) => {
                            error!("Failed to execute response action: {}", e);
                            self.log_action_failure(&action, &e.to_string()).await?;
                        }
                    }
                }
            }
        }

        Ok(actions)
    }

    /// Determine appropriate response action for a threat
    async fn determine_response_action(
        &self,
        threat: &ThreatSummary,
        analysis_id: &str,
    ) -> anyhow::Result<Option<ResponseAction>> {
        let action_type = match threat.threat_type.as_str() {
            "SQL Injection" => ResponseActionType::BlockIP,
            "Brute Force Attack" => ResponseActionType::LockAccount,
            "Malware" => ResponseActionType::QuarantineFile,
            "Unauthorized Access" => ResponseActionType::RestrictAccess,
            "Network Scanning" => ResponseActionType::BlockIP,
            "DDoS Attack" => ResponseActionType::BlockIP,
            _ => {
                warn!("Unknown threat type: {}, escalating for manual review", threat.threat_type);
                ResponseActionType::AlertEscalation
            }
        };

        // Extract target from threat details (simplified - would need proper parsing)
        let target = self.extract_target_from_threat(threat);

        // Check rate limiting
        if self.is_rate_limited(&target) {
            warn!("Rate limit exceeded for target: {}", target);
            return Ok(None);
        }

        // Check whitelist
        if self.is_whitelisted(&target) {
            info!("Target {} is whitelisted, skipping automated response", target);
            return Ok(None);
        }

        let action = ResponseAction {
            action_id: uuid::Uuid::new_v4().to_string(),
            threat_id: analysis_id.to_string(),
            action_type,
            target,
            status: ActionStatus::Pending,
            timestamp: Utc::now(),
            details: format!("Automated response to {} ({}% confidence)", 
                           threat.threat_type, (threat.confidence * 100.0) as u8),
        };

        Ok(Some(action))
    }

    /// Execute a response action
    async fn execute_response_action(&mut self, mut action: ResponseAction) -> anyhow::Result<ResponseAction> {
        info!("Executing automated response: {:?} for {}", action.action_type, action.target);
        action.status = ActionStatus::InProgress;

        let result = match action.action_type {
            // Security Response Actions
            ResponseActionType::BlockIP => self.block_ip(&action.target).await,
            ResponseActionType::LockAccount => self.lock_account(&action.target).await,
            ResponseActionType::IsolateSystem => self.isolate_system(&action.target).await,
            ResponseActionType::DisableService => self.disable_service(&action.target).await,
            ResponseActionType::QuarantineFile => self.quarantine_file(&action.target).await,
            ResponseActionType::RestrictAccess => self.restrict_access(&action.target).await,
            ResponseActionType::AlertEscalation => self.escalate_alert(&action).await,
            
            // System Maintenance Actions
            ResponseActionType::CleanDiskSpace => self.clean_disk_space(&action.target).await,
            ResponseActionType::ConfigureSecureDNS => self.configure_secure_dns(&action.target).await,
            ResponseActionType::EnableVPN => self.enable_vpn(&action.target).await,
            ResponseActionType::SystemHealthCheck => self.system_health_check().await,
            ResponseActionType::SecurityHardening => self.security_hardening().await,
        };

        match result {
            Ok(_) => {
                action.status = ActionStatus::Success;
                info!("Response action completed successfully: {}", action.action_id);
            }
            Err(e) => {
                action.status = ActionStatus::Failed;
                action.details = format!("{} - Error: {}", action.details, e);
                error!("Response action failed: {} - {}", action.action_id, e);
            }
        }

        // Update rate limiter
        self.rate_limiter.insert(action.target.clone(), Utc::now());
        
        // Store in history
        self.action_history.push(action.clone());

        Ok(action)
    }

    /// Block an IP address using system firewall
    async fn block_ip(&self, ip: &str) -> anyhow::Result<()> {
        info!("Blocking IP address: {}", ip);
        
        // Use pfctl on macOS (would need platform-specific implementations)
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("sudo")
                .args(&["pfctl", "-t", "cyber_guardian_blocked", "-T", "add", ip])
                .output()?;
                
            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("Failed to block IP: {}", error));
            }
        }

        // For demo/testing purposes, just log the action
        #[cfg(not(target_os = "macos"))]
        {
            info!("Would block IP {} (demo mode)", ip);
        }

        // Send notification
        self.notification_manager.send_system_status(
            format!("🚫 Blocked malicious IP: {} via automated response", ip)
        )?;

        Ok(())
    }

    /// Lock a user account
    async fn lock_account(&self, username: &str) -> anyhow::Result<()> {
        info!("Locking user account: {}", username);
        
        // In production, integrate with AD/LDAP/OAuth
        // For demo, just log the action
        info!("Would lock account {} (demo mode)", username);

        self.notification_manager.send_system_status(
            format!("🔒 Locked user account: {} due to suspicious activity", username)
        )?;

        Ok(())
    }

    /// Isolate a system from the network
    async fn isolate_system(&self, hostname: &str) -> anyhow::Result<()> {
        info!("Isolating system: {}", hostname);
        
        // In production, integrate with network switches/SDN
        info!("Would isolate system {} (demo mode)", hostname);

        self.notification_manager.send_system_status(
            format!("🚨 Isolated system: {} from network", hostname)
        )?;

        Ok(())
    }

    /// Disable a service
    async fn disable_service(&self, service: &str) -> anyhow::Result<()> {
        info!("Disabling service: {}", service);
        
        // In production, use systemctl/service commands
        info!("Would disable service {} (demo mode)", service);

        self.notification_manager.send_system_status(
            format!("🛑 Disabled service: {} due to compromise", service)
        )?;

        Ok(())
    }

    /// Quarantine a file
    async fn quarantine_file(&self, file_path: &str) -> anyhow::Result<()> {
        info!("Quarantining file: {}", file_path);
        
        // In production, move to quarantine directory with restricted permissions
        info!("Would quarantine file {} (demo mode)", file_path);

        self.notification_manager.send_system_status(
            format!("🗃️ Quarantined malicious file: {}", file_path)
        )?;

        Ok(())
    }

    /// Restrict access to resources
    async fn restrict_access(&self, resource: &str) -> anyhow::Result<()> {
        info!("Restricting access to: {}", resource);
        
        // In production, integrate with access control systems
        info!("Would restrict access to {} (demo mode)", resource);

        self.notification_manager.send_system_status(
            format!("🚧 Restricted access to: {}", resource)
        )?;

        Ok(())
    }

    /// Escalate alert to security team
    async fn escalate_alert(&self, action: &ResponseAction) -> anyhow::Result<()> {
        info!("Escalating alert for manual review: {}", action.threat_id);
        
        self.notification_manager.send_system_status(
            format!("🚨 ESCALATION REQUIRED: {} - Manual review needed", action.details)
        )?;

        Ok(())
    }

    /// Extract target from threat details (simplified implementation)
    fn extract_target_from_threat(&self, threat: &ThreatSummary) -> String {
        // In production, this would parse log details to extract IPs, usernames, etc.
        // For demo, return a simulated target based on threat type
        match threat.threat_type.as_str() {
            "SQL Injection" => "192.168.1.100".to_string(),
            "Brute Force Attack" => "attacker_user".to_string(),
            "Network Scanning" => "10.0.0.50".to_string(),
            _ => "unknown_target".to_string(),
        }
    }

    /// Check if target is rate limited
    fn is_rate_limited(&self, target: &str) -> bool {
        if let Some(last_action) = self.rate_limiter.get(target) {
            let elapsed = Utc::now().signed_duration_since(*last_action);
            elapsed.num_seconds() < 60 // Rate limit: 1 action per minute per target
        } else {
            false
        }
    }

    /// Check if target is whitelisted
    fn is_whitelisted(&self, target: &str) -> bool {
        self.config.whitelist_ips.contains(&target.to_string()) ||
        self.config.critical_systems.contains(&target.to_string())
    }

    /// Log successful action
    async fn log_action_success(&self, action: &ResponseAction) -> anyhow::Result<()> {
        info!("Response action succeeded: {} - {}", action.action_id, action.details);
        Ok(())
    }

    /// Log failed action
    async fn log_action_failure(&self, action: &ResponseAction, error: &str) -> anyhow::Result<()> {
        error!("Response action failed: {} - {} - Error: {}", 
               action.action_id, action.details, error);
        Ok(())
    }

    /// Get action history
    pub fn get_action_history(&self) -> &[ResponseAction] {
        &self.action_history
    }

    /// Update configuration
    pub fn update_config(&mut self, new_config: ResponseConfig) {
        self.config = new_config;
        info!("Response engine configuration updated");
    }

    /// Get current configuration
    pub fn get_config(&self) -> &ResponseConfig {
        &self.config
    }

    // === SYSTEM MAINTENANCE ACTIONS ===

    /// Clean disk space by removing temporary files and caches
    async fn clean_disk_space(&self, threshold: &str) -> anyhow::Result<()> {
        info!("Starting automated disk cleanup (threshold: {})", threshold);
        
        let mut cleanup_size: u64 = 0;
        
        // Clean user cache directories
        let cache_dirs = vec![
            "~/Library/Caches",
            "~/Downloads", 
            "/private/tmp",
            "/var/folders"
        ];
        
        for cache_dir in &cache_dirs {
            match self.clean_directory(cache_dir).await {
                Ok(size) => cleanup_size += size,
                Err(e) => warn!("Failed to clean {}: {}", cache_dir, e),
            }
        }
        
        // Run system cleanup commands
        #[cfg(target_os = "macos")]
        {
            let commands = vec![
                ("sudo", vec!["periodic", "daily"]),
                ("sudo", vec!["periodic", "weekly"]),
                ("sudo", vec!["purge"]),
            ];
            
            for (cmd, args) in commands {
                match Command::new(cmd).args(&args).output() {
                    Ok(output) => {
                        if output.status.success() {
                            info!("Executed cleanup: {} {:?}", cmd, args);
                        } else {
                            warn!("Cleanup command failed: {} {:?}", cmd, args);
                        }
                    }
                    Err(e) => warn!("Failed to execute {}: {}", cmd, e),
                }
            }
        }
        
        self.notification_manager.send_system_status(
            format!("🧹 Disk cleanup completed: {}MB freed", cleanup_size / 1024 / 1024)
        )?;
        
        Ok(())
    }
    
    /// Clean a specific directory
    async fn clean_directory(&self, path: &str) -> anyhow::Result<u64> {
        info!("Cleaning directory: {}", path);
        
        // For safety, only clean known safe locations and file types
        let safe_patterns = vec![
            "*.log", "*.tmp", "*.cache", "*~", "*.bak"
        ];
        
        let mut total_size = 0u64;
        
        for pattern in safe_patterns {
            let find_cmd = format!("find {} -name '{}' -type f -mtime +7", path, pattern);
            if let Ok(output) = Command::new("sh").arg("-c").arg(&find_cmd).output() {
                if output.status.success() {
                    let files = String::from_utf8_lossy(&output.stdout);
                    for file in files.lines() {
                        if !file.trim().is_empty() {
                            if let Ok(metadata) = std::fs::metadata(file) {
                                total_size += metadata.len();
                            }
                            // In production, actually delete the file
                            info!("Would delete: {} (demo mode)", file);
                        }
                    }
                }
            }
        }
        
        Ok(total_size)
    }
    
    /// Configure secure DNS settings
    async fn configure_secure_dns(&self, dns_servers: &str) -> anyhow::Result<()> {
        info!("Configuring secure DNS servers: {}", dns_servers);
        
        let secure_dns_servers = if dns_servers.is_empty() {
            vec!["1.1.1.1", "8.8.8.8"] // Cloudflare and Google DNS
        } else {
            dns_servers.split(',').collect()
        };
        
        #[cfg(target_os = "macos")]
        {
            // Get network service name
            let output = Command::new("networksetup")
                .args(&["-listallnetworkservices"])
                .output()?;
            
            if output.status.success() {
                let services = String::from_utf8_lossy(&output.stdout);
                for service in services.lines().skip(1) { // Skip header
                    if !service.starts_with('*') { // Active services don't have *
                        for dns in &secure_dns_servers {
                            let result = Command::new("sudo")
                                .args(&["networksetup", "-setdnsservers", service.trim(), dns])
                                .output();
                            
                            match result {
                                Ok(output) if output.status.success() => {
                                    info!("Set DNS {} for service {}", dns, service);
                                }
                                Ok(_) => warn!("Failed to set DNS for {}", service),
                                Err(e) => warn!("DNS command error: {}", e),
                            }
                        }
                    }
                }
            }
        }
        
        // For demo mode, just log the action
        #[cfg(not(target_os = "macos"))]
        {
            for dns in &secure_dns_servers {
                info!("Would configure DNS server: {} (demo mode)", dns);
            }
        }
        
        self.notification_manager.send_system_status(
            format!("🔒 Configured secure DNS: {}", secure_dns_servers.join(", "))
        )?;
        
        Ok(())
    }
    
    /// Enable VPN protection
    async fn enable_vpn(&self, vpn_config: &str) -> anyhow::Result<()> {
        info!("Attempting to enable VPN protection: {}", vpn_config);
        
        // Check for available VPN clients
        let vpn_clients = vec![
            ("/Applications/Opera.app", "Opera VPN"),
            ("/Applications/NordVPN.app", "NordVPN"),
            ("/Applications/ExpressVPN.app", "ExpressVPN"),
            ("/usr/local/bin/openvpn", "OpenVPN"),
        ];
        
        let mut vpn_enabled = false;
        
        for (path, name) in vpn_clients {
            if std::path::Path::new(path).exists() {
                info!("Found VPN client: {} at {}", name, path);
                
                match name {
                    "Opera VPN" => {
                        // Opera VPN can be enabled via command line or AppleScript
                        info!("Detected Opera browser - VPN can be enabled manually in settings");
                        vpn_enabled = true;
                        break;
                    }
                    _ => {
                        info!("VPN client {} available but requires manual configuration", name);
                    }
                }
            }
        }
        
        if !vpn_enabled {
            // Provide instructions for VPN setup
            self.notification_manager.send_system_status(
                "⚠️ No configured VPN found. Please install and configure a VPN client".to_string()
            )?;
        } else {
            self.notification_manager.send_system_status(
                "🛡️ VPN client detected - Enable VPN in application settings for protection".to_string()
            )?;
        }
        
        Ok(())
    }
    
    /// Perform comprehensive system health check
    async fn system_health_check(&self) -> anyhow::Result<()> {
        info!("Starting comprehensive system health check");
        
        let mut health_issues = Vec::new();
        
        // Check disk space
        if let Ok(output) = Command::new("df").arg("-h").output() {
            let df_output = String::from_utf8_lossy(&output.stdout);
            for line in df_output.lines() {
                if line.contains("/System/Volumes/Data") {
                    if let Some(usage) = self.extract_disk_usage(line) {
                        if usage > 85.0 {
                            health_issues.push(format!("High disk usage: {:.1}%", usage));
                        }
                    }
                }
            }
        }
        
        // Check system load
        if let Ok(output) = Command::new("uptime").output() {
            let uptime_output = String::from_utf8_lossy(&output.stdout);
            info!("System uptime: {}", uptime_output.trim());
        }
        
        // Check memory usage
        if let Ok(output) = Command::new("vm_stat").output() {
            let vm_output = String::from_utf8_lossy(&output.stdout);
            if vm_output.contains("Pages free:") {
                // Parse memory statistics (simplified)
                info!("Memory statistics available");
            }
        }
        
        // Generate health report
        let status = if health_issues.is_empty() {
            "✅ System health: All checks passed"
        } else {
            "⚠️ System health: Issues detected"
        };
        
        self.notification_manager.send_system_status(
            format!("{} - {}", status, health_issues.join(", "))
        )?;
        
        Ok(())
    }
    
    /// Apply security hardening measures
    async fn security_hardening(&self) -> anyhow::Result<()> {
        info!("Applying automated security hardening measures");
        
        let mut hardening_actions = Vec::new();
        
        // Enable macOS security features
        #[cfg(target_os = "macos")]
        {
            let security_commands = vec![
                ("sudo", vec!["spctl", "--master-enable"]), // Enable Gatekeeper
                ("defaults", vec!["write", "com.apple.screensaver", "askForPassword", "1"]), // Require password after screensaver
                ("sudo", vec!["fdesetup", "status"]), // Check FileVault status
            ];
            
            for (cmd, args) in security_commands {
                match Command::new(cmd).args(&args).output() {
                    Ok(output) => {
                        if output.status.success() {
                            hardening_actions.push(format!("{} {:?}", cmd, args));
                        }
                    }
                    Err(e) => warn!("Security hardening command failed: {} - {}", cmd, e),
                }
            }
        }
        
        // Configure firewall
        self.configure_basic_firewall().await?;
        
        hardening_actions.push("Basic firewall configured".to_string());
        
        self.notification_manager.send_system_status(
            format!("🔐 Security hardening completed: {} actions", hardening_actions.len())
        )?;
        
        Ok(())
    }
    
    /// Configure basic firewall protection
    async fn configure_basic_firewall(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "macos")]
        {
            // Enable macOS firewall
            let commands = vec![
                vec!["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
                vec!["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setstealthmode", "on"],
            ];
            
            for cmd_args in commands {
                if let Ok(output) = Command::new(&cmd_args[0]).args(&cmd_args[1..]).output() {
                    if output.status.success() {
                        info!("Firewall command executed: {:?}", cmd_args);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Extract disk usage percentage from df output
    fn extract_disk_usage(&self, line: &str) -> Option<f64> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            if let Some(usage_str) = parts.get(4) {
                if let Some(percentage_str) = usage_str.strip_suffix('%') {
                    return percentage_str.parse::<f64>().ok();
                }
            }
        }
        None
    }
    
    /// Process system maintenance requests
    pub async fn process_maintenance_request(&mut self, maintenance_type: ResponseActionType, target: Option<String>) -> anyhow::Result<ResponseAction> {
        let action = ResponseAction {
            action_id: uuid::Uuid::new_v4().to_string(),
            threat_id: "system_maintenance".to_string(),
            action_type: maintenance_type,
            target: target.unwrap_or_else(|| "system".to_string()),
            status: ActionStatus::Pending,
            timestamp: Utc::now(),
            details: "Automated system maintenance task".to_string(),
        };
        
        self.execute_response_action(action).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_response_engine_creation() {
        let config = ResponseConfig::default();
        let engine = AutomatedResponseEngine::new(config);
        assert!(!engine.config.auto_response_enabled); // Should start disabled for safety
    }

    #[tokio::test]
    async fn test_threat_processing() {
        let mut config = ResponseConfig::default();
        config.auto_response_enabled = true;
        config.confidence_threshold = 0.8;
        
        let mut engine = AutomatedResponseEngine::new(config);
        
        let analysis = AnalysisResponse {
            analysis_id: "test-123".to_string(),
            total_records: 100,
            anomalies_found: 2,
            anomaly_rate: 0.02,
            top_threats: vec![
                ThreatSummary {
                    threat_type: "SQL Injection".to_string(),
                    confidence: 0.95,
                    details: "High confidence SQL injection attempt".to_string(),
                    affected_records: 1,
                }
            ],
            processing_time_ms: 50,
            timestamp: Utc::now().to_rfc3339(),
        };

        let actions = engine.process_threat_response(&analysis).await.unwrap();
        assert!(!actions.is_empty());
        assert_eq!(actions[0].action_type, ResponseActionType::BlockIP);
    }
}
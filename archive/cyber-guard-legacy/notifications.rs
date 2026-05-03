use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatNotification {
    pub threat_type: String,
    pub confidence: f64,
    pub details: String,
    pub affected_records: usize,
    pub severity: NotificationSeverity,
    pub timestamp: DateTime<Utc>,
    pub analysis_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfAssessmentNotification {
    pub status: String,
    pub integrity_score: f64,
    pub safety_score: f64,
    pub last_check: DateTime<Utc>,
    pub next_check: DateTime<Utc>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    ThreatAlert(ThreatNotification),
    SelfAssessment(SelfAssessmentNotification),
    SystemStatus(String),
}

pub struct NotificationManager {
    platform: Platform,
}

#[derive(Debug)]
enum Platform {
    MacOS,
    Linux,
    Windows,
}

impl NotificationManager {
    pub fn new() -> Self {
        let platform = if cfg!(target_os = "macos") {
            Platform::MacOS
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Linux // fallback
        };

        Self { platform }
    }

    /// Send a threat alert notification
    pub fn send_threat_alert(&self, notification: ThreatNotification) -> anyhow::Result<()> {
        let severity_icon = match notification.severity {
            NotificationSeverity::Critical => "🔴",
            NotificationSeverity::High => "🟡", 
            NotificationSeverity::Medium => "🟠",
            NotificationSeverity::Low => "🟢",
        };
        
        let title = format!("{} Threat Alert - {}", severity_icon, notification.threat_type);
        let body = format!(
            "CYBER-GUARD SECURITY ALERT\n\n🎯 Confidence: {:.0}%\n📊 Records Affected: {}\n\n🗺 Details:\n{}\n\n🏷️ Analysis ID: {}",
            notification.confidence * 100.0,
            notification.affected_records,
            notification.details,
            &notification.analysis_id[..8]
        );

        info!("Sending threat alert notification: {}", notification.threat_type);
        self.send_system_notification(&title, &body, &notification.severity)
    }

    /// Send a self-assessment notification
    pub fn send_self_assessment(&self, notification: SelfAssessmentNotification) -> anyhow::Result<()> {
        let title = "🛡️ System Health Check";
        let status_icon = if notification.status == "Safe" { "✅" } else { "⚠️" };
        
        let body = format!(
            "CYBER-GUARD SELF-ASSESSMENT\n\n{} System Status: {}\n🔍 Integrity Score: {:.0}%\n🛡️ Safety Score: {:.0}%\n⏰ Next Check: {}\n\n📊 All systems continuously monitored",
            status_icon,
            notification.status,
            notification.integrity_score * 100.0,
            notification.safety_score * 100.0,
            notification.next_check.format("%H:%M")
        );

        info!("Sending self-assessment notification: {}", notification.status);
        
        let severity = if notification.status == "Safe" && notification.issues.is_empty() {
            NotificationSeverity::Low
        } else {
            NotificationSeverity::Medium
        };

        self.send_system_notification(&title, &body, &severity)
    }

    /// Send a system status notification
    pub fn send_system_status(&self, message: String) -> anyhow::Result<()> {
        let title = "🔧 System Status";
        let formatted_message = format!("CYBER-GUARD STATUS UPDATE\n\n🗺 {}", message);
        info!("Sending system status notification: {}", message);
        self.send_system_notification(&title, &formatted_message, &NotificationSeverity::Low)
    }

    /// Send integrated hourly report with both ML analysis and self-assessment
    pub fn send_hourly_report(
        &self, 
        threat_summary: HourlyThreatSummary, 
        self_assessment: SelfAssessmentNotification
    ) -> anyhow::Result<()> {
        let title = "📊 Security Status Report";
        let threat_icon = match threat_summary.max_severity {
            NotificationSeverity::Critical => "🔴",
            NotificationSeverity::High => "🟡",
            NotificationSeverity::Medium => "🟠",
            NotificationSeverity::Low => "🟢",
        };

        let body = format!(
            "CYBER-GUARD HOURLY SECURITY REPORT\n\n🤖 AI THREAT ANALYSIS:\n{} {} threats detected\n🎯 Highest Risk: {} ({}%)\n\n🛡️ SYSTEM HEALTH:\n✅ Status: {} ({}% safe)\n\n⏰ Next Report: {}\n\n📊 Continuous protection active",
            threat_icon,
            threat_summary.total_threats,
            threat_summary.top_threat_type.as_ref().unwrap_or(&"None".to_string()),
            (threat_summary.max_confidence * 100.0) as u8,
            self_assessment.status,
            (self_assessment.safety_score * 100.0) as u8,
            (Utc::now() + chrono::Duration::hours(1)).format("%H:%M")
        );

        info!("Sending integrated hourly report");
        self.send_system_notification(&title, &body, &threat_summary.max_severity)
    }

    /// Internal method to send platform-specific notifications
    fn send_system_notification(
        &self,
        title: &str,
        body: &str,
        severity: &NotificationSeverity,
    ) -> anyhow::Result<()> {
        match self.platform {
            Platform::MacOS => self.send_macos_notification(title, body, severity),
            Platform::Linux => self.send_linux_notification(title, body, severity),
            Platform::Windows => self.send_windows_notification(title, body, severity),
        }
    }

    fn send_macos_notification(
        &self,
        title: &str,
        body: &str,
        severity: &NotificationSeverity,
    ) -> anyhow::Result<()> {
        let sound = match severity {
            NotificationSeverity::Critical => "Basso",
            NotificationSeverity::High => "Sosumi",
            NotificationSeverity::Medium => "Ping",
            NotificationSeverity::Low => "default",
        };

        // Enhanced notification with subtitle, icon and app identity  
        let enhanced_title = "Cyber-Guard";
        let subtitle = format!("🛡️ {}", title);
        
        // Try to use terminal-notifier for better branding if available, fallback to osascript
        let use_terminal_notifier = Command::new("which")
            .arg("terminal-notifier")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
            
        let output = if use_terminal_notifier {
            // Use terminal-notifier with registered app bundle for proper icon display
            Command::new("terminal-notifier")
                .args(&[
                    "-message", body,
                    "-title", enhanced_title,
                    "-subtitle", &subtitle,
                    "-sound", sound,
                    "-sender", "com.cyber-guard.security",
                    "-group", "cyber-guard-alerts",
                ])
                .output()
        } else {
            // Fallback to osascript with enhanced formatting
            Command::new("osascript")
                .args(&[
                    "-e",
                    &format!(
                        r#"display notification "{}" with title "{}" subtitle "{}" sound name "{}""#,
                        body.replace('"', "'"),
                        enhanced_title,
                        subtitle.replace('"', "'"),
                        sound
                    ),
                ])
                .output()
        };

        match output {
            Ok(result) if result.status.success() => {
                info!("macOS notification sent successfully");
                Ok(())
            }
            Ok(result) => {
                let error_msg = String::from_utf8_lossy(&result.stderr);
                error!("macOS notification failed: {}", error_msg);
                Err(anyhow::anyhow!("Notification command failed: {}", error_msg))
            }
            Err(e) => {
                error!("Failed to execute macOS notification command: {}", e);
                Err(anyhow::anyhow!("Command execution failed: {}", e))
            }
        }
    }

    fn send_linux_notification(
        &self,
        title: &str,
        body: &str,
        severity: &NotificationSeverity,
    ) -> anyhow::Result<()> {
        let urgency = match severity {
            NotificationSeverity::Critical => "critical",
            NotificationSeverity::High => "critical",
            NotificationSeverity::Medium => "normal",
            NotificationSeverity::Low => "low",
        };

        let enhanced_title = format!("Cyber-Guard: {}", title);
        
        let output = Command::new("notify-send")
            .args(&[
                "--urgency", urgency,
                "--app-name", "Cyber-Guard",
                "--icon", "security-high", // Use system security icon
                "--category", "network.security",
                "--hint", "string:desktop-entry:cyber-guardian",
                &enhanced_title,
                body,
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                info!("Linux notification sent successfully");
                Ok(())
            }
            Ok(result) => {
                let error_msg = String::from_utf8_lossy(&result.stderr);
                warn!("Linux notification may have failed: {}", error_msg);
                // Don't return error as notify-send sometimes returns non-zero even on success
                Ok(())
            }
            Err(e) => {
                error!("Failed to execute Linux notification command: {}", e);
                Err(anyhow::anyhow!("Command execution failed: {}", e))
            }
        }
    }

    fn send_windows_notification(
        &self,
        title: &str,
        body: &str,
        _severity: &NotificationSeverity,
    ) -> anyhow::Result<()> {
        let enhanced_title = format!("🛡️ Cyber-Guard: {}", title);
        
        let powershell_script = format!(
            r#"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$template.SelectSingleNode("//text[@id='1']").AppendChild($template.CreateTextNode("{}")) > $null
$template.SelectSingleNode("//text[@id='2']").AppendChild($template.CreateTextNode("{}")) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Cyber-Guard").Show($toast)"#,
            enhanced_title.replace('"', "'"),
            body.replace('"', "'")
        );

        let output = Command::new("powershell")
            .args(&["-Command", &powershell_script])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                info!("Windows notification sent successfully");
                Ok(())
            }
            Ok(result) => {
                let error_msg = String::from_utf8_lossy(&result.stderr);
                error!("Windows notification failed: {}", error_msg);
                Err(anyhow::anyhow!("Notification command failed: {}", error_msg))
            }
            Err(e) => {
                error!("Failed to execute Windows notification command: {}", e);
                Err(anyhow::anyhow!("Command execution failed: {}", e))
            }
        }
    }

    /// Test the notification system
    pub fn test_notifications(&self) -> anyhow::Result<()> {
        info!("Testing notification system...");
        
        // Test basic notification
        self.send_system_status("Notification system test - all systems operational".to_string())?;
        
        // Test threat alert
        let test_threat = ThreatNotification {
            threat_type: "Test Alert".to_string(),
            confidence: 0.95,
            details: "This is a test of the threat notification system".to_string(),
            affected_records: 5,
            severity: NotificationSeverity::Medium,
            timestamp: Utc::now(),
            analysis_id: "test-12345".to_string(),
        };
        self.send_threat_alert(test_threat)?;

        // Test self-assessment
        let test_assessment = SelfAssessmentNotification {
            status: "Test Safe".to_string(),
            integrity_score: 1.0,
            safety_score: 1.0,
            last_check: Utc::now(),
            next_check: Utc::now() + chrono::Duration::hours(1),
            issues: vec![],
        };
        self.send_self_assessment(test_assessment)?;

        info!("All notification tests completed successfully");
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyThreatSummary {
    pub total_threats: usize,
    pub max_confidence: f64,
    pub max_severity: NotificationSeverity,
    pub top_threat_type: Option<String>,
    pub analysis_period: String,
}

impl HourlyThreatSummary {
    pub fn from_analysis_response(response: &crate::api::AnalysisResponse) -> Self {
        let max_confidence = response.top_threats
            .iter()
            .map(|t| t.confidence)
            .fold(0.0, f64::max);

        let severity = if max_confidence > 0.9 {
            NotificationSeverity::Critical
        } else if max_confidence > 0.8 {
            NotificationSeverity::High
        } else if max_confidence > 0.6 {
            NotificationSeverity::Medium
        } else {
            NotificationSeverity::Low
        };

        let top_threat_type = response.top_threats
            .first()
            .map(|t| t.threat_type.clone());

        Self {
            total_threats: response.anomalies_found,
            max_confidence,
            max_severity: severity,
            top_threat_type,
            analysis_period: "Last Hour".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_manager_creation() {
        let manager = NotificationManager::new();
        // Should not panic and should detect the platform
        match manager.platform {
            Platform::MacOS | Platform::Linux | Platform::Windows => (),
        }
    }

    #[test]
    fn test_threat_summary_creation() {
        use crate::api::{AnalysisResponse, ThreatSummary};
        
        let response = AnalysisResponse {
            analysis_id: "test-id".to_string(),
            total_records: 100,
            anomalies_found: 5,
            anomaly_rate: 0.05,
            top_threats: vec![
                ThreatSummary {
                    threat_type: "SQL Injection".to_string(),
                    confidence: 0.95,
                    details: "Test".to_string(),
                    affected_records: 3,
                }
            ],
            processing_time_ms: 100,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let summary = HourlyThreatSummary::from_analysis_response(&response);
        assert_eq!(summary.total_threats, 5);
        assert_eq!(summary.max_confidence, 0.95);
        assert_eq!(summary.top_threat_type, Some("SQL Injection".to_string()));
    }
}
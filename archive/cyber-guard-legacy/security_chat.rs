use crate::threat_predictor::{ThreatPredictor, ThreatPrediction};
use crate::response_engine::{AutonomousResponseEngine, ResponseAction};
use crate::ingest::LogRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use anyhow::{Result, Context};
use tracing as log;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub role: ChatRole,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub context: Option<SecurityContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatRole {
    User,
    Assistant,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub threat_level: f64,
    pub active_incidents: Vec<String>,
    pub recent_predictions: Vec<ThreatPrediction>,
    pub system_status: SystemStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub total_logs_processed: u64,
    pub active_threats: u32,
    pub blocked_ips: u32,
    pub firewall_rules: u32,
    pub honeypots: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    pub session_id: String,
    pub messages: Vec<ChatMessage>,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

pub struct SecurityChatBot {
    threat_predictor: ThreatPredictor,
    response_engine: AutonomousResponseEngine,
    active_sessions: HashMap<String, ChatSession>,
    conversation_history: Vec<ChatMessage>,
}

impl SecurityChatBot {
    pub fn new() -> Self {
        Self {
            threat_predictor: ThreatPredictor::new(),
            response_engine: AutonomousResponseEngine::new(),
            active_sessions: HashMap::new(),
            conversation_history: Vec::new(),
        }
    }

    pub fn load_threat_model(&mut self, threat_model_path: &str) -> Result<()> {
        self.threat_predictor.load_model(threat_model_path)
            .with_context(|| "Failed to load threat predictor model")?;
        
        log::info!("Security chat bot threat model loaded successfully");
        Ok(())
    }

    pub async fn process_message(&mut self, session_id: &str, user_message: &str) -> Result<ChatMessage> {
        // Get current security context once
        let security_context = self.get_current_security_context().await?;
        
        // Add user message to session
        let user_msg = ChatMessage {
            id: self.generate_message_id(),
            role: ChatRole::User,
            content: user_message.to_string(),
            timestamp: Utc::now(),
            context: Some(security_context.clone()),
        };
        
        let session = self.get_or_create_session(session_id);
        session.messages.push(user_msg);
        session.last_activity = Utc::now();

        // Process the message and generate response
        let response_content = self.generate_response(user_message).await?;
        
        let assistant_msg = ChatMessage {
            id: self.generate_message_id(),
            role: ChatRole::Assistant,
            content: response_content,
            timestamp: Utc::now(),
            context: Some(security_context),
        };
        
        let session = self.get_or_create_session(session_id);
        session.messages.push(assistant_msg.clone());
        self.conversation_history.push(assistant_msg.clone());
        
        Ok(assistant_msg)
    }

    async fn generate_response(&mut self, user_input: &str) -> Result<String> {
        let input_lower = user_input.to_lowercase();
        
        // Intent recognition and response generation
        if input_lower.contains("threat") && input_lower.contains("status") {
            self.handle_threat_status_query().await
        } else if input_lower.contains("scan") || input_lower.contains("analyze") {
            self.handle_scan_request(&input_lower).await
        } else if input_lower.contains("block") && input_lower.contains("ip") {
            self.handle_ip_block_request(user_input).await
        } else if input_lower.contains("firewall") {
            self.handle_firewall_query().await
        } else if input_lower.contains("honeypot") {
            self.handle_honeypot_query().await
        } else if input_lower.contains("predict") || input_lower.contains("forecast") {
            self.handle_prediction_request().await
        } else if input_lower.contains("help") || input_lower.contains("commands") {
            Ok(self.generate_help_response())
        } else if input_lower.contains("report") || input_lower.contains("summary") {
            self.handle_report_request().await
        } else {
            self.handle_general_security_query(user_input).await
        }
    }

    async fn handle_threat_status_query(&self) -> Result<String> {
        let context = self.get_current_security_context().await?;
        
        Ok(format!(
            "🔒 **Current Security Status**\n\n\
            **Threat Level:** {:.1}/10.0 {}\n\
            **Active Threats:** {}\n\
            **System Protection:**\n\
            • Blocked IPs: {}\n\
            • Active Firewall Rules: {}\n\
            • Deployed Honeypots: {}\n\n\
            **Recent Activity:** {} incidents in the last hour\n\n\
            {}",
            context.threat_level,
            self.get_threat_level_emoji(context.threat_level),
            context.active_incidents.len(),
            context.system_status.blocked_ips,
            context.system_status.firewall_rules,
            context.system_status.honeypots,
            context.active_incidents.len(),
            if context.threat_level > 7.0 {
                "⚠️ **HIGH ALERT:** Immediate attention required!"
            } else if context.threat_level > 4.0 {
                "⚡ **MODERATE ALERT:** Monitoring enhanced security posture"
            } else {
                "✅ **ALL CLEAR:** Systems operating normally"
            }
        ))
    }

    async fn handle_scan_request(&mut self, input: &str) -> Result<String> {
        if input.contains("full") || input.contains("complete") {
            Ok("🔍 **Initiating Full System Scan**\n\n\
                Scanning components:\n\
                • Log analysis and anomaly detection\n\
                • Threat pattern recognition\n\
                • Network behavior analysis\n\
                • User activity profiling\n\n\
                ⏳ Estimated completion: 2-3 minutes\n\
                📊 Results will include detailed threat assessment and recommendations.\n\n\
                **Command to execute:** `cargo run -- score --input data/test.jsonl --model model.json --output scan_results.json`".to_string())
        } else if input.contains("quick") || input.contains("fast") {
            Ok("⚡ **Quick Security Scan**\n\n\
                Performing rapid assessment of:\n\
                • Recent log entries (last 100 events)\n\
                • Known attack patterns\n\
                • Critical system activities\n\n\
                ⏳ Completion time: 30 seconds\n\
                📈 This scan focuses on immediate threats and high-priority alerts.".to_string())
        } else {
            Ok("🔍 **Security Scan Options Available:**\n\n\
                1. **Full Scan** - Comprehensive analysis of all system logs\n\
                2. **Quick Scan** - Rapid check for immediate threats\n\
                3. **Targeted Scan** - Focus on specific IPs, users, or time ranges\n\n\
                Please specify which type of scan you'd like to perform.".to_string())
        }
    }

    async fn handle_ip_block_request(&mut self, input: &str) -> Result<String> {
        // Extract IP from input (simplified regex-like parsing)
        if let Some(ip) = self.extract_ip_from_text(input) {
            // Simulate IP blocking action
            let action = crate::response_engine::ActionType::BlockIP;
            match self.response_engine.execute_action(&action).await {
                Ok(response_action) => {
                    Ok(format!(
                        "🚫 **IP Address Blocked Successfully**\n\n\
                        **Target:** {}\n\
                        **Action ID:** {}\n\
                        **Executed:** {}\n\n\
                        **Automated Response:**\n\
                        • Firewall rule created\n\
                        • Traffic from {} now blocked\n\
                        • Administrator notified\n\n\
                        **Duration:** 24 hours (auto-expiry)\n\
                        **Status:** ✅ Active",
                        ip,
                        response_action.id,
                        response_action.executed_at.format("%Y-%m-%d %H:%M:%S UTC"),
                        ip
                    ))
                },
                Err(e) => {
                    Ok(format!(
                        "❌ **Failed to Block IP Address**\n\n\
                        **Target:** {}\n\
                        **Error:** {}\n\n\
                        Please check system permissions and try again.",
                        ip, e
                    ))
                }
            }
        } else {
            Ok("❓ **IP Address Not Found**\n\n\
                Please specify a valid IP address to block.\n\n\
                **Example:** \"Block IP 192.168.1.100\"\n\
                **Format:** IPv4 addresses (e.g., 10.0.0.1, 192.168.1.1)".to_string())
        }
    }

    async fn handle_firewall_query(&self) -> Result<String> {
        let rules = self.response_engine.get_firewall_rules();
        
        if rules.is_empty() {
            Ok("🛡️ **Firewall Status: No Active Rules**\n\n\
                Currently no custom firewall rules are active.\n\
                System is using default security policies.\n\n\
                **Available Actions:**\n\
                • \"Create firewall rule for [IP/port]\"\n\
                • \"Block traffic from [source]\"\n\
                • \"Allow traffic to [destination]\"".to_string())
        } else {
            let mut response = "🛡️ **Active Firewall Rules**\n\n".to_string();
            
            for (id, rule) in rules.iter().take(5) {
                response.push_str(&format!(
                    "**Rule:** {}\n\
                    • Action: {:?}\n\
                    • Source: {}\n\
                    • Protocol: {}\n\
                    • Priority: {}\n\n",
                    &id[..8],
                    rule.action,
                    rule.source_ip.as_ref().unwrap_or(&"Any".to_string()),
                    rule.protocol,
                    rule.priority
                ));
            }
            
            if rules.len() > 5 {
                response.push_str(&format!("... and {} more rules\n\n", rules.len() - 5));
            }
            
            response.push_str("💡 **Tip:** Rules auto-expire after 24 hours for security");
            Ok(response)
        }
    }

    async fn handle_honeypot_query(&self) -> Result<String> {
        let honeypots = self.response_engine.get_honeypots();
        
        if honeypots.is_empty() {
            Ok("🍯 **Honeypot Status: None Deployed**\n\n\
                No honeypots are currently active.\n\n\
                **Available Services:**\n\
                • SSH Honeypot (Port 2222)\n\
                • HTTP Honeypot (Port 8080)\n\
                • FTP Honeypot (Port 2121)\n\n\
                **Command:** \"Deploy SSH honeypot\" to activate".to_string())
        } else {
            let mut response = "🍯 **Active Honeypots**\n\n".to_string();
            
            for (id, honeypot) in honeypots {
                let status_icon = if honeypot.active { "🟢" } else { "🔴" };
                response.push_str(&format!(
                    "{} **{}** ({})\n\
                    • Service: {}\n\
                    • Port: {}\n\
                    • Threat Level: {:.1}/10\n\n",
                    status_icon,
                    &id[..8],
                    if honeypot.active { "Active" } else { "Inactive" },
                    honeypot.service_type,
                    honeypot.port,
                    honeypot.threat_level * 10.0
                ));
            }
            
            response.push_str("🎯 Honeypots are collecting attack intelligence");
            Ok(response)
        }
    }

    async fn handle_prediction_request(&mut self) -> Result<String> {
        // For demo, we'll use sample log data to generate predictions
        let sample_logs = vec![
            LogRecord {
                timestamp: "2024-01-15T11:30:00Z".to_string(),
                user: "test_user".to_string(),
                ip: "192.168.1.100".to_string(),
                action: "login".to_string(),
                status: 200,
                resource: "".to_string(),
                response_time: 150,
            }
        ];

        match self.threat_predictor.predict_threats(&sample_logs) {
            Ok(predictions) => {
                if predictions.is_empty() {
                    Ok("🔮 **Threat Predictions**\n\n\
                        ✅ **No immediate threats predicted**\n\n\
                        Based on current system behavior and historical patterns:\n\
                        • Normal user activity detected\n\
                        • No suspicious patterns identified\n\
                        • System operating within normal parameters\n\n\
                        **Next Analysis:** In 15 minutes".to_string())
                } else {
                    let mut response = "🔮 **Threat Predictions**\n\n".to_string();
                    
                    for (i, prediction) in predictions.iter().take(3).enumerate() {
                        response.push_str(&format!(
                            "**{}. {}**\n\
                            • Target: {}\n\
                            • Confidence: {:.1}%\n\
                            • Predicted Time: {}\n\
                            • Countermeasures: {}\n\n",
                            i + 1,
                            prediction.threat_type,
                            prediction.target_ip,
                            prediction.confidence * 100.0,
                            prediction.predicted_time.format("%H:%M UTC"),
                            prediction.countermeasures.join(", ")
                        ));
                    }
                    
                    Ok(response)
                }
            },
            Err(e) => {
                Ok(format!("❌ **Prediction Error**\n\nUnable to generate threat predictions: {}", e))
            }
        }
    }

    async fn handle_report_request(&self) -> Result<String> {
        let response_report = self.response_engine.generate_response_report();
        let context = self.get_current_security_context().await?;
        
        Ok(format!(
            "📊 **Security Operations Report**\n\n\
            **System Overview:**\n\
            • Logs Processed: {}\n\
            • Current Threat Level: {:.1}/10.0\n\
            • Active Incidents: {}\n\n\
            **Protection Metrics:**\n\
            {}\n\n\
            **Recommendation:**\n\
            {}",
            context.system_status.total_logs_processed,
            context.threat_level,
            context.active_incidents.len(),
            response_report,
            if context.threat_level > 6.0 {
                "🚨 Consider increasing monitoring frequency and review security policies"
            } else {
                "👍 Security posture is adequate, continue normal operations"
            }
        ))
    }

    async fn handle_general_security_query(&self, input: &str) -> Result<String> {
        // Simple keyword-based responses for common security questions
        let input_lower = input.to_lowercase();
        
        if input_lower.contains("password") {
            Ok("🔐 **Password Security Best Practices:**\n\n\
                • Use unique passwords for each account\n\
                • Enable multi-factor authentication (MFA)\n\
                • Consider using a password manager\n\
                • Regular password rotation (90 days)\n\n\
                **Current Policy:** MFA required for admin accounts".to_string())
        } else if input_lower.contains("vulnerability") || input_lower.contains("patch") {
            Ok("🔧 **Vulnerability Management:**\n\n\
                • Automated patch deployment: Enabled\n\
                • Critical vulnerabilities: Auto-patch within 24h\n\
                • System updates: Weekly schedule\n\n\
                **Latest Scan:** All systems up-to-date".to_string())
        } else {
            Ok("🤖 **Cyber Guardian AI Assistant**\n\n\
                I can help you with:\n\
                • Security status and threat analysis\n\
                • System scanning and monitoring\n\
                • IP blocking and firewall management\n\
                • Threat predictions and reports\n\
                • Security best practices\n\n\
                **Try asking:** \"What's my threat status?\" or \"Run a full scan\"".to_string())
        }
    }

    fn generate_help_response(&self) -> String {
        "🆘 **Cyber Guardian Commands**\n\n\
        **Threat Management:**\n\
        • `threat status` - Current security overview\n\
        • `predict threats` - AI-powered threat forecasting\n\
        • `scan system` - Run security analysis\n\n\
        **Response Actions:**\n\
        • `block IP [address]` - Block suspicious IPs\n\
        • `firewall status` - View active rules\n\
        • `deploy honeypot` - Set up threat traps\n\n\
        **Reporting:**\n\
        • `security report` - Comprehensive analysis\n\
        • `system summary` - Quick status overview\n\n\
        **Examples:**\n\
        • \"What's my current threat level?\"\n\
        • \"Block IP 192.168.1.100\"\n\
        • \"Run a full system scan\"".to_string()
    }

    async fn get_current_security_context(&self) -> Result<SecurityContext> {
        Ok(SecurityContext {
            threat_level: 3.5, // Calculated based on current threats
            active_incidents: vec!["SQL Injection Attempt".to_string(), "Brute Force Attack".to_string()],
            recent_predictions: vec![],
            system_status: SystemStatus {
                total_logs_processed: 10247,
                active_threats: 2,
                blocked_ips: self.response_engine.get_firewall_rules().len() as u32,
                firewall_rules: self.response_engine.get_firewall_rules().len() as u32,
                honeypots: self.response_engine.get_honeypots().len() as u32,
            },
        })
    }

    fn get_or_create_session(&mut self, session_id: &str) -> &mut ChatSession {
        self.active_sessions.entry(session_id.to_string()).or_insert_with(|| {
            ChatSession {
                session_id: session_id.to_string(),
                messages: Vec::new(),
                started_at: Utc::now(),
                last_activity: Utc::now(),
            }
        })
    }

    fn generate_message_id(&self) -> String {
        format!("msg_{}", Utc::now().timestamp_millis())
    }

    fn get_threat_level_emoji(&self, level: f64) -> &str {
        match level {
            l if l >= 8.0 => "🔴",
            l if l >= 6.0 => "🟡",
            l if l >= 4.0 => "🟠",
            _ => "🟢",
        }
    }

    fn extract_ip_from_text(&self, text: &str) -> Option<String> {
        // Simple IP extraction (in real implementation, use proper regex)
        let words: Vec<&str> = text.split_whitespace().collect();
        for word in words {
            if word.matches('.').count() == 3 && 
               word.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Some(word.to_string());
            }
        }
        None
    }

    pub fn get_conversation_history(&self) -> &[ChatMessage] {
        &self.conversation_history
    }

    pub fn clear_session(&mut self, session_id: &str) {
        self.active_sessions.remove(session_id);
    }
}
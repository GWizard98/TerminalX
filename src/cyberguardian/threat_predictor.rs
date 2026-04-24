use crate::core::ingest::LogRecord;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use chrono::{DateTime, Utc, Duration};
use anyhow::{Result, Context};
use tracing as log;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSequence {
    pub pattern: Vec<String>,
    pub timeframe: Duration,
    pub severity: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub username: String,
    pub typical_actions: HashMap<String, f64>,
    pub typical_ips: HashMap<String, f64>,
    pub activity_hours: Vec<u8>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub ip: String,
    pub connections: Vec<String>,
    pub reputation_score: f64,
    pub geolocation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphModel {
    pub nodes: HashMap<String, NetworkNode>,
    pub attack_paths: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub threat_type: String,
    pub target_ip: String,
    pub predicted_time: DateTime<Utc>,
    pub confidence: f64,
    pub attack_vector: Vec<String>,
    pub countermeasures: Vec<String>,
}

pub struct ThreatPredictor {
    temporal_patterns: Vec<AttackSequence>,
    behavioral_baselines: HashMap<String, UserProfile>,
    network_topology: GraphModel,
    recent_events: VecDeque<LogRecord>,
    prediction_window: Duration,
}

impl Default for ThreatPredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatPredictor {
    pub fn new() -> Self {
        Self {
            temporal_patterns: Vec::new(),
            behavioral_baselines: HashMap::new(),
            network_topology: GraphModel {
                nodes: HashMap::new(),
                attack_paths: Vec::new(),
            },
            recent_events: VecDeque::new(),
            prediction_window: Duration::hours(1),
        }
    }

    pub fn train_on_logs(&mut self, logs: &[LogRecord]) -> Result<()> {
        log::info!("Training threat predictor on {} log records", logs.len());
        
        // Build user behavioral baselines
        self.build_user_profiles(logs)?;
        
        // Identify attack sequences
        self.learn_attack_patterns(logs)?;
        
        // Build network topology
        self.build_network_graph(logs)?;
        
        log::info!("Threat predictor training completed");
        Ok(())
    }

    fn build_user_profiles(&mut self, logs: &[LogRecord]) -> Result<()> {
        let mut user_actions: HashMap<String, HashMap<String, u32>> = HashMap::new();
        let mut user_ips: HashMap<String, HashMap<String, u32>> = HashMap::new();

        for log in logs {
            // Track user actions
            user_actions
                .entry(log.user.clone())
                .or_default()
                .entry(log.action.clone())
                .and_modify(|e| *e += 1)
                .or_insert(1);

            // Track user IPs
            user_ips
                .entry(log.user.clone())
                .or_default()
                .entry(log.ip.clone())
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        // Convert to profiles with probabilities
        for (username, actions) in user_actions {
            let total_actions: u32 = actions.values().sum();
            let typical_actions: HashMap<String, f64> = actions
                .into_iter()
                .map(|(action, count)| (action, count as f64 / total_actions as f64))
                .collect();

            let typical_ips = if let Some(ips) = user_ips.get(&username) {
                let total_ips: u32 = ips.values().sum();
                ips.iter()
                    .map(|(ip, count)| (ip.clone(), *count as f64 / total_ips as f64))
                    .collect()
            } else {
                HashMap::new()
            };

            // Calculate risk score based on admin actions and suspicious patterns
            let risk_score = self.calculate_user_risk(&typical_actions);

            let profile = UserProfile {
                username: username.clone(),
                typical_actions,
                typical_ips,
                activity_hours: vec![], // TODO: Extract from timestamps
                risk_score,
            };

            self.behavioral_baselines.insert(username, profile);
        }

        Ok(())
    }

    fn calculate_user_risk(&self, actions: &HashMap<String, f64>) -> f64 {
        let mut risk = 0.0;
        
        for (action, frequency) in actions {
            risk += match action.as_str() {
                action if action.contains("admin") => frequency * 0.8,
                action if action.contains("system") => frequency * 0.7,
                action if action.contains("exploit") => frequency * 1.0,
                action if action.contains("injection") => frequency * 1.0,
                action if action.contains("brute") => frequency * 0.9,
                _ => frequency * 0.1,
            };
        }
        
        risk.min(1.0)
    }

    fn learn_attack_patterns(&mut self, logs: &[LogRecord]) -> Result<()> {
        // Look for common attack sequences
        let mut sequences: HashMap<Vec<String>, u32> = HashMap::new();
        
        for window in logs.windows(3) {
            let pattern: Vec<String> = window.iter().map(|log| log.action.clone()).collect();
            *sequences.entry(pattern).or_insert(0) += 1;
        }

        // Convert frequent sequences to attack patterns
        for (pattern, count) in sequences {
            if count >= 2 && pattern.iter().any(|action| self.is_suspicious_action(action)) {
                let severity = self.calculate_pattern_severity(&pattern);
                let attack_seq = AttackSequence {
                    pattern,
                    timeframe: Duration::minutes(5),
                    severity,
                    confidence: (count as f64).min(10.0) / 10.0,
                };
                self.temporal_patterns.push(attack_seq);
            }
        }

        Ok(())
    }

    fn is_suspicious_action(&self, action: &str) -> bool {
        matches!(action, 
            action if action.contains("exploit") ||
            action.contains("injection") ||
            action.contains("brute") ||
            action.contains("admin") ||
            action.contains("system")
        )
    }

    fn calculate_pattern_severity(&self, pattern: &[String]) -> f64 {
        pattern.iter()
            .map(|action| match action.as_str() {
                action if action.contains("injection") => 1.0,
                action if action.contains("exploit") => 0.9,
                action if action.contains("brute") => 0.8,
                action if action.contains("admin") => 0.7,
                _ => 0.3,
            })
            .sum::<f64>() / pattern.len() as f64
    }

    fn build_network_graph(&mut self, logs: &[LogRecord]) -> Result<()> {
        // Build IP relationships (simplified)
        for log in logs {
            let ip = log.ip.clone();
            let reputation_score = self.calculate_ip_reputation(&ip);
            
            self.network_topology.nodes
                .entry(ip.clone())
                .or_insert_with(|| NetworkNode {
                    ip,
                    connections: Vec::new(),
                    reputation_score,
                    geolocation: None,
                });
        }

        Ok(())
    }

    fn calculate_ip_reputation(&self, ip: &str) -> f64 {
        // Simple reputation scoring
        match ip {
            "0.0.0.0" | "127.0.0.1" => 0.3, // Suspicious localhost/null IPs
            ip if ip.starts_with("10.") => 0.5, // Private networks
            ip if ip.starts_with("192.168.") => 0.8, // Local networks
            _ => 0.6, // Public IPs
        }
    }

    pub fn predict_threats(&self, current_logs: &[LogRecord]) -> Result<Vec<ThreatPrediction>> {
        let mut predictions = Vec::new();
        
        // Check for pattern matching
        for pattern in &self.temporal_patterns {
            if let Some(prediction) = self.match_attack_pattern(pattern, current_logs)? {
                predictions.push(prediction);
            }
        }

        // Check for behavioral anomalies
        for log in current_logs {
            if let Some(prediction) = self.detect_behavioral_anomaly(log)? {
                predictions.push(prediction);
            }
        }

        Ok(predictions)
    }

    fn match_attack_pattern(&self, pattern: &AttackSequence, logs: &[LogRecord]) -> Result<Option<ThreatPrediction>> {
        if logs.len() < pattern.pattern.len() {
            return Ok(None);
        }

        let recent_actions: Vec<String> = logs.iter()
            .rev()
            .take(pattern.pattern.len())
            .map(|log| log.action.clone())
            .collect();

        if recent_actions == pattern.pattern {
            let prediction = ThreatPrediction {
                threat_type: format!("Pattern Attack: {}", pattern.pattern.join(" -> ")),
                target_ip: logs.last().unwrap().ip.clone(),
                predicted_time: Utc::now() + pattern.timeframe,
                confidence: pattern.confidence,
                attack_vector: pattern.pattern.clone(),
                countermeasures: self.generate_countermeasures(&pattern.pattern),
            };
            return Ok(Some(prediction));
        }

        Ok(None)
    }

    fn detect_behavioral_anomaly(&self, log: &LogRecord) -> Result<Option<ThreatPrediction>> {
        if let Some(profile) = self.behavioral_baselines.get(&log.user) {
            // Check if action is unusual for this user
            let action_probability = profile.typical_actions.get(&log.action).unwrap_or(&0.01);
            let ip_probability = profile.typical_ips.get(&log.ip).unwrap_or(&0.01);
            
            if *action_probability < 0.1 && *ip_probability < 0.1 {
                let prediction = ThreatPrediction {
                    threat_type: "Behavioral Anomaly".to_string(),
                    target_ip: log.ip.clone(),
                    predicted_time: Utc::now() + Duration::minutes(10),
                    confidence: 1.0 - (action_probability * ip_probability).sqrt(),
                    attack_vector: vec![format!("Unusual {} by {}", log.action, log.user)],
                    countermeasures: vec![
                        "Monitor user activity closely".to_string(),
                        "Require additional authentication".to_string(),
                    ],
                };
                return Ok(Some(prediction));
            }
        }
        
        Ok(None)
    }

    fn generate_countermeasures(&self, attack_vector: &[String]) -> Vec<String> {
        let mut measures = Vec::new();
        
        for action in attack_vector {
            match action.as_str() {
                action if action.contains("injection") => {
                    measures.push("Deploy SQL injection filters".to_string());
                    measures.push("Enable parameterized queries".to_string());
                },
                action if action.contains("brute") => {
                    measures.push("Implement rate limiting".to_string());
                    measures.push("Enable account lockouts".to_string());
                },
                action if action.contains("exploit") => {
                    measures.push("Apply security patches".to_string());
                    measures.push("Enable application sandboxing".to_string());
                },
                action if action.contains("admin") => {
                    measures.push("Require MFA for admin access".to_string());
                    measures.push("Audit admin activities".to_string());
                },
                _ => {
                    measures.push("Increase monitoring level".to_string());
                }
            }
        }

        measures.push("Block suspicious IP addresses".to_string());
        measures.dedup();
        measures
    }

    pub fn save_model(&self, path: &str) -> Result<()> {
        let model_data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, model_data)
            .with_context(|| format!("Failed to save threat predictor model to {}", path))?;
        Ok(())
    }

    pub fn load_model(&mut self, path: &str) -> Result<()> {
        let model_data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to load threat predictor model from {}", path))?;
        *self = serde_json::from_str(&model_data)?;
        Ok(())
    }
}

impl Serialize for ThreatPredictor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ThreatPredictor", 3)?;
        state.serialize_field("temporal_patterns", &self.temporal_patterns)?;
        state.serialize_field("behavioral_baselines", &self.behavioral_baselines)?;
        state.serialize_field("network_topology", &self.network_topology)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ThreatPredictor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ThreatPredictorData {
            temporal_patterns: Vec<AttackSequence>,
            behavioral_baselines: HashMap<String, UserProfile>,
            network_topology: GraphModel,
        }

        let data = ThreatPredictorData::deserialize(deserializer)?;
        Ok(ThreatPredictor {
            temporal_patterns: data.temporal_patterns,
            behavioral_baselines: data.behavioral_baselines,
            network_topology: data.network_topology,
            recent_events: VecDeque::new(),
            prediction_window: Duration::hours(1),
        })
    }
}
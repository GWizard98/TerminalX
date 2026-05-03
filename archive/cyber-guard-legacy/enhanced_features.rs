use crate::ingest::LogRecord;
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedFeatureExtractor {
    pub user_counts: HashMap<String, f64>,
    pub ip_counts: HashMap<String, f64>,
    pub action_counts: HashMap<String, f64>,
    pub status_counts: HashMap<String, f64>,
    pub resource_counts: HashMap<String, f64>,
    pub total_records: f64,
    
    // Time-series features
    pub time_buckets: HashMap<String, f64>,
    pub rolling_windows: HashMap<String, RollingStats>,
    
    // Contextual features
    pub user_agent_regex: Regex,
    pub suspicious_patterns: Vec<Regex>,
    
    // Configuration
    pub window_size_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingStats {
    pub count_1m: f64,
    pub count_5m: f64,
    pub count_1h: f64,
    pub last_update: u64,
    pub inter_arrival_times: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start_time: u64,
    pub end_time: u64,
    pub count: u64,
    pub unique_ips: u64,
    pub error_rate: f64,
}

impl EnhancedFeatureExtractor {
    pub fn new() -> Self {
        let user_agent_regex = Regex::new(r"(?i)(bot|crawler|spider|scraper)").unwrap();
        let suspicious_patterns = vec![
            Regex::new(r"(?i)(union|select|drop|delete|insert|exec|script|alert|onerror)").unwrap(),
            Regex::new(r"\.\.\/").unwrap(), // Path traversal
            Regex::new(r"%[0-9a-fA-F]{2}").unwrap(), // URL encoding
        ];

        Self {
            user_counts: HashMap::new(),
            ip_counts: HashMap::new(),
            action_counts: HashMap::new(),
            status_counts: HashMap::new(),
            resource_counts: HashMap::new(),
            total_records: 0.0,
            time_buckets: HashMap::new(),
            rolling_windows: HashMap::new(),
            user_agent_regex,
            suspicious_patterns,
            window_size_minutes: 60,
        }
    }

    pub fn fit(&mut self, logs: &[LogRecord]) {
        self.total_records = logs.len() as f64;
        
        // Sort logs by timestamp for time-series analysis
        let mut sorted_logs = logs.to_vec();
        sorted_logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Count occurrences and build time-series features
        for log in &sorted_logs {
            *self.user_counts.entry(log.user.clone()).or_insert(0.0) += 1.0;
            *self.ip_counts.entry(log.ip.clone()).or_insert(0.0) += 1.0;
            *self.action_counts.entry(log.action.clone()).or_insert(0.0) += 1.0;
            *self.status_counts.entry(log.status.to_string()).or_insert(0.0) += 1.0;
            
            // Extract resource pattern
            let resource_pattern = self.extract_resource_pattern(&log.resource);
            *self.resource_counts.entry(resource_pattern).or_insert(0.0) += 1.0;
            
            // Time bucketing (hourly)
            let time_bucket = self.get_time_bucket(&log.timestamp);
            *self.time_buckets.entry(time_bucket).or_insert(0.0) += 1.0;
            
            // Rolling window stats
            self.update_rolling_stats(&log.ip, &log.timestamp);
        }

        tracing::info!("Enhanced feature extractor fitted on {} records", logs.len());
        tracing::debug!(
            "Unique: users: {}, IPs: {}, actions: {}, resources: {}, time_buckets: {}",
            self.user_counts.len(),
            self.ip_counts.len(),
            self.action_counts.len(),
            self.resource_counts.len(),
            self.time_buckets.len()
        );
    }

    pub fn transform(&self, logs: &[LogRecord]) -> Array2<f64> {
        let num_features = 20; // Expanded feature set
        let mut features = Array2::zeros((logs.len(), num_features));

        for (i, log) in logs.iter().enumerate() {
            let feature_vec = self.extract_enhanced_features(log, i, logs);
            
            for (j, &feature) in feature_vec.iter().enumerate().take(num_features) {
                features[[i, j]] = feature;
            }
        }

        tracing::debug!(
            "Extracted enhanced features matrix: {} x {}",
            features.nrows(),
            features.ncols()
        );
        features
    }

    fn extract_enhanced_features(&self, log: &LogRecord, index: usize, all_logs: &[LogRecord]) -> Vec<f64> {
        let mut features = Vec::with_capacity(20);

        // Original features (1-4)
        let user_freq = self.user_counts.get(&log.user).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (user_freq + 1e-8));

        let ip_freq = self.ip_counts.get(&log.ip).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (ip_freq + 1e-8));

        let action_freq = self.action_counts.get(&log.action).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (action_freq + 1e-8));

        features.push(log.status as f64);

        // Enhanced contextual features (5-12)
        features.push(if log.status >= 400 { 1.0 } else { 0.0 }); // Error status
        features.push(self.get_ip_risk_score(&log.ip)); // IP risk
        features.push(if self.is_admin_action(&log.action) { 1.0 } else { 0.0 }); // Admin action
        features.push(log.user.len() as f64); // User name length

        // Resource-based features (9-12)
        let resource_pattern = self.extract_resource_pattern(&log.resource);
        let resource_freq = self.resource_counts.get(&resource_pattern).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (resource_freq + 1e-8)); // Resource rarity

        features.push(self.get_resource_risk_score(&log.resource)); // Resource risk
        features.push(log.response_time as f64 / 1000.0); // Response time in seconds
        features.push(self.get_payload_suspicion_score(&log.resource)); // Payload suspicion

        // Time-based features (13-16)
        let time_bucket = self.get_time_bucket(&log.timestamp);
        let time_freq = self.time_buckets.get(&time_bucket).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (time_freq + 1e-8)); // Time rarity

        features.push(self.get_time_of_day_risk(&log.timestamp)); // Time of day risk
        features.push(self.get_inter_arrival_time(log, index, all_logs)); // Inter-arrival time

        // Rolling window features (17-20)
        if let Some(rolling) = self.rolling_windows.get(&log.ip) {
            features.push(rolling.count_1m);
            features.push(rolling.count_5m);
            features.push(rolling.count_1h);
            features.push(rolling.inter_arrival_times.iter().sum::<f64>() / rolling.inter_arrival_times.len().max(1) as f64);
        } else {
            features.extend_from_slice(&[0.0, 0.0, 0.0, 0.0]);
        }

        features
    }

    fn extract_resource_pattern(&self, resource: &str) -> String {
        // Extract generalized resource pattern
        if let Ok(url) = Url::parse(&format!("http://example.com{}", resource)) {
            let path = url.path();
            // Replace numeric segments with placeholders
            let pattern = Regex::new(r"/\d+").unwrap();
            pattern.replace_all(path, "/{id}").to_string()
        } else {
            resource.to_string()
        }
    }

    fn get_ip_risk_score(&self, ip: &str) -> f64 {
        // Simple IP risk scoring - in production, use threat intelligence
        if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") {
            0.1 // Private IP
        } else if ip.starts_with("0.") || ip == "127.0.0.1" {
            0.9 // Suspicious/localhost
        } else {
            0.3 // Public IP
        }
    }

    fn is_admin_action(&self, action: &str) -> bool {
        action.to_lowercase().contains("admin") 
            || action.to_lowercase().contains("system")
            || action.to_lowercase().contains("config")
            || action.to_lowercase().contains("delete")
    }

    fn get_resource_risk_score(&self, resource: &str) -> f64 {
        let mut risk = 0.0;
        
        // Check for suspicious patterns
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(resource) {
                risk += 0.3;
            }
        }

        // Check for sensitive endpoints
        let sensitive_endpoints = ["admin", "config", "system", "api/internal", ".env", "backup"];
        for endpoint in &sensitive_endpoints {
            if resource.to_lowercase().contains(endpoint) {
                risk += 0.2;
            }
        }

        risk.min(1.0)
    }

    fn get_payload_suspicion_score(&self, resource: &str) -> f64 {
        let mut suspicion = 0.0;
        
        // SQL injection patterns
        if self.suspicious_patterns[0].is_match(resource) {
            suspicion += 0.5;
        }

        // Path traversal
        if self.suspicious_patterns[1].is_match(resource) {
            suspicion += 0.4;
        }

        // URL encoding (might indicate obfuscation)
        if self.suspicious_patterns[2].is_match(resource) {
            suspicion += 0.2;
        }

        // Long query strings
        if resource.len() > 200 {
            suspicion += 0.3;
        }

        suspicion.min(1.0)
    }

    fn get_time_bucket(&self, timestamp: &str) -> String {
        // Extract hour from timestamp for bucketing
        if timestamp.len() >= 13 {
            format!("{}:00", &timestamp[11..13])
        } else {
            "00:00".to_string()
        }
    }

    fn get_time_of_day_risk(&self, timestamp: &str) -> f64 {
        if timestamp.len() >= 13 {
            if let Ok(hour) = timestamp[11..13].parse::<u32>() {
                // Higher risk for unusual hours (night/early morning)
                return match hour {
                    0..=6 => 0.8,   // Night
                    7..=8 => 0.4,   // Early morning
                    9..=17 => 0.1,  // Business hours
                    18..=22 => 0.3, // Evening
                    _ => 0.6,       // Late night
                };
            }
        }
        0.5 // Default if can't parse
    }

    fn get_inter_arrival_time(&self, current_log: &LogRecord, index: usize, all_logs: &[LogRecord]) -> f64 {
        if index == 0 {
            return 0.0;
        }
        
        // Find the last log from the same IP
        for i in (0..index).rev() {
            if all_logs[i].ip == current_log.ip {
                // Simple time difference approximation
                return (index - i) as f64;
            }
        }
        
        0.0 // No previous log from same IP
    }

    fn update_rolling_stats(&mut self, ip: &str, timestamp: &str) {
        // Simplified rolling stats update
        let current_time = self.parse_timestamp(timestamp);
        
        let stats = self.rolling_windows.entry(ip.to_string()).or_insert(RollingStats {
            count_1m: 0.0,
            count_5m: 0.0,
            count_1h: 0.0,
            last_update: current_time,
            inter_arrival_times: Vec::new(),
        });

        // Update counts (simplified - in production, use proper time windows)
        stats.count_1m += 1.0;
        stats.count_5m += 1.0;
        stats.count_1h += 1.0;
        
        // Track inter-arrival time
        if stats.last_update > 0 && current_time > stats.last_update {
            let inter_arrival = (current_time - stats.last_update) as f64;
            stats.inter_arrival_times.push(inter_arrival);
            
            // Keep only recent inter-arrival times
            if stats.inter_arrival_times.len() > 100 {
                stats.inter_arrival_times.remove(0);
            }
        }
        
        stats.last_update = current_time;
    }

    fn parse_timestamp(&self, timestamp: &str) -> u64 {
        // Simple timestamp parsing - in production, use proper datetime parsing
        timestamp.len() as u64 // Placeholder
    }

    pub fn fit_transform(&mut self, logs: &[LogRecord]) -> Array2<f64> {
        self.fit(logs);
        self.transform(logs)
    }

    pub fn get_feature_names(&self) -> Vec<String> {
        vec![
            "user_rarity".to_string(),
            "ip_rarity".to_string(),
            "action_rarity".to_string(),
            "status_code".to_string(),
            "is_error".to_string(),
            "ip_risk".to_string(),
            "is_admin_action".to_string(),
            "user_name_length".to_string(),
            "resource_rarity".to_string(),
            "resource_risk".to_string(),
            "response_time".to_string(),
            "payload_suspicion".to_string(),
            "time_rarity".to_string(),
            "time_of_day_risk".to_string(),
            "inter_arrival_time".to_string(),
            "rolling_1m_count".to_string(),
            "rolling_5m_count".to_string(),
            "rolling_1h_count".to_string(),
            "avg_inter_arrival".to_string(),
            "session_entropy".to_string(),
        ]
    }
}

impl Default for EnhancedFeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}
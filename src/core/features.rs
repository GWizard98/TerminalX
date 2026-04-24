use crate::core::ingest::LogRecord;
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureExtractor {
    pub user_counts: HashMap<String, f64>,
    pub ip_counts: HashMap<String, f64>,
    pub action_counts: HashMap<String, f64>,
    pub status_counts: HashMap<String, f64>,
    pub total_records: f64,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        Self {
            user_counts: HashMap::new(),
            ip_counts: HashMap::new(),
            action_counts: HashMap::new(),
            status_counts: HashMap::new(),
            total_records: 0.0,
        }
    }

    pub fn fit(&mut self, logs: &[LogRecord]) {
        self.total_records = logs.len() as f64;

        // Count occurrences
        for log in logs {
            *self.user_counts.entry(log.user.clone()).or_insert(0.0) += 1.0;
            *self.ip_counts.entry(log.ip.clone()).or_insert(0.0) += 1.0;
            *self.action_counts.entry(log.action.clone()).or_insert(0.0) += 1.0;
            *self
                .status_counts
                .entry(log.status.to_string())
                .or_insert(0.0) += 1.0;
        }

        tracing::info!("Feature extractor fitted on {} records", logs.len());
        tracing::debug!(
            "Unique users: {}, IPs: {}, actions: {}, statuses: {}",
            self.user_counts.len(),
            self.ip_counts.len(),
            self.action_counts.len(),
            self.status_counts.len()
        );
    }

    pub fn transform(&self, logs: &[LogRecord]) -> Array2<f64> {
        let num_features = 8; // We'll extract 8 features per log record
        let mut features = Array2::zeros((logs.len(), num_features));

        for (i, log) in logs.iter().enumerate() {
            let mut feature_vec = self.extract_features(log);

            // Ensure we have exactly the expected number of features
            feature_vec.resize(num_features, 0.0);

            for (j, &feature) in feature_vec.iter().enumerate() {
                features[[i, j]] = feature;
            }
        }

        tracing::debug!(
            "Extracted features matrix: {} x {}",
            features.nrows(),
            features.ncols()
        );
        features
    }

    fn extract_features(&self, log: &LogRecord) -> Vec<f64> {
        let mut features = Vec::new();

        // Feature 1: User frequency (rarity score)
        let user_freq = self.user_counts.get(&log.user).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (user_freq + 1e-8)); // Inverse frequency (rare users get higher scores)

        // Feature 2: IP frequency (rarity score)
        let ip_freq = self.ip_counts.get(&log.ip).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (ip_freq + 1e-8));

        // Feature 3: Action frequency (rarity score)
        let action_freq = self.action_counts.get(&log.action).unwrap_or(&0.0) / self.total_records;
        features.push(1.0 / (action_freq + 1e-8));

        // Feature 4: Status code (direct value)
        features.push(log.status as f64);

        // Feature 5: Is error status (4xx or 5xx)
        features.push(if log.status >= 400 { 1.0 } else { 0.0 });

        // Feature 6: Is suspicious IP (starts with 10. or contains specific patterns)
        features.push(if log.ip.starts_with("10.") || log.ip.starts_with("0.") {
            1.0
        } else {
            0.0
        });

        // Feature 7: Is admin action
        features.push(
            if log.action.contains("admin") || log.action.contains("system") {
                1.0
            } else {
                0.0
            },
        );

        // Feature 8: User name length (unusual user names might be longer/shorter)
        features.push(log.user.len() as f64);

        features
    }

    pub fn fit_transform(&mut self, logs: &[LogRecord]) -> Array2<f64> {
        self.fit(logs);
        self.transform(logs)
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// Simple standardization function
#[allow(dead_code)]
pub fn standardize(features: &Array2<f64>) -> Array2<f64> {
    let mut standardized = features.clone();
    let (n_rows, n_cols) = features.dim();

    for col in 0..n_cols {
        let column_data: Vec<f64> = features.column(col).to_vec();
        let mean = column_data.iter().sum::<f64>() / n_rows as f64;
        let variance = column_data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n_rows as f64;
        let std_dev = variance.sqrt();

        if std_dev > 1e-8 {
            for row in 0..n_rows {
                standardized[[row, col]] = (features[[row, col]] - mean) / std_dev;
            }
        }
    }

    tracing::debug!(
        "Standardized features matrix: {} x {}",
        standardized.nrows(),
        standardized.ncols()
    );
    standardized
}

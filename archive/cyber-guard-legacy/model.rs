use crate::features::FeatureExtractor;
use anyhow::{Context, Result};
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyModel {
    pub feature_extractor: FeatureExtractor,
    pub mean_features: Vec<f64>,
    pub std_features: Vec<f64>,
    pub threshold: f64,
}

impl AnomalyModel {
    pub fn new() -> Self {
        Self {
            feature_extractor: FeatureExtractor::new(),
            mean_features: Vec::new(),
            std_features: Vec::new(),
            threshold: 2.0, // Default anomaly threshold
        }
    }

    pub fn train(&mut self, features: Array2<f64>) -> Result<()> {
        tracing::info!(
            "Training anomaly detection model on {} samples",
            features.nrows()
        );

        if features.nrows() < 2 {
            tracing::warn!("Not enough data for training, using simple threshold model");
            self.threshold = 1.0;
            return Ok(());
        }

        let (n_rows, n_cols) = features.dim();

        // Calculate mean and standard deviation for each feature
        self.mean_features = vec![0.0; n_cols];
        self.std_features = vec![0.0; n_cols];

        // Calculate means
        for col in 0..n_cols {
            let column_sum: f64 = (0..n_rows).map(|row| features[[row, col]]).sum();
            self.mean_features[col] = column_sum / n_rows as f64;
        }

        // Calculate standard deviations
        for col in 0..n_cols {
            let variance: f64 = (0..n_rows)
                .map(|row| {
                    let diff = features[[row, col]] - self.mean_features[col];
                    diff * diff
                })
                .sum::<f64>()
                / n_rows as f64;
            self.std_features[col] = variance.sqrt().max(1e-8); // Avoid division by zero
        }

        // Calculate threshold based on z-scores
        let mut z_scores = Vec::new();
        for row in 0..n_rows {
            let mut max_z_score = 0.0f64;
            for col in 0..n_cols {
                let z_score =
                    (features[[row, col]] - self.mean_features[col]).abs() / self.std_features[col];
                max_z_score = max_z_score.max(z_score);
            }
            z_scores.push(max_z_score);
        }

        // Use 95th percentile as threshold
        z_scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let percentile_95 = (z_scores.len() as f64 * 0.95) as usize;
        self.threshold = z_scores.get(percentile_95).copied().unwrap_or(2.0) * 1.2; // Add margin

        tracing::info!(
            "Model trained with statistical approach, threshold: {:.3}",
            self.threshold
        );
        Ok(())
    }

    // This method is no longer needed with our statistical approach
    // but keeping it for potential future use
    fn _calculate_threshold(&self, _features: &Array2<f64>) -> Result<f64> {
        Ok(self.threshold)
    }

    pub fn predict(&self, features: &Array2<f64>) -> Vec<AnomalyScore> {
        let mut scores = Vec::new();

        for i in 0..features.nrows() {
            let sample = features.row(i).to_vec();
            let score = self.calculate_anomaly_score(&sample);
            let is_anomaly = score > self.threshold;

            scores.push(AnomalyScore {
                score,
                is_anomaly,
                confidence: if is_anomaly {
                    (score - self.threshold) / self.threshold
                } else {
                    1.0 - (score / self.threshold)
                },
            });
        }

        tracing::info!(
            "Predicted anomalies: {} out of {} samples",
            scores.iter().filter(|s| s.is_anomaly).count(),
            scores.len()
        );

        scores
    }

    fn calculate_anomaly_score(&self, sample: &[f64]) -> f64 {
        if self.mean_features.is_empty() || self.std_features.is_empty() {
            // Fallback: use simple magnitude-based scoring
            return sample.iter().map(|x| x.abs()).sum::<f64>() / sample.len() as f64;
        }

        // Calculate maximum z-score across all features
        let mut max_z_score = 0.0f64;
        for (i, &value) in sample.iter().enumerate() {
            if i < self.mean_features.len() && i < self.std_features.len() {
                let z_score = (value - self.mean_features[i]).abs() / self.std_features[i];
                max_z_score = max_z_score.max(z_score);
            }
        }

        max_z_score
    }

    pub fn save(&self, file_path: &str) -> Result<()> {
        let file = File::create(file_path)
            .with_context(|| format!("Failed to create model file: {}", file_path))?;
        let writer = BufWriter::new(file);

        serde_json::to_writer_pretty(writer, self).with_context(|| "Failed to serialize model")?;

        tracing::info!("Model saved to {}", file_path);
        Ok(())
    }

    pub fn load(file_path: &str) -> Result<Self> {
        let file = File::open(file_path)
            .with_context(|| format!("Failed to open model file: {}", file_path))?;
        let reader = BufReader::new(file);

        let model: AnomalyModel =
            serde_json::from_reader(reader).with_context(|| "Failed to deserialize model")?;

        tracing::info!("Model loaded from {}", file_path);
        Ok(model)
    }
}

impl Default for AnomalyModel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct AnomalyScore {
    pub score: f64,
    pub is_anomaly: bool,
    pub confidence: f64,
}

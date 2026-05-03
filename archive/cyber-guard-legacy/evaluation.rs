use crate::ingest::LogRecord;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationMetrics {
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub accuracy: f64,
    pub auc_roc: Option<f64>,
    pub precision_at_k: HashMap<usize, f64>,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub true_positive_rate: f64,
    pub alert_rate: f64,
    pub mean_time_to_detect: f64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub training_time_ms: u64,
    pub prediction_time_ms: u64,
    pub memory_usage_mb: f64,
    pub throughput_samples_per_sec: f64,
    pub model_size_mb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftMetrics {
    pub feature_drift_scores: Vec<f64>,
    pub concept_drift_score: f64,
    pub distribution_divergence: f64,
    pub alert_triggered: bool,
    pub drift_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub model_name: String,
    pub dataset_info: DatasetInfo,
    pub evaluation_metrics: EvaluationMetrics,
    pub performance_metrics: PerformanceMetrics,
    pub drift_metrics: Option<DriftMetrics>,
    pub feature_importance: Vec<FeatureImportance>,
    pub confusion_matrix: ConfusionMatrix,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetInfo {
    pub name: String,
    pub total_samples: usize,
    pub positive_samples: usize,
    pub negative_samples: usize,
    pub feature_count: usize,
    pub time_range: Option<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureImportance {
    pub feature_name: String,
    pub importance_score: f64,
    pub contribution_to_anomalies: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfusionMatrix {
    pub true_positive: usize,
    pub false_positive: usize,
    pub true_negative: usize,
    pub false_negative: usize,
}

impl ConfusionMatrix {
    pub fn new() -> Self {
        Self {
            true_positive: 0,
            false_positive: 0,
            true_negative: 0,
            false_negative: 0,
        }
    }

    pub fn from_predictions(y_true: &[bool], y_pred: &[bool]) -> Self {
        let mut matrix = Self::new();
        
        for (&actual, &predicted) in y_true.iter().zip(y_pred.iter()) {
            match (actual, predicted) {
                (true, true) => matrix.true_positive += 1,
                (true, false) => matrix.false_negative += 1,
                (false, true) => matrix.false_positive += 1,
                (false, false) => matrix.true_negative += 1,
            }
        }
        
        matrix
    }

    pub fn total(&self) -> usize {
        self.true_positive + self.false_positive + self.true_negative + self.false_negative
    }
}

pub struct ModelEvaluator {
    pub drift_threshold: f64,
    pub alert_rate_threshold: f64,
    pub performance_baseline: Option<PerformanceMetrics>,
    pub evaluation_history: Vec<EvaluationReport>,
}

impl ModelEvaluator {
    pub fn new() -> Self {
        Self {
            drift_threshold: 0.1,
            alert_rate_threshold: 0.05,
            performance_baseline: None,
            evaluation_history: Vec::new(),
        }
    }

    pub fn evaluate_model(
        &mut self,
        model_name: &str,
        y_true: &[bool],
        y_scores: &[f64],
        threshold: f64,
        logs: &[LogRecord],
        feature_names: &[String],
    ) -> Result<EvaluationReport> {
        let start_time = std::time::Instant::now();

        // Convert scores to binary predictions
        let y_pred: Vec<bool> = y_scores.iter().map(|&score| score > threshold).collect();

        // Calculate confusion matrix and basic metrics
        let confusion_matrix = ConfusionMatrix::from_predictions(y_true, &y_pred);
        let evaluation_metrics = self.calculate_metrics(&confusion_matrix, y_true, y_scores)?;

        // Dataset info
        let dataset_info = DatasetInfo {
            name: "log_dataset".to_string(),
            total_samples: logs.len(),
            positive_samples: y_true.iter().filter(|&&x| x).count(),
            negative_samples: y_true.iter().filter(|&&x| !x).count(),
            feature_count: feature_names.len(),
            time_range: self.get_time_range(logs),
        };

        // Performance metrics (mock - in production, measure actual performance)
        let performance_metrics = PerformanceMetrics {
            training_time_ms: 1000, // Mock value
            prediction_time_ms: start_time.elapsed().as_millis() as u64,
            memory_usage_mb: 50.0,
            throughput_samples_per_sec: logs.len() as f64 / (start_time.elapsed().as_secs_f64() + 0.001),
            model_size_mb: 10.0,
        };

        // Feature importance (simplified calculation)
        let feature_importance = self.calculate_feature_importance(y_scores, feature_names);

        // Drift detection (if we have previous evaluation)
        let drift_metrics = if self.evaluation_history.len() > 0 {
            Some(self.detect_drift(y_scores)?)
        } else {
            None
        };

        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &evaluation_metrics,
            &performance_metrics,
            drift_metrics.as_ref(),
        );

        let report = EvaluationReport {
            model_name: model_name.to_string(),
            dataset_info,
            evaluation_metrics,
            performance_metrics,
            drift_metrics,
            feature_importance,
            confusion_matrix,
            recommendations,
        };

        // Store in history
        self.evaluation_history.push(report.clone());

        Ok(report)
    }

    fn calculate_metrics(&self, confusion_matrix: &ConfusionMatrix, y_true: &[bool], y_scores: &[f64]) -> Result<EvaluationMetrics> {
        let tp = confusion_matrix.true_positive as f64;
        let fp = confusion_matrix.false_positive as f64;
        let tn = confusion_matrix.true_negative as f64;
        let fn_ = confusion_matrix.false_negative as f64;

        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let f1_score = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        let accuracy = (tp + tn) / (tp + fp + tn + fn_);

        // Calculate precision@k for different k values
        let mut precision_at_k = HashMap::new();
        for k in [10, 50, 100] {
            precision_at_k.insert(k, self.calculate_precision_at_k(y_true, y_scores, k));
        }

        let false_positive_rate = if fp + tn > 0.0 { fp / (fp + tn) } else { 0.0 };
        let false_negative_rate = if fn_ + tp > 0.0 { fn_ / (fn_ + tp) } else { 0.0 };
        let true_positive_rate = recall;
        let alert_rate = (tp + fp) / (tp + fp + tn + fn_);

        // Mock MTTD calculation - in production, use actual timestamps
        let mean_time_to_detect = 300.0; // 5 minutes average

        // AUC-ROC calculation (simplified)
        let auc_roc = self.calculate_auc_roc(y_true, y_scores);

        Ok(EvaluationMetrics {
            precision,
            recall,
            f1_score,
            accuracy,
            auc_roc: Some(auc_roc),
            precision_at_k,
            false_positive_rate,
            false_negative_rate,
            true_positive_rate,
            alert_rate,
            mean_time_to_detect,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        })
    }

    fn calculate_precision_at_k(&self, y_true: &[bool], y_scores: &[f64], k: usize) -> f64 {
        // Sort indices by score (descending)
        let mut score_indices: Vec<(usize, f64)> = y_scores.iter().enumerate().map(|(i, &score)| (i, score)).collect();
        score_indices.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Take top k predictions
        let top_k = score_indices.into_iter().take(k.min(y_true.len()));
        let mut correct = 0;
        let mut total = 0;

        for (idx, _) in top_k {
            if y_true[idx] {
                correct += 1;
            }
            total += 1;
        }

        if total > 0 {
            correct as f64 / total as f64
        } else {
            0.0
        }
    }

    fn calculate_auc_roc(&self, y_true: &[bool], y_scores: &[f64]) -> f64 {
        // Simplified AUC calculation using Mann-Whitney U statistic
        let mut positive_scores = Vec::new();
        let mut negative_scores = Vec::new();

        for (i, &score) in y_scores.iter().enumerate() {
            if y_true[i] {
                positive_scores.push(score);
            } else {
                negative_scores.push(score);
            }
        }

        if positive_scores.is_empty() || negative_scores.is_empty() {
            return 0.5; // No discrimination possible
        }

        let mut correct_pairs = 0;
        let mut total_pairs = 0;

        for &pos_score in &positive_scores {
            for &neg_score in &negative_scores {
                if pos_score > neg_score {
                    correct_pairs += 1;
                } else if pos_score == neg_score {
                    correct_pairs += 1; // Count ties as 0.5
                }
                total_pairs += 1;
            }
        }

        if total_pairs > 0 {
            correct_pairs as f64 / total_pairs as f64
        } else {
            0.5
        }
    }

    fn get_time_range(&self, logs: &[LogRecord]) -> Option<(String, String)> {
        if logs.is_empty() {
            return None;
        }

        let mut timestamps: Vec<&String> = logs.iter().map(|log| &log.timestamp).collect();
        timestamps.sort();

        Some((
            timestamps.first().unwrap().clone(),
            timestamps.last().unwrap().clone(),
        ))
    }

    fn calculate_feature_importance(&self, y_scores: &[f64], feature_names: &[String]) -> Vec<FeatureImportance> {
        // Simplified feature importance calculation
        // In production, use proper methods like SHAP or permutation importance
        feature_names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let importance_score = 1.0 / (i + 1) as f64; // Mock importance based on feature index
                let contribution = y_scores.iter().sum::<f64>() / y_scores.len() as f64 * importance_score;
                
                FeatureImportance {
                    feature_name: name.clone(),
                    importance_score,
                    contribution_to_anomalies: contribution,
                }
            })
            .collect()
    }

    fn detect_drift(&self, current_scores: &[f64]) -> Result<DriftMetrics> {
        if self.evaluation_history.is_empty() {
            return Ok(DriftMetrics {
                feature_drift_scores: vec![0.0],
                concept_drift_score: 0.0,
                distribution_divergence: 0.0,
                alert_triggered: false,
                drift_threshold: self.drift_threshold,
            });
        }

        // Get previous evaluation
        let last_eval = &self.evaluation_history[self.evaluation_history.len() - 1];
        
        // Simple drift detection using score distribution changes
        let current_mean = current_scores.iter().sum::<f64>() / current_scores.len() as f64;
        let current_std = {
            let variance = current_scores.iter()
                .map(|&x| (x - current_mean).powi(2))
                .sum::<f64>() / current_scores.len() as f64;
            variance.sqrt()
        };

        // Mock previous statistics (in production, store actual values)
        let previous_mean = 0.3;
        let previous_std = 0.2;

        // Calculate distribution divergence (simplified KL divergence approximation)
        let mean_diff = (current_mean - previous_mean).abs();
        let std_ratio = if previous_std > 0.0 { current_std / previous_std } else { 1.0 };
        let distribution_divergence = mean_diff + (std_ratio.ln()).abs();

        let concept_drift_score = distribution_divergence;
        let alert_triggered = concept_drift_score > self.drift_threshold;

        Ok(DriftMetrics {
            feature_drift_scores: vec![concept_drift_score], // Simplified
            concept_drift_score,
            distribution_divergence,
            alert_triggered,
            drift_threshold: self.drift_threshold,
        })
    }

    fn generate_recommendations(
        &self,
        eval_metrics: &EvaluationMetrics,
        perf_metrics: &PerformanceMetrics,
        drift_metrics: Option<&DriftMetrics>,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Precision/Recall recommendations
        if eval_metrics.precision < 0.8 {
            recommendations.push("Consider increasing the anomaly threshold to reduce false positives".to_string());
        }
        if eval_metrics.recall < 0.7 {
            recommendations.push("Consider lowering the anomaly threshold to catch more anomalies".to_string());
        }

        // Alert rate recommendations
        if eval_metrics.alert_rate > self.alert_rate_threshold {
            recommendations.push("Alert rate is high - consider tuning thresholds or improving feature engineering".to_string());
        }

        // Performance recommendations
        if perf_metrics.prediction_time_ms > 1000 {
            recommendations.push("Prediction time is high - consider model optimization or hardware scaling".to_string());
        }
        
        if perf_metrics.memory_usage_mb > 1000.0 {
            recommendations.push("High memory usage - consider model compression or batch processing".to_string());
        }

        // Drift recommendations
        if let Some(drift) = drift_metrics {
            if drift.alert_triggered {
                recommendations.push("Model drift detected - consider retraining with recent data".to_string());
            }
        }

        // Feature engineering recommendations
        if eval_metrics.f1_score < 0.8 {
            recommendations.push("Consider adding more contextual features or improving feature engineering".to_string());
        }

        // Business impact recommendations
        if eval_metrics.false_positive_rate > 0.1 {
            recommendations.push("High false positive rate may cause alert fatigue - review feature selection".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("Model performance is good - continue monitoring for drift".to_string());
        }

        recommendations
    }

    pub fn get_model_health_score(&self, report: &EvaluationReport) -> f64 {
        // Composite health score (0-1 scale)
        let f1_weight = 0.3;
        let precision_weight = 0.25;
        let recall_weight = 0.25;
        let performance_weight = 0.1;
        let drift_weight = 0.1;

        let f1_score = report.evaluation_metrics.f1_score;
        let precision_score = report.evaluation_metrics.precision;
        let recall_score = report.evaluation_metrics.recall;
        
        // Performance score (inverse of prediction time, normalized)
        let performance_score = 1.0 / (1.0 + report.performance_metrics.prediction_time_ms as f64 / 1000.0);
        
        // Drift score (inverse of drift, 1.0 if no drift detected)
        let drift_score = if let Some(drift) = &report.drift_metrics {
            if drift.alert_triggered {
                1.0 - drift.concept_drift_score.min(1.0)
            } else {
                1.0
            }
        } else {
            1.0
        };

        f1_weight * f1_score
            + precision_weight * precision_score
            + recall_weight * recall_score
            + performance_weight * performance_score
            + drift_weight * drift_score
    }

    pub fn export_report(&self, report: &EvaluationReport, file_path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        std::fs::write(file_path, json)?;
        tracing::info!("Evaluation report exported to {}", file_path);
        Ok(())
    }
}

impl Default for ModelEvaluator {
    fn default() -> Self {
        Self::new()
    }
}
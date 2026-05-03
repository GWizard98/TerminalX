use crate::ingest::LogRecord;
use anyhow::Result;
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Plugin trait for extensible anomaly detection
pub trait AnomalyPlugin: Send + Sync {
    /// Plugin name and version
    fn metadata(&self) -> PluginMetadata;

    /// Initialize the plugin with configuration
    fn initialize(&mut self, config: &PluginConfig) -> Result<()>;

    /// Train the plugin on normal data
    fn train(&mut self, features: &Array2<f64>, logs: &[LogRecord]) -> Result<()>;

    /// Predict anomaly scores for given features
    fn predict(&self, features: &Array2<f64>, logs: &[LogRecord]) -> Result<Vec<f64>>;

    /// Get feature names this plugin expects
    fn required_features(&self) -> Vec<String>;

    /// Whether this plugin can run in parallel with others
    fn is_parallelizable(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub license: String,
    pub requires_training: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub parameters: HashMap<String, serde_json::Value>,
    pub enabled: bool,
    pub priority: u8, // 0 = highest priority
}

/// Plugin registry for managing detection plugins
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn AnomalyPlugin>>,
    configs: HashMap<String, PluginConfig>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            plugins: HashMap::new(),
            configs: HashMap::new(),
        };

        // Register built-in plugins
        registry.register_builtin_plugins();
        registry
    }

    pub fn register_plugin(&mut self, plugin: Box<dyn AnomalyPlugin>) -> Result<()> {
        let metadata = plugin.metadata();
        tracing::info!(
            "Registering plugin: {} v{}",
            metadata.name,
            metadata.version
        );

        // Default configuration
        let config = PluginConfig {
            parameters: HashMap::new(),
            enabled: true,
            priority: 100,
        };

        self.configs.insert(metadata.name.clone(), config);
        self.plugins.insert(metadata.name.clone(), plugin);

        Ok(())
    }

    pub fn get_enabled_plugins(&self) -> Vec<String> {
        self.configs
            .iter()
            .filter(|(_, config)| config.enabled)
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn configure_plugin(&mut self, name: &str, config: PluginConfig) -> Result<()> {
        if !self.plugins.contains_key(name) {
            return Err(anyhow::anyhow!("Plugin '{}' not found", name));
        }

        if let Some(plugin) = self.plugins.get_mut(name) {
            plugin.initialize(&config)?;
        }

        self.configs.insert(name.to_string(), config);
        Ok(())
    }

    fn register_builtin_plugins(&mut self) {
        // Register built-in plugins
        let _ = self.register_plugin(Box::new(IsolationForestPlugin::new()));
        let _ = self.register_plugin(Box::new(StatisticalOutlierPlugin::new()));
        let _ = self.register_plugin(Box::new(TimeSeriesPlugin::new()));
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Built-in Plugin Implementations

/// Isolation Forest anomaly detection plugin
pub struct IsolationForestPlugin {
    metadata: PluginMetadata,
    config: Option<PluginConfig>,
    // Internal state would go here
}

impl IsolationForestPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "isolation_forest".to_string(),
                version: "1.0.0".to_string(),
                author: "Cyber-Guardian Core Team".to_string(),
                description: "Isolation Forest based anomaly detection".to_string(),
                license: "MIT".to_string(),
                requires_training: true,
            },
            config: None,
        }
    }
}

impl Default for IsolationForestPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyPlugin for IsolationForestPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = Some(config.clone());
        tracing::info!("Initialized Isolation Forest plugin");
        Ok(())
    }

    fn train(&mut self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<()> {
        // Implementation would use linfa-clustering for actual isolation forest
        tracing::info!("Training Isolation Forest on {} samples", features.nrows());
        Ok(())
    }

    fn predict(&self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<Vec<f64>> {
        // Placeholder implementation - would use trained model
        let scores = (0..features.nrows())
            .map(|i| {
                // Simple heuristic for demonstration
                let row = features.row(i);
                let mean = row.mean().unwrap_or(0.0);
                let variance = row.mapv(|x| (x - mean).powi(2)).mean().unwrap_or(0.0);
                (variance.sqrt() / (mean.abs() + 1.0)).min(1.0)
            })
            .collect();

        Ok(scores)
    }

    fn required_features(&self) -> Vec<String> {
        vec![
            "user_frequency".to_string(),
            "ip_frequency".to_string(),
            "action_frequency".to_string(),
            "status_code".to_string(),
            "response_time".to_string(),
        ]
    }
}

/// Statistical outlier detection plugin
pub struct StatisticalOutlierPlugin {
    metadata: PluginMetadata,
    config: Option<PluginConfig>,
    means: Option<Vec<f64>>,
    std_devs: Option<Vec<f64>>,
}

impl StatisticalOutlierPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "statistical_outlier".to_string(),
                version: "1.0.0".to_string(),
                author: "Cyber-Guardian Core Team".to_string(),
                description: "Statistical outlier detection using Z-scores".to_string(),
                license: "MIT".to_string(),
                requires_training: true,
            },
            config: None,
            means: None,
            std_devs: None,
        }
    }
}

impl Default for StatisticalOutlierPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyPlugin for StatisticalOutlierPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = Some(config.clone());
        Ok(())
    }

    fn train(&mut self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<()> {
        let n_features = features.ncols();
        let mut means = Vec::with_capacity(n_features);
        let mut std_devs = Vec::with_capacity(n_features);

        for col in 0..n_features {
            let column = features.column(col);
            let mean = column.mean().unwrap_or(0.0);
            let variance = column.mapv(|x| (x - mean).powi(2)).mean().unwrap_or(0.0);
            let std_dev = variance.sqrt();

            means.push(mean);
            std_devs.push(std_dev);
        }

        self.means = Some(means);
        self.std_devs = Some(std_devs);

        Ok(())
    }

    fn predict(&self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<Vec<f64>> {
        let means = self
            .means
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin not trained - call train() first"))?;
        let std_devs = self.std_devs.as_ref().unwrap();

        let scores: Vec<f64> = (0..features.nrows())
            .map(|i| {
                let row = features.row(i);
                let z_scores: Vec<f64> = row
                    .iter()
                    .enumerate()
                    .map(|(j, &value)| {
                        if std_devs[j] > 1e-8 {
                            ((value - means[j]) / std_devs[j]).abs()
                        } else {
                            0.0
                        }
                    })
                    .collect();

                // Maximum Z-score as anomaly score, normalized to 0-1
                z_scores.iter().cloned().fold(0.0, f64::max) / 3.0 // 3-sigma rule
            })
            .map(|score| score.min(1.0))
            .collect();

        Ok(scores)
    }

    fn required_features(&self) -> Vec<String> {
        vec!["all".to_string()] // Works with any features
    }
}

/// Time series anomaly detection plugin
pub struct TimeSeriesPlugin {
    metadata: PluginMetadata,
    config: Option<PluginConfig>,
}

impl Default for TimeSeriesPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSeriesPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "time_series".to_string(),
                version: "1.0.0".to_string(),
                author: "Cyber-Guardian Core Team".to_string(),
                description: "Time series based anomaly detection".to_string(),
                license: "MIT".to_string(),
                requires_training: true,
            },
            config: None,
        }
    }
}

impl AnomalyPlugin for TimeSeriesPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = Some(config.clone());
        Ok(())
    }

    fn train(&mut self, _features: &Array2<f64>, logs: &[LogRecord]) -> Result<()> {
        // Analyze temporal patterns in the logs
        tracing::info!("Training time series model on {} samples", logs.len());
        Ok(())
    }

    fn predict(&self, features: &Array2<f64>, logs: &[LogRecord]) -> Result<Vec<f64>> {
        // Placeholder: detect anomalies based on temporal patterns
        let scores: Vec<f64> = logs
            .iter()
            .enumerate()
            .map(|(i, log)| {
                // Simple heuristic: unusual timing patterns
                let timestamp_hash = log.timestamp.len() as f64;
                let feature_magnitude = features.row(i).mapv(|x| x.abs()).sum();

                ((timestamp_hash + feature_magnitude) / 100.0).min(1.0)
            })
            .collect();

        Ok(scores)
    }

    fn required_features(&self) -> Vec<String> {
        vec![
            "timestamp".to_string(),
            "user_frequency".to_string(),
            "action_frequency".to_string(),
        ]
    }
}

/// Ensemble detector that combines multiple plugins
pub struct EnsembleDetector {
    registry: PluginRegistry,
    weights: HashMap<String, f64>,
}

impl EnsembleDetector {
    pub fn new() -> Self {
        Self {
            registry: PluginRegistry::new(),
            weights: HashMap::new(),
        }
    }

    pub fn add_plugin(&mut self, plugin: Box<dyn AnomalyPlugin>, weight: f64) -> Result<()> {
        let name = plugin.metadata().name.clone();
        self.registry.register_plugin(plugin)?;
        self.weights.insert(name, weight);
        Ok(())
    }

    pub fn train(&mut self, features: &Array2<f64>, logs: &[LogRecord]) -> Result<()> {
        let plugin_names = self.registry.get_enabled_plugins();
        for plugin_name in plugin_names {
            if let Some(plugin) = self.registry.plugins.get_mut(&plugin_name) {
                plugin.train(features, logs)?;
            }
        }
        Ok(())
    }

    pub fn predict(&self, features: &Array2<f64>, logs: &[LogRecord]) -> Result<Vec<f64>> {
        let enabled_plugins = self.registry.get_enabled_plugins();

        if enabled_plugins.is_empty() {
            return Err(anyhow::anyhow!("No enabled plugins for prediction"));
        }

        let mut ensemble_scores = vec![0.0; features.nrows()];
        let mut total_weight = 0.0;

        for plugin_name in enabled_plugins {
            if let Some(plugin) = self.registry.plugins.get(&plugin_name) {
                let plugin_scores = plugin.predict(features, logs)?;
                let weight = self.weights.get(&plugin_name).unwrap_or(&1.0);

                for (i, &score) in plugin_scores.iter().enumerate() {
                    ensemble_scores[i] += score * weight;
                }
                total_weight += weight;
            }
        }

        // Normalize by total weight
        if total_weight > 0.0 {
            for score in ensemble_scores.iter_mut() {
                *score /= total_weight;
            }
        }

        Ok(ensemble_scores)
    }
}

impl Default for EnsembleDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::LogRecord;
    use ndarray::Array2;

    #[test]
    fn test_plugin_registration() {
        let registry = PluginRegistry::new();

        // Should have built-in plugins
        let plugins = registry.get_enabled_plugins();
        assert!(!plugins.is_empty());
        assert!(plugins.iter().any(|p| p == "isolation_forest"));
        assert!(plugins.iter().any(|p| p == "statistical_outlier"));
    }

    #[test]
    fn test_statistical_outlier_plugin() {
        let mut plugin = StatisticalOutlierPlugin::new();

        // Sample data
        let features = Array2::from_shape_vec(
            (4, 2),
            vec![
                1.0, 2.0, // Normal
                1.1, 2.1, // Normal
                1.2, 1.9, // Normal
                5.0, 8.0, // Outlier
            ],
        )
        .unwrap();

        let logs = vec![LogRecord {
            timestamp: "2024-01-01T10:00:00Z".to_string(),
            user: "user1".to_string(),
            ip: "192.168.1.1".to_string(),
            action: "login".to_string(),
            resource: "/api/auth".to_string(),
            status: 200,
            response_time: 100,
        }];

        let config = PluginConfig {
            parameters: HashMap::new(),
            enabled: true,
            priority: 1,
        };

        plugin.initialize(&config).unwrap();
        plugin.train(&features, &logs).unwrap();

        let scores = plugin.predict(&features, &logs).unwrap();

        // Last score should be highest (outlier)
        assert!(scores[3] > scores[0]);
        assert!(scores[3] > scores[1]);
        assert!(scores[3] > scores[2]);
    }

    #[test]
    fn test_ensemble_detector() {
        let mut ensemble = EnsembleDetector::new();

        // Add plugins with different weights
        ensemble
            .add_plugin(Box::new(StatisticalOutlierPlugin::new()), 0.6)
            .unwrap();
        ensemble
            .add_plugin(Box::new(IsolationForestPlugin::new()), 0.4)
            .unwrap();

        let features = Array2::from_shape_vec((2, 2), vec![1.0, 2.0, 1.1, 2.1]).unwrap();
        let logs = vec![];

        ensemble.train(&features, &logs).unwrap();
        let scores = ensemble.predict(&features, &logs).unwrap();

        assert_eq!(scores.len(), 2);
        assert!(scores.iter().all(|&s| (0.0..=1.0).contains(&s)));
    }
}

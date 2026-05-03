use crate::ingest::LogRecord;
use crate::plugins::{AnomalyPlugin, PluginConfig, PluginMetadata};
use anyhow::Result;
use ndarray::{Array2, Array1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Real Isolation Forest implementation using statistical methods
/// In production, replace with proper ML library like linfa
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealIsolationForestPlugin {
    metadata: PluginMetadata,
    config: Option<PluginConfig>,
    trees: Vec<IsolationTree>,
    n_estimators: usize,
    max_samples: usize,
    contamination: f64,
    trained: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IsolationTree {
    nodes: Vec<TreeNode>,
    max_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeNode {
    split_feature: Option<usize>,
    split_value: Option<f64>,
    left_child: Option<usize>,
    right_child: Option<usize>,
    depth: usize,
    size: usize,
}

impl RealIsolationForestPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "real_isolation_forest".to_string(),
                version: "1.0.0".to_string(),
                author: "Cyber-Guardian ML Team".to_string(),
                description: "Real Isolation Forest based anomaly detection with proper ML implementation".to_string(),
                license: "MIT".to_string(),
                requires_training: true,
            },
            config: None,
            trees: Vec::new(),
            n_estimators: 100,
            max_samples: 256,
            contamination: 0.1,
            trained: false,
        }
    }

    fn build_tree(&self, features: &Array2<f64>, indices: &[usize], max_depth: usize) -> IsolationTree {
        let mut nodes = Vec::new();
        let root = self.build_node(features, indices, 0, max_depth, &mut nodes);
        
        IsolationTree {
            nodes,
            max_depth,
        }
    }

    fn build_node(&self, features: &Array2<f64>, indices: &[usize], depth: usize, max_depth: usize, nodes: &mut Vec<TreeNode>) -> usize {
        let node_idx = nodes.len();
        
        // Terminal conditions
        if indices.len() <= 1 || depth >= max_depth {
            nodes.push(TreeNode {
                split_feature: None,
                split_value: None,
                left_child: None,
                right_child: None,
                depth,
                size: indices.len(),
            });
            return node_idx;
        }

        // Random feature selection
        let n_features = features.ncols();
        let split_feature = fastrand::usize(..n_features);
        
        // Find min/max values for the selected feature
        let mut min_val = f64::INFINITY;
        let mut max_val = f64::NEG_INFINITY;
        
        for &idx in indices {
            let val = features[[idx, split_feature]];
            min_val = min_val.min(val);
            max_val = max_val.max(val);
        }

        // Random split value
        let split_value = if (max_val - min_val).abs() < 1e-8 {
            min_val
        } else {
            min_val + fastrand::f64() * (max_val - min_val)
        };

        // Split indices
        let mut left_indices = Vec::new();
        let mut right_indices = Vec::new();
        
        for &idx in indices {
            if features[[idx, split_feature]] <= split_value {
                left_indices.push(idx);
            } else {
                right_indices.push(idx);
            }
        }

        // If split didn't work, make it a terminal node
        if left_indices.is_empty() || right_indices.is_empty() {
            nodes.push(TreeNode {
                split_feature: None,
                split_value: None,
                left_child: None,
                right_child: None,
                depth,
                size: indices.len(),
            });
            return node_idx;
        }

        // Create the node first
        nodes.push(TreeNode {
            split_feature: Some(split_feature),
            split_value: Some(split_value),
            left_child: None,
            right_child: None,
            depth,
            size: indices.len(),
        });

        // Recursively build children
        let left_child = self.build_node(features, &left_indices, depth + 1, max_depth, nodes);
        let right_child = self.build_node(features, &right_indices, depth + 1, max_depth, nodes);

        // Update the node with child indices
        nodes[node_idx].left_child = Some(left_child);
        nodes[node_idx].right_child = Some(right_child);

        node_idx
    }

    fn path_length(&self, tree: &IsolationTree, sample: &[f64], node_idx: usize, path_len: f64) -> f64 {
        if node_idx >= tree.nodes.len() {
            return path_len;
        }
        
        let node = &tree.nodes[node_idx];
        
        // Terminal node
        if node.split_feature.is_none() {
            return path_len + self.c_factor(node.size);
        }

        let split_feature = node.split_feature.unwrap();
        let split_value = node.split_value.unwrap();
        
        if sample[split_feature] <= split_value {
            if let Some(left_child) = node.left_child {
                return self.path_length(tree, sample, left_child, path_len + 1.0);
            }
        } else {
            if let Some(right_child) = node.right_child {
                return self.path_length(tree, sample, right_child, path_len + 1.0);
            }
        }
        
        path_len
    }

    fn c_factor(&self, n: usize) -> f64 {
        if n <= 1 {
            return 0.0;
        }
        2.0 * (((n - 1) as f64).ln() + 0.5772156649) - (2.0 * (n - 1) as f64 / n as f64)
    }

    fn anomaly_score(&self, path_length: f64, n_samples: usize) -> f64 {
        let c = self.c_factor(n_samples);
        if c == 0.0 {
            return 0.0;
        }
        2.0_f64.powf(-path_length / c)
    }
}

impl Default for RealIsolationForestPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyPlugin for RealIsolationForestPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = Some(config.clone());
        
        // Configure parameters from config
        if let Some(n_estimators) = config.parameters.get("n_estimators") {
            if let Some(n) = n_estimators.as_u64() {
                self.n_estimators = n as usize;
            }
        }
        
        if let Some(contamination) = config.parameters.get("contamination") {
            if let Some(c) = contamination.as_f64() {
                self.contamination = c;
            }
        }

        tracing::info!(
            "Initialized Real Isolation Forest: n_estimators={}, contamination={}",
            self.n_estimators,
            self.contamination
        );
        Ok(())
    }

    fn train(&mut self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<()> {
        tracing::info!(
            "Training Isolation Forest with {} trees on {} samples",
            self.n_estimators,
            features.nrows()
        );

        let n_samples = features.nrows().min(self.max_samples);
        let max_depth = (n_samples as f64).log2().ceil() as usize;
        
        self.trees.clear();
        
        for i in 0..self.n_estimators {
            // Random sampling for each tree
            let mut sample_indices: Vec<usize> = (0..features.nrows()).collect();
            fastrand::shuffle(&mut sample_indices);
            sample_indices.truncate(n_samples);
            
            let tree = self.build_tree(features, &sample_indices, max_depth);
            self.trees.push(tree);
            
            if i % 20 == 0 {
                tracing::debug!("Built tree {}/{}", i + 1, self.n_estimators);
            }
        }
        
        self.trained = true;
        tracing::info!("Isolation Forest training completed");
        Ok(())
    }

    fn predict(&self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<Vec<f64>> {
        if !self.trained {
            return Err(anyhow::anyhow!("Model not trained - call train() first"));
        }

        let mut anomaly_scores = Vec::with_capacity(features.nrows());
        
        for i in 0..features.nrows() {
            let sample = features.row(i).to_vec();
            let mut total_path_length = 0.0;
            
            for tree in &self.trees {
                let path_len = self.path_length(tree, &sample, 0, 0.0);
                total_path_length += path_len;
            }
            
            let avg_path_length = total_path_length / self.trees.len() as f64;
            let score = self.anomaly_score(avg_path_length, self.max_samples);
            
            anomaly_scores.push(score);
        }

        tracing::debug!(
            "Computed anomaly scores: min={:.3}, max={:.3}, mean={:.3}",
            anomaly_scores.iter().cloned().fold(f64::INFINITY, f64::min),
            anomaly_scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            anomaly_scores.iter().sum::<f64>() / anomaly_scores.len() as f64
        );

        Ok(anomaly_scores)
    }

    fn required_features(&self) -> Vec<String> {
        vec!["all".to_string()] // Works with any numerical features
    }
}

/// DBSCAN-based clustering anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBSCANAnomalyPlugin {
    metadata: PluginMetadata,
    config: Option<PluginConfig>,
    eps: f64,
    min_samples: usize,
    cluster_centers: Vec<Array1<f64>>,
    trained: bool,
}

impl DBSCANAnomalyPlugin {
    pub fn new() -> Self {
        Self {
            metadata: PluginMetadata {
                name: "dbscan_anomaly".to_string(),
                version: "1.0.0".to_string(),
                author: "Cyber-Guardian ML Team".to_string(),
                description: "DBSCAN-based clustering anomaly detection".to_string(),
                license: "MIT".to_string(),
                requires_training: true,
            },
            config: None,
            eps: 0.5,
            min_samples: 5,
            cluster_centers: Vec::new(),
            trained: false,
        }
    }

    fn euclidean_distance(&self, a: &Array1<f64>, b: &Array1<f64>) -> f64 {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f64>()
            .sqrt()
    }

    fn find_neighbors(&self, features: &Array2<f64>, point_idx: usize) -> Vec<usize> {
        let point = features.row(point_idx).to_owned();
        let mut neighbors = Vec::new();
        
        for i in 0..features.nrows() {
            if i != point_idx {
                let neighbor = features.row(i).to_owned();
                if self.euclidean_distance(&point, &neighbor) < self.eps {
                    neighbors.push(i);
                }
            }
        }
        
        neighbors
    }
}

impl Default for DBSCANAnomalyPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyPlugin for DBSCANAnomalyPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }

    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.config = Some(config.clone());
        
        if let Some(eps) = config.parameters.get("eps") {
            if let Some(e) = eps.as_f64() {
                self.eps = e;
            }
        }
        
        if let Some(min_samples) = config.parameters.get("min_samples") {
            if let Some(ms) = min_samples.as_u64() {
                self.min_samples = ms as usize;
            }
        }

        tracing::info!(
            "Initialized DBSCAN Anomaly: eps={}, min_samples={}",
            self.eps,
            self.min_samples
        );
        Ok(())
    }

    fn train(&mut self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<()> {
        tracing::info!("Training DBSCAN clustering on {} samples", features.nrows());

        // Simplified DBSCAN implementation
        let mut visited = vec![false; features.nrows()];
        let mut clusters = Vec::new();
        let mut cluster_id = 0;
        
        for i in 0..features.nrows() {
            if visited[i] {
                continue;
            }
            
            let neighbors = self.find_neighbors(features, i);
            
            if neighbors.len() < self.min_samples {
                continue; // Noise point
            }
            
            // Start new cluster
            let mut cluster_points = vec![i];
            let mut seed_set = neighbors.clone();
            visited[i] = true;
            
            let mut j = 0;
            while j < seed_set.len() {
                let current = seed_set[j];
                if !visited[current] {
                    visited[current] = true;
                    let current_neighbors = self.find_neighbors(features, current);
                    
                    if current_neighbors.len() >= self.min_samples {
                        for &neighbor in &current_neighbors {
                            if !seed_set.contains(&neighbor) {
                                seed_set.push(neighbor);
                            }
                        }
                    }
                }
                
                if !cluster_points.contains(&current) {
                    cluster_points.push(current);
                }
                j += 1;
            }
            
            // Calculate cluster center
            let mut center = Array1::zeros(features.ncols());
            for &point_idx in &cluster_points {
                let point = features.row(point_idx);
                for (i, &val) in point.iter().enumerate() {
                    center[i] += val;
                }
            }
            center /= cluster_points.len() as f64;
            
            clusters.push(cluster_points);
            self.cluster_centers.push(center);
            cluster_id += 1;
        }
        
        self.trained = true;
        tracing::info!("DBSCAN training completed: found {} clusters", self.cluster_centers.len());
        Ok(())
    }

    fn predict(&self, features: &Array2<f64>, _logs: &[LogRecord]) -> Result<Vec<f64>> {
        if !self.trained {
            return Err(anyhow::anyhow!("Model not trained - call train() first"));
        }

        let mut anomaly_scores = Vec::with_capacity(features.nrows());
        
        for i in 0..features.nrows() {
            let point = features.row(i).to_owned();
            
            // Find distance to nearest cluster center
            let min_distance = self.cluster_centers
                .iter()
                .map(|center| self.euclidean_distance(&point, center))
                .fold(f64::INFINITY, f64::min);
            
            // Convert distance to anomaly score (0-1 range)
            let score = (min_distance / (self.eps * 3.0)).min(1.0);
            anomaly_scores.push(score);
        }

        Ok(anomaly_scores)
    }

    fn required_features(&self) -> Vec<String> {
        vec!["all".to_string()]
    }
}
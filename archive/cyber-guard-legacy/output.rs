use crate::ingest::LogRecord;
use crate::model::AnomalyScore;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufWriter, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub log_record: LogRecord,
    pub anomaly_score: f64,
    pub is_anomaly: bool,
    pub confidence: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub total_records: usize,
    pub anomalies_found: usize,
    pub findings: Vec<Finding>,
    pub model_threshold: f64,
    pub analysis_timestamp: String,
}

impl AnalysisResults {
    pub fn new(logs: &[LogRecord], scores: &[AnomalyScore], threshold: f64) -> Self {
        let mut findings = Vec::new();
        let anomalies_found = scores.iter().filter(|s| s.is_anomaly).count();

        for (log, score) in logs.iter().zip(scores.iter()) {
            let reasons = Self::generate_reasons(log, score);

            findings.push(Finding {
                log_record: log.clone(),
                anomaly_score: score.score,
                is_anomaly: score.is_anomaly,
                confidence: score.confidence,
                reasons,
            });
        }

        Self {
            total_records: logs.len(),
            anomalies_found,
            findings,
            model_threshold: threshold,
            analysis_timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn generate_reasons(log: &LogRecord, score: &AnomalyScore) -> Vec<String> {
        let mut reasons = Vec::new();

        if score.is_anomaly {
            if log.status >= 400 {
                reasons.push(format!("HTTP error status: {}", log.status));
            }

            if log.ip.starts_with("10.") || log.ip.starts_with("0.") {
                reasons.push(format!("Suspicious IP address: {}", log.ip));
            }

            if log.action.contains("admin") || log.action.contains("system") {
                reasons.push(format!("Administrative action: {}", log.action));
            }

            if log.user.len() > 10 || log.user.len() < 3 {
                reasons.push(format!("Unusual username length: {}", log.user));
            }

            if log.action.contains("injection") || log.action.contains("exploit") {
                reasons.push(format!("Potential attack pattern: {}", log.action));
            }

            if reasons.is_empty() {
                reasons.push("Statistical anomaly detected".to_string());
            }
        }

        reasons
    }

    pub fn save_json(&self, file_path: &str) -> Result<()> {
        let file = File::create(file_path)
            .with_context(|| format!("Failed to create output file: {}", file_path))?;
        let writer = BufWriter::new(file);

        serde_json::to_writer_pretty(writer, self)
            .with_context(|| "Failed to write JSON output")?;

        tracing::info!("Analysis results saved to {}", file_path);
        Ok(())
    }

    pub fn print_summary(&self) {
        println!("\n=== Cyber Guardian Analysis Summary ===");
        println!("Total records analyzed: {}", self.total_records);
        println!(
            "Anomalies detected: {} ({:.1}%)",
            self.anomalies_found,
            (self.anomalies_found as f64 / self.total_records as f64) * 100.0
        );
        println!("Model threshold: {:.3}", self.model_threshold);
        println!("Analysis time: {}", self.analysis_timestamp);

        if self.anomalies_found > 0 {
            println!("\n=== Top Anomalies ===");
            let mut anomalies: Vec<&Finding> =
                self.findings.iter().filter(|f| f.is_anomaly).collect();

            anomalies.sort_by(|a, b| b.anomaly_score.partial_cmp(&a.anomaly_score).unwrap());

            for (i, finding) in anomalies.iter().take(5).enumerate() {
                println!(
                    "\n{}. Score: {:.3} | Confidence: {:.2}",
                    i + 1,
                    finding.anomaly_score,
                    finding.confidence
                );
                println!(
                    "   User: {} | IP: {} | Action: {} | Status: {}",
                    finding.log_record.user,
                    finding.log_record.ip,
                    finding.log_record.action,
                    finding.log_record.status
                );
                println!("   Timestamp: {}", finding.log_record.timestamp);
                if !finding.reasons.is_empty() {
                    println!("   Reasons: {}", finding.reasons.join(", "));
                }
            }
        } else {
            println!("\n✅ No anomalies detected in this dataset.");
        }

        println!();
    }

    pub fn save_csv(&self, file_path: &str) -> Result<()> {
        let file = File::create(file_path)
            .with_context(|| format!("Failed to create CSV file: {}", file_path))?;
        let mut writer = BufWriter::new(file);

        // Write CSV header
        writeln!(
            writer,
            "timestamp,user,ip,action,status,anomaly_score,is_anomaly,confidence,reasons"
        )?;

        // Write data rows
        for finding in &self.findings {
            writeln!(
                writer,
                "{},{},{},{},{},{:.3},{},{:.3},\"{}\"",
                finding.log_record.timestamp,
                finding.log_record.user,
                finding.log_record.ip,
                finding.log_record.action,
                finding.log_record.status,
                finding.anomaly_score,
                finding.is_anomaly,
                finding.confidence,
                finding.reasons.join("; ")
            )?;
        }

        writer.flush()?;
        tracing::info!("Analysis results saved to CSV: {}", file_path);
        Ok(())
    }
}

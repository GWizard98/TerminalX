use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogRecord {
    pub timestamp: String,
    pub user: String,
    pub ip: String,
    pub action: String,
    pub status: u32,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub response_time: u64,
}

pub fn read_jsonl_logs(file_path: &str) -> Result<Vec<LogRecord>> {
    let file =
        File::open(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;

    let reader = BufReader::new(file);
    let mut logs = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("Failed to read line {}", line_num + 1))?;

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        let record: LogRecord = serde_json::from_str(&line)
            .with_context(|| format!("Failed to parse JSON on line {}: {}", line_num + 1, line))?;

        logs.push(record);
    }

    tracing::info!(
        "Successfully ingested {} log records from {}",
        logs.len(),
        file_path
    );
    Ok(logs)
}

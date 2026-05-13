use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api: ApiConfig,
    pub notifycore: NotifyCoreConfig,
    pub osint: OsintConfig,
    pub countermeasures: CountermeasuresConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub port: u16,
    pub bind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyCoreConfig {
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintConfig {
    pub ipinfo_token: Option<String>,
    pub scan_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountermeasuresConfig {
    pub enabled: bool,
    pub auto_block: bool,
    pub block_asn_range: bool,
    pub protected_ports: Vec<u16>,
    pub vpn_interface: String,
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}

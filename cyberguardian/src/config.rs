//! CyberGuardian configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub monitors: MonitorConfig,
    pub notifycore: NotifyCoreConfig,
    pub vpn: crate::vpn::manager::VpnConfig,
    pub active_response: ActiveResponseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_name: String,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub ssh: SshMonitorConfig,
    pub filesystem: FilesystemMonitorConfig,
    pub process: ProcessMonitorConfig,
    pub network: NetworkMonitorConfig,
    pub integrity: IntegrityMonitorConfig,
    pub cowrie: CowrieMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshMonitorConfig {
    pub enabled: bool,
    pub auth_log_path: PathBuf,
    pub fail_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemMonitorConfig {
    pub enabled: bool,
    pub watch_paths: Vec<PathBuf>,
    pub ignore_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub enabled: bool,
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    pub enabled: bool,
    pub allowed_destinations: Vec<String>,
    pub alert_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyCoreConfig {
    pub bot_token: String,
    pub chat_id: String,
    pub min_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityMonitorConfig {
    pub enabled: bool,
    pub watch_paths: Vec<PathBuf>,
    pub ignore_extensions: Vec<String>,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowrieMonitorConfig {
    pub enabled: bool,
    pub log_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActiveResponseConfig {
    pub enabled: bool,
    pub auto_block_threshold: f64,
    pub escalate_threshold: f64,
    pub ip_whitelist: Vec<String>,
    pub known_abuse_asns: Vec<String>,
    pub bulletproof_keywords: Vec<String>,
    pub evidence_log_path: String,
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn default_example() -> Self {
        Config {
            agent: AgentConfig {
                server_name: "terminalx-nyc1".to_string(),
                poll_interval_secs: 30,
            },
            monitors: MonitorConfig {
                ssh: SshMonitorConfig {
                    enabled: true,
                    auth_log_path: PathBuf::from("/var/log/auth.log"),
                    fail_threshold: 5,
                },
                filesystem: FilesystemMonitorConfig {
                    enabled: true,
                    watch_paths: vec![
                        PathBuf::from("/etc/cyberguardian"),
                    ],
                    ignore_extensions: vec!["log".to_string()],
                },
                process: ProcessMonitorConfig {
                    enabled: true,
                    whitelist: vec![
                        "cyberguardian".to_string(),
                        "sshd".to_string(),
                        "systemd".to_string(),
                        "cron".to_string(),
                    ],
                },
                network: NetworkMonitorConfig {
                    enabled: true,
                    allowed_destinations: vec![
                        "api.telegram.org".to_string(),
                        "ipinfo.io".to_string(),
                    ],
                    alert_ports: vec![4444, 1337, 31337],
                },
                integrity: IntegrityMonitorConfig {
                    enabled: true,
                    watch_paths: vec![
                        PathBuf::from("/etc/cyberguardian"),
                    ],
                    ignore_extensions: vec!["log".to_string()],
                    poll_interval_secs: 60,
                },
                cowrie: CowrieMonitorConfig {
                    enabled: true,
                    log_path: PathBuf::from("/home/cowrie/cowrie/var/log/cowrie/cowrie.json"),
                },
            },
            notifycore: NotifyCoreConfig {
                bot_token: "your-bot-token".to_string(),
                chat_id: "8691529662".to_string(),
                min_severity: "warning".to_string(),
            },
            vpn: crate::vpn::manager::VpnConfig::default(),
            active_response: ActiveResponseConfig::default(),
        }
    }
}
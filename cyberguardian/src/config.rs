//! CyberGuardian configuration
//!
//! Loaded from /etc/cyberguardian/config.toml on the server
//! or from a local path passed via --config flag

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub monitors: MonitorConfig,
    pub notifycore: NotifyCoreConfig,
    pub vpn: crate::vpn::manager::VpnConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Human-readable name for this server instance
    pub server_name: String,
    /// Poll interval in seconds for process/network monitors
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub ssh: SshMonitorConfig,
    pub filesystem: FilesystemMonitorConfig,
    pub process: ProcessMonitorConfig,
    pub network: NetworkMonitorConfig,
    pub integrity: IntegrityMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshMonitorConfig {
    pub enabled: bool,
    /// Path to auth log — /var/log/auth.log on Ubuntu
    pub auth_log_path: PathBuf,
    /// Number of failed attempts before alerting
    pub fail_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemMonitorConfig {
    pub enabled: bool,
    /// Directories to watch for changes
    pub watch_paths: Vec<PathBuf>,
    /// File extensions to ignore (e.g. log files that change constantly)
    pub ignore_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub enabled: bool,
    /// Known-good process names — anything outside this list alerts
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    pub enabled: bool,
    /// Allowed outbound destination IPs/ranges
    pub allowed_destinations: Vec<String>,
    /// Ports that should never have outbound connections
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

impl Config {
    /// Creates a new [`Config`].
    pub fn new(agent: AgentConfig, monitors: MonitorConfig, notifycore: NotifyCoreConfig, vpn: crate::vpn::manager::VpnConfig) -> Self {
        Self { agent, monitors, notifycore, vpn }
    }
    
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Returns a default config for initial setup
    pub fn default_example() -> Self {
        Config {
            agent: AgentConfig {
                server_name: "tradeco-droplet".to_string(),
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
                PathBuf::from("/root/TradeEco"),
                PathBuf::from("/etc/cyberguardian"),
            ],
            ignore_extensions: vec!["log".to_string()],
        },
            process: ProcessMonitorConfig {
                enabled: true,
                whitelist: vec![
                    "hq".to_string(),
                    "cyberguardian".to_string(),
                    "sshd".to_string(),
                    "systemd".to_string(),
                    "journald".to_string(),
                    "ntpd".to_string(),
                    "cron".to_string(),
                ],
            },
            network: NetworkMonitorConfig {
                enabled: true,
                allowed_destinations: vec![
                    "api-fxtrade.oanda.com".to_string(),
                    "stream-fxtrade.oanda.com".to_string(),
                    "ntfy.sh".to_string(),
                ],
                alert_ports: vec![4444, 1337, 8080, 31337],
            },
            integrity: IntegrityMonitorConfig {
                enabled: true,
                watch_paths: vec![
                     PathBuf::from("/root/TradeEco"),
                ],
                ignore_extensions: vec!["log".to_string()],
        poll_interval_secs: 60,
    },
},
            notifycore: NotifyCoreConfig {
                 bot_token: "your-bot-token".to_string(),
                 chat_id: "8691529662".to_string(),
                 min_severity: "warning".to_string(),
            },
            vpn: crate::vpn::manager::VpnConfig::default(),
        }
    }
}

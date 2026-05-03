pub mod api;
pub mod chat_tui;
pub mod features;
pub mod health;
pub mod ingest;
pub mod license;
pub mod model;
pub mod output;
pub mod threat_predictor;
pub mod response_engine;
pub mod security_chat;
pub mod layered_defense;
pub mod decentralized_network;
pub mod darkweb_monitor;
pub mod adaptive_vpn;
pub mod vpn_circuits;
pub mod ethical_hacking;
pub mod ml_ethical_hacking;
pub mod network_defense;
pub mod metrics;
pub mod automated_response;
pub mod notifications;

// New enterprise modules
pub mod real_tor;
pub mod siem_integration;
pub mod web_dashboard;

// Re-export commonly used types and functions that exist in the current codebase
pub use features::FeatureExtractor;
pub use ingest::LogRecord;
pub use license::{LicenseManager, LicenseTier};
pub use model::{AnomalyModel, AnomalyScore};

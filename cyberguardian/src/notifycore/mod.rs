//! NotifyCore — CyberGuardian internal alert system
//! Delivery: ntfy.sh now, dashboard WebSocket later

pub mod alert;

use alert::{Alert, Severity};
use anyhow::Result;
use tracing::{info, warn, error};

pub struct NotifyCore {
    bot_token: String,
    chat_id: String,
    min_severity: Severity,
    client: reqwest::Client,
}

impl NotifyCore {
    pub fn new(bot_token: String, chat_id: String, min_severity: String) -> Self {
        let min = match min_severity.as_str() {
            "critical" => Severity::Critical,
            "warning"  => Severity::Warning,
            _          => Severity::Info,
        };
       NotifyCore { bot_token, chat_id, min_severity: min, client: reqwest::Client::new() }
    }

    pub async fn send(&self, alert: Alert) -> Result<()> {
        match alert.severity {
            Severity::Critical => error!("[CRITICAL] {} — {}", alert.source, alert.message),
            Severity::Warning  => warn!("[WARNING] {} — {}", alert.source, alert.message),
            Severity::Info     => info!("[INFO] {} — {}", alert.source, alert.message),
        }

        if alert.severity < self.min_severity {
            return Ok(());
        }

       let emoji = match alert.severity {
    Severity::Critical => "🚨",
    Severity::Warning  => "⚠️",
    Severity::Info     => "✅",
};

let text = format!(
    "{} *CyberGuardian [{}]*\n\n*Server:* {}\n*Source:* {}\n*Message:* {}\n*Evidence:* {}\n*Time:* {}",
    emoji,
    alert.severity.label(),
    alert.server_name,
    alert.source,
    alert.message,
    alert.evidence,
    alert.timestamp,
);

let url = format!(
    "https://api.telegram.org/bot{}/sendMessage",
    self.bot_token
);

let res = self.client
    .post(&url)
    .json(&serde_json::json!({
        "chat_id": self.chat_id,
        "text": text,
    }))
    .send()
    .await;

match res {
    Ok(r) if r.status().is_success() => info!("NotifyCore: alert dispatched to Telegram"),
    Ok(r) => warn!("NotifyCore: Telegram returned {}", r.status()),
    Err(e) => error!("NotifyCore: failed to reach Telegram — {}", e),
}
Ok(())
    }
}

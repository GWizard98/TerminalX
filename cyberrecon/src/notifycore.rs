use anyhow::Result;
use serde_json::json;
use tracing::{info, error};

pub struct NotifyCore {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
}

impl NotifyCore {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        NotifyCore {
            bot_token,
            chat_id,
            client: reqwest::Client::new(),
        }
    }

    pub async fn send(&self, message: &str) -> Result<()> {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        let res = self.client
            .post(&url)
            .json(&json!({
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML"
            }))
            .send()
            .await;

        match res {
            Ok(_) => info!("CyberRecon alert dispatched to Telegram"),
            Err(e) => error!("Failed to send Telegram alert: {}", e),
        }

        Ok(())
    }
}

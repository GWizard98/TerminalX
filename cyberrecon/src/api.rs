use crate::config::Config;
use crate::osint::OsintEngine;
use crate::countermeasures::CounterDefense;
use crate::notifycore::NotifyCore;
use crate::report::generate_threat_report;
use axum::{
    routing::post,
    Router,
    Json,
    extract::State,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, error};

#[derive(Debug, Deserialize)]
pub struct EscalatedIncident {
    pub ip: Option<String>,
    pub description: String,
    pub evidence: String,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct EscalateResponse {
    pub status: String,
    pub message: String,
}

struct AppState {
    config: Config,
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let state = Arc::new(AppState { config });

    let app = Router::new()
        .route("/escalate", post(handle_escalation))
        .route("/health", axum::routing::get(health_check))
        .with_state(state);

    let bind = "127.0.0.1:7734";
    info!("CyberRecon API listening on {}", bind);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_escalation(
    State(state): State<Arc<AppState>>,
    Json(incident): Json<EscalatedIncident>,
) -> (StatusCode, Json<EscalateResponse>) {
    info!("recon: received escalation — {}", incident.description);

    let ip = match &incident.ip {
        Some(ip) => ip.clone(),
        None => {
            return (StatusCode::OK, Json(EscalateResponse {
                status: "skipped".to_string(),
                message: "No IP in incident".to_string(),
            }));
        }
    };

    let config = state.config.clone();
    let description = incident.description.clone();

    tokio::spawn(async move {
        let notifycore = NotifyCore::new(
            config.notifycore.bot_token.clone(),
            config.notifycore.chat_id.clone(),
        );
        let osint = OsintEngine::new(config.osint.scan_timeout_secs);
        let counter = CounterDefense::new(config.countermeasures.clone());

        match osint.investigate(&ip).await {
            Ok(profile) => {
                match counter.respond(&profile).await {
                    Ok(response) => {
                        let report = generate_threat_report(&profile, &response, &description);
                        if let Err(e) = notifycore.send(&report).await {
                            error!("recon: failed to send report: {}", e);
                        }
                    }
                    Err(e) => error!("recon: counter-defense failed: {}", e),
                }
            }
            Err(e) => error!("recon: OSINT investigation failed: {}", e),
        }
    });

    (StatusCode::OK, Json(EscalateResponse {
        status: "accepted".to_string(),
        message: "Incident received — investigating".to_string(),
    }))
}

async fn health_check() -> &'static str {
    "CyberRecon online"
}

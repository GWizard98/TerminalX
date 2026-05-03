use anyhow::Result;
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    response::{Html, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub total_threats: u64,
    pub active_incidents: u64,
    pub threat_level: f64,
    pub system_health: SystemHealth,
    pub recent_alerts: Vec<AlertSummary>,
    pub network_stats: NetworkStats,
    pub ai_stats: AIStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_latency: f64,
    pub services_status: Vec<ServiceStatus>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub status: String,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub response_time_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub active_connections: u64,
    pub tor_circuits: u64,
    pub vpn_status: String,
    pub bandwidth_in: u64,
    pub bandwidth_out: u64,
    pub blocked_ips: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIStats {
    pub models_loaded: u64,
    pub predictions_made: u64,
    pub accuracy_score: f64,
    pub processing_time_ms: f64,
    pub threats_predicted: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub event_type: String,
    pub severity: String,
    pub source_ip: String,
    pub target: String,
    pub description: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub mitigation_action: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DashboardState {
    pub metrics: Arc<RwLock<DashboardMetrics>>,
    pub threat_events: Arc<RwLock<Vec<ThreatEvent>>>,
    pub connected_clients: Arc<RwLock<Vec<WebSocketClient>>>,
}

#[derive(Debug, Clone)]
pub struct WebSocketClient {
    pub id: String,
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

impl DashboardState {
    pub fn new() -> Self {
        let metrics = DashboardMetrics {
            total_threats: 0,
            active_incidents: 0,
            threat_level: 2.5,
            system_health: SystemHealth {
                cpu_usage: 15.5,
                memory_usage: 42.3,
                disk_usage: 68.1,
                network_latency: 23.4,
                services_status: vec![
                    ServiceStatus {
                        name: "TOR Service".to_string(),
                        status: "Running".to_string(),
                        last_check: chrono::Utc::now(),
                        response_time_ms: Some(12.5),
                    },
                    ServiceStatus {
                        name: "VPN Manager".to_string(),
                        status: "Running".to_string(),
                        last_check: chrono::Utc::now(),
                        response_time_ms: Some(8.2),
                    },
                    ServiceStatus {
                        name: "AI Engine".to_string(),
                        status: "Running".to_string(),
                        last_check: chrono::Utc::now(),
                        response_time_ms: Some(156.7),
                    },
                ],
                uptime_seconds: 86400,
            },
            recent_alerts: Vec::new(),
            network_stats: NetworkStats {
                active_connections: 24,
                tor_circuits: 3,
                vpn_status: "Connected".to_string(),
                bandwidth_in: 1024 * 1024 * 5,
                bandwidth_out: 1024 * 1024 * 2,
                blocked_ips: 127,
            },
            ai_stats: AIStats {
                models_loaded: 8,
                predictions_made: 1543,
                accuracy_score: 0.94,
                processing_time_ms: 23.7,
                threats_predicted: 12,
            },
        };

        Self {
            metrics: Arc::new(RwLock::new(metrics)),
            threat_events: Arc::new(RwLock::new(Vec::new())),
            connected_clients: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn add_threat_event(&self, event: ThreatEvent) {
        let mut events = self.threat_events.write().await;
        events.insert(0, event.clone()); // Insert at beginning for latest-first order
        
        // Keep only last 1000 events
        if events.len() > 1000 {
            events.truncate(1000);
        }

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.total_threats += 1;
        
        if event.severity == "Critical" || event.severity == "High" {
            metrics.active_incidents += 1;
        }

        // Create alert summary
        let alert = AlertSummary {
            id: event.id.clone(),
            severity: event.severity.clone(),
            title: event.description.clone(),
            timestamp: event.timestamp,
            source: event.source_ip.clone(),
            status: "Active".to_string(),
        };

        metrics.recent_alerts.insert(0, alert);
        
        // Keep only last 50 alerts
        if metrics.recent_alerts.len() > 50 {
            metrics.recent_alerts.truncate(50);
        }

        info!("📊 Added threat event to dashboard: {}", event.id);
    }

    pub async fn update_metrics(&self, new_metrics: DashboardMetrics) {
        let mut metrics = self.metrics.write().await;
        *metrics = new_metrics;
        info!("📈 Dashboard metrics updated");
    }
}

pub fn create_dashboard_router() -> Router<DashboardState> {
    Router::new()
        .route("/", get(dashboard_home))
        .route("/api/metrics", get(get_metrics))
        .route("/api/threats", get(get_threats))
        .route("/api/alerts", get(get_alerts))
        .route("/api/system-health", get(get_system_health))
        .route("/api/network-stats", get(get_network_stats))
        .route("/api/ai-stats", get(get_ai_stats))
        .route("/api/threats", post(add_threat))
        .route("/ws", get(websocket_handler))
        .route("/dashboard/:view", get(dashboard_view))
}

async fn dashboard_home() -> Html<String> {
    Html(generate_overview_page())
}

async fn dashboard_view(Path(view): Path<String>) -> Html<String> {
    let content = match view.as_str() {
        "threats" => generate_threats_page(),
        "network" => generate_network_page(),
        "ai" => generate_ai_page(),
        "alerts" => generate_alerts_page(),
        "settings" => generate_settings_page(),
        _ => generate_overview_page(),
    };
    
    Html(content)
}

async fn get_metrics(State(state): State<DashboardState>) -> Json<DashboardMetrics> {
    let metrics = state.metrics.read().await;
    Json(metrics.clone())
}

async fn get_threats(State(state): State<DashboardState>) -> Json<Vec<ThreatEvent>> {
    let events = state.threat_events.read().await;
    Json(events.clone())
}

async fn get_alerts(State(state): State<DashboardState>) -> Json<Vec<AlertSummary>> {
    let metrics = state.metrics.read().await;
    Json(metrics.recent_alerts.clone())
}

async fn get_system_health(State(state): State<DashboardState>) -> Json<SystemHealth> {
    let metrics = state.metrics.read().await;
    Json(metrics.system_health.clone())
}

async fn get_network_stats(State(state): State<DashboardState>) -> Json<NetworkStats> {
    let metrics = state.metrics.read().await;
    Json(metrics.network_stats.clone())
}

async fn get_ai_stats(State(state): State<DashboardState>) -> Json<AIStats> {
    let metrics = state.metrics.read().await;
    Json(metrics.ai_stats.clone())
}

#[derive(Debug, Deserialize)]
struct AddThreatRequest {
    event_type: String,
    severity: String,
    source_ip: String,
    target: String,
    description: String,
    mitigation_action: Option<String>,
}

async fn add_threat(
    State(state): State<DashboardState>,
    Json(request): Json<AddThreatRequest>,
) -> Json<ThreatEvent> {
    let threat_event = ThreatEvent {
        id: Uuid::new_v4().to_string(),
        event_type: request.event_type,
        severity: request.severity,
        source_ip: request.source_ip,
        target: request.target,
        description: request.description,
        timestamp: chrono::Utc::now(),
        mitigation_action: request.mitigation_action,
    };

    state.add_threat_event(threat_event.clone()).await;
    
    // Broadcast to all WebSocket clients
    broadcast_threat_event(&state, &threat_event).await;

    Json(threat_event)
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<DashboardState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_websocket(socket, state))
}

async fn handle_websocket(
    socket: axum::extract::ws::WebSocket,
    state: DashboardState,
) {
    let client_id = Uuid::new_v4().to_string();
    let client = WebSocketClient {
        id: client_id.clone(),
        connected_at: chrono::Utc::now(),
    };

    // Add client to connected clients list
    {
        let mut clients = state.connected_clients.write().await;
        clients.push(client);
    }

    info!("🔌 WebSocket client connected: {}", client_id);

    // Handle WebSocket messages here
    // This would include real-time metrics updates, alerts, etc.
}

async fn broadcast_threat_event(state: &DashboardState, event: &ThreatEvent) {
    let clients = state.connected_clients.read().await;
    info!("📡 Broadcasting threat event to {} clients", clients.len());
    
    // In a real implementation, you'd send the event to all WebSocket connections
    // For now, we just log that we would broadcast
}

// HTML page generators
fn generate_overview_page() -> String {
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Guardian - Overview</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: #2d2d2d; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .metric { font-size: 2em; font-weight: bold; color: #4CAF50; }
        .status-good { color: #4CAF50; }
        .status-warning { color: #FF9800; }
        .status-critical { color: #F44336; }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin: 20px 0; }
        .nav a { color: #4CAF50; text-decoration: none; margin: 0 15px; }
    </style>
    <script>
        // Auto-refresh every 5 seconds
        setInterval(() => location.reload(), 5000);
    </script>
</head>
<body>
    <div class="header">
        <h1>🛡️ Cyber Guardian Dashboard</h1>
        <div class="nav">
            <a href="/dashboard/overview">Overview</a>
            <a href="/dashboard/threats">Threats</a>
            <a href="/dashboard/network">Network</a>
            <a href="/dashboard/ai">AI Engine</a>
            <a href="/dashboard/alerts">Alerts</a>
        </div>
    </div>
    
    <div class="dashboard-grid">
        <div class="card">
            <h3>🎯 Threat Status</h3>
            <div class="metric status-good">LOW</div>
            <p>System operating normally</p>
        </div>
        
        <div class="card">
            <h3>🔍 Active Monitoring</h3>
            <div class="metric">24</div>
            <p>Network connections monitored</p>
        </div>
        
        <div class="card">
            <h3>🤖 AI Engine</h3>
            <div class="metric status-good">94%</div>
            <p>Model accuracy</p>
        </div>
        
        <div class="card">
            <h3>🌐 Network Status</h3>
            <div class="metric status-good">SECURE</div>
            <p>3 Tor circuits active</p>
        </div>
    </div>
</body>
</html>
    "#.to_string()
}

fn generate_threats_page() -> String {
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Guardian - Threats</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .threat-list { display: flex; flex-direction: column; gap: 10px; }
        .threat-item { background: #2d2d2d; padding: 15px; border-radius: 8px; border-left: 4px solid #4CAF50; }
        .threat-critical { border-left-color: #F44336; }
        .threat-high { border-left-color: #FF9800; }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin: 20px 0; }
        .nav a { color: #4CAF50; text-decoration: none; margin: 0 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Threat Monitoring</h1>
        <div class="nav">
            <a href="/dashboard/overview">Overview</a>
            <a href="/dashboard/threats">Threats</a>
            <a href="/dashboard/network">Network</a>
            <a href="/dashboard/ai">AI Engine</a>
            <a href="/dashboard/alerts">Alerts</a>
        </div>
    </div>
    
    <div class="threat-list">
        <div class="threat-item">
            <h4>No active threats detected</h4>
            <p>All systems operating normally • Last scan: Just now</p>
        </div>
    </div>
</body>
</html>
    "#.to_string()
}

fn generate_network_page() -> String {
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Guardian - Network</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .network-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .card { background: #2d2d2d; border-radius: 8px; padding: 20px; }
        .metric { font-size: 1.5em; font-weight: bold; color: #4CAF50; }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin: 20px 0; }
        .nav a { color: #4CAF50; text-decoration: none; margin: 0 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 Network Operations</h1>
        <div class="nav">
            <a href="/dashboard/overview">Overview</a>
            <a href="/dashboard/threats">Threats</a>
            <a href="/dashboard/network">Network</a>
            <a href="/dashboard/ai">AI Engine</a>
            <a href="/dashboard/alerts">Alerts</a>
        </div>
    </div>
    
    <div class="network-grid">
        <div class="card">
            <h3>🧅 Tor Circuits</h3>
            <div class="metric">3 Active</div>
            <p>All circuits operational</p>
        </div>
        
        <div class="card">
            <h3>🛡️ VPN Status</h3>
            <div class="metric">Connected</div>
            <p>5-hop circuit active</p>
        </div>
        
        <div class="card">
            <h3>📊 Bandwidth</h3>
            <div class="metric">5MB/s</div>
            <p>In: 5MB/s • Out: 2MB/s</p>
        </div>
        
        <div class="card">
            <h3>🚫 Blocked IPs</h3>
            <div class="metric">127</div>
            <p>Threats neutralized</p>
        </div>
    </div>
</body>
</html>
    "#.to_string()
}

fn generate_ai_page() -> String {
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Guardian - AI Engine</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .ai-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .card { background: #2d2d2d; border-radius: 8px; padding: 20px; }
        .metric { font-size: 1.5em; font-weight: bold; color: #4CAF50; }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin: 20px 0; }
        .nav a { color: #4CAF50; text-decoration: none; margin: 0 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🤖 AI Security Engine</h1>
        <div class="nav">
            <a href="/dashboard/overview">Overview</a>
            <a href="/dashboard/threats">Threats</a>
            <a href="/dashboard/network">Network</a>
            <a href="/dashboard/ai">AI Engine</a>
            <a href="/dashboard/alerts">Alerts</a>
        </div>
    </div>
    
    <div class="ai-grid">
        <div class="card">
            <h3>🧠 Models Loaded</h3>
            <div class="metric">8</div>
            <p>All models operational</p>
        </div>
        
        <div class="card">
            <h3>🎯 Accuracy</h3>
            <div class="metric">94%</div>
            <p>Threat prediction accuracy</p>
        </div>
        
        <div class="card">
            <h3>⚡ Processing Time</h3>
            <div class="metric">23.7ms</div>
            <p>Average response time</p>
        </div>
        
        <div class="card">
            <h3>🔮 Predictions</h3>
            <div class="metric">1543</div>
            <p>Total predictions made</p>
        </div>
    </div>
</body>
</html>
    "#.to_string()
}

fn generate_alerts_page() -> String {
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Guardian - Alerts</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .alert-list { display: flex; flex-direction: column; gap: 10px; }
        .alert-item { background: #2d2d2d; padding: 15px; border-radius: 8px; }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin: 20px 0; }
        .nav a { color: #4CAF50; text-decoration: none; margin: 0 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Security Alerts</h1>
        <div class="nav">
            <a href="/dashboard/overview">Overview</a>
            <a href="/dashboard/threats">Threats</a>
            <a href="/dashboard/network">Network</a>
            <a href="/dashboard/ai">AI Engine</a>
            <a href="/dashboard/alerts">Alerts</a>
        </div>
    </div>
    
    <div class="alert-list">
        <div class="alert-item">
            <h4>✅ System Status: All Clear</h4>
            <p>No security alerts at this time • Last check: Just now</p>
        </div>
    </div>
</body>
</html>
    "#.to_string()
}

fn generate_settings_page() -> String {
    r#"
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Guardian - Settings</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
        .settings-form { max-width: 600px; margin: 0 auto; }
        .form-group { margin: 20px 0; }
        .form-group label { display: block; margin-bottom: 5px; }
        .form-group input, .form-group select { 
            width: 100%; padding: 10px; border-radius: 4px; border: 1px solid #555; 
            background: #2d2d2d; color: #fff; 
        }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin: 20px 0; }
        .nav a { color: #4CAF50; text-decoration: none; margin: 0 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚙️ System Settings</h1>
        <div class="nav">
            <a href="/dashboard/overview">Overview</a>
            <a href="/dashboard/threats">Threats</a>
            <a href="/dashboard/network">Network</a>
            <a href="/dashboard/ai">AI Engine</a>
            <a href="/dashboard/alerts">Alerts</a>
        </div>
    </div>
    
    <form class="settings-form">
        <div class="form-group">
            <label>Threat Detection Level:</label>
            <select>
                <option>Low</option>
                <option selected>Medium</option>
                <option>High</option>
                <option>Maximum</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>Alert Notifications:</label>
            <select>
                <option>Disabled</option>
                <option selected>Email Only</option>
                <option>Email + SMS</option>
                <option>All Channels</option>
            </select>
        </div>
        
        <div class="form-group">
            <label>VPN Security Level:</label>
            <select>
                <option>Basic (1-2 hops)</option>
                <option>Professional (3-4 hops)</option>
                <option selected>Enterprise (5-6 hops)</option>
                <option>Paranoid (7+ hops)</option>
            </select>
        </div>
    </form>
</body>
</html>
    "#.to_string()
}
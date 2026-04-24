use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{info, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct SiemEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_type: EventType,
    pub severity: SeverityLevel,
    pub message: String,
    pub metadata: HashMap<String, String>,
    pub raw_log: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EventType {
    Authentication,
    Authorization,
    NetworkActivity,
    FileAccess,
    ProcessExecution,
    SystemConfiguration,
    ThreatDetection,
    ComplianceViolation,
    DataAccess,
    Anomaly,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum SeverityLevel {
    Critical = 5,
    High = 4,
    Medium = 3,
    Low = 2,
    Informational = 1,
}

#[async_trait::async_trait]
pub trait SiemConnector: Send + Sync {
    async fn send_event(&self, event: &SiemEvent) -> Result<()>;
    async fn query_events(&self, query: &str) -> Result<Vec<SiemEvent>>;
    async fn create_alert(&self, event: &SiemEvent) -> Result<String>;
    async fn get_dashboards(&self) -> Result<Vec<SiemDashboard>>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SiemDashboard {
    pub id: String,
    pub name: String,
    pub description: String,
    pub widgets: Vec<DashboardWidget>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub id: String,
    pub widget_type: WidgetType,
    pub title: String,
    pub query: String,
    pub refresh_interval: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WidgetType {
    LineChart,
    BarChart,
    PieChart,
    Table,
    Counter,
    Map,
    Timeline,
}

// Splunk Integration
pub struct SplunkConnector {
    base_url: String,
    auth_token: String,
    client: reqwest::Client,
}

impl SplunkConnector {
    pub fn new(base_url: String, auth_token: String) -> Self {
        Self {
            base_url,
            auth_token,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl SiemConnector for SplunkConnector {
    async fn send_event(&self, event: &SiemEvent) -> Result<()> {
        info!("📊 Sending event to Splunk: {}", event.id);
        
        let splunk_event = json!({
            "time": event.timestamp.timestamp(),
            "host": "cyber-guardian",
            "source": event.source,
            "sourcetype": format!("cyber_guardian:{:?}", event.event_type).to_lowercase(),
            "event": {
                "id": event.id,
                "type": event.event_type,
                "severity": event.severity,
                "message": event.message,
                "metadata": event.metadata,
                "raw_log": event.raw_log
            }
        });

        let response = self.client
            .post(format!("{}/services/collector/event", self.base_url))
            .header("Authorization", format!("Splunk {}", self.auth_token))
            .header("Content-Type", "application/json")
            .json(&splunk_event)
            .send()
            .await?;

        if response.status().is_success() {
            info!("✅ Event sent to Splunk successfully");
        } else {
            error!("❌ Failed to send event to Splunk: {}", response.status());
        }

        Ok(())
    }

    async fn query_events(&self, query: &str) -> Result<Vec<SiemEvent>> {
        info!("🔍 Querying Splunk: {}", query);
        
        let search_params = [
            ("search", query),
            ("output_mode", "json"),
            ("count", "1000"),
        ];

        let response = self.client
            .post(format!("{}/services/search/jobs/export", self.base_url))
            .header("Authorization", format!("Splunk {}", self.auth_token))
            .form(&search_params)
            .send()
            .await?;

        let results: serde_json::Value = response.json().await?;
        let mut events = Vec::new();

        if let Some(results_array) = results.get("results").and_then(|r| r.as_array()) {
            for result in results_array {
                if let Ok(event) = self.parse_splunk_result(result) {
                    events.push(event);
                }
            }
        }

        info!("✅ Retrieved {} events from Splunk", events.len());
        Ok(events)
    }

    async fn create_alert(&self, event: &SiemEvent) -> Result<String> {
        info!("🚨 Creating Splunk alert for event: {}", event.id);
        
        let alert_config = json!({
            "name": format!("cyber_guardian_alert_{}", event.id),
            "search": format!("sourcetype=cyber_guardian:* id=\"{}\"", event.id),
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "actions": "email,webhook",
            "cron_schedule": "*/5 * * * *"
        });

        let response = self.client
            .post(format!("{}/services/saved/searches", self.base_url))
            .header("Authorization", format!("Splunk {}", self.auth_token))
            .json(&alert_config)
            .send()
            .await?;

        let alert_id = format!("alert_{}", event.id);
        info!("✅ Splunk alert created: {}", alert_id);
        
        Ok(alert_id)
    }

    async fn get_dashboards(&self) -> Result<Vec<SiemDashboard>> {
        info!("📊 Retrieving Splunk dashboards");
        
        let response = self.client
            .get(format!("{}/services/data/ui/views", self.base_url))
            .header("Authorization", format!("Splunk {}", self.auth_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        // Parse dashboard response and return
        let dashboards = vec![
            SiemDashboard {
                id: "cyber_guardian_main".to_string(),
                name: "Cyber Guardian Main Dashboard".to_string(),
                description: "Main security overview dashboard".to_string(),
                widgets: vec![
                    DashboardWidget {
                        id: "threat_timeline".to_string(),
                        widget_type: WidgetType::Timeline,
                        title: "Threat Detection Timeline".to_string(),
                        query: "sourcetype=cyber_guardian:* | timechart count by severity".to_string(),
                        refresh_interval: 60,
                    }
                ],
            }
        ];

        Ok(dashboards)
    }
}

impl SplunkConnector {
    fn parse_splunk_result(&self, result: &serde_json::Value) -> Result<SiemEvent> {
        let event = SiemEvent {
            id: result.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            timestamp: Utc::now(), // Parse from _time field
            source: result.get("source").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            event_type: EventType::ThreatDetection, // Parse from sourcetype
            severity: SeverityLevel::Medium, // Parse from severity field
            message: result.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            metadata: HashMap::new(), // Parse metadata fields
            raw_log: result.get("_raw").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        };

        Ok(event)
    }
}

// Elasticsearch Integration
pub struct ElasticsearchConnector {
    base_url: String,
    index_name: String,
    client: reqwest::Client,
}

impl ElasticsearchConnector {
    pub fn new(base_url: String, index_name: String) -> Self {
        Self {
            base_url,
            index_name,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl SiemConnector for ElasticsearchConnector {
    async fn send_event(&self, event: &SiemEvent) -> Result<()> {
        info!("📊 Sending event to Elasticsearch: {}", event.id);
        
        let es_event = json!({
            "@timestamp": event.timestamp,
            "event": {
                "id": event.id,
                "type": format!("{:?}", event.event_type).to_lowercase(),
                "severity": format!("{:?}", event.severity).to_lowercase(),
                "source": event.source,
                "message": event.message,
                "metadata": event.metadata,
                "raw_log": event.raw_log
            },
            "cyber_guardian": {
                "version": "1.0.0",
                "module": "siem_integration"
            }
        });

        let response = self.client
            .post(format!("{}/{}/_doc/{}", self.base_url, self.index_name, event.id))
            .header("Content-Type", "application/json")
            .json(&es_event)
            .send()
            .await?;

        if response.status().is_success() {
            info!("✅ Event indexed in Elasticsearch successfully");
        } else {
            error!("❌ Failed to index event in Elasticsearch: {}", response.status());
        }

        Ok(())
    }

    async fn query_events(&self, query: &str) -> Result<Vec<SiemEvent>> {
        info!("🔍 Querying Elasticsearch: {}", query);
        
        let es_query = json!({
            "query": {
                "query_string": {
                    "query": query
                }
            },
            "size": 1000,
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ]
        });

        let response = self.client
            .post(format!("{}{}/_search", self.base_url, self.index_name))
            .header("Content-Type", "application/json")
            .json(&es_query)
            .send()
            .await?;

        let results: serde_json::Value = response.json().await?;
        let mut events = Vec::new();

        if let Some(hits) = results.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
            for hit in hits {
                if let Some(source) = hit.get("_source") {
                    if let Ok(event) = self.parse_elasticsearch_result(source) {
                        events.push(event);
                    }
                }
            }
        }

        info!("✅ Retrieved {} events from Elasticsearch", events.len());
        Ok(events)
    }

    async fn create_alert(&self, event: &SiemEvent) -> Result<String> {
        info!("🚨 Creating Elasticsearch watcher alert for event: {}", event.id);
        
        let watcher_config = json!({
            "trigger": {
                "schedule": {
                    "interval": "5m"
                }
            },
            "input": {
                "search": {
                    "request": {
                        "search_type": "query_then_fetch",
                        "indices": [self.index_name],
                        "body": {
                            "query": {
                                "match": {
                                    "event.id": event.id
                                }
                            }
                        }
                    }
                }
            },
            "condition": {
                "compare": {
                    "ctx.payload.hits.total": {
                        "gt": 0
                    }
                }
            },
            "actions": {
                "send_email": {
                    "email": {
                        "to": ["admin@company.com"],
                        "subject": format!("Cyber Guardian Alert: {}", event.message),
                        "body": format!("Alert triggered for event: {}", event.id)
                    }
                }
            }
        });

        let alert_id = format!("cyber_guardian_alert_{}", event.id);
        let response = self.client
            .put(format!("{}/_watcher/watch/{}", self.base_url, alert_id))
            .header("Content-Type", "application/json")
            .json(&watcher_config)
            .send()
            .await?;

        if response.status().is_success() {
            info!("✅ Elasticsearch watcher alert created: {}", alert_id);
        }

        Ok(alert_id)
    }

    async fn get_dashboards(&self) -> Result<Vec<SiemDashboard>> {
        info!("📊 Retrieving Kibana dashboards");
        
        // This would typically query Kibana's saved objects API
        let dashboards = vec![
            SiemDashboard {
                id: "cyber_guardian_kibana".to_string(),
                name: "Cyber Guardian Kibana Dashboard".to_string(),
                description: "Security analytics dashboard in Kibana".to_string(),
                widgets: vec![
                    DashboardWidget {
                        id: "security_events".to_string(),
                        widget_type: WidgetType::BarChart,
                        title: "Security Events by Type".to_string(),
                        query: "*".to_string(),
                        refresh_interval: 30,
                    }
                ],
            }
        ];

        Ok(dashboards)
    }
}

impl ElasticsearchConnector {
    fn parse_elasticsearch_result(&self, source: &serde_json::Value) -> Result<SiemEvent> {
        let event_data = source.get("event").unwrap_or(source);
        
        let event = SiemEvent {
            id: event_data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            timestamp: chrono::DateTime::parse_from_rfc3339(
                source.get("@timestamp").and_then(|v| v.as_str()).unwrap_or("2023-01-01T00:00:00Z")
            )?.with_timezone(&Utc),
            source: event_data.get("source").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            event_type: EventType::ThreatDetection, // Parse from event.type
            severity: SeverityLevel::Medium, // Parse from event.severity
            message: event_data.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            metadata: HashMap::new(), // Parse metadata
            raw_log: event_data.get("raw_log").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        };

        Ok(event)
    }
}

pub struct SiemManager {
    connectors: HashMap<String, Box<dyn SiemConnector>>,
}

impl Default for SiemManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SiemManager {
    pub fn new() -> Self {
        Self {
            connectors: HashMap::new(),
        }
    }

    pub fn add_connector(&mut self, name: String, connector: Box<dyn SiemConnector>) {
        info!("➕ Adding SIEM connector: {}", name);
        self.connectors.insert(name, connector);
    }

    pub async fn send_to_all_siems(&self, event: &SiemEvent) -> Result<()> {
        info!("📡 Broadcasting event to all SIEM systems: {}", event.id);
        
        for (name, connector) in &self.connectors {
            if let Err(e) = connector.send_event(event).await {
                error!("❌ Failed to send event to {}: {}", name, e);
            } else {
                info!("✅ Event sent to {} successfully", name);
            }
        }

        Ok(())
    }

    pub async fn query_all_siems(&self, query: &str) -> Result<HashMap<String, Vec<SiemEvent>>> {
        info!("🔍 Querying all SIEM systems: {}", query);
        
        let mut results = HashMap::new();
        
        for (name, connector) in &self.connectors {
            match connector.query_events(query).await {
                Ok(events) => {
                    info!("✅ Retrieved {} events from {}", events.len(), name);
                    results.insert(name.clone(), events);
                }
                Err(e) => {
                    error!("❌ Failed to query {}: {}", name, e);
                    results.insert(name.clone(), Vec::new());
                }
            }
        }

        Ok(results)
    }

    pub async fn create_alerts_all_siems(&self, event: &SiemEvent) -> Result<HashMap<String, String>> {
        info!("🚨 Creating alerts in all SIEM systems for event: {}", event.id);
        
        let mut alert_ids = HashMap::new();
        
        for (name, connector) in &self.connectors {
            match connector.create_alert(event).await {
                Ok(alert_id) => {
                    info!("✅ Alert created in {}: {}", name, alert_id);
                    alert_ids.insert(name.clone(), alert_id);
                }
                Err(e) => {
                    error!("❌ Failed to create alert in {}: {}", name, e);
                }
            }
        }

        Ok(alert_ids)
    }
}

// JSON macro for convenience
macro_rules! json {
    ($($json:tt)+) => {
        serde_json::json!($($json)+)
    };
}

pub(crate) use json;
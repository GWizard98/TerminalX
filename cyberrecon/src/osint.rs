use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerProfile {
    pub ip: String,
    pub hostname: Option<String>,
    pub country: String,
    pub org: String,
    pub asn: String,
    pub asn_range: Option<String>,
    pub abuse_score: f64,
    pub known_malicious: bool,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
    pub threat_tags: Vec<String>,
}

pub struct OsintEngine {
    client: reqwest::Client,
    timeout: std::time::Duration,
}

impl OsintEngine {
    pub fn new(timeout_secs: u64) -> Self {
        OsintEngine {
            client: reqwest::Client::new(),
            timeout: std::time::Duration::from_secs(timeout_secs),
        }
    }

    pub async fn investigate(&self, ip: &str) -> Result<AttackerProfile> {
        info!("osint: investigating {}", ip);

        let ipinfo = self.query_ipinfo(ip).await?;
        let hostname = self.reverse_dns(ip).await;
        let open_ports = self.scan_common_ports(ip).await;
        let threat_tags = self.classify_threat(&ipinfo.org, &ipinfo.asn);

        let profile = AttackerProfile {
            ip: ip.to_string(),
            hostname,
            country: ipinfo.country,
            org: ipinfo.org,
            asn: ipinfo.asn.clone(),
            asn_range: ipinfo.asn_range,
            abuse_score: self.calculate_abuse_score(&ipinfo.asn, &threat_tags),
            known_malicious: threat_tags.contains(&"MALICIOUS".to_string()),
            open_ports,
            services: vec![],
            threat_tags,
        };

        info!("osint: profile built for {} — abuse score {:.2}", ip, profile.abuse_score);
        Ok(profile)
    }

    async fn query_ipinfo(&self, ip: &str) -> Result<IpInfoResponse> {
        let url = format!("https://ipinfo.io/{}/json", ip);
        let res = self.client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await;

        match res {
            Ok(r) if r.status().is_success() => {
                let json: serde_json::Value = r.json().await.unwrap_or_default();
                let org = json["org"].as_str().unwrap_or("Unknown").to_string();
                let asn = org.split_whitespace().next().unwrap_or("Unknown").to_string();
                Ok(IpInfoResponse {
                    country: json["country"].as_str().unwrap_or("Unknown").to_string(),
                    org,
                    asn,
                    asn_range: None,
                })
            }
            _ => Ok(IpInfoResponse {
                country: "Unknown".to_string(),
                org: "Unknown".to_string(),
                asn: "Unknown".to_string(),
                asn_range: None,
            })
        }
    }

    async fn reverse_dns(&self, ip: &str) -> Option<String> {
        use std::net::IpAddr;
        use std::str::FromStr;
        let addr = IpAddr::from_str(ip).ok()?;
        let octets = match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
            }
            _ => return None,
        };
        info!("osint: reverse DNS for {} → {}", ip, octets);
        Some(octets)
    }

    async fn scan_common_ports(&self, ip: &str) -> Vec<u16> {
        let common_ports = [21, 22, 23, 25, 80, 443, 3306, 4444, 6666, 8080, 8443, 31337];
        let mut open = vec![];
        for port in &common_ports {
            let addr = format!("{}:{}", ip, port);
            if let Ok(Ok(_)) = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::net::TcpStream::connect(&addr),
            ).await {
                open.push(*port);
                info!("osint: found open port {}/{}", ip, port);
            }
        }
        open
    }

    fn classify_threat(&self, org: &str, _asn: &str) -> Vec<String> {
        let mut tags = vec![];
        let org_upper = org.to_uppercase();
        let bulletproof = ["FRANTECH", "BUYVM", "COMBAHTON", "SERVERIUS", "TRABIA", "SHARKTECH"];
        let c2_indicators = ["TOR", "VPN", "PROXY", "BULLETPROOF", "OFFSHORE"];
        let cloud = ["DIGITALOCEAN", "LINODE", "VULTR", "HETZNER", "OVH", "AMAZON", "GOOGLE", "AZURE"];
        for keyword in &bulletproof {
            if org_upper.contains(keyword) {
                tags.push("BULLETPROOF_HOST".to_string());
                tags.push("MALICIOUS".to_string());
            }
        }
        for keyword in &c2_indicators {
            if org_upper.contains(keyword) {
                tags.push("POSSIBLE_C2".to_string());
            }
        }
        for keyword in &cloud {
            if org_upper.contains(keyword) {
                tags.push("CLOUD_VPS".to_string());
            }
        }
        tags
    }

    fn calculate_abuse_score(&self, _asn: &str, tags: &[String]) -> f64 {
        let mut score: f64 = 0.0;
        if tags.contains(&"BULLETPROOF_HOST".to_string()) { score += 0.95; }
        else if tags.contains(&"POSSIBLE_C2".to_string()) { score += 0.70; }
        else if tags.contains(&"CLOUD_VPS".to_string()) { score += 0.60; }
        if tags.contains(&"MALICIOUS".to_string()) { score = score.max(0.80); }
        score.min(1.0)
    }
}

struct IpInfoResponse {
    country: String,
    org: String,
    asn: String,
    asn_range: Option<String>,
}

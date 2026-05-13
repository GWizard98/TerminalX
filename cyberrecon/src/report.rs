use crate::osint::AttackerProfile;
use crate::countermeasures::CounterResponse;
use chrono::Utc;

pub fn generate_threat_report(
    profile: &AttackerProfile,
    response: &CounterResponse,
    incident_description: &str,
) -> String {
    let mut report = String::new();

    report.push_str("🔍 <b>CyberRecon Threat Report</b>\n");
    report.push_str("━━━━━━━━━━━━━━━━━━━━━━\n\n");
    report.push_str(&format!("🕐 <b>Time:</b> {}\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    report.push_str(&format!("⚡ <b>Incident:</b> {}\n\n", incident_description));
    report.push_str("🌐 <b>Attacker Profile</b>\n");
    report.push_str(&format!("  IP: <code>{}</code>\n", profile.ip));
    if let Some(hostname) = &profile.hostname {
        report.push_str(&format!("  Host: <code>{}</code>\n", hostname));
    }
    report.push_str(&format!("  Country: {}\n", profile.country));
    report.push_str(&format!("  Org: {}\n", profile.org));
    report.push_str(&format!("  ASN: {}\n", profile.asn));
    report.push_str(&format!("  Abuse Score: {:.0}%\n\n", profile.abuse_score * 100.0));

    if !profile.threat_tags.is_empty() {
        report.push_str("🏷 <b>Threat Tags</b>\n");
        for tag in &profile.threat_tags {
            report.push_str(&format!("  • {}\n", tag));
        }
        report.push('\n');
    }

    if !profile.open_ports.is_empty() {
        report.push_str("🔓 <b>Open Ports</b>\n");
        let ports: Vec<String> = profile.open_ports.iter().map(|p| p.to_string()).collect();
        report.push_str(&format!("  {}\n\n", ports.join(", ")));
    }

    report.push_str("🛡 <b>Counter-Defense Actions</b>\n");
    if response.actions_taken.is_empty() {
        report.push_str("  No actions taken\n");
    } else {
        for action in &response.actions_taken {
            report.push_str(&format!("  ✅ {}\n", action));
        }
    }

    report.push_str("\n━━━━━━━━━━━━━━━━━━━━━━\n");
    report.push_str("🔴 <b>GorTech TerminalX — CyberRecon v0.1</b>");

    report
}

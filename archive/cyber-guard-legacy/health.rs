use sysinfo::{System, CpuRefreshKind, MemoryRefreshKind, RefreshKind, Disks};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct HealthSnapshot {
    pub cpu_usage: f32,
    pub total_memory: u64,
    pub used_memory: u64,
    pub uptime_secs: u64,
    pub disk_total: u64,
    pub disk_available: u64,
}

fn find_local_cg_binary() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let candidates = [
        home.join("Projects/cyber-guard/target/release/cyber-guard"),
        home.join("Projects/cyber-guard/target/debug/cyber-guard"),
    ];
    for p in candidates {
        if p.exists() {
            return Some(p);
        }
    }
    None
}

pub fn trigger_local_self_check() -> std::io::Result<String> {
    if let Some(bin) = find_local_cg_binary() {
        // Use a short, non-daemonizing path so the TUI doesn't hang.
        // The local binary supports --test-notifications which exits quickly.
        let out = Command::new(bin)
            .arg("--test-notifications")
            .output()?;
        let mut msg = String::new();
        if !out.stdout.is_empty() {
            msg.push_str(&String::from_utf8_lossy(&out.stdout));
        }
        if !out.stderr.is_empty() {
            if !msg.is_empty() { msg.push_str("\n"); }
            msg.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        Ok(msg)
    } else {
        Ok("Local Cyber-Guard binary not found".to_string())
    }
}

pub fn read_self_awareness_summary<P: AsRef<Path>>(path: Option<P>) -> Option<String> {
    let default_path = dirs::home_dir()
        .map(|p| p.join("Projects/cyber-guard/self_awareness.log"));
    let path = path
        .as_ref()
        .map(|p| p.as_ref().to_path_buf())
        .or(default_path)?;
    let content = fs::read_to_string(path).ok()?;
    content
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|s| s.to_string())
}

impl HealthSnapshot {
    pub fn format_summary(&self) -> String {
        let mem_pct = if self.total_memory > 0 {
            (self.used_memory as f64 / self.total_memory as f64) * 100.0
        } else { 0.0 };
        format!(
            "CPU: {cpu:.1}% | Mem: {used} / {total} MiB ({pct:.1}%) | Disk free: {free} / {disk} GiB | Uptime: {up}s",
            cpu = self.cpu_usage,
            used = self.used_memory / 1024,
            total = self.total_memory / 1024,
            pct = mem_pct,
            free = self.disk_available / (1024*1024),
            disk = self.disk_total / (1024*1024),
            up = self.uptime_secs,
        )
    }
}

pub fn quick_self_check() -> HealthSnapshot {
    // Build a System with minimal refresh for speed
    let refresh = RefreshKind::new()
        .with_cpu(CpuRefreshKind::everything())
        .with_memory(MemoryRefreshKind::everything());

    let mut sys = System::new_with_specifics(refresh);
    sys.refresh_cpu();
    sys.refresh_memory();

    // Disks (one-time struct; query totals)
    let disks = Disks::new_with_refreshed_list();
    let mut disk_total = 0u64;
    let mut disk_avail = 0u64;
    for d in disks.list() {
        disk_total = disk_total.saturating_add(d.total_space());
        disk_avail = disk_avail.saturating_add(d.available_space());
    }

    // Note: sys.global_cpu_info().cpu_usage() returns a float 0..100
    let cpu = sys.global_cpu_info().cpu_usage();

    HealthSnapshot {
        cpu_usage: cpu,
        total_memory: sys.total_memory(),      // in KiB
        used_memory: sys.used_memory(),        // in KiB
        uptime_secs: System::uptime(),
        disk_total,
        disk_available: disk_avail,
    }
}

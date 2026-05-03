//! CyberGuardian agent — entry point
//!
//! Spawns each monitor as an independent tokio task.
//! All alerts route through a shared NotifyCore instance.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use cyberguardian::{
    config::Config,
    monitors::{ssh, filesystem, process, network},
    notifycore::NotifyCore,
};

#[derive(Parser, Debug)]
#[command(name = "cyberguardian", about = "TerminalX CyberGuardian — server monitoring agent")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/cyberguardian/config.toml")]
    config: PathBuf,

    /// Print example config and exit
    #[arg(long)]
    print_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cyberguardian=info".parse()?)
        )
        .init();

    let cli = Cli::parse();

    // Print example config and exit
    if cli.print_config {
        let example = Config::default_example();
        println!("{}", toml::to_string_pretty(&example)?);
        return Ok(());
    }

    info!("CyberGuardian v0.1 — TerminalX");
    info!("Loading config from {:?}", cli.config);

    let config = Config::load(&cli.config)?;
    let server_name = config.agent.server_name.clone();
    let poll_secs   = config.agent.poll_interval_secs;

    info!("Agent: {} | Poll interval: {}s", server_name, poll_secs);

    // Shared NotifyCore instance
    let notifycore = Arc::new(NotifyCore::new(
        config.notifycore.bot_token.clone(),
        config.notifycore.chat_id.clone(),
        config.notifycore.min_severity.clone(),
    ));

    info!("Spawning monitors...");

    // SSH monitor
    let nc = Arc::clone(&notifycore);
    let ssh_cfg = config.monitors.ssh.clone();
    let sn = server_name.clone();
    tokio::spawn(async move {
        if let Err(e) = ssh::run(ssh_cfg, nc, sn).await {
            tracing::error!("SSH monitor crashed: {}", e);
        }
    });

    // Filesystem monitor
    let nc = Arc::clone(&notifycore);
    let fs_cfg = config.monitors.filesystem.clone();
    let sn = server_name.clone();
    tokio::spawn(async move {
        if let Err(e) = filesystem::run(fs_cfg, nc, sn).await {
            tracing::error!("Filesystem monitor crashed: {}", e);
        }
    });

    // Process monitor
    let nc = Arc::clone(&notifycore);
    let proc_cfg = config.monitors.process.clone();
    let sn = server_name.clone();
    tokio::spawn(async move {
        if let Err(e) = process::run(proc_cfg, nc, sn, poll_secs).await {
            tracing::error!("Process monitor crashed: {}", e);
        }
    });

    // Network monitor
    let nc = Arc::clone(&notifycore);
    let net_cfg = config.monitors.network.clone();
    let sn = server_name.clone();
    tokio::spawn(async move {
        if let Err(e) = network::run(net_cfg, nc, sn, poll_secs).await {
            tracing::error!("Network monitor crashed: {}", e);
        }
    });

    info!("All monitors running. CyberGuardian is live.");

    // Keep main alive
    tokio::signal::ctrl_c().await?;
    info!("Shutting down CyberGuardian.");
    Ok(())
}

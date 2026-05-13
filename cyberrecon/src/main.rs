//! CyberRecon v0.1 — Counter-Defense Engine

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

mod config;
mod api;
mod osint;
mod countermeasures;
mod report;
mod notifycore;

#[derive(Parser, Debug)]
#[command(name = "cyberrecon", about = "TerminalX CyberRecon — Counter-Defense Engine")]
struct Cli {
    #[arg(short, long, default_value = "/etc/cyberrecon/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cyberrecon=info".parse()?)
        )
        .init();

    let cli = Cli::parse();

    info!("CyberRecon v0.1 — TerminalX");
    info!("Loading config from {:?}", cli.config);

    let config = config::Config::load(&cli.config)?;

    info!("Starting API server on 127.0.0.1:{}", config.api.port);

    api::serve(config).await?;

    Ok(())
}

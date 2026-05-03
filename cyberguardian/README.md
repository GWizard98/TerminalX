# CyberGuardian

TerminalX server monitoring agent. Protects the TradeEco droplet.

## What it monitors

| Monitor | What it catches |
|---------|----------------|
| SSH | Brute force, invalid users, successful logins |
| Filesystem | Changes to /root/TradeEco and /etc/cyberguardian |
| Process | Unknown processes not on whitelist |
| Network | Connections on suspicious ports (reverse shell indicators) |

All alerts route through **NotifyCore** → **ntfy.sh** (same topic as TradeEco).

## Build (Mac Pro → Linux droplet)

```bash
# Install musl cross-compiler (one time)
brew install filosottile/musl-cross/musl-cross
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# Deploy
./deploy.sh root@your-droplet-ip
```

## First run — generate config

```bash
cyberguardian --print-config > /etc/cyberguardian/config.toml
# Edit config.toml — set your ntfy.sh topic and watch paths
```

## Structure

```
src/
├── main.rs              — tokio entry point, spawns monitor tasks
├── lib.rs               — module declarations
├── config.rs            — TOML config loading
├── monitors/
│   ├── ssh.rs           — auth.log tail and parse
│   ├── filesystem.rs    — inotify via notify crate
│   ├── process.rs       — sysinfo process polling
│   └── network.rs       — /proc/net/tcp connection scanning
└── notifycore/
    ├── mod.rs           — NotifyCore dispatcher
    └── alert.rs         — Alert type and Severity enum
```

## Status

v0.1 — functional, targets TradeEco droplet.
Dashboard (NotifyCore v2) in development.

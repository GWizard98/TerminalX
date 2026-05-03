#!/bin/bash
# CyberGuardian deploy script
# Run from Mac Pro after cross-compiling for Linux
#
# Prerequisites on Mac Pro:
#   brew install filosottile/musl-cross/musl-cross
#   rustup target add x86_64-unknown-linux-musl
#
# Build (static binary, no glibc dependency):
#   cargo build --release --target x86_64-unknown-linux-musl
#
# Then run this script:
#   ./deploy.sh root@your-droplet-ip

set -e

SERVER=${1:-"root@your-droplet-ip"}
BINARY="target/x86_64-unknown-linux-musl/release/cyberguardian"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Build first:"
    echo "  cargo build --release --target x86_64-unknown-linux-musl"
    exit 1
fi

echo "Deploying CyberGuardian to $SERVER..."

# Create user and config directory on server
ssh $SERVER << 'REMOTE'
    id cyberguardian &>/dev/null || useradd -r -s /bin/false cyberguardian
    mkdir -p /etc/cyberguardian
    # Give cyberguardian user read access to auth.log
    usermod -aG adm cyberguardian 2>/dev/null || true
REMOTE

# Copy binary
scp $BINARY $SERVER:/usr/local/bin/cyberguardian
ssh $SERVER "chmod +x /usr/local/bin/cyberguardian"

# Copy config if it doesn't exist yet
ssh $SERVER "[ -f /etc/cyberguardian/config.toml ] || echo 'CONFIG NEEDED: copy config.toml.example to /etc/cyberguardian/config.toml and edit ntfy topic'"

# Copy and enable systemd service
scp cyberguardian.service $SERVER:/etc/systemd/system/cyberguardian.service
ssh $SERVER "systemctl daemon-reload && systemctl enable cyberguardian && systemctl restart cyberguardian"

echo ""
echo "CyberGuardian deployed."
echo "Check status: ssh $SERVER 'systemctl status cyberguardian'"
echo "Watch logs:   ssh $SERVER 'journalctl -fu cyberguardian'"

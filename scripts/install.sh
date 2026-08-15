#!/bin/bash
# ═══════════════════════════════════════════════════════
# DOGE OS Integration — Install Script
# ═══════════════════════════════════════════════════════
#
# Run this once to make DOGE a first-class citizen
# of your operating system.
#
# What it does:
#   1. Builds the DOGE binary
#   2. Installs to /usr/local/bin/doge
#   3. Installs doge-session launcher
#   4. Sets up bash completion
#   5. Adds shell aliases to ~/.bashrc
#   6. Creates investigation directory structure
#
# Usage:
#   cd /mnt/c/Users/k8659/OneDrive/Desktop/Doge
#   bash scripts/install.sh

set -e

DOGE_SOURCE="/mnt/c/Users/k8659/OneDrive/Desktop/Doge"
DOGE_VERSION="1.1.0"
INSTALL_DIR="/usr/local/bin"
COMPLETION_DIR="/etc/bash_completion.d"
INV_DIR="$HOME/investigations"

echo ""
echo "🐕 DOGE v${DOGE_VERSION} — OS Integration"
echo "═══════════════════════════════════════"
echo ""

# 1. Build
echo "[1/6] Building DOGE..."
cd "$DOGE_SOURCE"
go build -ldflags "-s -w \
    -X main.version=${DOGE_VERSION} \
    -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) \
    -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /tmp/doge ./cmd/workspace
echo "  ✓ Binary built"

# 2. Install binary
echo "[2/6] Installing binary..."
sudo cp /tmp/doge "$INSTALL_DIR/doge"
sudo chmod +x "$INSTALL_DIR/doge"
echo "  ✓ Installed to $INSTALL_DIR/doge"

# 3. Install launcher
echo "[3/6] Installing doge-session launcher..."
sudo cp "$DOGE_SOURCE/scripts/doge-session.sh" "$INSTALL_DIR/doge-session"
sudo chmod +x "$INSTALL_DIR/doge-session"
echo "  ✓ Installed to $INSTALL_DIR/doge-session"

# 4. Bash completion
echo "[4/6] Setting up bash completion..."
if [ -d "$COMPLETION_DIR" ]; then
    doge completion bash | sudo tee "$COMPLETION_DIR/doge" > /dev/null
    echo "  ✓ Bash completion installed"
else
    echo "  ⚠ $COMPLETION_DIR not found, skipping"
fi

# 5. Shell aliases
echo "[5/6] Adding shell aliases..."
ALIAS_MARKER="# ─── DOGE v${DOGE_VERSION} ───"
ALIAS_BLOCK="
${ALIAS_MARKER}
alias ds='doge start'
alias dr='doge runtime'
alias dc='doge console'
alias dl='doge logs -f'
alias da='doge approvals'
alias dst='doge status'

# Quick HTB start
htb() {
    local ip=\"\$1\"
    if [ -z \"\$ip\" ]; then
        echo \"Usage: htb <target-ip>\"
        return 1
    fi
    mkdir -p ~/investigations/\"htb-\$(date +%Y%m%d)-\${ip}\"
    cd ~/investigations/\"htb-\$(date +%Y%m%d)-\${ip}\"
    doge start --target \"\$ip\" --env htb --headless
}

# Quick investigation directory jump
inv() {
    cd ~/investigations/\"\$1\" 2>/dev/null || ls ~/investigations/
}
# ─── END DOGE ───
"

# Check if aliases already exist
if grep -q "DOGE v" ~/.bashrc 2>/dev/null; then
    echo "  ⚠ DOGE aliases already in ~/.bashrc, skipping"
else
    echo "$ALIAS_BLOCK" >> ~/.bashrc
    echo "  ✓ Aliases added to ~/.bashrc"
fi

# 6. Investigation directory
echo "[6/6] Creating investigation directory..."
mkdir -p "$INV_DIR"
echo "  ✓ $INV_DIR created"

echo ""
echo "═══════════════════════════════════════"
echo "🐕 DOGE installed successfully!"
echo ""
echo "  Binary:     $INSTALL_DIR/doge"
echo "  Launcher:   $INSTALL_DIR/doge-session"
echo "  Aliases:    ~/.bashrc"
echo "  Tab-comp:   $COMPLETION_DIR/doge"
echo "  Workspaces: $INV_DIR/"
echo ""
echo "  Reload your shell:  source ~/.bashrc"
echo ""
echo "  Quick start:"
echo "    htb 10.10.11.XXX              # alias"
echo "    doge-session 10.10.11.XXX htb # tmux"
echo "    doge start --target IP        # manual"
echo ""
echo "  Verify:"
echo "    doge version"
echo ""

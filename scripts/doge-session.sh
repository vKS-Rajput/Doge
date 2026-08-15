#!/bin/bash
# ═══════════════════════════════════════════════════════
# DOGE Investigation Session — tmux multi-pane launcher
# ═══════════════════════════════════════════════════════
#
# Usage:
#   doge-session <target-ip> [environment]
#
# Examples:
#   doge-session 10.10.11.123 htb
#   doge-session 192.168.1.50 lab
#   doge-session target.com authorized
#
# Creates a tmux session with 4 panes:
#   ┌─────────────────┬──────────────────┐
#   │  DOGE MACHINE   │  LIVE LOGS       │
#   │  (headless)     │  (streaming)     │
#   ├─────────────────┼──────────────────┤
#   │  RUNTIME STATUS │  CONSOLE         │
#   │  (auto-refresh) │  (interactive)   │
#   └─────────────────┴──────────────────┘
#
# Controls:
#   Ctrl+B D       Detach (DOGE continues in background)
#   tmux attach    Reattach
#   Ctrl+C         Stop DOGE (in machine pane only)
#
# Requirements:
#   - tmux
#   - doge binary in PATH

set -e

TARGET="${1:?Usage: doge-session <target-ip> [env]}"
ENV="${2:-htb}"
SESSION_NAME="doge-${TARGET//./-}"
WORKSPACE="$HOME/investigations/${ENV}-$(date +%Y%m%d)-${TARGET}"

echo "🐕 DOGE Investigation Session"
echo ""
echo "  Target:      $TARGET"
echo "  Environment: $ENV"
echo "  Workspace:   $WORKSPACE"
echo "  Session:     $SESSION_NAME"
echo ""

# Ensure workspace exists.
mkdir -p "$WORKSPACE"

# Kill existing session if any.
tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true

# Create new tmux session.
tmux new-session -d -s "$SESSION_NAME" -c "$WORKSPACE"

# Pane 0 (top-left): The DOGE machine.
tmux send-keys -t "$SESSION_NAME:0.0" \
    "echo '🐕 DOGE Machine — $TARGET ($ENV)' && echo '' && doge start --target $TARGET --env $ENV --headless" C-m

# Wait for DOGE to initialize.
sleep 4

# Split horizontally → creates pane 1 (right side).
tmux split-window -h -t "$SESSION_NAME:0" -c "$WORKSPACE"

# Pane 1 (top-right): Live logs.
tmux send-keys -t "$SESSION_NAME:0.1" \
    "echo '📋 Live Event Log' && echo '' && doge logs -f" C-m

# Split pane 0 vertically → creates pane 2 (bottom-left).
tmux split-window -v -t "$SESSION_NAME:0.0" -c "$WORKSPACE"

# Pane 2 (bottom-left): Runtime status with auto-refresh.
tmux send-keys -t "$SESSION_NAME:0.2" \
    "watch -n 10 doge runtime" C-m

# Split pane 1 vertically → creates pane 3 (bottom-right).
tmux split-window -v -t "$SESSION_NAME:0.1" -c "$WORKSPACE"

# Pane 3 (bottom-right): Interactive console.
tmux send-keys -t "$SESSION_NAME:0.3" \
    "sleep 3 && doge console" C-m

# Set balanced layout.
tmux select-layout -t "$SESSION_NAME:0" tiled

# Select the console pane as active.
tmux select-pane -t "$SESSION_NAME:0.3"

echo "Launching tmux session..."
echo ""

# Attach to the session.
tmux attach-session -t "$SESSION_NAME"

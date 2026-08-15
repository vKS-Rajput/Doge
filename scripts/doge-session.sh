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

# ──────────────────────────────────────────────────────
# Create tmux session with 4 panes
# ──────────────────────────────────────────────────────

# Create session. Pane 0 = top-left = DOGE machine.
tmux new-session -d -s "$SESSION_NAME" -c "$WORKSPACE" -x 200 -y 50

# Pane 0 (top-left): Start the DOGE machine.
# We start headless so it runs as a background process.
tmux send-keys -t "$SESSION_NAME:0.0" \
    "doge start --target $TARGET --env $ENV --headless" C-m

# Wait for DOGE to initialize, create .doge/doge.log, and session.json.
# This is important — the other panes need these files to exist.
sleep 6

# Split horizontally → pane 1 (right half).
tmux split-window -h -t "$SESSION_NAME:0.0" -c "$WORKSPACE"

# Pane 1 (top-right): Live logs with follow mode.
# This tails .doge/doge.log with color-coded output.
tmux send-keys -t "$SESSION_NAME:0.1" \
    "doge logs -f" C-m

# Split pane 0 vertically → pane 2 (bottom-left).
tmux split-window -v -t "$SESSION_NAME:0.0" -c "$WORKSPACE"

# Pane 2 (bottom-left): Runtime dashboard with auto-refresh.
tmux send-keys -t "$SESSION_NAME:0.2" \
    "watch -n 10 -c doge runtime" C-m

# Split pane 1 vertically → pane 3 (bottom-right).
tmux split-window -v -t "$SESSION_NAME:0.1" -c "$WORKSPACE"

# Pane 3 (bottom-right): Interactive research console.
tmux send-keys -t "$SESSION_NAME:0.3" \
    "doge console" C-m

# Set balanced layout.
tmux select-layout -t "$SESSION_NAME:0" tiled

# Set pane titles for clarity.
tmux select-pane -t "$SESSION_NAME:0.0" -T "MACHINE"
tmux select-pane -t "$SESSION_NAME:0.1" -T "LOGS"
tmux select-pane -t "$SESSION_NAME:0.2" -T "RUNTIME"
tmux select-pane -t "$SESSION_NAME:0.3" -T "CONSOLE"

# Enable pane borders with titles (if tmux supports it).
tmux set-option -t "$SESSION_NAME" pane-border-status top 2>/dev/null || true
tmux set-option -t "$SESSION_NAME" pane-border-format " #{pane_title} " 2>/dev/null || true

# Select the console pane as active.
tmux select-pane -t "$SESSION_NAME:0.3"

echo "Launching tmux session..."
echo ""
echo "  Ctrl+B D  → detach (DOGE continues)"
echo "  tmux a    → reattach"
echo ""

# Attach to the session.
tmux attach-session -t "$SESSION_NAME"

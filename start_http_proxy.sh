#!/bin/bash
# Start the PII-masking HTTP reverse proxy for remote MCP servers.
# Run this before starting Claude Code so the proxy is available.
#
# Usage:
#   ./start_http_proxy.sh              # foreground
#   ./start_http_proxy.sh --daemon     # background (logs to ~/Library/Logs/mcp-privacy-proxy.log)

set -e
cd "$(dirname "$0")"

PORT="${PORT:-9100}"
HOST="${HOST:-127.0.0.1}"
SERVERS="${SERVERS:-${1:-servers.yaml}}"

# Accept --daemon as first or second arg
DAEMON=false
for arg in "$@"; do
    [ "$arg" = "--daemon" ] && DAEMON=true
done

if [ "$DAEMON" = true ]; then
    LOG_DIR="$HOME/Library/Logs"
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/mcp-privacy-proxy.log"
    nohup python http_proxy.py --port "$PORT" --host "$HOST" --servers "$SERVERS" \
        >> "$LOG_FILE" 2>&1 &
    echo "PII proxy started (pid $!) — log: $LOG_FILE"
else
    python http_proxy.py --port "$PORT" --host "$HOST" --servers "$SERVERS"
fi

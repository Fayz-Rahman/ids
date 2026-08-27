#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

echo "=== Network Monitor Startup ==="

pkill -f "relay -listen" 2>/dev/null

echo "#!/bin/bash" > "$SCRIPT_DIR/stop.sh"
echo "echo 'Stopping processes...'" >> "$SCRIPT_DIR/stop.sh"
chmod +x "$SCRIPT_DIR/stop.sh"

read -p "Enter Discord Webhook URL: " DISCORD_WEBHOOK_URL
export DISCORD_WEBHOOK_URL

echo -e "\nAvailable network interfaces:"
./ids -list

read -p "Enter the interface to monitor: " IFACE

echo "Applying configuration..."
cat <<EOF > config.yaml
interface: $IFACE
bpf: "tcp or udp"
interval_ms: 1000
snaplen: 128
evict_idle_s: 120
rules:
  port_scan_ports: 15
  rate_spike_multiple: 5.0
  syn_flood_ratio: 0.8
notify:
  webhook: "http://127.0.0.1:8080/webhook"
  log_file: "ids.log"
  cooldown_s: 300
EOF

echo "Starting Discord Relay in the background..."
go run ./relay -listen :8080 -path /webhook &
RELAY_PID=$!
echo "sudo kill $RELAY_PID 2>/dev/null" >> "$SCRIPT_DIR/stop.sh"

sleep 2

echo ""
echo "----------------------------------------"
read -p "Run IDS in the background? (y/N): " RUN_BG

if [[ "$RUN_BG" =~ ^[Yy]$ ]]; then
    echo "Starting IDS in the background (requires sudo)..."
    sudo ./ids -config config.yaml &
    IDS_PID=$!
    echo "sudo kill $IDS_PID 2>/dev/null" >> "$SCRIPT_DIR/stop.sh"
    echo -e "\nAll services are running in the background."
    echo "Run $SCRIPT_DIR/stop.sh whenever you are ready to terminate them."
else
    echo -e "\nStarting IDS in the foreground (requires sudo)..."
    echo "Press Ctrl+C to stop the IDS, then run $SCRIPT_DIR/stop.sh to kill the background relay."
    sudo ./ids -config config.yaml
fi

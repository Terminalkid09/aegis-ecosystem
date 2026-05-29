#!/bin/bash
set -euo pipefail

# Aegis-Guard Native Installation (Linux/systemd)

echo "--- Aegis-Guard Hardened Setup ---"

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POM_PATH="$(cd "$SCRIPT_DIR" && cd ../../ && pwd)/pom.xml"
ENV_FILE="$(cd "$SCRIPT_DIR" && cd ../../../ && pwd)/.env"

echo "[INFO] Script directory: $SCRIPT_DIR"
echo "[INFO] POM file: $POM_PATH"
echo "[INFO] ENV file: $ENV_FILE"

# Check prerequisites
if ! command -v mvn &> /dev/null; then
    echo "[ERROR] Maven not found in PATH. Please install Maven 3.8+"
    exit 1
fi

if [ ! -f "$POM_PATH" ]; then
    echo "[ERROR] pom.xml not found at $POM_PATH"
    exit 1
fi

# Load .env variables safely
if [ ! -f "$ENV_FILE" ]; then
    echo "[ERROR] .env not found at $ENV_FILE"
    exit 1
fi

echo "[INFO] Loading environment from .env"
export $(grep -v '^#' "$ENV_FILE" | xargs)

if [ -z "${AEGIS_API_KEY:-}" ]; then
    echo "[ERROR] AEGIS_API_KEY not defined in .env"
    exit 1
fi

# 1. Build
echo "[INFO] Building aegis-guard..."
mvn clean package -DskipTests -f "$POM_PATH" || { echo "[ERROR] Maven build failed"; exit 1; }

# 2. Determine gateway URL (rewrite Docker URL for host execution)
GATEWAY_URL="${AEGIS_GATEWAY_URL}"
if [[ $GATEWAY_URL == *"aegis-link:8080"* ]]; then
    EXTERNAL_PORT="${LINK_PORT_EXTERNAL:-8088}"
    GATEWAY_URL="${GATEWAY_URL//aegis-link:8080/localhost:$EXTERNAL_PORT}"
    echo "[INFO] Adjusting Gateway URL for host execution: $GATEWAY_URL"
fi

# 3. Create secure directories and set permissions (Root only)
echo "[INFO] Setting up secure directories..."
sudo mkdir -p /opt/aegis/guard
sudo chown root:root /opt/aegis/guard
sudo chmod 700 /opt/aegis/guard

# 4. Verify and copy JAR
JAR_SOURCE="$SCRIPT_DIR/../../target/aegis-guard.jar"
if [ ! -f "$JAR_SOURCE" ]; then
    echo "[ERROR] JAR file not found at $JAR_SOURCE"
    exit 1
fi

echo "[INFO] Computing file hash..."
sha256sum "$JAR_SOURCE" | tee /tmp/aegis-guard.sha256
sudo cp "$JAR_SOURCE" /opt/aegis/guard/aegis-guard.jar
sudo chmod 600 /opt/aegis/guard/aegis-guard.jar
sudo mv /tmp/aegis-guard.sha256 /opt/aegis/guard/aegis-guard.sha256
sudo chmod 644 /opt/aegis/guard/aegis-guard.sha256

# 5. Create systemd unit
echo "[INFO] Creating systemd service..."
AGENT_ID="${AEGIS_AGENT_ID:-$(cat /etc/machine-id)}"
SCAN_INTERVAL="${AEGIS_SCAN_INTERVAL_MS:-1000}"

sudo tee /etc/systemd/system/aegis-guard.service > /dev/null <<EOF
[Unit]
Description=Aegis-Guard EDR Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/java -jar /opt/aegis/guard/aegis-guard.jar
Environment="AEGIS_GATEWAY_URL=$GATEWAY_URL"
Environment="AEGIS_GUARD_API_KEY=${AEGIS_API_KEY}"
Environment="AEGIS_AGENT_ID=$AGENT_ID"
Environment="AEGIS_SCAN_INTERVAL_MS=$SCAN_INTERVAL"
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

# Security hardening
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/opt/aegis/guard

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable and start service
echo "[INFO] Enabling and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable aegis-guard
sudo systemctl start aegis-guard

# 7. Verify service
sleep 2
if sudo systemctl is-active --quiet aegis-guard; then
    echo "✓ Service aegis-guard is RUNNING securely."
else
    echo "[ERROR] Service failed to start. Check logs:"
    sudo journalctl -u aegis-guard -n 20
    exit 1
fi

echo ""
echo "[SUCCESS] Aegis-Guard native installation complete!"
echo "  Agent ID:      $AGENT_ID"
echo "  Gateway:       $GATEWAY_URL"
echo "  Logs:          sudo journalctl -u aegis-guard -f"
echo "  Hash:          /opt/aegis/guard/aegis-guard.sha256"

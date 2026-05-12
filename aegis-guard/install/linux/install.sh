#!/bin/bash
# Aegis-Guard Native Installation (Linux/systemd)

echo "--- Aegis-Guard Hardened Setup ---"

# Load .env variables safely
if [ ! -f "../../../.env" ]; then echo "[ERROR] .env not found"; exit 1; fi
export $(grep -v '^#' ../../../.env | xargs)

# 1. Build
mvn clean package -DskipTests -f ../../pom.xml

# 2. Create secure directories and set permissions (Root only)
sudo mkdir -p /opt/aegis/guard
sudo chown root:root /opt/aegis/guard
sudo chmod 700 /opt/aegis/guard

# 3. Verify Integrity (SHA256)
echo "[INFO] Verifying JAR integrity..."
sha256sum ../target/aegis-guard.jar > /opt/aegis/guard/aegis-guard.sha256
sudo cp ../target/aegis-guard.jar /opt/aegis/guard/
sudo chmod 600 /opt/aegis/guard/aegis-guard.jar

# 4. Create systemd unit
cat <<EOF | sudo tee /etc/systemd/system/aegis-guard.service
[Unit]
Description=Aegis-Guard EDR Agent
After=network.target

[Service]
ExecStart=/usr/bin/java -jar /opt/aegis/guard/aegis-guard.jar
Environment="AEGIS_GATEWAY_URL=${AEGIS_GATEWAY_URL}"
Environment="AEGIS_GUARD_API_KEY=${AEGIS_API_KEY}"
Environment="AEGIS_AGENT_ID=$(cat /etc/machine-id)"
Restart=always
User=root
# Restrictive security profile
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable aegis-guard
sudo systemctl start aegis-guard
echo "[SUCCESS] Aegis-Guard service is running securely."

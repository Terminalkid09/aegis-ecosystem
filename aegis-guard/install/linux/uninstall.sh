#!/bin/bash
# Aegis-Guard Uninstallation (Linux/systemd)

echo "--- Uninstalling Aegis-Guard ---"

sudo systemctl stop aegis-guard
sudo systemctl disable aegis-guard
sudo rm /etc/systemd/system/aegis-guard.service
sudo systemctl daemon-reload

sudo rm -rf /opt/aegis/guard

echo "[SUCCESS] Aegis-Guard has been successfully uninstalled."

#!/bin/bash
# Aegis — Deploy on-premise (Docker Compose, lab e pilot)
# Uso: ./install.sh [lab|pilot] [--observability]  (default: lab)
set -euo pipefail
MODE="${1:-lab}"
OBS="${2:-}"
if [[ "$MODE" == "--observability" ]]; then MODE="lab"; OBS="--observability"; fi
if [[ "$MODE" != "lab" && "$MODE" != "pilot" ]]; then
  echo "Uso: $0 [lab|pilot] [--observability]"; exit 2
fi
if [[ "$MODE" == "pilot" && "$OBS" == "--observability" ]]; then
  echo "[ERROR] --observability è un profilo lab: in pilot Prometheus/Grafana NON sono previsti."
  echo "        Le metriche pilot si raccolgono via scripts/benchmark.py e /metrics (solo brain)."; exit 2
fi
if [[ ! -f .env ]]; then
  echo "[INFO] .env mancante -> copio .env.example"
  cp .env.example .env
  echo "[WARN] Modifica .env con segreti reali prima del pilot."
fi
# Verifica segreti non placeholder in pilot
if [[ "$MODE" == "pilot" ]]; then
  if grep -q "replace-with" .env; then
    echo "[ERROR] .env contiene placeholder: sostituirli per pilot."; exit 1
  fi
  COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.mtls.yml"
  echo "[INFO] Modalità pilot: prod overlay + mTLS :8443"
else
  COMPOSE="docker compose -f docker-compose.yml"
  echo "[INFO] Modalità lab: Compose base (dev TLS internal)"
fi
if [[ "$OBS" == "--observability" ]]; then
  COMPOSE="$COMPOSE -f docker-compose.observability.yml --profile observability"
  echo "[INFO] Profilo observability: Prometheus + Grafana su localhost:9090/:3001 (GRAFANA_ADMIN_PASSWORD richiesta)"
fi
echo "[1/4] Build immagini..."
$COMPOSE build
echo "[2/4] Avvio stack..."
$COMPOSE up -d --remove-orphans
echo "[3/4] Attesa healthcheck..."
for i in {1..30}; do if $COMPOSE ps | grep -q "healthy"; then break; fi; sleep 2; done
$COMPOSE ps
echo "[4/4] Verifica health..."
curl -sk http://localhost:8000/health/live | head -c 200; echo
if [[ "$MODE" == "pilot" ]]; then
  echo "[INFO] PKI bootstrap (se prima installazione):"
  echo "  docker compose exec aegis-brain python -m app.services.pki --dir /app/pki"
  echo "[INFO] Verifica mTLS: :8443 richiede cert device (vedi docs/OPERATIONS.md §2b)"
fi
echo "[OK] Deploy $MODE completato. Dashboard: http://localhost:3000  API: http://localhost:8000  Caddy: https://aegis.local"

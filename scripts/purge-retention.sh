#!/bin/sh
# Aegis retention purge — SOLO manuale (dati cancellati = persi).
# Applica i cutoff approvati M0 (default: telemetria 14, alert 90, audit 365,
# syslog 30 giorni). DRY_RUN=1 (default) mostra i conteggi senza cancellare.
set -eu

DB_HOST="${DB_HOST:-aegis-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-aegis}"
DB_USER="${DB_USER:-postgres}"
export PGPASSWORD="${PGPASSWORD:-}"
DRY_RUN="${DRY_RUN:-1}"

TELEMETRY_DAYS="${RETENTION_TELEMETRY_DAYS:-14}"
ALERTS_DAYS="${RETENTION_ALERTS_DAYS:-90}"
AUDIT_DAYS="${RETENTION_AUDIT_DAYS:-365}"
SYSLOG_DAYS="${RETENTION_SYSLOG_DAYS:-30}"

PSQL="psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -At"

count() { # tabella, colonna, giorni
  $PSQL -c "SELECT count(*) FROM $1 WHERE $2 < now() - interval '$3 days';"
}

echo "telemetry oltre ${TELEMETRY_DAYS}gg: $(count telemetry timestamp "$TELEMETRY_DAYS")"
echo "alerts oltre ${ALERTS_DAYS}gg: $(count alerts timestamp "$ALERTS_DAYS")"
echo "audit oltre ${AUDIT_DAYS}gg: $(count audit_logs created_at "$AUDIT_DAYS")"
echo "syslog oltre ${SYSLOG_DAYS}gg: $(count syslog_events timestamp "$SYSLOG_DAYS")"

if [ "$DRY_RUN" != "0" ]; then
  echo "DRY_RUN=1: niente cancellato. Riesegui con DRY_RUN=0 per purgare."
  exit 0
fi
if [ "${I_CONFIRM_PURGE:-}" != "yes" ]; then
  echo "REFUSING: imposta I_CONFIRM_PURGE=yes per cancellare davvero." >&2
  exit 3
fi
$PSQL -c "DELETE FROM telemetry WHERE timestamp < now() - interval '$TELEMETRY_DAYS days';"
$PSQL -c "DELETE FROM alerts WHERE timestamp < now() - interval '$ALERTS_DAYS days';"
$PSQL -c "DELETE FROM audit_logs WHERE created_at < now() - interval '$AUDIT_DAYS days';"
$PSQL -c "DELETE FROM syslog_events WHERE timestamp < now() - interval '$SYSLOG_DAYS days';"
echo "Purge completata."

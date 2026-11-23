#!/bin/sh
set -eu

rand() {
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

db_pw="$(rand 16)"
redis_pw="$(rand 16)"
secret_key="$(rand 32)"
internal_api_key="$(rand 32)"
sso_secret="$(rand 32)"
broker_token="$(rand 32)"

cat <<EOF
COMPOSE_PROJECT_NAME=aegis-kraken
KRAKEN_DB_PASSWORD=$db_pw
KRAKEN_REDIS_PASSWORD=$redis_pw
KRAKEN_SECRET_KEY=$secret_key
KRAKEN_INTERNAL_API_KEY=$internal_api_key
KRAKEN_SSO_SECRET=$sso_secret
SANDBOX_BROKER_TOKEN=$broker_token
KRAKEN_SSO_ENABLED=false
KRAKEN_INGEST_ENABLED=false
KRAKEN_PORT_EXTERNAL=8001
KRAKEN_PUBLIC_BASE_PATH=
KRAKEN_SENSOR_PROTOCOLS=ssh,http,ftp,telnet,smb,rdp
KRAKEN_FILE_ANALYSIS_ENABLED=true
KRAKEN_OBJECT_STORE_BACKEND=local
KRAKEN_DETONATION_ENABLED=false
MALWARE_RETENTION_DAYS=30
MALWARE_MAX_TOTAL_BYTES=5368709120
EOF

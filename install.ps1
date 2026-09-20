# Aegis — Deploy on-premise (Docker Compose, lab e pilot) — Windows
# Uso: .\install.ps1 [lab|pilot] [-Observability]  (default: lab)
param([string]$Mode = "lab", [switch]$Observability)
if ($Mode -notin @("lab","pilot")) { Write-Error "Uso: .\install.ps1 [lab|pilot] [-Observability]"; exit 2 }
if ($Mode -eq "pilot" -and $Observability) { Write-Error "-Observability è un profilo lab: in pilot Prometheus/Grafana NON sono previsti."; exit 2 }
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env"; Write-Host "[WARN] Modifica .env con segreti reali prima del pilot." -ForegroundColor Yellow }
if ($Mode -eq "pilot" -and (Select-String -Path ".env" -Pattern "replace-with" -Quiet)) { Write-Error ".env contiene placeholder: sostituirli per pilot."; exit 1 }
$compose = if ($Mode -eq "pilot") { "docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.mtls.yml" } else { "docker compose -f docker-compose.yml" }
if ($Observability) {
  $compose = "$compose -f docker-compose.observability.yml --profile observability"
  Write-Host "[INFO] Profilo observability: Prometheus:9090 + Grafana:3001 (richiede GRAFANA_ADMIN_PASSWORD)." -ForegroundColor Cyan
}
Write-Host "[1/4] Build..." -ForegroundColor Cyan; Invoke-Expression "$compose build"
Write-Host "[2/4] Avvio stack..." -ForegroundColor Cyan; Invoke-Expression "$compose up -d --remove-orphans"
Write-Host "[3/4] Attesa healthcheck..." -ForegroundColor Cyan; Start-Sleep -Seconds 10; Invoke-Expression "$compose ps"
Write-Host "[4/4] Verifica health..." -ForegroundColor Cyan
try { (Invoke-WebRequest -Uri "http://localhost:8000/health/live" -UseBasicParsing -TimeoutSec 10).Content | Select-Object -First 1 } catch { Write-Warning $_ }
if ($Mode -eq "pilot") { Write-Host "PKI bootstrap: docker compose exec aegis-brain python -m app.services.pki --dir /app/pki" -ForegroundColor Yellow }
Write-Host "[OK] Deploy $Mode completato. Dashboard: http://localhost:3000  API: http://localhost:8000" -ForegroundColor Green

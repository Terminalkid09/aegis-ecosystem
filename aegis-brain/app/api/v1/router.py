from fastapi import APIRouter
from app.api.v1 import auth, vault, osint, ai, telemetry, nodetrace, enroll, history, rules, discovery, ws, playbooks, syslog, audit, deploy, total, incidents, ocsf, ingest, search, integrations, fim, yara, users, telegram

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth")
api_router.include_router(vault.router, prefix="/vault")
api_router.include_router(osint.router, prefix="/osint")
api_router.include_router(ai.router, prefix="/ai")
api_router.include_router(telemetry.router, prefix="/telemetry")
api_router.include_router(history.router, prefix="/telemetry")
api_router.include_router(enroll.router, prefix="/enroll")
api_router.include_router(rules.router, prefix="/rules")
api_router.include_router(discovery.router, prefix="/discovery")
api_router.include_router(deploy.router, prefix="/deploy")
api_router.include_router(total.router, prefix="/total")
api_router.include_router(incidents.router, prefix="/soc")
api_router.include_router(playbooks.router, prefix="/soar")
api_router.include_router(syslog.router, prefix="/syslog")
api_router.include_router(ocsf.router, prefix="/ocsf")
# SIEM v4: ingestione multi-sorgente e ricerca sugli eventi normalizzati.
api_router.include_router(ingest.router, prefix="/ingest")
api_router.include_router(search.router, prefix="/search")
api_router.include_router(audit.router, prefix="/audit")
# Chiavi di integrazione (OSINT ecc.): stato mascherato + override da UI.
api_router.include_router(integrations.router, prefix="/integrations")
api_router.include_router(fim.router, prefix="/fim")
api_router.include_router(yara.router, prefix="/yara")
api_router.include_router(telegram.router, prefix="/telegram")
# Gestione account (admin): il flag `active` ora è enforcement, non decorazione.
api_router.include_router(users.router, prefix="/users")
api_router.include_router(ws.router, prefix="/ws")
api_router.include_router(nodetrace.router) # Root level compatibility routes


@api_router.get("/health")
async def api_health():
    return {"status": "ok", "service": "aegis-brain"}

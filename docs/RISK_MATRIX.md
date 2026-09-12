# Aegis — Risk Matrix (M0)

Versione: 1.0 — 2026-09-11. Owner di default: SOC platform team.
Priorità: P0 blocca release, P1 prima del pilot, P2 hardening continuo.

| ID | Rischio (scenario) | Impatto / Probabilità | Owner | Pri | Mitigazione attuale (verificata) | Chiusura |
|---|---|---|---|---|---|---|
| R1 | Furto/riuso enroll token | Alto / Media | backend | P0 | single-use (`used_at`), scadenza 15 min, revoca, hash sha256, audit `deploy_token_*` (`deploy.py`) | Fase 7: +mTLS, GPO/Intune/Ansible |
| R2 | Brute-force login/enroll/approve | Alto / Media | backend | P0 | rate-limit (register 5/m, login 10/m, approve 5/m), `compare_digest` (`auth.py`, `enroll.py`, `deploy.py`) | Fase 7: lockout/accounting dedicato |
| R3 | JWT rubato riusato dopo logout | Alto / Bassa | backend | P0 | blacklist Redis `bl:{jti}`, fail-closed se Redis giù, cookie httpOnly+Secure(`!DEBUG`)+SameSite (`security.py`, `auth.py`, `deps.py`) | Fase 8: audit sessioni + retention |
| R4 | CSRF su mutazioni cookie | Alto / Bassa | backend | P0 | `csrf_origin_middleware` vs `ALLOWED_ORIGINS`, CORS allowlist, no wildcard+credenziali (`main.py`) | Fase 10: test CSRF/session/WS |
| R5 | Agent compromesso inietta eventi | Alto / Media | sensor | P0 | auth per-device, validazione `EventSchema`, mai solo-IP (`agent_deps`, Fase 2) | Fase 2: schema v2 + idempotenza |
| R6 | Perdita eventi invisibile (rete/reboot/disco) | Alto / Alta | sensor | P0 | outbox batch + fallback single, ack comandi (stato, non garanzia) | Fase 2: coda persistente cifrata + contatori |
| R7 | Artefatto/OTA alterato | Critico / Bassa | deploy | P0 | HMAC-SHA256 con `AGENT_ENROLL_KEY`, anti-traversal basename, stage solo se firma ok (`deploy.py`) | Fase 7: PKI + manifest firmato |
| R8 | Credenziali deploy persistite/rubate | Critico / Bassa | deploy | P0 | SSH/WinRM rifiutati (501/400), one-liner manuale, password mai salvate (`deploy.py:394`) | Fase 7: worker effimero + VaultX lease 60s |
| R9 | Isolamento ostile/errato su host reale | Critico / Bassa | soc | P0 | isolate/release espliciti, auditati, reversibili; niente auto-isolate in demo | Fase 6: precondizioni+approvatore+rollback |
| R10 | Accesso cross-sito (oggi nessun sito) | Alto / Media | soc | P1 | 3 ruoli + gating analyst/admin; siti assenti = boundary da costruire | Fase 8: siti/subnet/gruppi + 5 ruoli |
| R11 | PII oltre il consentito / retention indefinita | Alto / Media | platform | P1 | dati consentiti fissati; config retention nuova `RETENTION_*_DAYS`; enforcement da fare | Fase 8/9: job purge + test |
| R12 | Backup PG rubato (non cifrato) | Alto / Bassa | platform | P1 | cron 6h, retention 7gg, volume dedicato (`docker-compose.yml`, `backup-db.sh`) | Fase 9: cifratura + restore testato |
| R13 | Segreti in repo/log/artefatti | Critico / Bassa | platform | P0 | `.env`/`secret.json` ignored+non tracciati (Fase 0); validazione placeholder (`config.py`); chiavi solo env | Fase 10: secret-scan in CI |
| R14 | Supply-chain (dep/immagini/artefatti) | Alto / Media | platform | P1 | pin parziale immagini, SHA OTA, audit dep non continuo | Fase 10: SBOM, digest-pin, firma, provenance, scan |
| R15 | eBPF/ETW assenti o degradati in silenzio | Medio / Alta | sensor | P1 | tier documentati in `aegis-ebpf/README.md`; flag `ebpf_enabled`; fallback polling | Fase 3/4: feature-flag + coverage in dashboard |
| R16 | Redis/PG down = degrado silenzioso sicurezza | Alto / Media | backend | P0 | auth fail-closed; code comandi con 202 esplicito; readiness/liveness (`main.py`, `health.py`) | Fase 9: worker separato + migration job |
| R17 | Regole rumorose / auto-remediation distruttiva | Alto / Media | detection | P1 | MITRE + test endpoint, `script` solo admin, canary da fare | Fase 5: replay, corpus, KPI, canary/rollback |
| R18 | Log injection / query injection | Medio / Bassa | backend | P1 | logger strutturato, ORM parametrizzato | Fase 10: test injection dedicati |

Registro vivente: ogni modifica che cambia il threat model deve aggiornare
`THREAT_MODEL.md` + questa matrice (Definition of Done roadmap §10).

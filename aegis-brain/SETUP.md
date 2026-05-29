# Aegis-Brain: Setup e Testing Locale

Questa guida ti spiega come configurare e testare **Aegis-Brain** sul tuo ambiente locale.

---

## 📋 Prerequisiti

- **Python 3.11+** (verifica: `python --version`)
- **Docker & Docker Compose** (verifica: `docker --version && docker-compose --version`)
- **Git** (verifica: `git --version`)

---

## 🚀 Avvio Rapido

### 1. Clona il Repository

```bash
git clone https://github.com/your-org/aegis-ecosystem.git
cd aegis-ecosystem
```

### 2. Naviga nella Cartella Backend

```bash
cd aegis-brain
```

### 3. Configura le Variabili d'Ambiente

Copia il file di esempio e personalizza i valori:

```bash
cp .env.example .env
```

Modifica `.env` e assicurati di includere:

```bash
# Database PostgreSQL
DATABASE_URL=postgresql://postgres:password@localhost:5432/aegis

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET=your-super-secret-jwt-key-min-32-chars

# Encryption Master Key (base64-encoded 32 bytes)
# Genera un nuovo: python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
MASTER_KEY_B64=your-base64-encoded-32-byte-master-key

# LLM (Ollama)
OLLAMA_URL=http://localhost:11434

# OSINT APIs (test keys, replace with real ones)
SHODAN_API_KEY=your_shodan_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# MongoDB per migrazione (opzionale)
MONGO_URI=mongodb://localhost:27017/vaultx
```

---

## 🐳 Avvio Database e Redis con Docker

### Usa Docker Compose (Consigliato)

Se il repository contiene `docker-compose.yml`:

```bash
# Dal root del repository
docker-compose up -d postgres redis
```

**Verifica che i servizi siano attivi:**

```bash
docker ps | grep "postgres\|redis"
```

### Alternative Manuali

**PostgreSQL:**

```bash
docker run -d \
  --name aegis-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=aegis \
  -p 5432:5432 \
  postgres:15-alpine
```

**Redis:**

```bash
docker run -d \
  --name aegis-redis \
  -p 6379:6379 \
  redis:7-alpine
```

**Verifica connessioni:**

```bash
# PostgreSQL
psql postgresql://postgres:password@localhost:5432/aegis -c "SELECT 1"

# Redis
redis-cli ping  # Deve rispondere "PONG"
```

---

## 📦 Installa Dipendenze Python

```bash
# Crea ambiente virtuale (opzionale ma consigliato)
python -m venv venv

# Attiva venv
# Su Windows:
venv\Scripts\activate
# Su macOS/Linux:
source venv/bin/activate

# Installa dipendenze
pip install --upgrade pip
pip install -r requirements.txt
```

**Verifica installazione:**

```bash
python -c "import fastapi, sqlalchemy, redis; print('✅ All dependencies installed')"
```

---

## 🧪 Esecuzione Test

### Esegui Tutti i Test

```bash
pytest -v
```

### Esegui Test per Modulo Specifico

```bash
# Test OSINT
pytest tests/test_osint.py -v

# Test AI-Suite
pytest tests/test_ai.py -v

# Test Telemetry
pytest tests/test_telemetry.py -v

# Test Auth
pytest tests/test_auth.py -v

# Test Vault (Notes)
pytest tests/test_vault.py -v
```

### Esegui Test con Coverage

```bash
pytest --cov=app --cov=services --cov-report=html --cov-report=term
```

Apri `htmlcov/index.html` nel browser per visualizzare il rapporto di coverage.

### Test di Sicurezza Specifici

```bash
# Prompt Injection Detection
pytest tests/test_ai.py::test_prompt_injection_blocked -v

# Password Security
pytest tests/test_auth.py::test_register_password_hashed -v

# Note Encryption
pytest tests/test_vault.py::test_notes_encrypted_in_db -v

# Anomaly Detection
pytest tests/test_telemetry.py::test_anomaly_triggers_alert -v

# Agent Authentication
pytest tests/test_telemetry.py::test_invalid_agent_token_rejected -v
```

---

## 🛠️ Migrazione da MongoDB (VaultX)

Se hai dati legacy in MongoDB che vuoi migrare:

```bash
# Assicurati che MongoDB sia attivo
# mongodb://localhost:27017/vaultx

# Esegui la migrazione
python services/migrate_vaultx.py
```

**Output atteso:**

```
2024-01-XX 12:34:56,789 - root - INFO - Found 5 users in MongoDB
2024-01-XX 12:34:56,890 - root - INFO - Migrated user: john_doe (...) → ...
2024-01-XX 12:34:56,991 - root - INFO - Successfully migrated 5 users
2024-01-XX 12:34:57,092 - root - INFO - Committed 42 notes from user ...
2024-01-XX 12:34:57,193 - root - INFO - Total notes migrated: 42

✅ Migration Successful!
   Users migrated: 5
   Notes migrated: 42
```

---

## 🚀 Avvio del Server

### Development (con Hot Reload)

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**L'app sarà disponibile su:**
- **API Base:** http://localhost:8000
- **Swagger Docs:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### Production (senza Reload)

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## 🧹 Linting e Code Quality

### Lint con Ruff

```bash
ruff check . --fix
```

### Security Scan con Bandit

```bash
bandit -r app services -f json -o bandit-report.json
```

---

## 🔧 Troubleshooting

### Errore: "Cannot connect to PostgreSQL"

```bash
# Verifica che il container sia attivo
docker ps | grep postgres

# Se non è attivo, avvialo
docker run -d --name aegis-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=aegis \
  -p 5432:5432 \
  postgres:15-alpine

# Test connessione
psql postgresql://postgres:password@localhost:5432/aegis -c "SELECT 1"
```

### Errore: "Cannot connect to Redis"

```bash
# Verifica che Redis sia attivo
docker ps | grep redis

# Se non è attivo, avvialo
docker run -d --name aegis-redis -p 6379:6379 redis:7-alpine

# Test connessione
redis-cli ping  # Deve rispondere "PONG"
```

### Errore: "MASTER_KEY_B64 not set"

Genera una nuova chiave e aggiorna `.env`:

```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

Poi copia l'output nel file `.env`:

```bash
MASTER_KEY_B64=<your-output-here>
```

### Test Fallisce: "ModuleNotFoundError"

Assicurati che il venv sia attivato:

```bash
# Attiva venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows
```

---

## 📊 Verificare l'Ambiente

Esegui questo script per validare il setup:

```bash
python -m pytest --co -q  # Mostra tutti i test disponibili
pytest -v --tb=short 2>&1 | tail -20  # Esegui test e mostra ultimi 20 risultati
```

---

## 🔑 File di Configurazione Comuni

- **`.env`** — Variabili d'ambiente locali (NON committare)
- **`.env.example`** — Template per `.env` (committare)
- **`requirements.txt`** — Dipendenze Python
- **`pytest.ini`** — Configurazione pytest
- **`.github/workflows/ci.yml`** — Pipeline GitHub Actions

---

## 📝 Comandi Rapidi di Riferimento

| Comando | Descrizione |
|---------|-------------|
| `pip install -r requirements.txt` | Installa dipendenze |
| `pytest -v` | Esegui tutti i test |
| `pytest --cov=app --cov=services` | Test con coverage |
| `uvicorn main:app --reload` | Avvia server dev |
| `ruff check . --fix` | Lint e fix codice |
| `bandit -r app services` | Scan sicurezza |
| `python services/migrate_vaultx.py` | Migra da MongoDB |
| `redis-cli ping` | Test Redis |
| `psql postgresql://...` | Test PostgreSQL |

---

## 🎯 Checklist di Validazione

Prima di committare, verifica:

- [ ] `pytest -v` passa al 100%
- [ ] `ruff check .` non mostra errori critici
- [ ] `bandit -r app services` non segnala vulnerabilità alte
- [ ] `.env` non è committato (controllare `.gitignore`)
- [ ] `MASTER_KEY_B64` è impostato
- [ ] PostgreSQL e Redis sono attivi (locale o container)
- [ ] Server avvia senza errori (`uvicorn main:app --reload`)

---

## 📚 Riferimenti Ulteriori

- **FastAPI Docs:** https://fastapi.tiangolo.com/
- **SQLAlchemy Docs:** https://docs.sqlalchemy.org/
- **Redis Docs:** https://redis.io/docs/
- **PostgreSQL Docs:** https://www.postgresql.org/docs/

---

**Aegis-Brain è pronto! 🎉**

Per domande o problemi, apri una issue nel repository.

# ─── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS build

# Installa dipendenze di sistema necessarie per compilare alcuni pacchetti Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Installiamo libpq5 per il DB e wget per il healthcheck di Docker
# apt-get upgrade: tira gli aggiornamenti di sicurezza di Debian al build time
# (i residui senza fix upstream sono elencati in .trivyignore con motivo).
RUN apt-get update && apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    wget \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Copia le dipendenze installate dall'utente nello stage precedente
COPY --from=build /root/.local /home/aegis/.local
COPY . .

RUN useradd -m --shell /bin/false aegis
RUN chown -R aegis:aegis /app /home/aegis/.local
# Le dirs esistono nell'immagine così i volumi named (pki_data/artifact_data)
# nascono con proprietario `aegis` alla prima creazione (Docker ne copia owner).
RUN mkdir -p /app/pki /app/artifacts && chown -R aegis:aegis /app/pki /app/artifacts && chmod 700 /app/pki
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Runtime non-root (trivy AVD-DS-0002): il server gira come `aegis`; la correzione
# dei volumi legacy root-owned è gestita negli upgrade (docs/OPERATIONS.md).
USER aegis

ENTRYPOINT ["/app/entrypoint.sh"]

# Assicuriamoci che i binari installati siano nel PATH
ENV PATH=/home/aegis/.local/bin:$PATH
ENV PYTHONPATH=/app

EXPOSE 8000

# Ridotto a 1 worker per gestire correttamente il consumer Redis interno
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--http", "h11"]

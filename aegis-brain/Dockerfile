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
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copia le dipendenze installate dall'utente nello stage precedente
COPY --from=build /root/.local /home/aegis/.local
COPY . .

RUN useradd -m --shell /bin/false aegis
RUN chown -R aegis:aegis /app /home/aegis/.local
USER aegis

# Assicuriamoci che i binari installati siano nel PATH
ENV PATH=/home/aegis/.local/bin:$PATH

EXPOSE 8000

# Ridotto a 1 worker per gestire correttamente il consumer Redis interno
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

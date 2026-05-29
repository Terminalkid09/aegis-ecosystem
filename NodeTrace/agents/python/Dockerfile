FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m --shell /bin/false nodetrace \
    && mkdir -p /app/data \
    && chown -R nodetrace:nodetrace /app

USER nodetrace

CMD ["python", "agent.py"]

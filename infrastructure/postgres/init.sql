-- Aegis EDR — Schema PostgreSQL
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS agents (
    agent_id   UUID         PRIMARY KEY,
    hostname   VARCHAR(255),
    ip_address VARCHAR(45),
    os_type    VARCHAR(50),
    last_seen  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id           SERIAL       PRIMARY KEY,
    agent_id     UUID         NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    timestamp    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    severity     VARCHAR(20)  NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    process_name VARCHAR(255) NOT NULL,
    process_path TEXT,
    event_type   VARCHAR(100) NOT NULL,
    description  TEXT         NOT NULL,
    is_resolved  BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_alerts_agent_id    ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_is_resolved ON alerts(is_resolved);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts(timestamp DESC);

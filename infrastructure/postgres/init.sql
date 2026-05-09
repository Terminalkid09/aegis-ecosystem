CREATE TABLE IF NOT EXISTS agents (
    agent_id UUID PRIMARY KEY,
    hostname VARCHAR(255),
    ip_address VARCHAR(45),
    os_type VARCHAR(50),
    last_seen TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(agent_id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20),
    process_name VARCHAR(255),
    process_path TEXT,
    event_type VARCHAR(100),
    description TEXT,
    is_resolved BOOLEAN DEFAULT FALSE
);

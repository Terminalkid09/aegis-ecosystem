CREATE TABLE IF NOT EXISTS ai_threads (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    title VARCHAR(255) NOT NULL DEFAULT 'Security Investigation',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ai_threads_user_id ON ai_threads(user_id);

CREATE TABLE IF NOT EXISTS ai_messages (
    id SERIAL PRIMARY KEY,
    thread_id INTEGER NOT NULL REFERENCES ai_threads(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    model VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ai_messages_thread_id ON ai_messages(thread_id);
CREATE INDEX IF NOT EXISTS ix_ai_messages_user_id ON ai_messages(user_id);

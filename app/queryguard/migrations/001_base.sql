-- Applied at start-up by the bootstrap (admin) login. Idempotent.

CREATE TABLE IF NOT EXISTS users (
    id            serial PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'analyst')),
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS customers (
    id          serial PRIMARY KEY,
    full_name   text NOT NULL,
    email       text NOT NULL,
    phone       text NOT NULL,
    city        text NOT NULL,
    branch      text NOT NULL,
    pan         text NOT NULL,
    account_no  text NOT NULL,
    balance     numeric(12, 2) NOT NULL,
    opened_on   date NOT NULL
);

CREATE TABLE IF NOT EXISTS request_log (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    client_ip   text NOT NULL,
    method      text NOT NULL,
    path        text NOT NULL,
    status      integer NOT NULL,
    verdict     text NOT NULL CHECK (verdict IN ('normal', 'suspicious', 'blocked')),
    source      text NOT NULL,
    score       integer NOT NULL DEFAULT 0,
    rule_ids    text[] NOT NULL DEFAULT '{}',
    sample      text,
    username    text,
    latency_ms  integer
);
CREATE INDEX IF NOT EXISTS request_log_ts_idx ON request_log (ts DESC);
CREATE INDEX IF NOT EXISTS request_log_verdict_ts_idx ON request_log (verdict, ts DESC);

CREATE TABLE IF NOT EXISTS security_event (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    kind        text NOT NULL,
    severity    text NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    client_ip   text,
    username    text,
    summary     text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    alert       text NOT NULL DEFAULT 'none'   -- none | sent | logged | failed
);
CREATE INDEX IF NOT EXISTS security_event_ts_idx ON security_event (ts DESC);

-- Login lookup for the runtime role. The runtime role cannot read the
-- password_hash column directly, so a UNION-style injection that targets
-- users.password_hash fails with "permission denied" even if it slips past
-- every other layer. This definer function returns one hash for one name.
CREATE OR REPLACE FUNCTION auth_lookup(p_username text)
RETURNS TABLE (id integer, username text, role text, password_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT u.id, u.username, u.role, u.password_hash
    FROM users u
    WHERE u.username = p_username
$$;

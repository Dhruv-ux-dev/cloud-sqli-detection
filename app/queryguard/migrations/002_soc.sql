-- Security operations platform: roles, incident workflow, alerts, audit,
-- DLP access trail, blocklist, policies, rule state, simulation history.
-- Applied once by the migration runner (see db.py).

-- ---------------------------------------------------------------- users / RBAC
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('admin', 'analyst', 'viewer'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at timestamptz;
-- Bumped on role change, deactivation or password reset: every session
-- issued before the bump stops working.
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_epoch integer NOT NULL DEFAULT 0;

-- Login lookup now also returns the account state.
DROP FUNCTION IF EXISTS auth_lookup(text);
CREATE FUNCTION auth_lookup(p_username text)
RETURNS TABLE (id integer, username text, role text, password_hash text,
               is_active boolean, session_epoch integer)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT u.id, u.username, u.role, u.password_hash, u.is_active, u.session_epoch
    FROM users u
    WHERE u.username = p_username
$$;

-- ---------------------------------------------------------------- request log
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS user_agent text;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS query_preview text;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS category text;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS matches jsonb NOT NULL DEFAULT '[]'::jsonb;
CREATE INDEX IF NOT EXISTS request_log_ip_ts_idx ON request_log (client_ip, ts DESC);
CREATE INDEX IF NOT EXISTS request_log_path_idx ON request_log (path);
CREATE INDEX IF NOT EXISTS request_log_category_idx ON request_log (category) WHERE category IS NOT NULL;

-- ---------------------------------------------------------------- incidents
ALTER TABLE security_event DROP CONSTRAINT IF EXISTS security_event_severity_check;
ALTER TABLE security_event ADD CONSTRAINT security_event_severity_check
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational'));
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS category text;
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS endpoint text;
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'new';
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS assigned_to text;
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS occurrences integer NOT NULL DEFAULT 1;
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE security_event ADD COLUMN IF NOT EXISTS resolved_at timestamptz;
ALTER TABLE security_event DROP CONSTRAINT IF EXISTS security_event_status_check;
ALTER TABLE security_event ADD CONSTRAINT security_event_status_check
    CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive'));

-- Backfill categories for incidents recorded before this migration.
UPDATE security_event SET category = CASE kind
        WHEN 'repeated_injection' THEN 'sql_injection'
        WHEN 'brute_force'        THEN 'auth_failures'
        WHEN 'bulk_access'        THEN 'suspicious_data_access'
        WHEN 'pii_reveal'         THEN 'sensitive_data_exposure'
        ELSE 'unusual_traffic' END
    WHERE category IS NULL;
UPDATE security_event SET severity = 'informational', status = 'resolved', resolved_at = ts
    WHERE kind = 'pii_reveal' AND severity = 'low';

CREATE INDEX IF NOT EXISTS security_event_status_idx ON security_event (status, ts DESC);
CREATE INDEX IF NOT EXISTS security_event_ip_idx ON security_event (client_ip, ts DESC);

CREATE TABLE IF NOT EXISTS incident_note (
    id          bigserial PRIMARY KEY,
    incident_id bigint NOT NULL REFERENCES security_event (id),
    ts          timestamptz NOT NULL DEFAULT now(),
    author      text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('note', 'status', 'assignment', 'blocklist', 'recurrence')),
    body        text NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_note_incident_idx ON incident_note (incident_id, ts);

-- ---------------------------------------------------------------- alerts
CREATE TABLE IF NOT EXISTS security_alert (
    id              bigserial PRIMARY KEY,
    ts              timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    category        text NOT NULL,
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    title           text NOT NULL,
    description     text NOT NULL,
    incident_id     bigint REFERENCES security_event (id),
    dedup_key       text NOT NULL,
    occurrences     integer NOT NULL DEFAULT 1,
    status          text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    delivery        text NOT NULL DEFAULT 'none',   -- none | sent | logged | failed | suppressed
    is_read         boolean NOT NULL DEFAULT false,
    acknowledged_by text,
    resolved_by     text,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_alert_status_idx ON security_alert (status, ts DESC);
CREATE INDEX IF NOT EXISTS security_alert_dedup_idx ON security_alert (dedup_key, status);

-- ---------------------------------------------------------------- audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    actor       text,
    actor_role  text,
    action      text NOT NULL,
    resource    text,
    client_ip   text,
    result      text NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_idx ON audit_log (action, ts DESC);

-- Audit rows can be added, never changed or removed, whoever is connected.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- ---------------------------------------------------------------- DLP access trail
-- Field names only. Values are never stored.
CREATE TABLE IF NOT EXISTS dlp_access (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    username    text NOT NULL,
    role        text NOT NULL,
    customer_id integer,
    fields      text[] NOT NULL DEFAULT '{}',
    access_type text NOT NULL CHECK (access_type IN ('search', 'masked_view', 'reveal', 'reveal_denied', 'sample')),
    authorized  boolean NOT NULL,
    row_count   integer NOT NULL DEFAULT 0,
    client_ip   text
);
CREATE INDEX IF NOT EXISTS dlp_access_ts_idx ON dlp_access (ts DESC);

-- ---------------------------------------------------------------- blocklist
CREATE TABLE IF NOT EXISTS blocked_source (
    ip          text PRIMARY KEY,
    reason      text NOT NULL,
    incident_id bigint REFERENCES security_event (id),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    active      boolean NOT NULL DEFAULT true,
    removed_by  text,
    removed_at  timestamptz
);

-- ---------------------------------------------------------------- policies and rule state
CREATE TABLE IF NOT EXISTS security_policy (
    key         text PRIMARY KEY,
    value       integer NOT NULL,
    updated_by  text,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rule_state (
    rule_id     text PRIMARY KEY,
    enabled     boolean NOT NULL,
    updated_by  text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- simulation lab
CREATE TABLE IF NOT EXISTS simulation_run (
    id            bigserial PRIMARY KEY,
    ts            timestamptz NOT NULL DEFAULT now(),
    username      text NOT NULL,
    category      text NOT NULL,
    target        text NOT NULL,
    payload       text NOT NULL,
    score         integer NOT NULL,
    verdict       text NOT NULL,
    would_block   boolean NOT NULL,
    rule_ids      text[] NOT NULL DEFAULT '{}',
    analysis      jsonb NOT NULL DEFAULT '{}'::jsonb,
    duration_us   integer NOT NULL
);
CREATE INDEX IF NOT EXISTS simulation_run_ts_idx ON simulation_run (ts DESC);

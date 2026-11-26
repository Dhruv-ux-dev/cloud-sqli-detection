"""Database bootstrap, migrations and the runtime connection pool.

Two identities are used:
  * the bootstrap login (RDS master user, from Secrets Manager on AWS) applies
    migrations, owns the login function and creates the runtime role, then
    disconnects;
  * the runtime role (qg_app) serves every request. It can read customers,
    write logs and manage incident workflow, and nothing else: no DDL, no
    DELETE anywhere, no read access to password hashes, no way to edit or
    remove audit records. Its password is derived from SECRET_KEY, so nothing
    extra has to be stored.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from importlib import resources

import bcrypt
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import seed_data
from .config import Settings

log = logging.getLogger("queryguard.db")

_pool: ConnectionPool | None = None

# Runtime role privileges, re-applied at every start so they always match
# the code. {r} is the runtime role.
GRANTS = (
    "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {r}",
    "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {r}",
    "GRANT USAGE ON SCHEMA public TO {r}",
    "GRANT SELECT ON customers TO {r}",
    # Users: read everything except the hash; write the hash but never read it.
    "GRANT SELECT (id, username, role, created_at, display_name, is_active, last_login_at, session_epoch) ON users TO {r}",
    "GRANT INSERT (username, password_hash, role, display_name) ON users TO {r}",
    "GRANT UPDATE (role, display_name, is_active, last_login_at, session_epoch, password_hash) ON users TO {r}",
    "GRANT SELECT, INSERT ON request_log, dlp_access, simulation_run, incident_note TO {r}",
    "GRANT SELECT, INSERT, UPDATE ON security_event, security_alert, blocked_source TO {r}",
    "GRANT SELECT, INSERT, UPDATE ON security_policy, rule_state TO {r}",
    # Audit log: append and read only (a trigger also blocks UPDATE/DELETE).
    "GRANT SELECT, INSERT ON audit_log TO {r}",
    "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {r}",
    "REVOKE ALL ON FUNCTION auth_lookup(text) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION auth_lookup(text) TO {r}",
)


def _admin_credentials(s: Settings) -> tuple[str, str]:
    if s.db_admin_secret_arn:
        import boto3

        client = boto3.client("secretsmanager", region_name=s.aws_region)
        secret = json.loads(client.get_secret_value(SecretId=s.db_admin_secret_arn)["SecretString"])
        return secret["username"], secret["password"]
    assert s.db_admin_user and s.db_admin_password
    return s.db_admin_user, s.db_admin_password


def app_role_password(s: Settings) -> str:
    return hmac.new(s.secret_key.encode(), b"qg-db-app-role", hashlib.sha256).hexdigest()


def _conninfo(s: Settings, user: str, password: str) -> str:
    return make_conninfo(
        host=s.db_host,
        port=s.db_port,
        dbname=s.db_name,
        user=user,
        password=password,
        sslmode=s.db_sslmode,
        connect_timeout=10,
        application_name="queryguard",
    )


def migration_files() -> list[tuple[str, str]]:
    folder = resources.files("queryguard").joinpath("migrations")
    files = sorted(p for p in folder.iterdir() if p.name.endswith(".sql"))
    return [(p.name.removesuffix(".sql"), p.read_text()) for p in files]


def _migrate(conn: psycopg.Connection) -> list[str]:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
               version    text PRIMARY KEY,
               applied_at timestamptz NOT NULL DEFAULT now())"""
    )
    done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    applied = []
    for version, body in migration_files():
        if version in done:
            continue
        conn.execute(body)
        conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
        applied.append(version)
    return applied


def bootstrap(s: Settings) -> None:
    user, password = _admin_credentials(s)
    role = sql.Identifier(s.db_app_role)

    with psycopg.connect(_conninfo(s, user, password)) as conn:
        with conn.transaction():
            # Serialise concurrent start-ups.
            conn.execute("SELECT pg_advisory_xact_lock(531531)")
            applied = _migrate(conn)

            exists = conn.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (s.db_app_role,)
            ).fetchone()
            verb = "ALTER" if exists else "CREATE"
            conn.execute(
                sql.SQL(
                    verb + " ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "CONNECTION LIMIT 30 PASSWORD {}"
                ).format(role, sql.Literal(app_role_password(s)))
            )
            for stmt in GRANTS:
                conn.execute(sql.SQL(stmt).format(r=role))

            _seed_users(conn, s)
            _seed_customers(conn)
    log.info("database bootstrap complete; migrations applied: %s", applied or "none")


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _seed_users(conn: psycopg.Connection, s: Settings) -> None:
    accounts = [
        ("admin", "admin", "Platform administrator", s.admin_password),
        ("analyst", "analyst", "Security analyst", s.analyst_password),
    ]
    if s.viewer_password:
        accounts.append(("viewer", "viewer", "Read-only viewer", s.viewer_password))

    for username, role, display, password in accounts:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = %s", (username,)
        ).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO users (username, password_hash, role, display_name)
                   VALUES (%s, %s, %s, %s)""",
                (username, _hash(password), role, display),
            )
        elif not bcrypt.checkpw(password.encode(), row[0].encode()):
            # Environment password changed (e.g. Terraform re-generated it).
            conn.execute(
                """UPDATE users SET password_hash = %s, session_epoch = session_epoch + 1
                   WHERE username = %s""",
                (_hash(password), username),
            )


def _seed_customers(conn: psycopg.Connection) -> None:
    if conn.execute("SELECT EXISTS (SELECT 1 FROM customers)").fetchone()[0]:
        return
    with conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO customers
               (full_name, email, phone, city, branch, pan, account_no, balance, opened_on)
               VALUES (%(full_name)s, %(email)s, %(phone)s, %(city)s, %(branch)s,
                       %(pan)s, %(account_no)s, %(balance)s, %(opened_on)s)""",
            seed_data.generate(),
        )


def open_pool(s: Settings) -> ConnectionPool:
    global _pool
    _pool = ConnectionPool(
        _conninfo(s, s.db_app_role, app_role_password(s)),
        min_size=1,
        max_size=10,
        kwargs={"autocommit": True, "row_factory": dict_row},
        open=True,
        name="queryguard",
        timeout=5,
    )
    _pool.wait(timeout=30)
    return _pool


def pool() -> ConnectionPool:
    if _pool is None:
        raise RuntimeError("database pool not open")
    return _pool


def close_pool() -> None:
    if _pool is not None:
        _pool.close()

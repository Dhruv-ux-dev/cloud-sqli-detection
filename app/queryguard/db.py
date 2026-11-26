"""Database bootstrap and the runtime connection pool.

Two identities are used:
  * the bootstrap login (RDS master user, from Secrets Manager on AWS) creates
    tables, the login function and the runtime role, then disconnects;
  * the runtime role (qg_app) serves every request. It can read customers,
    write logs, and nothing else: no DDL, no DELETE, no access to password
    hashes. Its password is derived from SECRET_KEY, so nothing extra has to
    be stored anywhere.
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


def bootstrap(s: Settings) -> None:
    user, password = _admin_credentials(s)
    role = sql.Identifier(s.db_app_role)
    schema_sql = resources.files("queryguard").joinpath("schema.sql").read_text()

    with psycopg.connect(_conninfo(s, user, password)) as conn:
        with conn.transaction():
            # Serialise concurrent start-ups.
            conn.execute("SELECT pg_advisory_xact_lock(531531)")
            conn.execute(schema_sql)

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

            for stmt in (
                "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {r}",
                "GRANT USAGE ON SCHEMA public TO {r}",
                "GRANT SELECT ON customers TO {r}",
                "GRANT SELECT (id, username, role, created_at) ON users TO {r}",
                "GRANT SELECT, INSERT ON request_log, security_event TO {r}",
                "GRANT USAGE ON SEQUENCE request_log_id_seq, security_event_id_seq TO {r}",
                "REVOKE ALL ON FUNCTION auth_lookup(text) FROM PUBLIC",
                "GRANT EXECUTE ON FUNCTION auth_lookup(text) TO {r}",
            ):
                conn.execute(sql.SQL(stmt).format(r=role))

            _seed_users(conn, s)
            _seed_customers(conn)
    log.info("database bootstrap complete")


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _seed_users(conn: psycopg.Connection, s: Settings) -> None:
    for username, role, password in (
        ("admin", "admin", s.admin_password),
        ("analyst", "analyst", s.analyst_password),
    ):
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = %s", (username,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, _hash(password), role),
            )
        elif not bcrypt.checkpw(password.encode(), row[0].encode()):
            # Environment password changed (e.g. Terraform re-generated it).
            conn.execute(
                "UPDATE users SET password_hash = %s WHERE username = %s",
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

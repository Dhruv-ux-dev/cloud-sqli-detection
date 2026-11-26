"""Append-only audit trail for security-sensitive actions.

Rows can only be inserted (the runtime role has no UPDATE/DELETE grant and a
trigger rejects both anyway). Never pass passwords, tokens or full PII in
`detail`: field names and identifiers only.
"""

from __future__ import annotations

import json
import logging

from . import db
from .events import emit

log = logging.getLogger("queryguard.audit")

SENSITIVE_KEYS = {"password", "new_password", "token", "secret", "cookie", "session"}


def _scrub(detail: dict) -> dict:
    return {k: ("[redacted]" if k.lower() in SENSITIVE_KEYS else v) for k, v in detail.items()}


def record(
    action: str,
    *,
    actor: str | None,
    actor_role: str | None = None,
    resource: str | None = None,
    client_ip: str | None = None,
    result: str = "success",
    detail: dict | None = None,
) -> int | None:
    detail = _scrub(detail or {})
    emit({"event": "audit", "action": action, "actor": actor, "resource": resource,
          "client_ip": client_ip, "result": result})
    try:
        with db.pool().connection() as conn:
            row = conn.execute(
                """INSERT INTO audit_log (actor, actor_role, action, resource, client_ip, result, detail)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (actor, actor_role, action, resource, client_ip, result,
                 json.dumps(detail, default=str)),
            ).fetchone()
            return row["id"]
    except Exception:
        log.exception("could not write audit_log")
        return None

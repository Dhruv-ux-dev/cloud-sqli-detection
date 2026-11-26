"""Users and roles, audit log, security policies and runtime configuration."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from .. import audit, db, policy
from ..config import settings
from ..middleware import request_ip
from ..security import PERMISSIONS, ROLE_LABELS, ROLES, User, hash_password, invalidate_account, require
from .common import Page, audit_ref, paged, paging
from .soc import ANALYST_AUDIT_PREFIXES

router = APIRouter(prefix="/api", tags=["admin"])

USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")


def _check_password(v: str) -> str:
    if len(v) < 12:
        raise ValueError("Use at least 12 characters.")
    if not (re.search(r"[a-z]", v) and re.search(r"[A-Z]", v) and re.search(r"\d", v)):
        raise ValueError("Mix upper-case letters, lower-case letters and digits.")
    return v


# ---------------------------------------------------------------- users

@router.get("/users")
def list_users(user: User = Depends(require("users:manage"))):
    with db.pool().connection() as conn:
        rows = conn.execute(
            """SELECT id, username, display_name, role, is_active, created_at, last_login_at
               FROM users ORDER BY is_active DESC, role, username""").fetchall()
    for r in rows:
        r["role_label"] = ROLE_LABELS[r["role"]]
    return {
        "items": rows,
        "roles": [{"key": r, "label": ROLE_LABELS[r],
                   "permissions": sorted(p for p, roles in PERMISSIONS.items() if r in roles)} for r in ROLES],
    }


@router.get("/users/assignable")
def assignable(_: User = Depends(require("incidents:manage"))):
    with db.pool().connection() as conn:
        rows = conn.execute(
            """SELECT username, display_name, role FROM users
               WHERE is_active AND role IN ('admin', 'analyst') ORDER BY username""").fetchall()
    return {"items": rows}


class NewUser(BaseModel):
    username: str
    display_name: str = Field(min_length=2, max_length=80)
    role: str
    password: str

    @field_validator("username")
    @classmethod
    def _u(cls, v):
        v = v.strip().lower()
        if not USERNAME_RE.match(v):
            raise ValueError("3-32 characters: lower-case letters, digits, dot, dash or underscore; start with a letter.")
        return v

    @field_validator("role")
    @classmethod
    def _r(cls, v):
        if v not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return v

    @field_validator("password")
    @classmethod
    def _p(cls, v):
        return _check_password(v)


@router.post("/users")
def create_user(body: NewUser, request: Request, user: User = Depends(require("users:manage"))):
    with db.pool().connection() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = %s", (body.username,)).fetchone():
            raise HTTPException(409, "That username is taken.")
        row = conn.execute(
            """INSERT INTO users (username, password_hash, role, display_name)
               VALUES (%s, %s, %s, %s) RETURNING id""",
            (body.username, hash_password(body.password), body.role, body.display_name)).fetchone()
    audit.record("user.create", actor=user.username, actor_role=user.role, resource=body.username,
                 client_ip=request_ip(request), detail={"role": body.role})
    return {"ok": True, "id": row["id"]}


class UserUpdate(BaseModel):
    role: str | None = None
    display_name: str | None = Field(None, min_length=2, max_length=80)
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def _r(cls, v):
        if v is not None and v not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return v


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, user: User = Depends(require("users:manage"))):
    with db.pool().connection() as conn:
        with conn.transaction():
            target = conn.execute("SELECT id, username, role, is_active, display_name FROM users WHERE id = %s",
                                  (user_id,)).fetchone()
            if target is None:
                raise HTTPException(404, "No user has that ID.")
            if target["username"] == user.username and (
                    (body.role and body.role != "admin") or body.is_active is False):
                raise HTTPException(400, "You cannot demote or deactivate your own account.")
            changes = {}
            if body.role and body.role != target["role"]:
                changes["role"] = [target["role"], body.role]
            if body.is_active is not None and body.is_active != target["is_active"]:
                changes["is_active"] = [target["is_active"], body.is_active]
            if body.display_name and body.display_name != target["display_name"]:
                changes["display_name"] = True
            if not changes:
                raise HTTPException(400, "Nothing to change.")
            if target["role"] == "admin" and ("role" in changes or body.is_active is False):
                admins = conn.execute("SELECT count(*) AS n FROM users WHERE role = 'admin' AND is_active").fetchone()["n"]
                if admins <= 1:
                    raise HTTPException(400, "This is the last active administrator.")
            conn.execute(
                """UPDATE users SET role = COALESCE(%s, role), display_name = COALESCE(%s, display_name),
                       is_active = COALESCE(%s, is_active),
                       session_epoch = session_epoch + CASE WHEN %s THEN 1 ELSE 0 END
                   WHERE id = %s""",
                (body.role, body.display_name, body.is_active,
                 "role" in changes or "is_active" in changes, user_id))
    invalidate_account(target["username"])
    action = "user.role_change" if "role" in changes else "user.deactivate" if body.is_active is False \
        else "user.activate" if body.is_active else "user.update"
    audit.record(action, actor=user.username, actor_role=user.role, resource=target["username"],
                 client_ip=request_ip(request), detail=changes)
    return {"ok": True}


class PasswordReset(BaseModel):
    password: str
    @field_validator("password")
    @classmethod
    def _p(cls, v):
        return _check_password(v)


@router.post("/users/{user_id}/password")
def reset_password(user_id: int, body: PasswordReset, request: Request,
                   user: User = Depends(require("users:manage"))):
    with db.pool().connection() as conn:
        row = conn.execute(
            """UPDATE users SET password_hash = %s, session_epoch = session_epoch + 1
               WHERE id = %s RETURNING username""", (hash_password(body.password), user_id)).fetchone()
    if row is None:
        raise HTTPException(404, "No user has that ID.")
    invalidate_account(row["username"])
    audit.record("user.password_reset", actor=user.username, actor_role=user.role, resource=row["username"],
                 client_ip=request_ip(request))
    return {"ok": True}


# ---------------------------------------------------------------- audit log

@router.get("/audit")
def audit_log(
    p: Page = Depends(paging),
    action: str | None = Query(None, max_length=60),
    actor: str | None = Query(None, max_length=64),
    result: str | None = Query(None, pattern="^(success|failure|denied)$"),
    q: str | None = Query(None, max_length=100),
    user: User = Depends(require("audit:view")),
):
    full = user.can("audit:view_all")
    params = {"a": f"{action}%" if action else None, "actor": actor, "r": result,
              "q": f"%{q}%" if q else None, "qe": q, "all": full,
              "prefixes": [x + "%" for x in ANALYST_AUDIT_PREFIXES],
              "limit": p.page_size, "offset": p.offset}
    where = """(%(a)s::text IS NULL OR action LIKE %(a)s) AND (%(actor)s::text IS NULL OR actor = %(actor)s)
               AND (%(r)s::text IS NULL OR result = %(r)s)
               AND (%(q)s::text IS NULL OR resource ILIKE %(q)s OR action ILIKE %(q)s OR client_ip = %(qe)s
                    OR actor ILIKE %(q)s)
               AND (%(all)s OR action LIKE ANY(%(prefixes)s))"""
    with db.pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM audit_log WHERE {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"""SELECT id, ts, actor, actor_role, action, resource, client_ip, result, detail
                FROM audit_log WHERE {where} ORDER BY id DESC LIMIT %(limit)s OFFSET %(offset)s""",
            params).fetchall()
        actions = [r["action"] for r in conn.execute(
            f"SELECT DISTINCT action FROM audit_log WHERE (%(all)s OR action LIKE ANY(%(prefixes)s)) ORDER BY 1",
            params)]
    for r in rows:
        r["ref"] = audit_ref(r["id"])
    out = paged(rows, total, p)
    out["actions"] = actions
    out["scope"] = "all" if full else "operational"
    return out


@router.get("/audit/{audit_id}")
def audit_record(audit_id: int, user: User = Depends(require("audit:view"))):
    with db.pool().connection() as conn:
        row = conn.execute(
            """SELECT id, ts, actor, actor_role, action, resource, client_ip, result, detail
               FROM audit_log WHERE id = %(id)s AND (%(all)s OR action LIKE ANY(%(prefixes)s))""",
            {"id": audit_id, "all": user.can("audit:view_all"),
             "prefixes": [x + "%" for x in ANALYST_AUDIT_PREFIXES]}).fetchone()
    if row is None:
        raise HTTPException(404, "No audit record with that ID is visible to your role.")
    row["ref"] = audit_ref(row["id"])
    return row


# ---------------------------------------------------------------- policies

@router.get("/policies")
def get_policies(user: User = Depends(require("policy:view"))):
    values = policy.policies()
    with db.pool().connection() as conn:
        meta = {r["key"]: r for r in conn.execute("SELECT key, updated_by, updated_at FROM security_policy")}
    return {
        "items": [{"key": d.key, "label": d.label, "description": d.description, "value": values[d.key],
                   "default": d.default, "min": d.minimum, "max": d.maximum, "unit": d.unit,
                   "updated_by": meta.get(d.key, {}).get("updated_by"),
                   "updated_at": meta.get(d.key, {}).get("updated_at")} for d in policy.POLICIES],
        "can_manage": user.can("policy:manage"),
    }


class PolicyUpdate(BaseModel):
    values: dict[str, int]
    reason: str = Field(min_length=5, max_length=300)


@router.put("/policies")
def set_policies(body: PolicyUpdate, request: Request, user: User = Depends(require("policy:manage"))):
    current = policy.policies()
    changes = {}
    for key, value in body.values.items():
        d = policy.POLICY_BY_KEY.get(key)
        if d is None:
            raise HTTPException(400, f"Unknown policy {key}.")
        if not d.minimum <= value <= d.maximum:
            raise HTTPException(400, f"{d.label} must be between {d.minimum} and {d.maximum} {d.unit}.")
        if value != current[key]:
            changes[key] = [current[key], value]
    if not changes:
        raise HTTPException(400, "Nothing to change.")
    with db.pool().connection() as conn:
        with conn.transaction():
            for key, (_, value) in changes.items():
                conn.execute(
                    """INSERT INTO security_policy (key, value, updated_by) VALUES (%s, %s, %s)
                       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by,
                           updated_at = now()""", (key, value, user.username))
    policy.invalidate()
    audit.record("policy.update", actor=user.username, actor_role=user.role, resource="security_policy",
                 client_ip=request_ip(request), detail={"changes": changes, "reason": body.reason})
    return get_policies(user)


# ---------------------------------------------------------------- configuration

def _mask_arn(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.split(":")
    if len(parts) > 4:
        parts[4] = "••••" + parts[4][-4:]
    return ":".join(parts)


@router.get("/admin/config")
def config(user: User = Depends(require("config:view"))):
    """Runtime configuration without secrets."""
    return {
        "environment": settings.app_env,
        "waf_mode": settings.waf_mode,
        "trust_proxy": settings.trust_proxy,
        "cookie_secure": settings.cookie_secure,
        "vulnerable_demo": {"requested": settings.enable_vulnerable_demo,
                            "active": settings.vulnerable_demo_active},
        "database": {"host": settings.db_host, "name": settings.db_name, "sslmode": settings.db_sslmode,
                     "runtime_role": settings.db_app_role,
                     "bootstrap_credentials": "Secrets Manager" if settings.db_admin_secret_arn else "environment"},
        "aws": {"region": settings.aws_region, "web_acl": settings.waf_web_acl_name,
                "web_acl_arn": _mask_arn(settings.waf_web_acl_arn),
                "waf_rule_metrics": list(settings.waf_rule_metrics),
                "sns_topic": _mask_arn(settings.sns_topic_arn), "ec2_instance": settings.ec2_instance_id,
                "rds_instance": settings.db_instance_id, "app_log_group": settings.app_log_group,
                "alarm_prefix": settings.alarm_prefix},
        "secrets": {"SECRET_KEY": "set" if settings.secret_key else "missing",
                    "ADMIN_PASSWORD": "set" if settings.admin_password else "missing",
                    "ANALYST_PASSWORD": "set" if settings.analyst_password else "missing",
                    "VIEWER_PASSWORD": "set" if settings.viewer_password else "not set (no viewer account seeded)"},
        "session": {"cookie": "HttpOnly, SameSite=Strict" + (", Secure" if settings.cookie_secure else ""),
                    "lifetime_hours": 8, "revocation": "role change, deactivation and password reset end sessions"},
        "search_row_limit": settings.search_row_limit,
    }

"""Northfield: customer records app and security operations console, protected
by layered SQL injection defences."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import audit, aws_metrics, db, detector, dlp, events, health, policy
from .config import settings
from .middleware import InspectionMiddleware, request_ip
from .routers import admin, detection, incidents, infra, soc, traffic
from .routers import dlp as dlp_router
from .security import (
    ROLE_LABELS,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    User,
    check_password,
    current_user,
    failed_logins,
    invalidate_account,
    issue_session,
    lockouts,
    read_session,
    record_views,
    require,
    require_admin,
    searches,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("queryguard")

STATIC = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate()
    if settings.enable_vulnerable_demo and not settings.vulnerable_demo_active:
        log.warning("ENABLE_VULNERABLE_DEMO ignored: never active when APP_ENV=production")
    for attempt in range(1, 31):
        try:
            db.bootstrap(settings)
            break
        except psycopg.OperationalError as exc:
            log.warning("database not ready (attempt %d/30): %s", attempt, exc)
            time.sleep(2)
    else:
        raise RuntimeError("database never became reachable")
    db.open_pool(settings)
    monitor = asyncio.create_task(health.monitor_loop())
    log.info("Northfield ready, APP_ENV=%s WAF_MODE=%s", settings.app_env, settings.waf_mode)
    yield
    monitor.cancel()
    db.close_pool()


app = FastAPI(title="Northfield", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# Added last, so it runs first: nothing reaches a route before inspection.
app.add_middleware(InspectionMiddleware)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
for r in (soc.router, traffic.router, incidents.router, detection.router, dlp_router.router, admin.router,
          infra.router):
    app.include_router(r)


@app.exception_handler(StarletteHTTPException)
async def http_errors(request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_errors(request: Request, exc: RequestValidationError):
    # Field locations and messages only: never echo the submitted values back.
    return JSONResponse({"detail": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]}, status_code=422)


@app.exception_handler(Exception)
async def hide_internal_errors(request: Request, exc: Exception):
    # Database error text is exactly what error-based injection fishes for,
    # so it is logged server-side and never returned.
    log.exception("unhandled error on %s", request.url.path)
    if isinstance(exc, psycopg.OperationalError) or exc.__class__.__name__ == "PoolTimeout":
        return JSONResponse({"error": "The database is unreachable. The request was not completed."},
                            status_code=503)
    return JSONResponse({"error": "The server could not complete this request."}, status_code=500)


_ip = request_ip


# ---------------------------------------------------------------- pages

def _session_user(request: Request) -> User | None:
    try:
        return current_user(request)
    except HTTPException:
        return None


@app.get("/", include_in_schema=False)
def login_page(request: Request):
    if _session_user(request):
        return RedirectResponse("/console", status_code=303)
    return FileResponse(STATIC / "login.html")


@app.get("/records", include_in_schema=False)
def records_page(request: Request):
    if not _session_user(request):
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC / "records.html")


@app.get("/console", include_in_schema=False)
def console_page(request: Request):
    if not _session_user(request):
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC / "console.html")


@app.get("/security", include_in_schema=False)
def security_page():
    # The original single-page console now lives inside the SOC console.
    return RedirectResponse("/console#/command-center", status_code=303)


@app.get("/health", include_in_schema=False)
def health_check():
    with db.pool().connection(timeout=3) as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


# ---------------------------------------------------------------- auth

class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


@app.get("/api/config")
def public_config():
    return {"waf_mode": settings.waf_mode, "vulnerable_demo": settings.vulnerable_demo_active,
            "environment": settings.app_env}


@app.post("/api/login")
def login(body: LoginBody, request: Request):
    ip = _ip(request)
    threshold = policy.get("failed_login_threshold")
    if failed_logins.count(ip) >= threshold * 2:
        audit.record("auth.login", actor=body.username[:64], client_ip=ip, result="denied",
                     detail={"reason": "ip locked out after repeated failures"})
        raise HTTPException(429, "Too many failed sign-ins from this address. Try again in a few minutes.")

    with db.pool().connection() as conn:
        row = conn.execute("SELECT * FROM auth_lookup(%s)", (body.username,)).fetchone()

    valid = check_password(body.password, row["password_hash"] if row else None)
    if not valid or not row["is_active"]:
        fails = failed_logins.hit(ip)
        audit.record("auth.login", actor=body.username[:64], client_ip=ip, result="failure",
                     detail={"reason": "inactive account" if valid else "bad credentials"})
        if fails == threshold:
            events.raise_incident(
                "brute_force", "medium",
                f"{fails} failed sign-ins from {ip} within {policy.get('window_seconds') // 60} minutes",
                client_ip=ip, endpoint="/api/login", detail={"last_username": body.username[:64]},
            )
        raise HTTPException(401, "Username or password is incorrect.")

    failed_logins.reset(ip)
    with db.pool().connection() as conn:
        conn.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (row["id"],))
    invalidate_account(row["username"])
    user = User(username=row["username"], role=row["role"], id=row["id"], epoch=row["session_epoch"])
    audit.record("auth.login", actor=user.username, actor_role=user.role, client_ip=ip)
    response = JSONResponse({"username": user.username, "role": user.role, "home": "/console"})
    response.set_cookie(
        SESSION_COOKIE, issue_session(user), max_age=SESSION_MAX_AGE,
        httponly=True, samesite="strict", secure=settings.cookie_secure,
    )
    return response


@app.post("/api/logout")
def logout(request: Request):
    user = read_session(request.cookies.get(SESSION_COOKIE))
    if user:
        audit.record("auth.logout", actor=user.username, actor_role=user.role, client_ip=_ip(request))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username, "role": user.role, "role_label": ROLE_LABELS[user.role],
            "display_name": user.display_name, "permissions": user.permissions,
            "environment": settings.app_env, "waf_mode": settings.waf_mode}


# ---------------------------------------------------------------- records

def _check_lockout(user: User) -> None:
    left = lockouts.remaining(user.username)
    if left:
        raise HTTPException(
            429, f"Record access is paused for {left // 60 + 1} min after unusually heavy use."
        )


def _bulk_guard(counter, user: User, ip: str, limit: int, what: str) -> None:
    hits = counter.hit(user.username)
    if hits > limit:
        lock_s = policy.get("lockout_seconds")
        lockouts.lock(user.username, lock_s)
        events.raise_incident(
            "bulk_access", "high",
            f"{user.username} made {hits} {what} within {policy.get('window_seconds') // 60} minutes; "
            f"access paused for {lock_s // 60} minutes",
            client_ip=ip, username=user.username, endpoint="/api/customers",
            detail={"what": what, "count": hits},
        )
        counter.reset(user.username)
        _check_lockout(user)


@app.get("/api/customers")
def search_customers(
    request: Request,
    q: str = Query(min_length=2, max_length=64),
    user: User = Depends(require("records:search")),
):
    _check_lockout(user)
    ip = _ip(request)
    _bulk_guard(searches, user, ip, policy.get("search_threshold"), "searches")

    term = f"%{dlp.escape_like(q.strip())}%"
    limit = settings.search_row_limit
    with db.pool().connection() as conn:
        rows = conn.execute(
            """SELECT id, full_name, email, city, branch, account_no
               FROM customers
               WHERE full_name ILIKE %(t)s OR city ILIKE %(t)s OR branch ILIKE %(t)s
               ORDER BY full_name
               LIMIT %(n)s""",
            {"t": term, "n": limit + 1},
        ).fetchall()
    shown = rows[:limit]
    dlp.record_access(user.username, user.role, "search", authorized=True, fields=["email", "account_no"],
                      row_count=len(shown), client_ip=ip)
    return {
        "results": [dlp.summary_row(r) for r in shown],
        "limit": limit,
        "truncated": len(rows) > limit,
    }


@app.get("/api/customers/{customer_id}")
def customer_detail(
    customer_id: int,
    request: Request,
    reveal: bool = False,
    user: User = Depends(require("records:search")),
):
    _check_lockout(user)
    ip = _ip(request)
    _bulk_guard(record_views, user, ip, policy.get("record_view_threshold"), "record views")

    fields = ["email", "phone", "pan", "account_no", "balance"]
    if reveal and not user.can("dlp:reveal"):
        dlp.record_access(user.username, user.role, "reveal_denied", authorized=False,
                          customer_id=customer_id, fields=fields, client_ip=ip)
        audit.record("dlp.reveal", actor=user.username, actor_role=user.role,
                     resource=f"customer:{customer_id}", client_ip=ip, result="denied")
        events.raise_incident(
            "unauthorized_action", "medium",
            f"{user.username} ({user.role}) tried to reveal unmasked details of customer {customer_id}",
            client_ip=ip, username=user.username, endpoint=f"/api/customers/{customer_id}",
            detail={"customer_id": customer_id})
        raise HTTPException(403, "Only administrators can see unmasked details.")

    with db.pool().connection() as conn:
        row = conn.execute(
            """SELECT id, full_name, email, phone, city, branch, pan, account_no,
                      balance, opened_on
               FROM customers WHERE id = %s""",
            (customer_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "No customer has that ID.")

    dlp.record_access(user.username, user.role, "reveal" if reveal else "masked_view", authorized=True,
                      customer_id=customer_id, fields=fields, client_ip=ip)
    if reveal:
        audit.record("dlp.reveal", actor=user.username, actor_role=user.role,
                     resource=f"customer:{customer_id}", client_ip=ip, detail={"fields": fields})
        events.raise_incident(
            "pii_reveal", "informational", f"{user.username} viewed unmasked details of customer {customer_id}",
            client_ip=ip, username=user.username, endpoint=f"/api/customers/{customer_id}",
            detail={"customer_id": customer_id}, alert=False,
        )
    return dlp.detail_row(row, reveal=reveal)


# ---------------------------------------------------------------- original overview (kept for compatibility)

RANGES = {1: 120, 6: 900, 24: 3600, 168: 6 * 3600}


@app.get("/api/admin/overview")
def admin_overview(hours: int = 24, _: User = Depends(require_admin)):
    if hours not in RANGES:
        raise HTTPException(400, f"hours must be one of {sorted(RANGES)}")
    bucket = RANGES[hours]
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    p = {"start": start, "bucket": bucket}

    with db.pool().connection() as conn:
        totals = {r["verdict"]: r["n"] for r in conn.execute(
            "SELECT verdict, count(*) AS n FROM request_log WHERE ts >= %(start)s GROUP BY verdict", p)}
        timeline_rows = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS bucket,
                      verdict, count(*) AS n
               FROM request_log WHERE ts >= %(start)s
               GROUP BY 1, 2""", p).fetchall()
        ribbon = conn.execute(
            """SELECT extract(epoch FROM ts)::float AS t, verdict, method, path, client_ip, status
               FROM request_log WHERE ts >= %(start)s
               ORDER BY ts DESC LIMIT 480""", p).fetchall()
        flagged = conn.execute(
            """SELECT id, ts, client_ip, method, path, status, verdict, source, score,
                      rule_ids, sample, username
               FROM request_log WHERE ts >= %(start)s AND verdict <> 'normal'
               ORDER BY ts DESC LIMIT 60""", p).fetchall()
        top_ips = conn.execute(
            """SELECT client_ip, count(*) AS n,
                      count(*) FILTER (WHERE verdict = 'blocked') AS blocked
               FROM request_log WHERE ts >= %(start)s AND verdict <> 'normal'
               GROUP BY client_ip ORDER BY n DESC LIMIT 6""", p).fetchall()
        top_rules = conn.execute(
            """SELECT r AS rule_id, count(*) AS n
               FROM request_log, unnest(rule_ids) AS r
               WHERE ts >= %(start)s GROUP BY r ORDER BY n DESC LIMIT 8""", p).fetchall()
        incidents_rows = conn.execute(
            """SELECT id, ts, kind, severity, client_ip, username, summary, alert
               FROM security_event WHERE ts >= %(start)s
               ORDER BY ts DESC LIMIT 30""", p).fetchall()

    waf = aws_metrics.waf_overview(start, end, bucket)

    first_bucket = int(start.timestamp()) // bucket * bucket
    series = {b: {"t": b, "normal": 0, "suspicious": 0, "blocked": 0, "waf_blocked": 0}
              for b in range(first_bucket, int(end.timestamp()) + 1, bucket)}
    for r in timeline_rows:
        if r["bucket"] in series:
            series[r["bucket"]][r["verdict"]] = r["n"]
    for b, n in waf.get("timeline", {}).items():
        if b in series:
            series[b]["waf_blocked"] += n

    normal = totals.get("normal", 0)
    suspicious = totals.get("suspicious", 0)
    app_blocked = totals.get("blocked", 0)
    waf_blocked = waf.get("blocked", 0) if waf.get("available") else 0

    for r in top_rules:
        rule = detector.RULES_BY_ID.get(r["rule_id"])
        r["description"] = rule.description if rule else r["rule_id"]

    return {
        "mode": settings.waf_mode,
        "hours": hours,
        "bucket_seconds": bucket,
        "generated_at": end.isoformat(),
        "totals": {
            "total": normal + suspicious + app_blocked + waf_blocked,
            "normal": normal,
            "suspicious": suspicious,
            "blocked": app_blocked + waf_blocked,
            "blocked_by_app": app_blocked,
            "blocked_by_waf": waf_blocked,
        },
        "timeline": list(series.values()),
        "ribbon": list(reversed(ribbon)),
        "flagged": flagged,
        "top_ips": top_ips,
        "top_rules": top_rules,
        "incidents": incidents_rows,
        "waf": {k: v for k, v in waf.items() if k != "timeline"},
    }


# ---------------------------------------------------------------- unsafe demo

if settings.vulnerable_demo_active:
    @app.get("/api/demo/unsafe-search")
    def unsafe_search(q: str, _: User = Depends(require("simulation:run"))):
        """Deliberately vulnerable: string-built SQL. For the controlled demo only,
        never registered when APP_ENV=production.

        It runs as the least-privilege role, so even a successful injection
        cannot drop tables or read password hashes, but it can read every
        customer column, which is the data leak the other layers prevent.
        """
        query = f"SELECT id, full_name, city FROM customers WHERE full_name ILIKE '%{q}%' LIMIT 50"
        try:
            with db.pool().connection() as conn:
                cur = conn.execute(query)
                rows = cur.fetchall() if cur.description else []
            return {"query": query, "rows": rows}
        except psycopg.Error as exc:
            return JSONResponse({"query": query, "database_error": str(exc).strip()}, status_code=400)

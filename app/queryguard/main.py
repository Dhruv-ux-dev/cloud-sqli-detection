"""QueryGuard: customer records app protected by layered SQL injection defences."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import aws_metrics, db, detector, dlp, events
from .config import settings
from .middleware import InspectionMiddleware, client_ip
from .security import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    User,
    check_password,
    current_user,
    failed_logins,
    issue_session,
    lockouts,
    read_session,
    record_views,
    require_admin,
    searches,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("queryguard")

STATIC = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate()
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
    log.info("QueryGuard ready, WAF_MODE=%s", settings.waf_mode)
    yield
    db.close_pool()


app = FastAPI(title="QueryGuard", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# Added last, so it runs first: nothing reaches a route before inspection.
app.add_middleware(InspectionMiddleware)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.exception_handler(Exception)
async def hide_internal_errors(request: Request, exc: Exception):
    # Database error text is exactly what error-based injection fishes for,
    # so it is logged server-side and never returned.
    log.exception("unhandled error on %s", request.url.path)
    return JSONResponse({"error": "The server could not complete this request."}, status_code=500)


def _ip(request: Request) -> str:
    headers = {k.lower(): v for k, v in request.headers.items()}
    return client_ip(request.scope, headers)


# ---------------------------------------------------------------- pages

@app.get("/", include_in_schema=False)
def login_page(request: Request):
    if read_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/records", status_code=303)
    return FileResponse(STATIC / "login.html")


@app.get("/records", include_in_schema=False)
def records_page(request: Request):
    if not read_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC / "records.html")


@app.get("/security", include_in_schema=False)
def security_page(request: Request):
    user = read_session(request.cookies.get(SESSION_COOKIE))
    if not user:
        return RedirectResponse("/", status_code=303)
    if not user.is_admin:
        return RedirectResponse("/records", status_code=303)
    return FileResponse(STATIC / "security.html")


@app.get("/health", include_in_schema=False)
def health():
    with db.pool().connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok"}


# ---------------------------------------------------------------- auth

class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


@app.get("/api/config")
def public_config():
    return {"waf_mode": settings.waf_mode, "vulnerable_demo": settings.enable_vulnerable_demo}


@app.post("/api/login")
def login(body: LoginBody, request: Request):
    ip = _ip(request)
    if failed_logins.count(ip) >= settings.failed_login_threshold * 2:
        raise HTTPException(429, "Too many failed sign-ins from this address. Try again in a few minutes.")

    with db.pool().connection() as conn:
        row = conn.execute("SELECT * FROM auth_lookup(%s)", (body.username,)).fetchone()

    if not check_password(body.password, row["password_hash"] if row else None):
        fails = failed_logins.hit(ip)
        if fails == settings.failed_login_threshold:
            events.raise_incident(
                "brute_force", "medium",
                f"{fails} failed sign-ins from {ip} within {settings.window_seconds // 60} minutes",
                client_ip=ip, detail={"last_username": body.username[:64]},
            )
        raise HTTPException(401, "Username or password is incorrect.")

    failed_logins.reset(ip)
    user = User(username=row["username"], role=row["role"])
    response = JSONResponse({"username": user.username, "role": user.role,
                             "home": "/security" if user.is_admin else "/records"})
    response.set_cookie(
        SESSION_COOKIE, issue_session(user), max_age=SESSION_MAX_AGE,
        httponly=True, samesite="strict", secure=settings.cookie_secure,
    )
    return response


@app.post("/api/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username, "role": user.role}


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
        lockouts.lock(user.username, settings.lockout_seconds)
        events.raise_incident(
            "bulk_access", "high",
            f"{user.username} made {hits} {what} within {settings.window_seconds // 60} minutes; "
            f"access paused for {settings.lockout_seconds // 60} minutes",
            client_ip=ip, username=user.username, detail={"what": what, "count": hits},
        )
        counter.reset(user.username)
        _check_lockout(user)


@app.get("/api/customers")
def search_customers(
    request: Request,
    q: str = Query(min_length=2, max_length=64),
    user: User = Depends(current_user),
):
    _check_lockout(user)
    _bulk_guard(searches, user, _ip(request), settings.search_threshold, "searches")

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
    return {
        "results": [dlp.summary_row(r) for r in rows[:limit]],
        "limit": limit,
        "truncated": len(rows) > limit,
    }


@app.get("/api/customers/{customer_id}")
def customer_detail(
    customer_id: int,
    request: Request,
    reveal: bool = False,
    user: User = Depends(current_user),
):
    _check_lockout(user)
    ip = _ip(request)
    _bulk_guard(record_views, user, ip, settings.record_view_threshold, "record views")

    if reveal and not user.is_admin:
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

    if reveal:
        events.raise_incident(
            "pii_reveal", "low", f"{user.username} viewed unmasked details of customer {customer_id}",
            client_ip=ip, username=user.username, detail={"customer_id": customer_id}, alert=False,
        )
    return dlp.detail_row(row, reveal=reveal)


# ---------------------------------------------------------------- admin

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
        incidents = conn.execute(
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
        "incidents": incidents,
        "waf": {k: v for k, v in waf.items() if k != "timeline"},
    }


# ---------------------------------------------------------------- unsafe demo

if settings.enable_vulnerable_demo:
    @app.get("/api/demo/unsafe-search")
    def unsafe_search(q: str, _: User = Depends(current_user)):
        """Deliberately vulnerable: string-built SQL. For the controlled demo only.

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

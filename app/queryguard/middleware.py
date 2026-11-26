"""ASGI middleware that inspects every request before the app sees it.

Order of checks for each HTTP request:
  1. administrator blocklist            -> 403 (source "blocklist")
  2. SQL injection detector             -> 403 when the score reaches the block
                                           threshold (unless WAF_MODE=off)
  3. per-IP API rate limit              -> 429 + unusual-traffic incident
  4. CSRF header on state-changing API calls -> 403
  5. the route handler

Written as plain ASGI (not BaseHTTPMiddleware) so the request body can be
read once, inspected, and replayed to the route handler unchanged.
"""

from __future__ import annotations

import json
import secrets
import time
from urllib.parse import parse_qsl, urlencode

import anyio
from starlette.requests import Request, cookie_parser

from . import detector, events, policy
from .config import settings
from .security import CSRF_HEADER, SESSION_COOKIE, api_requests, attack_counter, read_session

MAX_BODY = 1_000_000
QUIET_PREFIXES = ("/static/", "/health", "/api/soc/", "/api/admin/", "/api/traffic", "/api/alerts",
                  "/api/infra", "/api/me", "/favicon")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SENSITIVE_FIELD_WORDS = ("password", "token", "secret", "cookie", "session", "authorization")
# A blocked request matching any of these opens a critical incident.
CRITICAL_RULES = {"SQLI-STACKED", "SQLI-DDL", "SQLI-DANGER-FN", "SQLI-TIME"}


def client_ip(scope: dict, headers: dict[str, str]) -> str:
    if settings.trust_proxy and headers.get("x-forwarded-for"):
        # The ALB appends the address it saw as the last entry; anything to
        # the left of it was supplied by the client and cannot be trusted.
        return headers["x-forwarded-for"].split(",")[-1].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"


def request_ip(request: Request) -> str:
    return client_ip(request.scope, {k.lower(): v for k, v in request.headers.items()})


def _is_sensitive(field_name: str) -> bool:
    lowered = field_name.lower()
    return any(word in lowered for word in SENSITIVE_FIELD_WORDS)


def request_fields(scope: dict, headers: dict[str, str], body: bytes) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = [("path", scope.get("path", ""))]

    query = scope.get("query_string", b"").decode("latin-1")
    for key, value in parse_qsl(query, keep_blank_values=True):
        fields.append(("query.key", key))
        fields.append((f"query.{key}", value))

    if body:
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()
        text = body[:65536].decode("utf-8", errors="replace")
        if ctype == "application/json":
            try:
                fields.extend(detector.flatten_json(json.loads(text)))
            except ValueError:
                fields.append(("body", text))
        elif ctype == "application/x-www-form-urlencoded":
            for key, value in parse_qsl(text, keep_blank_values=True):
                fields.append(("form.key", key))
                fields.append((f"form.{key}", value))
        else:
            fields.append(("body", text))

    if "user-agent" in headers:
        fields.append(("header:user-agent", headers["user-agent"]))
    return fields


def query_preview(scope: dict) -> str | None:
    """The query string with sensitive parameters replaced, truncated."""
    query = scope.get("query_string", b"").decode("latin-1")
    if not query:
        return None
    pairs = [(k, "[redacted]" if _is_sensitive(k) else v)
             for k, v in parse_qsl(query, keep_blank_values=True)]
    return urlencode(pairs)[:500]


def stored_matches(result: detector.Inspection) -> list[dict]:
    out = []
    for m in result.matches:
        snippet = "[redacted: sensitive field]" if _is_sensitive(m.field) else m.snippet[:200]
        out.append({"rule_id": m.rule_id, "field": m.field, "snippet": snippet, "decoded": m.decoded})
    return out


def stored_sample(result: detector.Inspection) -> str | None:
    if not result.matches:
        return None
    best = max(result.matches, key=lambda m: detector.RULES_BY_ID[m.rule_id].weight)
    if _is_sensitive(best.field):
        return f"{best.field}: [redacted: sensitive field]"
    return f"{best.field}: {best.snippet}"[:300]


class InspectionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}

        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            if len(body) > MAX_BODY:
                await _json(send, 413, {"error": "Request body is too large."})
                return
            if not message.get("more_body"):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        path = scope.get("path", "")
        method = scope.get("method", "GET")
        ip = client_ip(scope, headers)
        cookies = cookie_parser(headers.get("cookie", ""))
        user = read_session(cookies.get(SESSION_COOKIE))

        disabled = await anyio.to_thread.run_sync(policy.disabled_rules)
        result = detector.inspect_fields(request_fields(scope, headers, body), disabled)
        ctx = {"ip": ip, "user": user, "result": result, "headers": headers, "started": started,
               "category": detector.categorize(result, path), "scope": scope}

        blocked_ips = await anyio.to_thread.run_sync(policy.blocked_ips)
        if ip in blocked_ips:
            await _json(send, 403, {"error": "Requests from this address are blocked by an administrator.",
                                    "blocked_by": "administrator blocklist"})
            await self._record(ctx, status=403, source="blocklist", force_verdict="blocked")
            return

        if result.verdict == "blocked" and settings.waf_mode != "off":
            source = "waf-emulated" if settings.waf_mode == "emulated" else "app"
            await _json(send, 403, {
                "error": "Request rejected: it matched SQL injection rules.",
                "blocked_by": "WAF (local emulation)" if source == "waf-emulated" else "application filter",
                "reference": secrets.token_hex(4),
            })
            await self._record(ctx, status=403, source=source)
            return

        if path.startswith("/api/"):
            hits = api_requests.hit(ip)
            limit = await anyio.to_thread.run_sync(policy.get, "api_rate_limit")
            if hits > limit:
                await _json(send, 429, {"error": "Too many requests from this address. Slow down and retry shortly."})
                await self._record(ctx, status=429, source="rate-limit")
                if hits == limit + 1 or hits % limit == 0:
                    await anyio.to_thread.run_sync(lambda: events.raise_incident(
                        "unusual_traffic", "medium",
                        f"{ip} exceeded the API rate limit ({limit} requests per window)",
                        client_ip=ip, username=user.username if user else None, endpoint=path,
                        detail={"requests_in_window": hits, "limit": limit}))
                return

            if method in UNSAFE_METHODS and headers.get(CSRF_HEADER) != "1":
                await _json(send, 403, {"error": "Missing request header. Reload the page and try again."})
                await self._record(ctx, status=403, source="app")
                return

        status = 500

        async def capture(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, replay, capture)
        finally:
            await self._record(ctx, status=status, source="app")

    async def _record(self, ctx: dict, *, status: int, source: str, force_verdict: str | None = None):
        scope, result, ip, user = ctx["scope"], ctx["result"], ctx["ip"], ctx["user"]
        path = scope.get("path", "")
        verdict = force_verdict or result.verdict
        if verdict == "normal" and path.startswith(QUIET_PREFIXES) and status < 400:
            return
        row = {
            "client_ip": ip,
            "method": scope.get("method", "GET"),
            "path": path[:300],
            "status": status,
            "verdict": verdict,
            "source": source,
            "score": result.score,
            "rule_ids": result.rule_ids,
            "sample": stored_sample(result),
            "username": user.username if user else None,
            "latency_ms": int((time.perf_counter() - ctx["started"]) * 1000),
            "user_agent": ctx["headers"].get("user-agent", "")[:200] or None,
            "query_preview": query_preview(scope),
            "category": ctx["category"],
            "matches": stored_matches(result),
        }
        await anyio.to_thread.run_sync(events.record_request, row)

        if result.verdict == "normal":
            return
        username = row["username"]

        if result.verdict == "blocked" and CRITICAL_RULES.intersection(result.rule_ids):
            label = detector.CATEGORY_LABELS.get(ctx["category"] or "", "SQL injection")
            await anyio.to_thread.run_sync(lambda: events.raise_incident(
                "critical_injection", "critical",
                f"{label} from {ip} matched critical rules on {row['method']} {row['path']}",
                client_ip=ip, username=username, endpoint=row["path"],
                detail={"rules": result.rule_ids, "score": result.score, "sample": row["sample"]}))

        hits = attack_counter.hit(ip)
        threshold = await anyio.to_thread.run_sync(policy.get, "repeat_attack_threshold")
        window_min = max(1, (await anyio.to_thread.run_sync(policy.get, "window_seconds")) // 60)
        if hits < threshold:
            return
        # At the threshold (and every 4x after it) write a note; in between,
        # just record continued activity. No open incident (e.g. the last one
        # was resolved) means a new one is opened.
        milestone = hits == threshold or hits % (threshold * 4) == 0
        if milestone or not await anyio.to_thread.run_sync(events.touch_incident, "repeated_injection", ip):
            await anyio.to_thread.run_sync(lambda: events.raise_incident(
                "repeated_injection", "high",
                f"{hits} SQL injection attempts from {ip} within {window_min} minutes",
                client_ip=ip, username=username, endpoint=row["path"],
                detail={"last_rules": result.rule_ids, "last_sample": row["sample"],
                        "last_path": row["path"]}))


async def _json(send, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
        ],
    })
    await send({"type": "http.response.body", "body": body})

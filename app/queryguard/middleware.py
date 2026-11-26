"""ASGI middleware that inspects every request before the app sees it.

Written as plain ASGI (not BaseHTTPMiddleware) so the request body can be
read once, inspected, and replayed to the route handler unchanged.
"""

from __future__ import annotations

import json
import secrets
import time
from urllib.parse import parse_qsl

import anyio
from starlette.requests import cookie_parser

from . import detector, events
from .config import settings
from .security import SESSION_COOKIE, attack_counter, read_session

MAX_BODY = 1_000_000
QUIET_PREFIXES = ("/static/", "/health", "/api/admin/", "/favicon")


def client_ip(scope: dict, headers: dict[str, str]) -> str:
    if settings.trust_proxy and headers.get("x-forwarded-for"):
        # The ALB appends the address it saw as the last entry; anything to
        # the left of it was supplied by the client and cannot be trusted.
        return headers["x-forwarded-for"].split(",")[-1].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"


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

        ip = client_ip(scope, headers)
        cookies = cookie_parser(headers.get("cookie", ""))
        user = read_session(cookies.get(SESSION_COOKIE))
        result = detector.inspect_fields(request_fields(scope, headers, body))

        status = 500
        source = "app"
        if result.verdict == "blocked" and settings.waf_mode != "off":
            source = "waf-emulated" if settings.waf_mode == "emulated" else "app"
            status = 403
            await _json(send, 403, {
                "error": "Request rejected: it matched SQL injection rules.",
                "blocked_by": "WAF (local emulation)" if source == "waf-emulated" else "application filter",
                "reference": secrets.token_hex(4),
            })
        else:
            async def capture(message):
                nonlocal status
                if message["type"] == "http.response.start":
                    status = message["status"]
                await send(message)

            try:
                await self.app(scope, replay, capture)
            finally:
                await self._record(scope, ip, user, result, status, source, started)
            return

        await self._record(scope, ip, user, result, status, source, started)

    async def _record(self, scope, ip, user, result, status, source, started):
        path = scope.get("path", "")
        if result.verdict == "normal" and path.startswith(QUIET_PREFIXES):
            return
        row = {
            "client_ip": ip,
            "method": scope.get("method", "GET"),
            "path": path[:300],
            "status": status,
            "verdict": result.verdict,
            "source": source,
            "score": result.score,
            "rule_ids": result.rule_ids,
            "sample": result.sample,
            "username": user.username if user else None,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
        await anyio.to_thread.run_sync(events.record_request, row)

        if result.verdict != "normal":
            hits = attack_counter.hit(ip)
            threshold = settings.repeat_attack_threshold
            if hits == threshold or (hits > threshold and hits % (threshold * 4) == 0):
                await anyio.to_thread.run_sync(
                    lambda: events.raise_incident(
                        "repeated_injection",
                        "high",
                        f"{hits} SQL injection attempts from {ip} within "
                        f"{settings.window_seconds // 60} minutes",
                        client_ip=ip,
                        username=row["username"],
                        detail={"last_rules": result.rule_ids, "last_sample": result.sample,
                                "last_path": row["path"]},
                    )
                )


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

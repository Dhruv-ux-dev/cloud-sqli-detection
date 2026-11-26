"""Security Command Center, threat analytics, global search and exports."""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from .. import audit, aws_metrics, db, detector, events, health
from ..config import settings
from ..middleware import request_ip
from ..security import User, require
from .common import (RANGES, SEVERITIES, Window, csv_response, empty_series, incident_ref,
                     request_ref, window)

router = APIRouter(prefix="/api", tags=["soc"])

DISTRIBUTION_CATEGORIES = ("union", "boolean", "comment", "time", "auth_bypass", "catalogue", "encoded")
ANALYST_AUDIT_PREFIXES = ("incident.", "alert.", "simulation.", "blocklist.", "detection.", "export.",
                          "dlp.", "authz.")


# ---------------------------------------------------------------- threat level

LEVELS = ((8, "LOW"), (20, "GUARDED"), (40, "ELEVATED"), (65, "HIGH"), (math.inf, "CRITICAL"))
LEVEL_GUIDANCE = {
    "LOW": "No open incidents and little hostile traffic. Normal monitoring.",
    "GUARDED": "Some hostile traffic is being stopped. Review flagged requests when convenient.",
    "ELEVATED": "Active attack traffic or open incidents. Triage the incident queue.",
    "HIGH": "Several serious signals at once. Investigate the top sources now and consider blocking them.",
    "CRITICAL": "Critical incidents are open or an attack is in progress. Respond immediately.",
}


def threat_level(conn) -> dict:
    """Deterministic posture score from the last hour of signals plus open work."""
    sig = conn.execute(
        """SELECT
             count(*) FILTER (WHERE verdict = 'blocked')    AS blocked,
             count(*) FILTER (WHERE verdict = 'suspicious') AS suspicious,
             count(DISTINCT client_ip) FILTER (WHERE verdict <> 'normal') AS attackers
           FROM request_log WHERE ts >= now() - interval '1 hour'"""
    ).fetchone()
    inc = {r["severity"]: r["n"] for r in conn.execute(
        """SELECT severity, count(*) AS n FROM security_event
           WHERE status IN ('new', 'investigating') AND last_seen_at >= now() - interval '24 hours'
           GROUP BY severity""")}
    alerts = conn.execute(
        """SELECT count(*) AS n FROM security_alert
           WHERE status = 'open' AND severity IN ('critical', 'high')"""
    ).fetchone()["n"]

    reasons = []

    def add(signal: str, value, points: float):
        if points > 0:
            reasons.append({"signal": signal, "value": value, "points": round(points, 1)})

    weights = {"critical": 35, "high": 15, "medium": 6, "low": 2}
    for sev, w in weights.items():
        n = inc.get(sev, 0)
        add(f"Open {sev} incidents (last 24 h)", n, n * w)
    add("Requests blocked in the last hour", sig["blocked"], min(20, 4 * math.log2(1 + sig["blocked"])))
    add("Suspicious requests in the last hour", sig["suspicious"],
        min(10, 2 * math.log2(1 + sig["suspicious"])))
    if sig["attackers"] > 1:
        add("Distinct attacking IPs in the last hour", sig["attackers"], min(15, 5 * (sig["attackers"] - 1)))
    add("Unacknowledged critical/high alerts", alerts, min(15, alerts * 5))

    score = min(100.0, sum(r["points"] for r in reasons))
    level = next(name for limit, name in LEVELS if score < limit)
    reasons.sort(key=lambda r: r["points"], reverse=True)
    return {"level": level, "score": round(score), "reasons": reasons, "guidance": LEVEL_GUIDANCE[level],
            "scale": [{"level": n, "below": None if l == math.inf else l} for l, n in LEVELS]}


# ---------------------------------------------------------------- command center

def _pct(cur: float, prev: float) -> float | None:
    if prev == 0:
        return None
    return round((cur - prev) / prev * 100, 1)


@router.get("/soc/overview")
def overview(w: Window = Depends(window), user: User = Depends(require("dashboard:view"))):
    p = {"start": w.start, "prev": w.prev_start, "bucket": w.bucket}
    with db.pool().connection() as conn:
        k = conn.execute(
            """SELECT
                 count(*) FILTER (WHERE ts >= %(start)s) AS total,
                 count(*) FILTER (WHERE ts >= %(start)s AND verdict = 'blocked') AS blocked,
                 count(*) FILTER (WHERE ts >= %(start)s AND verdict = 'suspicious') AS suspicious,
                 count(*) FILTER (WHERE ts >= %(start)s AND verdict = 'normal' AND status < 400) AS successful,
                 count(*) FILTER (WHERE ts < %(start)s) AS p_total,
                 count(*) FILTER (WHERE ts < %(start)s AND verdict = 'blocked') AS p_blocked,
                 count(*) FILTER (WHERE ts < %(start)s AND verdict = 'suspicious') AS p_suspicious,
                 count(*) FILTER (WHERE ts < %(start)s AND verdict = 'normal' AND status < 400) AS p_successful
               FROM request_log WHERE ts >= %(prev)s""", p).fetchone()
        inc = conn.execute(
            """SELECT
                 (SELECT count(*) FROM security_event WHERE status IN ('new', 'investigating')) AS active,
                 count(*) FILTER (WHERE ts >= %(start)s) AS opened,
                 count(*) FILTER (WHERE ts < %(start)s) AS p_opened
               FROM security_event WHERE ts >= %(prev)s AND severity <> 'informational'""", p).fetchone()
        dl = conn.execute(
            """SELECT count(*) FILTER (WHERE ts >= %(start)s) AS cur,
                      count(*) FILTER (WHERE ts < %(start)s) AS prev
               FROM dlp_access WHERE ts >= %(prev)s""", p).fetchone()
        tl_rows = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS b,
                      verdict, (status < 400) AS ok, count(*) AS n
               FROM request_log WHERE ts >= %(start)s GROUP BY 1, 2, 3""", p).fetchall()
        inc_tl = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS b, count(*) AS n
               FROM security_event WHERE ts >= %(start)s AND severity <> 'informational' GROUP BY 1""",
            p).fetchall()
        dlp_tl = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS b, count(*) AS n
               FROM dlp_access WHERE ts >= %(start)s GROUP BY 1""", p).fetchall()
        dist = {r["category"]: r["n"] for r in conn.execute(
            """SELECT category, count(*) AS n FROM request_log
               WHERE ts >= %(start)s AND category IS NOT NULL GROUP BY category""", p)}
        sources = conn.execute(
            """SELECT client_ip, count(*) AS requests,
                      count(*) FILTER (WHERE verdict = 'blocked') AS blocked,
                      count(*) FILTER (WHERE verdict = 'suspicious') AS suspicious,
                      mode() WITHIN GROUP (ORDER BY path) AS top_endpoint,
                      max(ts) AS last_seen
               FROM request_log
               WHERE ts >= %(start)s AND client_ip IN (
                   SELECT client_ip FROM request_log
                   WHERE ts >= %(start)s AND verdict <> 'normal')
               GROUP BY client_ip
               ORDER BY count(*) FILTER (WHERE verdict <> 'normal') DESC, requests DESC
               LIMIT 8""", p).fetchall()
        recent = conn.execute(
            """SELECT id, ts, last_seen_at, kind, category, severity, client_ip, username, endpoint,
                      summary, status, assigned_to, occurrences
               FROM security_event WHERE severity <> 'informational'
               ORDER BY last_seen_at DESC LIMIT 8""").fetchall()
        posture = threat_level(conn)

    waf = aws_metrics.waf_overview(w.start, w.end, w.bucket)
    waf_prev = aws_metrics.waf_overview(w.prev_start, w.start, w.bucket) if waf.get("available") else {}
    waf_blocked = waf.get("blocked", 0) if waf.get("available") else 0
    waf_prev_blocked = waf_prev.get("blocked", 0) if waf_prev.get("available") else 0

    series = empty_series(w, ("normal", "suspicious", "blocked", "waf_blocked", "successful", "incidents", "dlp"))
    for r in tl_rows:
        if r["b"] in series:
            series[r["b"]][r["verdict"]] += r["n"]
            if r["verdict"] == "normal" and r["ok"]:
                series[r["b"]]["successful"] += r["n"]
    for b, n in waf.get("timeline", {}).items():
        if b in series:
            series[b]["waf_blocked"] += n
    for rows, key in ((inc_tl, "incidents"), (dlp_tl, "dlp")):
        for r in rows:
            if r["b"] in series:
                series[r["b"]][key] = r["n"]
    timeline = list(series.values())

    def spark(*keys):
        return [sum(s[k] for k in keys) for s in timeline]

    total = k["total"] + waf_blocked
    p_total = k["p_total"] + waf_prev_blocked
    kpis = [
        {"key": "total", "label": "Total requests", "value": total, "previous": p_total,
         "change_pct": _pct(total, p_total), "spark": spark("normal", "suspicious", "blocked", "waf_blocked"),
         "hint": "Every request that reached the platform in this period, including those AWS WAF blocked "
                 "(when WAF is connected).", "good_direction": None},
        {"key": "blocked", "label": "Blocked requests", "value": k["blocked"] + waf_blocked,
         "previous": k["p_blocked"] + waf_prev_blocked,
         "change_pct": _pct(k["blocked"] + waf_blocked, k["p_blocked"] + waf_prev_blocked),
         "spark": spark("blocked", "waf_blocked"),
         "hint": "Rejected by AWS WAF, the application filter or the administrator blocklist.",
         "good_direction": "down", "split": {"app": k["blocked"], "waf": waf_blocked}},
        {"key": "suspicious", "label": "Suspicious requests", "value": k["suspicious"],
         "previous": k["p_suspicious"], "change_pct": _pct(k["suspicious"], k["p_suspicious"]),
         "spark": spark("suspicious"),
         "hint": "Scored between the suspicious and block thresholds: served, but flagged and counted.",
         "good_direction": "down"},
        {"key": "successful", "label": "Successful requests", "value": k["successful"],
         "previous": k["p_successful"], "change_pct": _pct(k["successful"], k["p_successful"]),
         "spark": spark("successful"), "hint": "Clean requests answered with a 2xx or 3xx status.",
         "good_direction": None},
        {"key": "incidents", "label": "Active incidents", "value": inc["active"], "previous": None,
         "change_pct": None, "opened": inc["opened"], "opened_previous": inc["p_opened"],
         "spark": spark("incidents"),
         "hint": "Incidents in New or Investigating state right now. The comparison counts incidents opened "
                 "in this period versus the previous one.", "good_direction": "down"},
        {"key": "dlp", "label": "Sensitive data access", "value": dl["cur"], "previous": dl["prev"],
         "change_pct": _pct(dl["cur"], dl["prev"]), "spark": spark("dlp"),
         "hint": "Searches, masked record views and full reveals of customer records (field names are "
                 "logged, never values).", "good_direction": None},
    ]

    dist_total = sum(dist.values())
    distribution = [{"category": c, "label": detector.CATEGORY_LABELS[c], "count": dist.get(c, 0),
                     "pct": round(dist.get(c, 0) / dist_total * 100, 1) if dist_total else 0}
                    for c in DISTRIBUTION_CATEGORIES]
    others = {c: n for c, n in dist.items() if c not in DISTRIBUTION_CATEGORIES}
    for c, n in sorted(others.items(), key=lambda kv: -kv[1]):
        distribution.append({"category": c, "label": detector.CATEGORY_LABELS.get(c, c), "count": n,
                             "pct": round(n / dist_total * 100, 1)})

    for r in recent:
        r["ref"] = incident_ref(r["id"])
        r["category_label"] = events.INCIDENT_CATEGORY_LABELS.get(r["category"], r["category"])

    return {
        "generated_at": w.end.isoformat(),
        "hours": w.hours, "bucket_seconds": w.bucket,
        "mode": settings.waf_mode, "environment": settings.app_env,
        "waf_connected": bool(waf.get("available")) and not waf.get("error"),
        "kpis": kpis, "threat": posture, "timeline": timeline, "distribution": distribution,
        "sources": sources, "incidents": recent,
        "health": health.snapshot(),
    }


# ---------------------------------------------------------------- analytics

@router.get("/analytics")
def analytics(w: Window = Depends(window), user: User = Depends(require("analytics:view"))):
    p = {"start": w.start, "bucket": w.bucket}
    with db.pool().connection() as conn:
        trend = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS b, category, count(*) AS n
               FROM request_log WHERE ts >= %(start)s AND category IS NOT NULL GROUP BY 1, 2""", p).fetchall()
        traffic = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS b, verdict, count(*) AS n
               FROM request_log WHERE ts >= %(start)s GROUP BY 1, 2""", p).fetchall()
        endpoints = conn.execute(
            """SELECT path, count(*) AS requests,
                      count(*) FILTER (WHERE verdict <> 'normal') AS flagged,
                      count(*) FILTER (WHERE verdict = 'blocked') AS blocked
               FROM request_log WHERE ts >= %(start)s
               GROUP BY path ORDER BY flagged DESC, requests DESC LIMIT 10""", p).fetchall()
        ips = conn.execute(
            """SELECT client_ip, count(*) AS requests,
                      count(*) FILTER (WHERE verdict = 'blocked') AS blocked,
                      count(*) FILTER (WHERE verdict = 'suspicious') AS suspicious
               FROM request_log WHERE ts >= %(start)s
               GROUP BY client_ip ORDER BY count(*) FILTER (WHERE verdict <> 'normal') DESC, requests DESC
               LIMIT 10""", p).fetchall()
        rules = conn.execute(
            """SELECT r AS rule_id, count(*) AS matches,
                      count(*) FILTER (WHERE verdict = 'blocked') AS in_blocked,
                      count(*) FILTER (WHERE verdict = 'suspicious') AS in_suspicious
               FROM request_log, unnest(rule_ids) AS r
               WHERE ts >= %(start)s GROUP BY r ORDER BY matches DESC""", p).fetchall()
        severities = {r["severity"]: r["n"] for r in conn.execute(
            "SELECT severity, count(*) AS n FROM security_event WHERE ts >= %(start)s GROUP BY 1", p)}
        dlp_rows = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS b, access_type, count(*) AS n
               FROM dlp_access WHERE ts >= %(start)s GROUP BY 1, 2""", p).fetchall()

    cats = sorted({r["category"] for r in trend})
    trend_series = empty_series(w, tuple(cats))
    for r in trend:
        if r["b"] in trend_series:
            trend_series[r["b"]][r["category"]] = r["n"]
    tr = empty_series(w, ("normal", "suspicious", "blocked"))
    for r in traffic:
        if r["b"] in tr:
            tr[r["b"]][r["verdict"]] = r["n"]
    dtypes = ("search", "masked_view", "reveal", "reveal_denied", "sample")
    dl = empty_series(w, dtypes)
    for r in dlp_rows:
        if r["b"] in dl:
            dl[r["b"]][r["access_type"]] = r["n"]
    cat_totals = {}
    for r in trend:
        cat_totals[r["category"]] = cat_totals.get(r["category"], 0) + r["n"]
    for r in rules:
        rule = detector.RULES_BY_ID.get(r["rule_id"])
        r["rule"] = rule.description if rule else r["rule_id"]
        r["weight"] = rule.weight if rule else None

    return {
        "hours": w.hours, "bucket_seconds": w.bucket, "generated_at": w.end.isoformat(),
        "attack_trend": {"categories": [{"key": c, "label": detector.CATEGORY_LABELS.get(c, c)} for c in cats],
                         "series": list(trend_series.values())},
        "categories": [{"category": c, "label": detector.CATEGORY_LABELS.get(c, c), "count": n}
                       for c, n in sorted(cat_totals.items(), key=lambda kv: -kv[1])],
        "traffic": list(tr.values()),
        "top_ips": ips, "top_endpoints": endpoints, "rules": rules,
        "severity": [{"severity": s, "count": severities.get(s, 0)} for s in SEVERITIES],
        "dlp": list(dl.values()),
    }


# ---------------------------------------------------------------- global search

@router.get("/search")
def search(q: str = Query(min_length=2, max_length=100), user: User = Depends(require("dashboard:view"))):
    term = q.strip()
    like = f"%{term}%"
    results: dict[str, list] = {"incidents": [], "requests": [], "rules": [], "audit": [], "alerts": []}
    inc_id = _ref_id(term, "INC")
    req_id = _ref_id(term, "REQ")
    aud_id = _ref_id(term, "AUD")

    with db.pool().connection() as conn:
        results["incidents"] = [
            {"id": r["id"], "ref": incident_ref(r["id"]), "title": r["summary"], "severity": r["severity"],
             "status": r["status"], "ts": r["ts"]}
            for r in conn.execute(
                """SELECT id, summary, severity, status, ts FROM security_event
                   WHERE id = %(id)s OR client_ip = %(t)s OR summary ILIKE %(l)s OR kind ILIKE %(l)s
                         OR endpoint ILIKE %(l)s
                   ORDER BY ts DESC LIMIT 6""", {"id": inc_id or -1, "t": term, "l": like})]
        results["requests"] = [
            {"id": r["id"], "ref": request_ref(r["id"]), "title": f"{r['method']} {r['path']}",
             "verdict": r["verdict"], "client_ip": r["client_ip"], "ts": r["ts"]}
            for r in conn.execute(
                """SELECT id, method, path, verdict, client_ip, ts FROM request_log
                   WHERE id = %(id)s OR client_ip = %(t)s OR path ILIKE %(l)s
                   ORDER BY ts DESC LIMIT 6""", {"id": req_id or -1, "t": term, "l": like})]
        results["alerts"] = [
            {"id": r["id"], "title": r["title"], "severity": r["severity"], "status": r["status"], "ts": r["ts"]}
            for r in conn.execute(
                """SELECT id, title, severity, status, ts FROM security_alert
                   WHERE title ILIKE %(l)s OR description ILIKE %(l)s ORDER BY ts DESC LIMIT 4""", {"l": like})]
        if user.can("audit:view"):
            rows = conn.execute(
                """SELECT id, ts, actor, action, resource, result FROM audit_log
                   WHERE (id = %(id)s OR action ILIKE %(l)s OR actor ILIKE %(l)s OR resource ILIKE %(l)s
                          OR client_ip = %(t)s)
                     AND (%(all)s OR action LIKE ANY(%(prefixes)s))
                   ORDER BY ts DESC LIMIT 6""",
                {"id": aud_id or -1, "l": like, "t": term, "all": user.can("audit:view_all"),
                 "prefixes": [p + "%" for p in ANALYST_AUDIT_PREFIXES]}).fetchall()
            results["audit"] = [{"id": r["id"], "ref": f"AUD-{r['id']:07d}",
                                 "title": f"{r['action']} by {r['actor'] or 'system'}",
                                 "result": r["result"], "ts": r["ts"]} for r in rows]

    lowered = term.lower()
    results["rules"] = [
        {"id": r.id, "title": r.description, "weight": r.weight,
         "category": detector.CATEGORY_LABELS.get(detector.RULE_INFO[r.id]["category"], "")}
        for r in detector.RULES if lowered in r.id.lower() or lowered in r.description.lower()
        or lowered in detector.RULE_INFO[r.id]["category"]][:6]
    return {"query": term, "results": results, "total": sum(len(v) for v in results.values())}


def _ref_id(term: str, prefix: str) -> int | None:
    m = re.fullmatch(rf"(?i){prefix}-?0*(\d{{1,12}})", term)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------- exports

def _export_audit(user: User, request: Request, what: str, detail: dict) -> None:
    audit.record("export." + what, actor=user.username, actor_role=user.role,
                 client_ip=request_ip(request), detail=detail)


@router.get("/export/requests.csv")
def export_requests(request: Request, w: Window = Depends(window),
                    verdict: str | None = Query(None, pattern="^(normal|suspicious|blocked)$"),
                    user: User = Depends(require("reports:export"))):
    with db.pool().connection() as conn:
        rows = conn.execute(
            """SELECT id, ts, client_ip, method, path, status, verdict, source, score,
                      array_to_string(rule_ids, ' '), category, username
               FROM request_log WHERE ts >= %(start)s AND (%(v)s::text IS NULL OR verdict = %(v)s)
               ORDER BY ts DESC LIMIT 50000""", {"start": w.start, "v": verdict}).fetchall()
    _export_audit(user, request, "requests", {"hours": w.hours, "verdict": verdict, "rows": len(rows)})
    return csv_response(f"northfield-requests-{w.hours}h.csv",
                        ["request_id", "time_utc", "source_ip", "method", "endpoint", "status", "verdict",
                         "stopped_by", "score", "rules", "category", "user"],
                        [[request_ref(r["id"]), r["ts"].isoformat(), *list(r.values())[2:]] for r in rows])


@router.get("/export/incidents.csv")
def export_incidents(request: Request, w: Window = Depends(window),
                     user: User = Depends(require("reports:export"))):
    with db.pool().connection() as conn:
        rows = conn.execute(
            """SELECT id, ts, last_seen_at, severity, category, kind, status, client_ip, username, endpoint,
                      occurrences, assigned_to, alert, summary
               FROM security_event WHERE ts >= %(start)s ORDER BY ts DESC LIMIT 20000""",
            {"start": w.start}).fetchall()
    _export_audit(user, request, "incidents", {"hours": w.hours, "rows": len(rows)})
    return csv_response(f"northfield-incidents-{w.hours}h.csv",
                        ["incident_id", "opened_utc", "last_seen_utc", "severity", "category", "kind", "status",
                         "source_ip", "user", "endpoint", "occurrences", "assigned_to", "alert", "summary"],
                        [[incident_ref(r["id"]), r["ts"].isoformat(), r["last_seen_at"].isoformat(),
                          *list(r.values())[3:]] for r in rows])


@router.get("/export/summary.md", response_class=PlainTextResponse)
def export_summary(request: Request, w: Window = Depends(window),
                   user: User = Depends(require("reports:export"))):
    data = analytics(w, user)
    with db.pool().connection() as conn:
        posture = threat_level(conn)
        open_inc = conn.execute(
            """SELECT id, severity, summary FROM security_event
               WHERE status IN ('new', 'investigating') ORDER BY ts DESC LIMIT 15""").fetchall()
    totals = {k: sum(s[k] for s in data["traffic"]) for k in ("normal", "suspicious", "blocked")}
    lines = [
        "# Northfield security activity summary", "",
        f"Period: last {w.hours} hours, ending {w.end:%Y-%m-%d %H:%M} UTC  ",
        f"Environment: {settings.app_env}, WAF mode: {settings.waf_mode}  ",
        f"Generated by: {user.username}", "",
        f"## Threat level: {posture['level']} (score {posture['score']}/100)", "", posture["guidance"], "",
        *[f"- {r['signal']}: {r['value']} (+{r['points']})" for r in posture["reasons"]], "",
        "## Traffic seen by the application", "",
        "| Verdict | Requests |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in totals.items()], "",
        "## Attack categories", "", "| Category | Requests |", "|---|---|",
        *([f"| {c['label']} | {c['count']} |" for c in data["categories"]] or ["| none | 0 |"]), "",
        "## Top attack sources", "", "| Source IP | Requests | Blocked | Suspicious |", "|---|---|---|---|",
        *[f"| {r['client_ip']} | {r['requests']} | {r['blocked']} | {r['suspicious']} |" for r in data["top_ips"]],
        "", "## Detection rules matched", "", "| Rule | Matches | In blocked requests |", "|---|---|---|",
        *[f"| {r['rule_id']} ({r['rule']}) | {r['matches']} | {r['in_blocked']} |" for r in data["rules"]], "",
        "## Open incidents", "",
        *([f"- {incident_ref(i['id'])} [{i['severity']}] {i['summary']}" for i in open_inc] or ["- none"]), "",
        "Note: requests blocked by AWS WAF never reach the application and are not in the tables above; "
        "see the CloudWatch dashboard for WAF totals.", "",
    ]
    _export_audit(user, request, "summary", {"hours": w.hours})
    return PlainTextResponse("\n".join(lines), headers={
        "Content-Disposition": f'attachment; filename="northfield-summary-{w.hours}h.md"'})


@router.get("/ranges")
def ranges(_: User = Depends(require("dashboard:view"))):
    return {"hours": sorted(RANGES)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

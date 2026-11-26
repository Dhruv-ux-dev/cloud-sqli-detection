"""Live traffic monitor: server-side paginated request history and details."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import db, detector
from ..security import User, require
from .common import Page, incident_ref, paged, paging, request_ref

router = APIRouter(prefix="/api/traffic", tags=["traffic"])

REDACTED = "[hidden for your role]"


def _shape(row: dict, user: User) -> dict:
    row["ref"] = request_ref(row["id"])
    row["category_label"] = detector.CATEGORY_LABELS.get(row.get("category") or "", None)
    if not user.can("traffic:payload"):
        if row.get("sample"):
            row["sample"] = REDACTED
        if "query_preview" in row and row["query_preview"]:
            row["query_preview"] = REDACTED
    return row


@router.get("")
def list_traffic(
    p: Page = Depends(paging),
    verdict: str | None = Query(None, pattern="^(normal|suspicious|blocked)$"),
    ip: str | None = Query(None, max_length=64),
    endpoint: str | None = Query(None, max_length=200),
    q: str | None = Query(None, max_length=100),
    since_id: int | None = Query(None, ge=0),
    user: User = Depends(require("traffic:view")),
):
    """Newest first. `since_id` returns only rows newer than that id (for polling)."""
    params = {"v": verdict, "ip": ip, "ep": f"%{endpoint}%" if endpoint else None,
              "q": f"%{q}%" if q else None, "qe": q, "since": since_id,
              "limit": p.page_size, "offset": p.offset}
    where = """(%(v)s::text IS NULL OR verdict = %(v)s)
               AND (%(ip)s::text IS NULL OR client_ip = %(ip)s)
               AND (%(ep)s::text IS NULL OR path ILIKE %(ep)s)
               AND (%(since)s::bigint IS NULL OR id > %(since)s)
               AND (%(q)s::text IS NULL OR path ILIKE %(q)s OR client_ip = %(qe)s
                    OR user_agent ILIKE %(q)s OR sample ILIKE %(q)s OR %(qe)s = ANY(rule_ids))"""
    with db.pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM request_log WHERE {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"""SELECT id, ts, client_ip, method, path, status, verdict, source, score, rule_ids, sample,
                       username, user_agent, category, latency_ms
                FROM request_log WHERE {where}
                ORDER BY id DESC LIMIT %(limit)s OFFSET %(offset)s""", params).fetchall()
        latest = conn.execute("SELECT max(id) AS id FROM request_log").fetchone()["id"]
    out = paged([_shape(r, user) for r in rows], total, p)
    out["latest_id"] = latest
    return out


@router.get("/{request_id}")
def traffic_detail(request_id: int, user: User = Depends(require("traffic:view"))):
    with db.pool().connection() as conn:
        row = conn.execute(
            """SELECT id, ts, client_ip, method, path, status, verdict, source, score, rule_ids, sample,
                      username, user_agent, category, latency_ms, query_preview, matches
               FROM request_log WHERE id = %s""", (request_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "No request has that ID.")
        related = conn.execute(
            """SELECT id, ts, kind, severity, status, summary FROM security_event
               WHERE client_ip = %s AND ts BETWEEN %s - interval '1 hour' AND %s + interval '1 hour'
               ORDER BY ts DESC LIMIT 10""", (row["client_ip"], row["ts"], row["ts"])).fetchall()
        neighbours = conn.execute(
            """SELECT id, ts, method, path, verdict, score FROM request_log
               WHERE client_ip = %s AND id <> %s AND ts BETWEEN %s - interval '30 minutes' AND %s + interval '30 minutes'
               ORDER BY ts LIMIT 40""", (row["client_ip"], row["id"], row["ts"], row["ts"])).fetchall()

    can_see = user.can("traffic:payload")
    explanation = []
    for m in row.pop("matches") or []:
        rule = detector.RULES_BY_ID.get(m["rule_id"])
        info = detector.RULE_INFO.get(m["rule_id"], {})
        explanation.append({
            "rule_id": m["rule_id"], "rule": rule.description if rule else m["rule_id"],
            "weight": rule.weight if rule else 0, "severity": info.get("severity"),
            "category_label": detector.CATEGORY_LABELS.get(info.get("category", ""), ""),
            "explanation": info.get("explanation", ""), "field": m["field"],
            "snippet": m["snippet"] if can_see else REDACTED, "decoded": m.get("decoded", False),
        })
    if not explanation and row["rule_ids"]:
        # Rows logged before per-match details were stored.
        for rid in row["rule_ids"]:
            rule = detector.RULES_BY_ID.get(rid)
            if rule:
                explanation.append({"rule_id": rid, "rule": rule.description, "weight": rule.weight,
                                    "severity": detector.RULE_INFO[rid]["severity"],
                                    "category_label": detector.CATEGORY_LABELS[detector.RULE_INFO[rid]["category"]],
                                    "explanation": detector.RULE_INFO[rid]["explanation"], "field": None,
                                    "snippet": None, "decoded": False})

    result = detector.Inspection(score=row["score"], verdict=row["verdict"])
    reason = detector.verdict_reason(result)
    if row["source"] == "blocklist":
        reason = "The source IP is on the administrator blocklist, so the request was refused before inspection mattered."
    elif row["source"] == "rate-limit":
        reason = "The source exceeded the API rate limit and was answered with 429."
    elif row["verdict"] == "blocked" and row["status"] != 403:
        reason += " Blocking was not enforced because WAF_MODE=off."

    for r in related:
        r["ref"] = incident_ref(r["id"])
    for n in neighbours:
        n["ref"] = request_ref(n["id"])
    return {
        **_shape(row, user),
        "thresholds": {"suspicious": detector.SUSPICIOUS_SCORE, "block": detector.BLOCK_SCORE},
        "explanation": explanation, "reason": reason,
        "related_incidents": related, "related_requests": neighbours,
    }

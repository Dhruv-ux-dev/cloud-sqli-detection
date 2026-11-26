"""Incident management, investigation, the IP blocklist and the alert center."""

from __future__ import annotations

import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from .. import audit, db, detector, events, policy
from ..middleware import request_ip
from ..security import User, require
from .common import INCIDENT_STATUSES, SEVERITIES, Page, incident_ref, paged, paging, request_ref

router = APIRouter(prefix="/api", tags=["incidents"])

SORTS = {"ts": "ts", "last_seen": "last_seen_at", "severity": "array_position(ARRAY['informational','low','medium','high','critical'], severity)",
         "status": "status", "occurrences": "occurrences"}


def _incident_shape(r: dict) -> dict:
    r["ref"] = incident_ref(r["id"])
    r["category_label"] = events.INCIDENT_CATEGORY_LABELS.get(r.get("category"), r.get("category"))
    return r


@router.get("/incidents")
def list_incidents(
    p: Page = Depends(paging),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    category: str | None = Query(None, max_length=40),
    q: str | None = Query(None, max_length=100),
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
    sort: str = Query("last_seen"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    user: User = Depends(require("incidents:view")),
):
    sev = [s for s in (severity or "").split(",") if s] or None
    sts = [s for s in (status or "").split(",") if s] or None
    if sev and not set(sev) <= set(SEVERITIES):
        raise HTTPException(400, "Unknown severity.")
    if sts and not set(sts) <= set(INCIDENT_STATUSES):
        raise HTTPException(400, "Unknown status.")
    if sort not in SORTS:
        raise HTTPException(400, f"sort must be one of {sorted(SORTS)}")
    inc_id = None
    if q and q.upper().startswith("INC-") and q[4:].lstrip("0").isdigit():
        inc_id = int(q[4:])
    params = {"sev": sev, "sts": sts, "cat": category, "q": f"%{q}%" if q else None, "qe": q, "id": inc_id,
              "from": date_from, "to": date_to, "limit": p.page_size, "offset": p.offset}
    where = """(%(sev)s::text[] IS NULL OR severity = ANY(%(sev)s))
               AND (%(sts)s::text[] IS NULL OR status = ANY(%(sts)s))
               AND (%(cat)s::text IS NULL OR category = %(cat)s)
               AND (%(from)s::timestamptz IS NULL OR ts >= %(from)s)
               AND (%(to)s::timestamptz IS NULL OR ts <= %(to)s)
               AND (%(q)s::text IS NULL OR id = %(id)s OR summary ILIKE %(q)s OR client_ip = %(qe)s
                    OR username ILIKE %(q)s OR endpoint ILIKE %(q)s OR assigned_to ILIKE %(q)s)"""
    order_by = f"{SORTS[sort]} {order.upper()}, id DESC"
    with db.pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM security_event WHERE {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"""SELECT id, ts, last_seen_at, kind, category, severity, client_ip, username, endpoint, summary,
                       status, assigned_to, occurrences, alert
                FROM security_event WHERE {where} ORDER BY {order_by}
                LIMIT %(limit)s OFFSET %(offset)s""", params).fetchall()
        counts = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, count(*) AS n FROM security_event GROUP BY status")}
    out = paged([_incident_shape(r) for r in rows], total, p)
    out["status_counts"] = counts
    out["categories"] = events.INCIDENT_CATEGORY_LABELS
    return out


def _attack_label(req: dict) -> str:
    """Stored category, or (for rows logged before categories existed) the
    category of the highest-weight matched rule."""
    if req.get("category"):
        return detector.CATEGORY_LABELS.get(req["category"], req["category"])
    rules = [r for r in req.get("rule_ids") or [] if r in detector.RULES_BY_ID]
    if not rules:
        return "—"
    best = max(rules, key=lambda r: detector.RULES_BY_ID[r].weight)
    return detector.CATEGORY_LABELS[detector.RULE_INFO[best]["category"]]


def _load_incident(conn, incident_id: int) -> dict:
    row = conn.execute("SELECT * FROM security_event WHERE id = %s", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "No incident has that ID.")
    return row


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, user: User = Depends(require("incidents:view"))):
    with db.pool().connection() as conn:
        inc = _load_incident(conn, incident_id)
        notes = conn.execute(
            "SELECT id, ts, author, kind, body FROM incident_note WHERE incident_id = %s ORDER BY ts",
            (incident_id,)).fetchall()
        alerts = conn.execute(
            """SELECT id, ts, title, severity, status, delivery, occurrences FROM security_alert
               WHERE incident_id = %s ORDER BY ts""", (incident_id,)).fetchall()
        related = []
        if inc["client_ip"]:
            related = conn.execute(
                """SELECT id, ts, method, path, status, verdict, source, score, rule_ids, category, sample
                   FROM request_log
                   WHERE client_ip = %s AND verdict <> 'normal'
                     AND ts BETWEEN %s - interval '30 minutes' AND %s + interval '5 minutes'
                   ORDER BY ts LIMIT 100""",
                (inc["client_ip"], inc["ts"], inc["last_seen_at"])).fetchall()
        actions = conn.execute(
            """SELECT id, ts, actor, action, result, detail FROM audit_log
               WHERE resource = %s ORDER BY ts""", (incident_ref(incident_id),)).fetchall()
        blocked = conn.execute(
            "SELECT ip, created_by, created_at FROM blocked_source WHERE ip = %s AND active",
            (inc["client_ip"],)).fetchone() if inc["client_ip"] else None

    can_see = user.can("traffic:payload")
    for r in related:
        r["ref"] = request_ref(r["id"])
        if not can_see:
            r["sample"] = "[hidden for your role]"

    # Detection explanation from the highest-scoring related request.
    explanation = None
    if related:
        worst = max(related, key=lambda r: r["score"])
        result = detector.Inspection(score=worst["score"], verdict=worst["verdict"])
        contributions = [{"rule_id": rid, "rule": detector.RULES_BY_ID[rid].description,
                          "weight": detector.RULES_BY_ID[rid].weight,
                          "severity": detector.RULE_INFO[rid]["severity"],
                          "category_label": detector.CATEGORY_LABELS[detector.RULE_INFO[rid]["category"]],
                          "explanation": detector.RULE_INFO[rid]["explanation"]}
                         for rid in worst["rule_ids"] if rid in detector.RULES_BY_ID]
        explanation = {
            "request_ref": worst["ref"], "request_id": worst["id"], "score": worst["score"],
            "verdict": worst["verdict"], "attack": _attack_label(worst),
            "thresholds": {"suspicious": detector.SUSPICIOUS_SCORE, "block": detector.BLOCK_SCORE},
            "reason": detector.verdict_reason(result), "contributions": contributions,
            "method": worst["method"], "endpoint": worst["path"], "sample": worst["sample"],
        }

    timeline = []
    if related:
        first = related[0]
        timeline.append({"ts": first["ts"], "type": "first_request",
                         "title": f"First flagged request: {first['method']} {first['path']}",
                         "detail": f"Score {first['score']}, {first['verdict']}", "ref": first["ref"]})
        for r in related[1:]:
            timeline.append({"ts": r["ts"], "type": "blocked" if r["verdict"] == "blocked" else "attempt",
                             "title": f"{'Blocked' if r['status'] == 403 else 'Flagged'}: {r['method']} {r['path']}",
                             "detail": f"Score {r['score']}, rules {', '.join(r['rule_ids'])}", "ref": r["ref"]})
    timeline.append({"ts": inc["ts"], "type": "incident", "title": f"Incident opened ({inc['severity']})",
                     "detail": inc["summary"], "ref": incident_ref(inc["id"])})
    for a in alerts:
        timeline.append({"ts": a["ts"], "type": "alert", "title": f"Alert raised: {a['title']}",
                         "detail": f"Notification: {a['delivery']}", "ref": None})
    for n in notes:
        timeline.append({"ts": n["ts"], "type": n["kind"],
                         "title": {"note": "Note added", "status": "Status changed", "assignment": "Assignment",
                                   "blocklist": "Blocklist", "recurrence": "Activity recurred"}[n["kind"]]
                         + f" by {n['author']}", "detail": n["body"], "ref": None})
    timeline.sort(key=lambda e: e["ts"])

    return {
        **_incident_shape(inc), "notes": notes, "alerts": alerts, "related_requests": related,
        "explanation": explanation, "timeline": timeline, "audit": actions,
        "source_blocked": blocked, "statuses": INCIDENT_STATUSES,
    }


class IncidentUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = Field(None, max_length=64)
    note: str | None = Field(None, max_length=2000)

    @field_validator("status")
    @classmethod
    def _status(cls, v):
        if v is not None and v not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {INCIDENT_STATUSES}")
        return v


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, request: Request,
                    user: User = Depends(require("incidents:manage"))):
    ip = request_ip(request)
    changes = {}
    with db.pool().connection() as conn:
        with conn.transaction():
            inc = _load_incident(conn, incident_id)
            if body.assigned_to is not None:
                assignee = body.assigned_to.strip() or None
                if assignee:
                    ok = conn.execute(
                        "SELECT 1 FROM users WHERE username = %s AND is_active AND role IN ('admin','analyst')",
                        (assignee,)).fetchone()
                    if not ok:
                        raise HTTPException(400, "Assign to an active administrator or analyst.")
                if assignee != inc["assigned_to"]:
                    conn.execute("UPDATE security_event SET assigned_to = %s, updated_at = now() WHERE id = %s",
                                 (assignee, incident_id))
                    conn.execute("INSERT INTO incident_note (incident_id, author, kind, body) VALUES (%s,%s,'assignment',%s)",
                                 (incident_id, user.username, f"Assigned to {assignee}" if assignee else "Unassigned"))
                    changes["assigned_to"] = [inc["assigned_to"], assignee]
            if body.status and body.status != inc["status"]:
                conn.execute(
                    """UPDATE security_event SET status = %s, updated_at = now(),
                           resolved_at = CASE WHEN %s IN ('resolved','false_positive') THEN now() END
                       WHERE id = %s""", (body.status, body.status, incident_id))
                conn.execute("INSERT INTO incident_note (incident_id, author, kind, body) VALUES (%s,%s,'status',%s)",
                             (incident_id, user.username,
                              f"{inc['status'].replace('_', ' ')} → {body.status.replace('_', ' ')}"))
                changes["status"] = [inc["status"], body.status]
            if body.note and body.note.strip():
                conn.execute("INSERT INTO incident_note (incident_id, author, kind, body) VALUES (%s,%s,'note',%s)",
                             (incident_id, user.username, body.note.strip()))
                changes["note"] = True
    if not changes:
        raise HTTPException(400, "Nothing to change.")
    audit.record("incident.update", actor=user.username, actor_role=user.role,
                 resource=incident_ref(incident_id), client_ip=ip, detail=changes)
    return incident_detail(incident_id, user)


@router.get("/incidents/{incident_id}/report", response_class=PlainTextResponse)
def incident_report(incident_id: int, request: Request, user: User = Depends(require("reports:export"))):
    d = incident_detail(incident_id, user)
    e = d["explanation"]
    lines = [
        f"# Incident report {d['ref']}", "",
        f"- Severity: {d['severity']}", f"- Category: {d['category_label']}", f"- Status: {d['status']}",
        f"- Source IP: {d['client_ip'] or '-'}", f"- User: {d['username'] or '-'}",
        f"- Endpoint: {d['endpoint'] or '-'}", f"- Opened: {d['ts']:%Y-%m-%d %H:%M:%S} UTC",
        f"- Last activity: {d['last_seen_at']:%Y-%m-%d %H:%M:%S} UTC", f"- Occurrences: {d['occurrences']}",
        f"- Assigned to: {d['assigned_to'] or 'unassigned'}",
        f"- Source on blocklist: {'yes' if d['source_blocked'] else 'no'}", "",
        "## Summary", "", d["summary"], "",
    ]
    if e:
        lines += ["## Detection", "", f"Attack: {e['attack']}  ", f"Request: {e['request_ref']} {e['method']} {e['endpoint']}  ",
                  f"Score: {e['score']} (suspicious at {e['thresholds']['suspicious']}, blocked at {e['thresholds']['block']})  ",
                  f"Verdict: {e['verdict']}", "", e["reason"], "", "| Rule | Weight | Why it matters |", "|---|---|---|",
                  *[f"| {c['rule_id']} {c['rule']} | +{c['weight']} | {c['explanation']} |" for c in e["contributions"]], ""]
    lines += ["## Timeline", "", *[f"- {t['ts']:%Y-%m-%d %H:%M:%S} UTC: {t['title']}. {t['detail']}" for t in d["timeline"]], ""]
    audit.record("export.incident_report", actor=user.username, actor_role=user.role,
                 resource=d["ref"], client_ip=request_ip(request))
    return PlainTextResponse("\n".join(lines), headers={
        "Content-Disposition": f'attachment; filename="{d["ref"]}.md"'})


# ---------------------------------------------------------------- blocklist

class BlockBody(BaseModel):
    ip: str = Field(max_length=64)
    reason: str = Field(min_length=3, max_length=300)
    incident_id: int | None = None

    @field_validator("ip")
    @classmethod
    def _ip(cls, v):
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("Enter a single IPv4 or IPv6 address.")


@router.get("/blocklist")
def list_blocklist(user: User = Depends(require("incidents:view"))):
    with db.pool().connection() as conn:
        rows = conn.execute(
            """SELECT ip, reason, incident_id, created_by, created_at, active, removed_by, removed_at
               FROM blocked_source ORDER BY active DESC, created_at DESC LIMIT 200""").fetchall()
    return {"items": rows}


@router.post("/blocklist")
def add_block(body: BlockBody, request: Request, user: User = Depends(require("blocklist:manage"))):
    ip = request_ip(request)
    if body.ip == ip:
        raise HTTPException(400, "That is your own address. Blocking it would lock you out.")
    with db.pool().connection() as conn:
        with conn.transaction():
            conn.execute(
                """INSERT INTO blocked_source (ip, reason, incident_id, created_by)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (ip) DO UPDATE SET reason = EXCLUDED.reason, incident_id = EXCLUDED.incident_id,
                       created_by = EXCLUDED.created_by, created_at = now(), active = true,
                       removed_by = NULL, removed_at = NULL""",
                (body.ip, body.reason, body.incident_id, user.username))
            if body.incident_id:
                conn.execute("INSERT INTO incident_note (incident_id, author, kind, body) VALUES (%s,%s,'blocklist',%s)",
                             (body.incident_id, user.username, f"Blocked {body.ip}: {body.reason}"))
    policy.invalidate()
    audit.record("blocklist.add", actor=user.username, actor_role=user.role, resource=body.ip, client_ip=ip,
                 detail={"reason": body.reason, "incident": incident_ref(body.incident_id) if body.incident_id else None})
    return {"ok": True, "ip": body.ip}


@router.delete("/blocklist/{blocked_ip}")
def remove_block(blocked_ip: str, request: Request, user: User = Depends(require("blocklist:manage"))):
    with db.pool().connection() as conn:
        row = conn.execute(
            """UPDATE blocked_source SET active = false, removed_by = %s, removed_at = now()
               WHERE ip = %s AND active RETURNING ip""", (user.username, blocked_ip)).fetchone()
    if row is None:
        raise HTTPException(404, "That address is not on the active blocklist.")
    policy.invalidate()
    audit.record("blocklist.remove", actor=user.username, actor_role=user.role, resource=blocked_ip,
                 client_ip=request_ip(request))
    return {"ok": True}


# ---------------------------------------------------------------- alerts

@router.get("/alerts")
def list_alerts(
    p: Page = Depends(paging),
    status: str | None = Query(None, pattern="^(open|acknowledged|resolved)$"),
    category: str | None = Query(None, max_length=40),
    unread: bool = False,
    user: User = Depends(require("alerts:view")),
):
    params = {"st": status, "cat": category, "unread": unread, "limit": p.page_size, "offset": p.offset}
    where = """(%(st)s::text IS NULL OR status = %(st)s) AND (%(cat)s::text IS NULL OR category = %(cat)s)
               AND (NOT %(unread)s OR NOT is_read)"""
    with db.pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM security_alert WHERE {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"""SELECT id, ts, last_seen_at, category, severity, title, description, incident_id, occurrences,
                       status, delivery, is_read, acknowledged_by, resolved_by
                FROM security_alert WHERE {where} ORDER BY last_seen_at DESC LIMIT %(limit)s OFFSET %(offset)s""",
            params).fetchall()
        unread_n = conn.execute(
            "SELECT count(*) AS n FROM security_alert WHERE NOT is_read AND status <> 'resolved'").fetchone()["n"]
    for r in rows:
        r["incident_ref"] = incident_ref(r["incident_id"]) if r["incident_id"] else None
        r["category_label"] = events.ALERT_CATEGORY_LABELS.get(r["category"], r["category"])
    out = paged(rows, total, p)
    out["unread"] = unread_n
    out["categories"] = events.ALERT_CATEGORY_LABELS
    return out


@router.post("/alerts/read-all")
def read_all(user: User = Depends(require("alerts:view"))):
    with db.pool().connection() as conn:
        n = conn.execute("UPDATE security_alert SET is_read = true WHERE NOT is_read").rowcount
    return {"ok": True, "updated": n}


class AlertUpdate(BaseModel):
    action: str = Field(pattern="^(read|acknowledge|resolve)$")


@router.post("/alerts/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, request: Request, user: User = Depends(require("alerts:view"))):
    if body.action != "read" and not user.can("alerts:manage"):
        raise HTTPException(403, "Your role does not allow this action.")
    sql = {
        "read": "UPDATE security_alert SET is_read = true WHERE id = %s RETURNING id",
        "acknowledge": """UPDATE security_alert SET status = 'acknowledged', is_read = true, acknowledged_by = %s,
                          updated_at = now() WHERE id = %s AND status = 'open' RETURNING id""",
        "resolve": """UPDATE security_alert SET status = 'resolved', is_read = true, resolved_by = %s,
                      updated_at = now() WHERE id = %s AND status <> 'resolved' RETURNING id""",
    }[body.action]
    args = (alert_id,) if body.action == "read" else (user.username, alert_id)
    with db.pool().connection() as conn:
        row = conn.execute(sql, args).fetchone()
    if row is None:
        raise HTTPException(409, "That alert is already in that state or does not exist.")
    if body.action != "read":
        audit.record(f"alert.{body.action}", actor=user.username, actor_role=user.role,
                     resource=f"ALERT-{alert_id}", client_ip=request_ip(request))
    return {"ok": True}

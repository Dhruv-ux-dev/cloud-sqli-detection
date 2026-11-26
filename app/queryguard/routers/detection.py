"""SQL injection detection center and the attack simulation lab."""

from __future__ import annotations

import base64
import binascii
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from .. import audit, db, detector, health, policy
from ..config import settings
from ..middleware import request_ip
from ..security import User, require
from .common import Page, paged, paging

router = APIRouter(prefix="/api", tags=["detection"])


# ---------------------------------------------------------------- detection center

@router.get("/detection/rules")
def rules(user: User = Depends(require("detection:view"))):
    with db.pool().connection() as conn:
        stats = {r["rule_id"]: r for r in conn.execute(
            """SELECT r AS rule_id, count(*) AS matches, max(ts) AS last_matched,
                      count(*) FILTER (WHERE ts >= now() - interval '24 hours') AS matches_24h
               FROM request_log, unnest(rule_ids) AS r
               WHERE ts >= now() - interval '30 days' GROUP BY r""")}
        states = {r["rule_id"]: r for r in conn.execute(
            "SELECT rule_id, enabled, updated_by, updated_at FROM rule_state")}
    out = []
    for r in detector.RULES:
        info = detector.RULE_INFO[r.id]
        st = states.get(r.id)
        s = stats.get(r.id, {})
        out.append({
            "id": r.id, "name": r.description, "category": info["category"],
            "category_label": detector.CATEGORY_LABELS[info["category"]], "severity": info["severity"],
            "weight": r.weight, "explanation": info["explanation"], "pattern": r.pattern.pattern,
            "scope": "User-Agent header only" if r.id == "SCANNER-UA" else "Path, query, form and JSON values",
            "enabled": st["enabled"] if st else True,
            "changed_by": st["updated_by"] if st else None, "changed_at": st["updated_at"] if st else None,
            "matches_30d": s.get("matches", 0), "matches_24h": s.get("matches_24h", 0),
            "last_matched": s.get("last_matched"),
        })
    return {"items": out, "can_manage": user.can("detection:manage")}


@router.get("/detection/stats")
def detection_stats(user: User = Depends(require("detection:view"))):
    with db.pool().connection() as conn:
        dist = conn.execute(
            """SELECT CASE WHEN score = 0 THEN '0'
                           WHEN score < %(s)s THEN '1-' || (%(s)s - 1)
                           WHEN score < %(b)s THEN %(s)s || '-' || (%(b)s - 1)
                           WHEN score < 16 THEN %(b)s || '-15'
                           WHEN score < 30 THEN '16-29' ELSE '30+' END AS bucket,
                      min(score) AS lo, count(*) AS n
               FROM request_log WHERE ts >= now() - interval '30 days'
               GROUP BY 1 ORDER BY lo""",
            {"s": detector.SUSPICIOUS_SCORE, "b": detector.BLOCK_SCORE}).fetchall()
        totals = conn.execute(
            """SELECT count(*) FILTER (WHERE cardinality(rule_ids) > 0) AS flagged,
                      coalesce(sum(cardinality(rule_ids)), 0) AS rule_matches,
                      count(*) AS inspected
               FROM request_log WHERE ts >= now() - interval '30 days'""").fetchone()
    disabled = policy.disabled_rules()
    return {
        "rules_total": len(detector.RULES), "rules_active": len(detector.RULES) - len(disabled),
        "rules_disabled": len(disabled), "pattern_matches_30d": totals["rule_matches"],
        "requests_flagged_30d": totals["flagged"], "requests_inspected_30d": totals["inspected"],
        "score_distribution": dist, "engine": health.check_detector(),
        "thresholds": {
            "suspicious": detector.SUSPICIOUS_SCORE, "block": detector.BLOCK_SCORE,
            "explanation": [
                f"Each rule has a weight. A request's score is the sum of the weights of the distinct rules it "
                f"matches across the path, query parameters, form and JSON values (and the User-Agent for the "
                f"scanner rule). A rule counts once, however many fields match it.",
                f"Score {detector.BLOCK_SCORE} or more: blocked. One high-confidence rule (weight 8-10) is "
                f"enough, or two medium ones together (e.g. a quote break plus a tautology).",
                f"Score {detector.SUSPICIOUS_SCORE} to {detector.BLOCK_SCORE - 1}: suspicious. The request is "
                f"served, but flagged, counted toward repeat-attack detection and shown here.",
                f"Below {detector.SUSPICIOUS_SCORE}: normal.",
                "Values are normalised first: URL-decoded up to three times, Unicode-folded (full-width quotes "
                "become ASCII), inline /**/ comments collapsed and whitespace squeezed.",
            ],
        },
        "enforcement": {"aws": "AWS WAF filters first; the application blocks what still scores high.",
                        "emulated": "No WAF in front: the application blocks like WAF would.",
                        "off": "Classification only: nothing is blocked (controlled demo)."}[settings.waf_mode],
    }


class RuleUpdate(BaseModel):
    enabled: bool
    reason: str = Field(min_length=5, max_length=300)


@router.patch("/detection/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, request: Request,
                user: User = Depends(require("detection:manage"))):
    if rule_id not in detector.RULES_BY_ID:
        raise HTTPException(404, "No rule has that ID.")
    with db.pool().connection() as conn:
        conn.execute(
            """INSERT INTO rule_state (rule_id, enabled, updated_by) VALUES (%s, %s, %s)
               ON CONFLICT (rule_id) DO UPDATE SET enabled = EXCLUDED.enabled,
                   updated_by = EXCLUDED.updated_by, updated_at = now()""",
            (rule_id, body.enabled, user.username))
    policy.invalidate()
    audit.record("detection.rule_" + ("enable" if body.enabled else "disable"), actor=user.username,
                 actor_role=user.role, resource=rule_id, client_ip=request_ip(request),
                 detail={"reason": body.reason})
    return {"ok": True, "rule_id": rule_id, "enabled": body.enabled}


# ---------------------------------------------------------------- simulation lab

TARGETS = {
    "search": {"label": "Customer search (GET /api/customers?q=)", "method": "GET", "path": "/api/customers"},
    "login": {"label": "Sign-in username (POST /api/login)", "method": "POST", "path": "/api/login"},
    "record": {"label": "Record ID in the URL (GET /api/customers/{id})", "method": "GET",
               "path": "/api/customers/"},
}

PRESETS = {
    "basic": ("Basic SQL injection", ["' OR '1'='1", "x' OR 'a'='a", "1' AND 'x'='x"]),
    "union": ("UNION-based injection", ["x' UNION SELECT username, password_hash, role FROM users--",
                                        "x' UNION ALL SELECT id, pan, account_no FROM customers--"]),
    "boolean": ("Boolean-based injection", ["1 OR 1=1", "1' AND (SELECT count(*) FROM users) > 0--",
                                           "x' AND 1=1--"]),
    "comment": ("Comment-based injection", ["admin'--", "admin'#", "x'/**/OR/**/1=1--"]),
    "time": ("Time-based injection", ["x' AND pg_sleep(5)--", "1; SELECT pg_sleep(10)--",
                                      "x' WAITFOR DELAY '0:0:5'--"]),
    "encoded": ("Encoded SQL injection", ["%27%20OR%20%271%27%3D%271", "%2527%2520OR%25201%253D1--",
                                          "＇ OR 1=1--", "x' AND 1=CHAR(49)--"]),
    "auth_bypass": ("Authentication bypass", ["admin'--", "' or ''='", "admin' OR '1'='1'--"]),
    "catalogue": ("System catalogue enumeration",
                  ["x' UNION SELECT table_name, null, null FROM information_schema.tables--",
                   "x' AND (SELECT count(*) FROM pg_catalog.pg_tables) > 0--"]),
    "control": ("Harmless control inputs", ["D'Souza", "Patiala", "union bank", "rock and roll"]),
}


@router.get("/simulations/presets")
def presets(_: User = Depends(require("simulation:run"))):
    return {
        "categories": [{"key": k, "label": label, "payloads": payloads} for k, (label, payloads) in PRESETS.items()],
        "targets": [{"key": k, **v} for k, v in TARGETS.items()],
        "environment": settings.app_env, "waf_mode": settings.waf_mode,
        "note": "Payloads run through the real detector inside the app. No HTTP request is sent to any endpoint, "
                "no SQL is executed, and AWS WAF is not simulated.",
    }


class SimulationBody(BaseModel):
    category: str
    target: str
    payload_b64: str = Field(max_length=4000)

    @field_validator("category")
    @classmethod
    def _cat(cls, v):
        if v not in PRESETS and v != "custom":
            raise ValueError("Unknown category.")
        return v

    @field_validator("target")
    @classmethod
    def _target(cls, v):
        if v not in TARGETS:
            raise ValueError("Unknown target.")
        return v


@router.post("/simulations")
def run_simulation(body: SimulationBody, request: Request, user: User = Depends(require("simulation:run"))):
    """The payload arrives base64-encoded so neither AWS WAF nor the request
    filter treats the lab's own traffic as an attack."""
    try:
        payload = base64.b64decode(body.payload_b64, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise HTTPException(400, "payload_b64 must be base64-encoded UTF-8 text.")
    if not payload.strip():
        raise HTTPException(400, "Enter a payload to test.")
    if len(payload) > 2000:
        raise HTTPException(400, "Payloads are limited to 2,000 characters.")

    t_start = time.perf_counter()
    target = TARGETS[body.target]
    if body.target == "search":
        path = target["path"]
        fields = [("path", path), ("query.key", "q"), ("query.q", payload)]
    elif body.target == "login":
        path = target["path"]
        fields = [("path", path)] + detector.flatten_json({"username": payload, "password": "x"})
        fields = [f for f in fields if f[0] != "body.password"]
    else:
        path = target["path"] + payload
        fields = [("path", path)]

    disabled = policy.disabled_rules()
    analysis = detector.analyse(fields, path, disabled)
    result: detector.Inspection = analysis["result"]
    would_block = result.verdict == "blocked" and settings.waf_mode != "off"
    decision = "block" if would_block else "flag" if result.verdict != "normal" else "allow"
    explanation = detector.explain(result)
    payload_field = next((n for n, _ in fields if n not in {"path", "query.key", "body.key"}), "path")
    normalised = next((t for n, t in analysis["normalised"] if n == payload_field), "")

    with db.pool().connection() as conn:
        row = conn.execute(
            """INSERT INTO simulation_run
               (username, category, target, payload, score, verdict, would_block, rule_ids, analysis, duration_us)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id, ts""",
            (user.username, body.category, body.target, payload[:500], result.score, result.verdict,
             would_block, result.rule_ids,
             __import__("json").dumps({"explanation": explanation, "category": analysis["category"],
                                       "timings_us": analysis["timings_us"]}),
             int((time.perf_counter() - t_start) * 1e6))).fetchone()
    audit_id = audit.record("simulation.run", actor=user.username, actor_role=user.role,
                            resource=f"SIM-{row['id']}", client_ip=request_ip(request),
                            detail={"category": body.category, "target": body.target, "verdict": result.verdict,
                                    "score": result.score})
    total_us = int((time.perf_counter() - t_start) * 1e6)
    t = analysis["timings_us"]
    enforcement = {
        "aws": "Application filter. In this deployment AWS WAF evaluates real traffic first; its verdict is not "
               "simulated here.",
        "emulated": "Application filter (standing in for AWS WAF in this local run).",
        "off": "None: WAF_MODE=off classifies without blocking.",
    }[settings.waf_mode]

    pipeline = [
        {"stage": "Input", "status": "done", "detail": f"{len(payload)} characters into {payload_field} of "
                                                         f"{target['method']} {target['path']}", "us": 0},
        {"stage": "Request normalisation", "status": "done",
         "detail": "Decoding changed the value." if normalised != payload.strip() else "No decoding needed.",
         "us": t["normalisation"]},
        {"stage": "SQLi detection", "status": "match" if result.matches else "clean",
         "detail": f"{len(result.rule_ids)} of {len(detector.RULES) - len(disabled)} active rules matched.",
         "us": t["detection"]},
        {"stage": "Risk scoring", "status": result.verdict,
         "detail": f"Score {result.score} (suspicious ≥ {detector.SUSPICIOUS_SCORE}, block ≥ {detector.BLOCK_SCORE}).",
         "us": t["scoring"]},
        {"stage": "Security policy", "status": "done",
         "detail": f"WAF_MODE={settings.waf_mode}; {len(disabled)} rule(s) disabled by an administrator.", "us": 0},
        {"stage": "Decision", "status": decision,
         "detail": {"block": "Block: rejected with 403 before any handler or query runs.",
                    "flag": "Flag: served, logged as suspicious, counted toward repeat-attack detection.",
                    "allow": "Allow: served normally."}[decision], "us": 0},
        {"stage": "Audit logging", "status": "done",
         "detail": f"Saved as SIM-{row['id']} and audit record AUD-{audit_id:07d}." if audit_id
         else f"Saved as SIM-{row['id']}; audit write failed.", "us": 0},
    ]
    return {
        "id": row["id"], "ts": row["ts"], "payload": payload, "normalised": normalised,
        "target": body.target, "category": body.category,
        "detected_category": detector.CATEGORY_LABELS.get(analysis["category"] or "", None),
        "score": result.score, "verdict": result.verdict, "would_block": would_block, "decision": decision,
        "enforced_by": enforcement, "reason": detector.verdict_reason(result),
        "thresholds": {"suspicious": detector.SUSPICIOUS_SCORE, "block": detector.BLOCK_SCORE},
        "explanation": explanation, "pipeline": pipeline, "timings_us": {**t, "total": total_us},
        "audit_id": audit_id,
    }


@router.get("/simulations")
def simulation_history(p: Page = Depends(paging), _: User = Depends(require("simulation:run"))):
    with db.pool().connection() as conn:
        total = conn.execute("SELECT count(*) AS n FROM simulation_run").fetchone()["n"]
        rows = conn.execute(
            """SELECT id, ts, username, category, target, payload, score, verdict, would_block, rule_ids,
                      duration_us, analysis->>'category' AS detected
               FROM simulation_run ORDER BY id DESC LIMIT %s OFFSET %s""", (p.page_size, p.offset)).fetchall()
    for r in rows:
        r["detected_label"] = detector.CATEGORY_LABELS.get(r.pop("detected") or "", None)
    return paged(rows, total, p)

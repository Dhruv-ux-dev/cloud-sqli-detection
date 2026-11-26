"""Recording requests, incidents and alerts, and sending notifications.

Every record is written twice:
  * to PostgreSQL, which feeds the console;
  * to stdout as one JSON line. On AWS the Docker awslogs driver ships stdout
    to CloudWatch Logs, where metric filters turn these lines into metrics and
    alarms, and the alarms notify the administrator through SNS.

Flood control:
  * an open incident of the same kind from the same source within 30 minutes
    is updated (occurrences + 1, a recurrence note) instead of duplicated;
  * an open alert with the same dedup key is updated the same way;
  * SNS is sent at most once per dedup key per alert cooldown.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone

from . import db, policy
from .config import settings

log = logging.getLogger("queryguard.events")

_stdout_lock = threading.Lock()
_last_alert: dict[str, float] = {}
_alert_lock = threading.Lock()
_sns = None
_last_sns: dict = {"ts": None, "status": None, "error": None}

INCIDENT_DEDUP_MINUTES = 30
IP_KEYED_KINDS = {"repeated_injection", "critical_injection", "brute_force", "unusual_traffic"}
SEVERITY_RANK = ['informational', 'low', 'medium', 'high', 'critical']

# kind -> (category, alert category)
INCIDENT_KINDS = {
    "critical_injection": ("sql_injection", "critical_sqli"),
    "repeated_injection": ("sql_injection", "repeated_attack"),
    "brute_force": ("auth_failures", "repeated_attack"),
    "bulk_access": ("suspicious_data_access", "suspicious_data_access"),
    "pii_reveal": ("sensitive_data_exposure", None),
    "unauthorized_action": ("unauthorized_action", "unauthorized_action"),
    "unusual_traffic": ("unusual_traffic", "repeated_attack"),
}

INCIDENT_CATEGORY_LABELS = {
    "sql_injection": "SQL injection",
    "auth_failures": "Repeated authentication failures",
    "suspicious_data_access": "Suspicious data access",
    "sensitive_data_exposure": "Sensitive data exposure",
    "unusual_traffic": "Unusual traffic pattern",
    "unauthorized_action": "Unauthorized privileged action",
}

ALERT_CATEGORY_LABELS = {
    "critical_sqli": "Critical SQL injection attack",
    "repeated_attack": "Repeated attacks from a source",
    "suspicious_data_access": "Suspicious data access",
    "unauthorized_action": "Unauthorized privileged action",
    "db_failure": "Database connectivity failure",
    "waf_failure": "AWS WAF configuration failure",
    "cloudwatch_alarm": "CloudWatch alarm",
    "sns_failure": "SNS notification delivery failure",
}


def emit(record: dict) -> None:
    """One JSON object per line on stdout (CloudWatch-friendly)."""
    line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **record}, default=str)
    with _stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def record_request(row: dict) -> None:
    emit({"event": "request", **{k: v for k, v in row.items() if k not in {"matches", "query_preview"}}})
    try:
        with db.pool().connection() as conn:
            conn.execute(
                """INSERT INTO request_log
                   (client_ip, method, path, status, verdict, source, score, rule_ids, sample,
                    username, latency_ms, user_agent, query_preview, category, matches)
                   VALUES (%(client_ip)s, %(method)s, %(path)s, %(status)s, %(verdict)s,
                           %(source)s, %(score)s, %(rule_ids)s, %(sample)s, %(username)s,
                           %(latency_ms)s, %(user_agent)s, %(query_preview)s, %(category)s,
                           %(matches)s)""",
                {**row, "matches": json.dumps(row.get("matches", []))},
            )
    except Exception:  # logging must never break a response
        log.exception("could not write request_log")


# ---------------------------------------------------------------- SNS

def _sns_client():
    global _sns
    if _sns is None:
        import boto3

        _sns = boto3.client("sns", region_name=settings.aws_region)
    return _sns


def last_sns_delivery() -> dict:
    return dict(_last_sns)


def _notify(key: str, subject: str, message: str) -> str:
    """Send through SNS with a per-key cooldown. Returns the delivery state."""
    now = time.time()
    cooldown = policy.get("alert_cooldown_seconds")
    with _alert_lock:
        if now - _last_alert.get(key, 0.0) < cooldown:
            return "suppressed"
        _last_alert[key] = now

    if not settings.sns_topic_arn:
        emit({"event": "alert", "delivery": "logged", "subject": subject, "message": message})
        return "logged"
    try:
        _sns_client().publish(TopicArn=settings.sns_topic_arn, Subject=subject[:99], Message=message)
        _last_sns.update(ts=datetime.now(timezone.utc).isoformat(), status="sent", error=None)
        emit({"event": "alert", "delivery": "sns", "subject": subject})
        return "sent"
    except Exception as exc:
        log.exception("SNS publish failed")
        _last_sns.update(ts=datetime.now(timezone.utc).isoformat(), status="failed",
                         error=exc.__class__.__name__)
        create_alert("sns_failure", "high", "SNS notification could not be delivered",
                     f"Publishing to the SNS topic failed with {exc.__class__.__name__}. "
                     f"Notification subject: {subject[:120]}",
                     dedup_key="sns_failure", notify=False)
        return "failed"


# ---------------------------------------------------------------- alerts

def create_alert(
    category: str,
    severity: str,
    title: str,
    description: str,
    *,
    dedup_key: str,
    incident_id: int | None = None,
    notify: bool = True,
    notification_body: str | None = None,
) -> int | None:
    """Open a new alert, or bump the open one with the same dedup key."""
    delivery = "none"
    if notify and severity in {"critical", "high", "medium"}:
        delivery = _notify(dedup_key, f"[Northfield] {severity.upper()}: {title}",
                           notification_body or description)
    try:
        with db.pool().connection() as conn:
            existing = conn.execute(
                """SELECT id FROM security_alert
                   WHERE dedup_key = %s AND status <> 'resolved'
                     AND last_seen_at > now() - make_interval(secs => %s)
                   ORDER BY id DESC LIMIT 1""",
                (dedup_key, max(policy.get("alert_cooldown_seconds"), 1800)),
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE security_alert
                       SET occurrences = occurrences + 1, last_seen_at = now(), updated_at = now(),
                           is_read = false, description = %s,
                           delivery = CASE WHEN %s IN ('sent', 'failed') THEN %s ELSE delivery END,
                           incident_id = COALESCE(incident_id, %s)
                       WHERE id = %s""",
                    (description, delivery, delivery, incident_id, existing["id"]),
                )
                return existing["id"]
            row = conn.execute(
                """INSERT INTO security_alert
                   (category, severity, title, description, incident_id, dedup_key, delivery)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (category, severity, title, description, incident_id, dedup_key, delivery),
            ).fetchone()
            return row["id"]
    except Exception:
        log.exception("could not write security_alert")
        return None


# ---------------------------------------------------------------- incidents

def raise_incident(
    kind: str,
    severity: str,
    summary: str,
    *,
    client_ip: str | None = None,
    username: str | None = None,
    endpoint: str | None = None,
    detail: dict | None = None,
    alert: bool = True,
) -> int | None:
    detail = detail or {}
    category, alert_category = INCIDENT_KINDS.get(kind, ("unusual_traffic", "repeated_attack"))
    # Attacks are tracked per source IP; account misuse per user.
    by_ip = kind in IP_KEYED_KINDS and bool(client_ip)
    source = (client_ip if by_ip else username or client_ip) or "-"
    emit({"event": "incident", "kind": kind, "severity": severity, "client_ip": client_ip,
          "username": username, "summary": summary})

    incident_id: int | None = None
    recurred = False
    try:
        with db.pool().connection() as conn:
            with conn.transaction():
                match = "client_ip = %s" if by_ip else "COALESCE(username, '') = COALESCE(%s, '')"
                existing = conn.execute(
                    f"""SELECT id FROM security_event
                       WHERE kind = %s AND status IN ('new', 'investigating') AND {match}
                         AND last_seen_at > now() - make_interval(mins => %s)
                       ORDER BY id DESC LIMIT 1 FOR UPDATE""",
                    (kind, client_ip if by_ip else username, INCIDENT_DEDUP_MINUTES),
                ).fetchone() if kind != "pii_reveal" else None
                if existing:
                    incident_id = existing["id"]
                    recurred = True
                    conn.execute(
                        """UPDATE security_event
                           SET occurrences = occurrences + 1, last_seen_at = now(), updated_at = now(),
                               severity = CASE
                                   WHEN array_position(%s::text[], %s) > array_position(%s::text[], severity)
                                   THEN %s ELSE severity END
                           WHERE id = %s""",
                        (SEVERITY_RANK, severity, SEVERITY_RANK, severity, incident_id),
                    )
                    conn.execute(
                        """INSERT INTO incident_note (incident_id, author, kind, body)
                           VALUES (%s, 'system', 'recurrence', %s)""",
                        (incident_id, summary),
                    )
                else:
                    status = "resolved" if severity == "informational" else "new"
                    row = conn.execute(
                        """INSERT INTO security_event
                           (kind, severity, client_ip, username, summary, detail, category,
                            endpoint, status, resolved_at)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                                   CASE WHEN %s = 'resolved' THEN now() END)
                           RETURNING id""",
                        (kind, severity, client_ip, username, summary,
                         json.dumps(detail, default=str), category, endpoint, status, status),
                    ).fetchone()
                    incident_id = row["id"]
    except Exception:
        log.exception("could not write security_event")

    if alert and alert_category and severity in {"critical", "high", "medium"}:
        body = "\n".join([
            summary, "",
            f"Incident:  INC-{incident_id:06d}" if incident_id else "Incident:  (not recorded)",
            f"Category:  {INCIDENT_CATEGORY_LABELS.get(category, category)}",
            f"Severity:  {severity}",
            f"Source IP: {client_ip or '-'}",
            f"User:      {username or '-'}",
            f"Endpoint:  {endpoint or '-'}",
            f"Time:      {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC",
            "", "Detail:", json.dumps(detail, indent=2, default=str)[:3000], "",
            "Investigate it in the Northfield console under Security incidents.",
        ])
        delivery_id = create_alert(
            alert_category, severity,
            ALERT_CATEGORY_LABELS.get(alert_category, alert_category) + f" ({source})",
            summary, dedup_key=f"{kind}:{source}", incident_id=incident_id,
            notification_body=body,
        )
        if incident_id and delivery_id and not recurred:
            _sync_incident_alert_state(incident_id, delivery_id)
    return incident_id


def _sync_incident_alert_state(incident_id: int, alert_id: int) -> None:
    try:
        with db.pool().connection() as conn:
            conn.execute(
                """UPDATE security_event SET alert = a.delivery
                   FROM security_alert a WHERE a.id = %s AND security_event.id = %s""",
                (alert_id, incident_id),
            )
    except Exception:
        log.exception("could not sync incident alert state")


def touch_incident(kind: str, client_ip: str) -> bool:
    """Record continued activity on the open incident for this source without
    adding a note. Returns False when no open incident exists."""
    try:
        with db.pool().connection() as conn:
            row = conn.execute(
                """UPDATE security_event
                   SET occurrences = occurrences + 1, last_seen_at = now(), updated_at = now()
                   WHERE id = (SELECT id FROM security_event
                               WHERE kind = %s AND client_ip = %s AND status IN ('new', 'investigating')
                                 AND last_seen_at > now() - make_interval(mins => %s)
                               ORDER BY id DESC LIMIT 1)
                   RETURNING id""",
                (kind, client_ip, INCIDENT_DEDUP_MINUTES),
            ).fetchone()
            return row is not None
    except Exception:
        log.exception("could not update incident activity")
        return False

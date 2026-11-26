"""Recording requests and incidents, and sending alerts.

Every record is written twice:
  * to PostgreSQL, which feeds the admin dashboard;
  * to stdout as one JSON line. On AWS the Docker awslogs driver ships stdout
    to CloudWatch Logs, where metric filters turn these lines into metrics and
    alarms, and the alarms notify the administrator through SNS.

The app also publishes high-severity incidents to SNS directly, so an alert
carries the offending IP and payload rather than only a metric breach.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone

from . import db
from .config import settings

log = logging.getLogger("queryguard.events")

_stdout_lock = threading.Lock()
_last_alert: dict[str, float] = {}
_alert_lock = threading.Lock()
_sns = None


def emit(record: dict) -> None:
    """One JSON object per line on stdout (CloudWatch-friendly)."""
    line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **record}, default=str)
    with _stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def record_request(row: dict) -> None:
    emit({"event": "request", **row})
    try:
        with db.pool().connection() as conn:
            conn.execute(
                """INSERT INTO request_log
                   (client_ip, method, path, status, verdict, source, score,
                    rule_ids, sample, username, latency_ms)
                   VALUES (%(client_ip)s, %(method)s, %(path)s, %(status)s, %(verdict)s,
                           %(source)s, %(score)s, %(rule_ids)s, %(sample)s,
                           %(username)s, %(latency_ms)s)""",
                row,
            )
    except Exception:  # logging must never break a response
        log.exception("could not write request_log")


def _sns_client():
    global _sns
    if _sns is None:
        import boto3

        _sns = boto3.client("sns", region_name=settings.aws_region)
    return _sns


def _send_alert(key: str, subject: str, message: str) -> str:
    """Returns the alert state stored with the incident."""
    now = time.time()
    with _alert_lock:
        last = _last_alert.get(key, 0.0)
        if now - last < settings.alert_cooldown_seconds:
            return "suppressed"
        _last_alert[key] = now

    if not settings.sns_topic_arn:
        emit({"event": "alert", "delivery": "logged", "subject": subject, "message": message})
        return "logged"
    try:
        _sns_client().publish(
            TopicArn=settings.sns_topic_arn,
            Subject=subject[:99],
            Message=message,
        )
        emit({"event": "alert", "delivery": "sns", "subject": subject})
        return "sent"
    except Exception:
        log.exception("SNS publish failed")
        return "failed"


def raise_incident(
    kind: str,
    severity: str,
    summary: str,
    *,
    client_ip: str | None = None,
    username: str | None = None,
    detail: dict | None = None,
    alert: bool = True,
) -> None:
    detail = detail or {}
    alert_state = "none"
    if alert and severity in {"medium", "high"}:
        body = "\n".join(
            [
                summary,
                "",
                f"Kind:      {kind}",
                f"Severity:  {severity}",
                f"Source IP: {client_ip or '-'}",
                f"User:      {username or '-'}",
                f"Time:      {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC",
                "",
                "Detail:",
                json.dumps(detail, indent=2, default=str)[:3000],
                "",
                "Review it on the QueryGuard security console (/security).",
            ]
        )
        alert_state = _send_alert(
            f"{kind}:{client_ip or username}",
            f"[QueryGuard] {severity.upper()}: {summary}",
            body,
        )

    emit({
        "event": "incident",
        "kind": kind,
        "severity": severity,
        "client_ip": client_ip,
        "username": username,
        "summary": summary,
        "alert": alert_state,
    })
    try:
        with db.pool().connection() as conn:
            conn.execute(
                """INSERT INTO security_event
                   (kind, severity, client_ip, username, summary, detail, alert)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (kind, severity, client_ip, username, summary,
                 json.dumps(detail, default=str), alert_state),
            )
    except Exception:
        log.exception("could not write security_event")

"""Component health checks and the background monitor that turns failures
into alerts (database outage, WAF misconfiguration, CloudWatch alarms)."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

import anyio

from . import cloud, db, detector, dlp, events
from .config import settings

log = logging.getLogger("queryguard.health")

STARTED_AT = time.time()
_db_down_since: float | None = None
_last_snapshot: dict = {}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_database() -> dict:
    t0 = time.perf_counter()
    try:
        with db.pool().connection(timeout=3) as conn:
            row = conn.execute(
                "SELECT version() AS v, (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()) AS c"
            ).fetchone()
        stats = db.pool().get_stats()
        return {"status": "healthy", "checked_at": _ts(),
                "metrics": {"latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                            "connections": row["c"], "pool_size": stats.get("pool_size"),
                            "pool_available": stats.get("pool_available")},
                "config": {"server": row["v"].split(",")[0],
                           "host": "Amazon RDS" if cloud.aws_mode() else settings.db_host}}
    except Exception as exc:
        return {"status": "down", "checked_at": _ts(), "error": exc.__class__.__name__}


def check_detector() -> dict:
    """Self-test: a known injection must block, a known-good value must pass."""
    t0 = time.perf_counter()
    bad = detector.inspect_fields([("query.q", "x' UNION SELECT username, password_hash FROM users--")])
    good = detector.inspect_fields([("query.q", "D'Souza")])
    ok = bad.verdict == "blocked" and good.verdict == "normal"
    return {"status": "healthy" if ok else "down", "checked_at": _ts(),
            "metrics": {"rules": len(detector.RULES), "self_test_us": int((time.perf_counter() - t0) * 1e6)},
            "detail": f"Self-test: known injection scored {bad.score} ({bad.verdict}); "
                      f"known-good input scored {good.score} ({good.verdict})."}


def check_dlp() -> dict:
    samples = {"email": ("ishita.gill42@example.in", dlp.mask_email),
               "phone": ("9876543210", dlp.mask_phone),
               "pan": ("ABCPG1234K", dlp.mask_pan),
               "account": ("123456789012", dlp.mask_account)}
    leaked = [k for k, (value, fn) in samples.items() if value in fn(value) or value[:-4] in fn(value)]
    return {"status": "down" if leaked else "healthy", "checked_at": _ts(),
            "metrics": {"masking_rules": len(samples)},
            "detail": "Self-test: every masking rule hides the original value."
            if not leaked else f"Masking self-test failed for: {', '.join(leaked)}"}


def snapshot() -> dict:
    """All component checks. AWS checks are cached for 30 s inside cloud.py."""
    components = {
        "api": {"status": "healthy", "checked_at": _ts(),
                "metrics": {"uptime_s": int(time.time() - STARTED_AT)},
                "config": {"environment": settings.app_env, "waf_mode": settings.waf_mode}},
        "database": check_database(),
        "detector": check_detector(),
        "dlp": check_dlp(),
        "waf": cloud.waf(),
        "cloudwatch": cloud.cloudwatch(),
        "sns": cloud.sns(events.last_sns_delivery()),
    }
    _last_snapshot.update(components)
    return components


async def monitor_loop(interval: int = 60) -> None:
    """Runs for the life of the app. Raises alerts on state changes."""
    global _db_down_since
    while True:
        try:
            await asyncio.sleep(interval)
            comps = await anyio.to_thread.run_sync(snapshot)

            if comps["database"]["status"] == "down":
                if _db_down_since is None:
                    _db_down_since = time.time()
                    log.error("database unreachable")
            elif _db_down_since is not None:
                downtime = int(time.time() - _db_down_since)
                _db_down_since = None
                # Persisted once the database is back.
                await anyio.to_thread.run_sync(lambda: events.create_alert(
                    "db_failure", "high", "Database connectivity was lost",
                    f"The app could not reach PostgreSQL for about {downtime} s. Requests during that "
                    f"period failed and were not logged.", dedup_key="db_failure"))

            if cloud.aws_mode() and comps["waf"]["status"] in {"error", "not_configured"}:
                await anyio.to_thread.run_sync(lambda: events.create_alert(
                    "waf_failure", "high", "AWS WAF could not be verified",
                    f"Web ACL check returned {comps['waf']['status']}: "
                    f"{comps['waf'].get('error') or comps['waf'].get('reason')}", dedup_key="waf_failure"))

            for alarm in comps["cloudwatch"].get("alarms", []):
                if alarm["state"] == "ALARM":
                    # CloudWatch already notifies SNS itself; record without re-sending.
                    await anyio.to_thread.run_sync(lambda a=alarm: events.create_alert(
                        "cloudwatch_alarm", "high", f"CloudWatch alarm: {a['name']}",
                        a["reason"] or f"{a['metric']} breached its threshold.",
                        dedup_key=f"cw:{a['name']}", notify=False))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("health monitor iteration failed")

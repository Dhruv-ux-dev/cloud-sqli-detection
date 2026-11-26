"""Runtime-adjustable security policy, detection rule state and the IP blocklist.

Values live in PostgreSQL so every change is persistent and audited; reads go
through a short cache so the request path does not hit the database each time.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from . import db
from .config import settings

log = logging.getLogger("queryguard.policy")

CACHE_SECONDS = 10


@dataclass(frozen=True)
class PolicyDef:
    key: str
    label: str
    description: str
    minimum: int
    maximum: int
    unit: str

    @property
    def default(self) -> int:
        return getattr(settings, self.key)


POLICIES: tuple[PolicyDef, ...] = (
    PolicyDef("repeat_attack_threshold", "Repeated attack threshold",
              "Flagged requests from one IP within the detection window before an incident is raised.",
              2, 100, "requests"),
    PolicyDef("failed_login_threshold", "Failed sign-in threshold",
              "Failed sign-ins from one IP within the window before a brute-force incident. Twice this "
              "number locks the IP out of sign-in.", 3, 50, "attempts"),
    PolicyDef("record_view_threshold", "Record view limit",
              "Customer records one user may open within the window before access is paused.",
              5, 500, "records"),
    PolicyDef("search_threshold", "Search limit",
              "Customer searches one user may run within the window before access is paused.",
              5, 1000, "searches"),
    PolicyDef("lockout_seconds", "Access pause length",
              "How long record access stays paused after bulk access.", 60, 86400, "seconds"),
    PolicyDef("alert_cooldown_seconds", "Alert cooldown",
              "Minimum time between notifications for the same source and alert type.", 30, 86400, "seconds"),
    PolicyDef("api_rate_limit", "API rate limit per IP",
              "API requests one IP may make within the window before the app answers 429 and raises an "
              "unusual-traffic incident.", 50, 100000, "requests"),
    PolicyDef("window_seconds", "Detection window",
              "Sliding window used by all of the counters above.", 60, 3600, "seconds"),
)
POLICY_BY_KEY = {p.key: p for p in POLICIES}

_lock = threading.Lock()
_policy_cache: tuple[float, dict[str, int]] | None = None
_rules_cache: tuple[float, frozenset[str]] | None = None
_block_cache: tuple[float, frozenset[str]] | None = None


def invalidate() -> None:
    global _policy_cache, _rules_cache, _block_cache
    with _lock:
        _policy_cache = _rules_cache = _block_cache = None


def policies() -> dict[str, int]:
    global _policy_cache
    now = time.time()
    with _lock:
        if _policy_cache and now - _policy_cache[0] < CACHE_SECONDS:
            return _policy_cache[1]
    values = {p.key: p.default for p in POLICIES}
    try:
        with db.pool().connection() as conn:
            for row in conn.execute("SELECT key, value FROM security_policy"):
                if row["key"] in values:
                    values[row["key"]] = row["value"]
    except Exception:
        log.warning("policy read failed; using defaults", exc_info=True)
    with _lock:
        _policy_cache = (now, values)
    return values


def get(key: str) -> int:
    return policies()[key]


def disabled_rules() -> frozenset[str]:
    global _rules_cache
    now = time.time()
    with _lock:
        if _rules_cache and now - _rules_cache[0] < CACHE_SECONDS:
            return _rules_cache[1]
    disabled: frozenset[str] = frozenset()
    try:
        with db.pool().connection() as conn:
            disabled = frozenset(
                r["rule_id"] for r in conn.execute("SELECT rule_id FROM rule_state WHERE NOT enabled")
            )
    except Exception:
        log.warning("rule state read failed; all rules enabled", exc_info=True)
    with _lock:
        _rules_cache = (now, disabled)
    return disabled


def blocked_ips() -> frozenset[str]:
    global _block_cache
    now = time.time()
    with _lock:
        if _block_cache and now - _block_cache[0] < CACHE_SECONDS:
            return _block_cache[1]
    ips: frozenset[str] = frozenset()
    try:
        with db.pool().connection() as conn:
            ips = frozenset(r["ip"] for r in conn.execute("SELECT ip FROM blocked_source WHERE active"))
    except Exception:
        log.warning("blocklist read failed", exc_info=True)
    with _lock:
        _block_cache = (now, ips)
    return ips

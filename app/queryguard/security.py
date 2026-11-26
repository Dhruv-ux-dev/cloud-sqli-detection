"""Sessions, role-based access control, password checks and the sliding-window
counters used for brute-force, repeated-attack and bulk-access detection."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable

import bcrypt
from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from . import db, policy
from .config import settings

SESSION_COOKIE = "qg_session"
SESSION_MAX_AGE = 8 * 3600
CSRF_HEADER = "x-northfield-csrf"

_serializer = URLSafeTimedSerializer(settings.secret_key or "unset", salt="qg-session")
# A real bcrypt hash of a random string, compared when the username does not
# exist so that both paths take the same time.
_DUMMY_HASH = bcrypt.hashpw(b"queryguard-timing-pad", bcrypt.gensalt(rounds=12))

ROLES = ("admin", "analyst", "viewer")
ROLE_LABELS = {"admin": "Administrator", "analyst": "Security analyst", "viewer": "Viewer"}

ALL = frozenset(ROLES)
OPS = frozenset({"admin", "analyst"})
ADMIN = frozenset({"admin"})

# Permission -> roles allowed. Enforced on the server by require(); the
# console only uses it to decide which controls to show.
PERMISSIONS: dict[str, frozenset[str]] = {
    "dashboard:view": ALL,
    "records:search": ALL,
    "traffic:view": ALL,
    "traffic:payload": OPS,          # raw matched input; viewers see it redacted
    "incidents:view": ALL,
    "incidents:manage": OPS,
    "alerts:view": ALL,
    "alerts:manage": OPS,
    "detection:view": ALL,
    "detection:manage": ADMIN,
    "simulation:run": OPS,
    "dlp:view": OPS,
    "dlp:reveal": ADMIN,
    "audit:view": OPS,               # analysts see operational records only
    "audit:view_all": ADMIN,
    "blocklist:manage": ADMIN,
    "infra:view": ALL,
    "analytics:view": ALL,
    "reports:export": OPS,
    "users:manage": ADMIN,
    "policy:view": OPS,
    "policy:manage": ADMIN,
    "config:view": ADMIN,
}
PRIVILEGED = {p for p, roles in PERMISSIONS.items() if roles == ADMIN}


@dataclass(frozen=True)
class User:
    username: str
    role: str
    id: int | None = None
    display_name: str | None = None
    epoch: int = 0

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def can(self, permission: str) -> bool:
        return self.role in PERMISSIONS.get(permission, frozenset())

    @property
    def permissions(self) -> list[str]:
        return sorted(p for p, roles in PERMISSIONS.items() if self.role in roles)


def issue_session(user: User) -> str:
    return _serializer.dumps({"u": user.username, "r": user.role, "e": user.epoch})


def read_session(token: str | None) -> User | None:
    """Signature and expiry check only (no database). Used for logging."""
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    return User(username=data["u"], role=data["r"], epoch=data.get("e", 0))


def check_password(password: str, stored_hash: str | None) -> bool:
    if stored_hash is None:
        bcrypt.checkpw(password.encode(), _DUMMY_HASH)
        return False
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


# ---------------------------------------------------------------- account lookup

_account_cache: dict[str, tuple[float, dict | None]] = {}
_account_lock = threading.Lock()
ACCOUNT_CACHE_SECONDS = 5


def invalidate_account(username: str | None = None) -> None:
    with _account_lock:
        if username is None:
            _account_cache.clear()
        else:
            _account_cache.pop(username, None)


def _account(username: str) -> dict | None:
    now = time.time()
    with _account_lock:
        hit = _account_cache.get(username)
        if hit and now - hit[0] < ACCOUNT_CACHE_SECONDS:
            return hit[1]
    with db.pool().connection() as conn:
        row = conn.execute(
            """SELECT id, username, role, display_name, is_active, session_epoch
               FROM users WHERE username = %s""",
            (username,),
        ).fetchone()
    with _account_lock:
        _account_cache[username] = (now, row)
    return row


def current_user(request: Request) -> User:
    """Valid signature, account still active, role and session epoch current."""
    token_user = read_session(request.cookies.get(SESSION_COOKIE))
    if token_user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    row = _account(token_user.username)
    if row is None or not row["is_active"] or row["session_epoch"] != token_user.epoch:
        raise HTTPException(status_code=401, detail="Your session ended. Sign in again.")
    user = User(username=row["username"], role=row["role"], id=row["id"],
                display_name=row["display_name"], epoch=row["session_epoch"])
    request.state.user = user
    return user


def require(permission: str) -> Callable[[Request], User]:
    """FastAPI dependency: the signed-in user must hold `permission`."""
    if permission not in PERMISSIONS:
        raise ValueError(f"unknown permission {permission}")

    def dependency(request: Request) -> User:
        user = current_user(request)
        if not user.can(permission):
            from . import audit, events  # local import: avoids a cycle at start-up
            from .middleware import request_ip

            ip = request_ip(request)
            audit.record("authz.denied", actor=user.username, actor_role=user.role,
                         resource=request.url.path, client_ip=ip, result="denied",
                         detail={"permission": permission, "method": request.method})
            if permission in PRIVILEGED:
                events.raise_incident(
                    "unauthorized_action", "medium",
                    f"{user.username} ({user.role}) tried an administrator-only action: {permission}",
                    client_ip=ip, username=user.username, endpoint=request.url.path,
                    detail={"permission": permission, "method": request.method},
                )
            raise HTTPException(status_code=403, detail="Your role does not allow this action.")
        return user

    return dependency


# Backwards-compatible names used by the original routes.
def require_admin(request: Request) -> User:
    return require("config:view")(request)


# ---------------------------------------------------------------- counters

class SlidingCounter:
    """Counts events per key inside a moving time window. Thread-safe.
    The window length is read from the security policy on every call."""

    def __init__(self, window: Callable[[], int]):
        self._window = window
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        window = self._window()
        with self._lock:
            q = self._events[key]
            q.append(now)
            while q and q[0] < now - window:
                q.popleft()
            return len(q)

    def count(self, key: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        window = self._window()
        with self._lock:
            q = self._events.get(key)
            if not q:
                return 0
            while q and q[0] < now - window:
                q.popleft()
            return len(q)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class Lockouts:
    """Temporary blocks on a key (user or IP) after bulk access."""

    def __init__(self) -> None:
        self._until: dict[str, float] = {}
        self._lock = threading.Lock()

    def lock(self, key: str, seconds: int) -> None:
        with self._lock:
            self._until[key] = time.time() + seconds

    def remaining(self, key: str) -> int:
        with self._lock:
            until = self._until.get(key)
            if until is None:
                return 0
            left = until - time.time()
            if left <= 0:
                del self._until[key]
                return 0
            return int(left) + 1


def _window() -> int:
    return policy.get("window_seconds")


attack_counter = SlidingCounter(_window)
failed_logins = SlidingCounter(_window)
record_views = SlidingCounter(_window)
searches = SlidingCounter(_window)
api_requests = SlidingCounter(_window)
lockouts = Lockouts()

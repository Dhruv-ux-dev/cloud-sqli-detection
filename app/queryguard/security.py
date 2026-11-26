"""Sessions, password checks and the sliding-window counters used for
brute-force, repeated-attack and bulk-access detection."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

import bcrypt
from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

SESSION_COOKIE = "qg_session"
SESSION_MAX_AGE = 8 * 3600

_serializer = URLSafeTimedSerializer(settings.secret_key or "unset", salt="qg-session")
# A real bcrypt hash of a random string, compared when the username does not
# exist so that both paths take the same time.
_DUMMY_HASH = bcrypt.hashpw(b"queryguard-timing-pad", bcrypt.gensalt(rounds=12))


@dataclass(frozen=True)
class User:
    username: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def issue_session(user: User) -> str:
    return _serializer.dumps({"u": user.username, "r": user.role})


def read_session(token: str | None) -> User | None:
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    return User(username=data["u"], role=data["r"])


def check_password(password: str, stored_hash: str | None) -> bool:
    if stored_hash is None:
        bcrypt.checkpw(password.encode(), _DUMMY_HASH)
        return False
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


def current_user(request: Request) -> User:
    user = read_session(request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return user


def require_admin(request: Request) -> User:
    user = current_user(request)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="This page is for administrators.")
    return user


class SlidingCounter:
    """Counts events per key inside a moving time window. Thread-safe."""

    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            q = self._events[key]
            q.append(now)
            while q and q[0] < now - self.window:
                q.popleft()
            return len(q)

    def count(self, key: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            q = self._events.get(key)
            if not q:
                return 0
            while q and q[0] < now - self.window:
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


attack_counter = SlidingCounter(settings.window_seconds)
failed_logins = SlidingCounter(settings.window_seconds)
record_views = SlidingCounter(settings.window_seconds)
searches = SlidingCounter(settings.window_seconds)
lockouts = Lockouts()

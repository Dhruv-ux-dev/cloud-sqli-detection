"""Runtime settings, read once from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    # Database. The bootstrap (admin) login creates the schema and the
    # least-privilege runtime role; the app then serves traffic as that role.
    db_host: str = field(default_factory=lambda: os.getenv("DB_HOST", "localhost"))
    db_port: int = field(default_factory=lambda: _int("DB_PORT", 5432))
    db_name: str = field(default_factory=lambda: os.getenv("DB_NAME", "queryguard"))
    db_sslmode: str = field(default_factory=lambda: os.getenv("DB_SSLMODE", "prefer"))
    db_admin_user: str | None = field(default_factory=lambda: os.getenv("DB_ADMIN_USER"))
    db_admin_password: str | None = field(default_factory=lambda: os.getenv("DB_ADMIN_PASSWORD"))
    # On AWS the RDS master password lives in Secrets Manager (managed by RDS).
    db_admin_secret_arn: str | None = field(default_factory=lambda: os.getenv("DB_ADMIN_SECRET_ARN"))
    db_app_role: str = field(default_factory=lambda: os.getenv("DB_APP_ROLE", "qg_app"))

    # Sessions and seeded accounts.
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))
    admin_password: str = field(default_factory=lambda: os.getenv("ADMIN_PASSWORD", ""))
    analyst_password: str = field(default_factory=lambda: os.getenv("ANALYST_PASSWORD", ""))
    cookie_secure: bool = field(default_factory=lambda: _bool("COOKIE_SECURE", False))

    # "aws": AWS WAF sits in front; the app still rejects high-confidence
    #        injections itself (defence in depth) and reads WAF metrics.
    # "emulated": no WAF available (local run); the app blocks like WAF would.
    # "off": no request blocking at all. Only for the controlled demo of what
    #        an unprotected endpoint leaks.
    waf_mode: str = field(default_factory=lambda: os.getenv("WAF_MODE", "emulated").lower())
    trust_proxy: bool = field(default_factory=lambda: _bool("TRUST_PROXY", False))
    enable_vulnerable_demo: bool = field(default_factory=lambda: _bool("ENABLE_VULNERABLE_DEMO", False))

    # AWS integration (all optional; features switch off when unset).
    aws_region: str | None = field(default_factory=lambda: os.getenv("AWS_REGION"))
    waf_web_acl_name: str | None = field(default_factory=lambda: os.getenv("WAF_WEB_ACL_NAME"))
    waf_web_acl_arn: str | None = field(default_factory=lambda: os.getenv("WAF_WEB_ACL_ARN"))
    waf_rule_metrics: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            m.strip() for m in os.getenv("WAF_RULE_METRICS", "").split(",") if m.strip()
        )
    )
    sns_topic_arn: str | None = field(default_factory=lambda: os.getenv("SNS_TOPIC_ARN"))

    # Detection thresholds.
    window_seconds: int = field(default_factory=lambda: _int("DETECTION_WINDOW_SECONDS", 300))
    repeat_attack_threshold: int = field(default_factory=lambda: _int("REPEAT_ATTACK_THRESHOLD", 5))
    failed_login_threshold: int = field(default_factory=lambda: _int("FAILED_LOGIN_THRESHOLD", 5))
    record_view_threshold: int = field(default_factory=lambda: _int("RECORD_VIEW_THRESHOLD", 25))
    search_threshold: int = field(default_factory=lambda: _int("SEARCH_THRESHOLD", 40))
    lockout_seconds: int = field(default_factory=lambda: _int("LOCKOUT_SECONDS", 600))
    alert_cooldown_seconds: int = field(default_factory=lambda: _int("ALERT_COOLDOWN_SECONDS", 300))
    search_row_limit: int = field(default_factory=lambda: _int("SEARCH_ROW_LIMIT", 25))

    def validate(self) -> None:
        if self.waf_mode not in {"aws", "emulated", "off"}:
            raise RuntimeError(f"WAF_MODE must be aws, emulated or off, got {self.waf_mode!r}")
        if len(self.secret_key) < 32:
            raise RuntimeError("SECRET_KEY must be set to at least 32 characters")
        if not self.admin_password or not self.analyst_password:
            raise RuntimeError("ADMIN_PASSWORD and ANALYST_PASSWORD must be set")
        if not (self.db_admin_secret_arn or (self.db_admin_user and self.db_admin_password)):
            raise RuntimeError("Set DB_ADMIN_SECRET_ARN, or DB_ADMIN_USER and DB_ADMIN_PASSWORD")


settings = Settings()

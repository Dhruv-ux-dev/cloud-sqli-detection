"""Unit tests for the SOC upgrade: no database needed."""

import pytest

from queryguard import detector
from queryguard.middleware import client_ip, query_preview, stored_matches, stored_sample
from queryguard.security import PERMISSIONS, PRIVILEGED, ROLES, User


# ---------------------------------------------------------------- detector metadata

def test_every_rule_has_console_metadata():
    for rule in detector.RULES:
        info = detector.RULE_INFO[rule.id]
        assert info["category"] in detector.CATEGORY_LABELS
        assert info["severity"] in detector.SEVERITY_ORDER
        assert len(info["explanation"]) > 30


def test_explain_contributions_sum_to_score():
    result = detector.inspect_fields([("query.q", "x' UNION SELECT username, password_hash FROM users--")])
    contributions = detector.explain(result)
    assert sum(c["weight"] for c in contributions) == result.score
    assert {c["rule_id"] for c in contributions} == set(result.rule_ids)


@pytest.mark.parametrize("payload,path,expected", [
    ("x' UNION SELECT a FROM b--", "/api/customers", "union"),
    ("x' AND pg_sleep(5)--", "/api/customers", "time"),
    ("x' AND (SELECT count(*) FROM pg_catalog.pg_tables) > 0--", "/api/customers", "boolean"),
    ("' UNION ALL SELECT table_name FROM information_schema.tables--", "/api/customers", "union"),
    ("admin'--", "/api/login", "auth_bypass"),
    ("%2527%2520OR%25201%253D1--", "/api/customers", "encoded"),
    ("＇ OR 1=1--", "/api/customers", "encoded"),
])
def test_categorize(payload, path, expected):
    result = detector.inspect_fields([("query.q", payload)])
    assert detector.categorize(result, path) == expected


def test_normal_traffic_has_no_category():
    result = detector.inspect_fields([("query.q", "Patiala")])
    assert detector.categorize(result, "/api/customers") is None


def test_disabled_rules_are_skipped_without_changing_other_weights():
    payload = [("query.q", "x' UNION SELECT a FROM b--")]
    full = detector.inspect_fields(payload)
    without_union = detector.inspect_fields(payload, disabled={"SQLI-UNION"})
    assert "SQLI-UNION" not in without_union.rule_ids
    assert without_union.score == full.score - detector.RULES_BY_ID["SQLI-UNION"].weight


def test_analyse_runs_the_real_detector_with_timings():
    out = detector.analyse([("query.q", "1 OR 1=1")], "/api/customers")
    assert out["result"].verdict == "blocked"
    assert set(out["timings_us"]) == {"normalisation", "detection", "scoring"}
    assert all(v >= 0 for v in out["timings_us"].values())


def test_verdict_reason_mentions_thresholds():
    blocked = detector.inspect_fields([("query.q", "1 OR 1=1")])
    assert str(detector.BLOCK_SCORE) in detector.verdict_reason(blocked)


# ---------------------------------------------------------------- middleware helpers

def test_password_field_snippets_are_redacted():
    result = detector.inspect_fields([("body.password", "' OR '1'='1"), ("body.username", "bob")])
    assert result.verdict == "blocked"
    for m in stored_matches(result):
        assert "OR '1'" not in m["snippet"]
    assert "redacted" in stored_sample(result)


def test_query_preview_hides_sensitive_parameters():
    scope = {"query_string": b"q=Patiala&token=abc123&session_id=xyz"}
    preview = query_preview(scope)
    assert "abc123" not in preview and "xyz" not in preview
    assert "q=Patiala" in preview


def test_client_ip_uses_rightmost_forwarded_entry(monkeypatch):
    import dataclasses

    from queryguard import middleware
    monkeypatch.setattr(middleware, "settings", dataclasses.replace(middleware.settings, trust_proxy=True))
    ip = client_ip({"client": ("10.0.0.5", 1)}, {"x-forwarded-for": "6.6.6.6, 203.0.113.9"})
    assert ip == "203.0.113.9"


# ---------------------------------------------------------------- RBAC

def test_roles_and_permissions():
    admin, analyst, viewer = (User("a", "admin"), User("b", "analyst"), User("c", "viewer"))
    assert all(admin.can(p) for p in PERMISSIONS)
    assert analyst.can("incidents:manage") and analyst.can("simulation:run")
    assert not analyst.can("users:manage") and not analyst.can("dlp:reveal") and not analyst.can("policy:manage")
    assert viewer.can("dashboard:view") and viewer.can("traffic:view")
    for p in ("incidents:manage", "dlp:reveal", "dlp:view", "simulation:run", "users:manage", "audit:view",
              "traffic:payload", "reports:export"):
        assert not viewer.can(p), p


def test_privileged_permissions_are_admin_only():
    assert PRIVILEGED == {p for p, roles in PERMISSIONS.items() if roles == frozenset({"admin"})}
    assert "dlp:reveal" in PRIVILEGED and "users:manage" in PRIVILEGED
    assert set(ROLES) == {"admin", "analyst", "viewer"}

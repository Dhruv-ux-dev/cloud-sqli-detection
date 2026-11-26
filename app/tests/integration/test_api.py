"""End-to-end tests against a running stack (docker compose up).

    BASE_URL=http://localhost:8000 pytest tests/integration

Needs the local test accounts from .env.example (admin, analyst, viewer).
DB_ADMIN_DSN (optional) enables the database-level audit immutability test.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

BASE = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
PASSWORDS = {
    "admin": os.environ.get("ADMIN_PASSWORD", "Admin@531local"),
    "analyst": os.environ.get("ANALYST_PASSWORD", "Analyst@531local"),
    "viewer": os.environ.get("VIEWER_PASSWORD", "Viewer@531local"),
}


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None, csrf=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if csrf and method != "GET":
            req.add_header("X-Northfield-CSRF", "1")
        try:
            with self.opener.open(req, timeout=30) as res:
                raw = res.read().decode()
                status = res.status
        except urllib.error.HTTPError as err:
            raw, status = err.read().decode(), err.code
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, raw

    def login(self, username, password=None):
        status, body = self.call("POST", "/api/login", {"username": username, "password": password or PASSWORDS[username]})
        assert status == 200, (username, status, body)
        return self


def q(value: str) -> str:
    return urllib.parse.quote(value, safe="")


@pytest.fixture(scope="module")
def admin():
    return Client().login("admin")


@pytest.fixture(scope="module")
def analyst():
    return Client().login("analyst")


@pytest.fixture(scope="module")
def viewer():
    return Client().login("viewer")


def latest_request(admin, **filters):
    status, d = admin.call("GET", "/api/traffic?page_size=5&" + urllib.parse.urlencode(filters))
    assert status == 200
    return d["items"][0]


# ---------------------------------------------------------------- detection and classification

def test_normal_request_is_allowed_and_logged(analyst, admin):
    status, d = analyst.call("GET", "/api/customers?q=Patiala")
    assert status == 200 and d["results"]
    row = latest_request(admin, endpoint="/api/customers", verdict="normal")
    assert row["score"] == 0 and row["rule_ids"] == []


def test_injection_is_blocked_with_rules_recorded(analyst, admin):
    status, d = analyst.call("GET", "/api/customers?q=" + q("x' UNION SELECT username, password_hash FROM users--"))
    assert status == 403 and "blocked_by" in d
    row = latest_request(admin, verdict="blocked")
    assert row["status"] == 403 and "SQLI-UNION" in row["rule_ids"] and row["score"] >= 8
    status, detail = admin.call("GET", f"/api/traffic/{row['id']}")
    assert status == 200
    assert sum(e["weight"] for e in detail["explanation"]) == detail["score"]
    assert detail["thresholds"] == {"suspicious": 3, "block": 8}


def test_low_score_input_is_suspicious_but_served(analyst, admin):
    status, _ = analyst.call("GET", "/api/customers?q=" + q("Patiala --"))
    assert status == 200
    row = latest_request(admin, verdict="suspicious")
    assert row["rule_ids"] == ["SQLI-COMMENT"] and 3 <= row["score"] < 8


def test_parameterised_query_treats_quote_as_data(analyst):
    status, d = analyst.call("GET", "/api/customers?q=" + q("D'Souza"))
    assert status == 200
    assert d["results"] and all("D'Souza" in r["full_name"] for r in d["results"])


def test_like_wildcards_are_escaped(analyst):
    status, d = analyst.call("GET", "/api/customers?q=" + q("%%"))
    assert status == 200 and d["results"] == []


# ---------------------------------------------------------------- DLP and authorisation

def test_search_and_detail_are_masked_for_analyst(analyst):
    _, d = analyst.call("GET", "/api/customers?q=Sharma")
    assert all("•" in r["email"] and "•" in r["account_no"] for r in d["results"])
    cid = d["results"][0]["id"]
    status, rec = analyst.call("GET", f"/api/customers/{cid}")
    assert status == 200 and rec["masked"] is True and "•" in rec["pan"]


def test_unauthorised_reveal_is_refused_logged_and_raised(analyst, admin):
    status, _ = analyst.call("POST", "/api/dlp/reveal", {"customer_id": 2, "reason": "integration test"})
    assert status == 403
    _, acc = admin.call("GET", "/api/dlp/access?access_type=reveal_denied&page_size=5")
    assert acc["items"][0]["username"] == "analyst" and acc["items"][0]["authorized"] is False
    _, aud = admin.call("GET", "/api/audit?action=dlp.reveal&result=denied&page_size=5")
    assert aud["items"][0]["actor"] == "analyst"
    _, inc = admin.call("GET", "/api/incidents?q=analyst&category=unauthorized_action&page_size=5")
    assert inc["items"], "unauthorized reveal should open an incident"


def test_admin_reveal_returns_full_values_and_is_audited(admin):
    status, rec = admin.call("POST", "/api/dlp/reveal", {"customer_id": 3, "reason": "integration test reveal"})
    assert status == 200 and rec["masked"] is False and "•" not in rec["email"]
    _, aud = admin.call("GET", "/api/audit?action=dlp.reveal&result=success&page_size=5")
    top = aud["items"][0]
    assert top["resource"] == "customer:3"
    assert rec["email"] not in json.dumps(top["detail"]), "audit must not contain the revealed value"


def test_viewer_permissions_are_enforced_by_api(viewer):
    assert viewer.call("GET", "/api/soc/overview?hours=24")[0] == 200
    for method, path, body in [
        ("GET", "/api/users", None), ("GET", "/api/audit", None), ("GET", "/api/dlp/overview", None),
        ("POST", "/api/simulations", {"category": "union", "target": "search", "payload_b64": "eA=="}),
        ("PATCH", "/api/incidents/1", {"status": "resolved"}), ("PUT", "/api/policies", {"values": {}, "reason": "nope!"}),
        ("GET", "/api/export/requests.csv?hours=24", None),
    ]:
        status, _ = viewer.call(method, path, body)
        assert status == 403, (method, path, status)


def test_viewer_sees_traffic_without_payloads(viewer):
    _, d = viewer.call("GET", "/api/traffic?verdict=blocked&page_size=5")
    assert d["items"] and all(r["sample"] in (None, "[hidden for your role]") for r in d["items"])


def test_analyst_cannot_manage_rules_or_users(analyst):
    assert analyst.call("PATCH", "/api/detection/rules/SQLI-UNION", {"enabled": False, "reason": "testing it"})[0] == 403
    assert analyst.call("GET", "/api/users")[0] == 403


# ---------------------------------------------------------------- incidents, alerts, audit

def test_incident_workflow_is_persisted_and_audited(admin):
    _, d = admin.call("GET", "/api/incidents?page_size=5&sort=ts&order=desc")
    inc = d["items"][0]
    status, after = admin.call("PATCH", f"/api/incidents/{inc['id']}",
                               {"status": "investigating", "assigned_to": "analyst", "note": "integration test note"})
    assert status == 200 and after["status"] == "investigating" and after["assigned_to"] == "analyst"
    assert any(n["body"] == "integration test note" for n in after["notes"])
    _, aud = admin.call("GET", f"/api/audit?q={inc['ref']}&page_size=5")
    assert aud["items"][0]["action"] == "incident.update"
    _, report = admin.call("GET", f"/api/incidents/{inc['id']}/report")
    assert report.startswith(f"# Incident report {inc['ref']}")


def test_repeated_injection_opens_one_incident_with_an_alert(admin):
    from datetime import datetime, timedelta, timezone
    started = datetime.now(timezone.utc) - timedelta(seconds=2)
    attacker = Client()
    for i in range(6):
        attacker.call("GET", "/api/customers?q=" + q(f"x' UNION SELECT {i} FROM users--"))
    time.sleep(0.5)
    _, d = admin.call("GET", "/api/incidents?category=sql_injection&status=new,investigating&page_size=20")
    # Only incidents this test produced (rows from before the dedup migration
    # were never merged and are not this test's concern).
    repeated = [i for i in d["items"] if "SQL injection attempts" in i["summary"]
                and datetime.fromisoformat(i["last_seen_at"]) >= started]
    assert repeated
    ips = [i["client_ip"] for i in repeated]
    assert len(ips) == len(set(ips)), "one open incident per source (deduplicated)"
    _, alerts = admin.call("GET", "/api/alerts?page_size=50")
    assert any(a["category"] in {"repeated_attack", "critical_sqli"} for a in alerts["items"])


def test_simulation_runs_real_detector_and_is_audited(analyst):
    def run(text, cat):
        return analyst.call("POST", "/api/simulations", {"category": cat, "target": "search",
                                                         "payload_b64": base64.b64encode(text.encode()).decode()})
    status, attack = run("x' UNION SELECT a FROM b--", "union")
    assert status == 200 and attack["verdict"] == "blocked" and attack["audit_id"]
    assert [s["stage"] for s in attack["pipeline"]][0] == "Input" and len(attack["pipeline"]) == 7
    status, benign = run("D'Souza", "control")
    assert status == 200 and benign["verdict"] == "normal" and benign["score"] == 0


def test_csrf_header_required_for_state_changes(admin):
    status, _ = admin.call("POST", "/api/alerts/read-all", csrf=False)
    assert status == 403


def test_errors_are_generic_and_validation_does_not_echo(admin):
    status, d = admin.call("GET", "/api/incidents/999999999")
    assert status == 404 and d == {"detail": "No incident has that ID."}
    status, d = admin.call("GET", "/api/traffic?verdict=" + q("<script>x</script>"))
    assert status == 422 and "<script>" not in json.dumps(d)


def test_pagination_is_server_side(admin):
    _, d = admin.call("GET", "/api/traffic?page_size=5&page=2")
    assert len(d["items"]) <= 5 and d["page"] == 2 and d["pages"] >= 1


def test_policy_validation_and_audit(admin):
    status, _ = admin.call("PUT", "/api/policies", {"values": {"record_view_threshold": 1}, "reason": "too low on purpose"})
    assert status == 400
    _, cur = admin.call("GET", "/api/policies")
    current = next(p for p in cur["items"] if p["key"] == "alert_cooldown_seconds")["value"]
    new = 301 if current != 301 else 300
    status, _ = admin.call("PUT", "/api/policies", {"values": {"alert_cooldown_seconds": new}, "reason": "integration test"})
    assert status == 200
    _, aud = admin.call("GET", "/api/audit?action=policy.update&page_size=5")
    assert aud["items"][0]["detail"]["changes"]["alert_cooldown_seconds"][1] == new


def test_blocklist_add_and_remove_are_audited(admin):
    ip = "203.0.113.77"
    assert admin.call("POST", "/api/blocklist", {"ip": ip, "reason": "integration test"})[0] == 200
    _, bl = admin.call("GET", "/api/blocklist")
    assert any(b["ip"] == ip and b["active"] for b in bl["items"])
    assert admin.call("DELETE", f"/api/blocklist/{ip}")[0] == 200
    _, aud = admin.call("GET", f"/api/audit?q={ip}&page_size=5")
    assert {a["action"] for a in aud["items"]} >= {"blocklist.add", "blocklist.remove"}
    assert admin.call("POST", "/api/blocklist", {"ip": "not-an-ip", "reason": "bad"})[0] == 422


def test_role_change_ends_existing_sessions(admin):
    name = f"it{int(time.time())}"
    password = "Integration1234"
    status, created = admin.call("POST", "/api/users", {"username": name, "display_name": "Integration test",
                                                        "role": "viewer", "password": password})
    assert status == 200
    user = Client().login(name, password)
    assert user.call("GET", "/api/me")[0] == 200
    assert admin.call("PATCH", f"/api/users/{created['id']}", {"role": "analyst"})[0] == 200
    assert user.call("GET", "/api/me")[0] == 401
    assert admin.call("PATCH", f"/api/users/{created['id']}", {"is_active": False})[0] == 200
    status, _ = Client().call("POST", "/api/login", {"username": name, "password": password})
    assert status == 401


def test_weak_password_rejected(admin):
    status, _ = admin.call("POST", "/api/users", {"username": "weakpw", "display_name": "Weak", "role": "viewer",
                                                  "password": "short"})
    assert status == 422


def test_health_and_local_mode_are_reported_truthfully(admin):
    _, d = admin.call("GET", "/api/health/components")
    c = d["components"]
    assert c["database"]["status"] == "healthy" and c["detector"]["status"] == "healthy" and c["dlp"]["status"] == "healthy"
    if d["mode"] == "local":
        for svc in ("waf", "cloudwatch"):
            assert c[svc]["status"] == "not_connected"
        _, infra = admin.call("GET", "/api/infra")
        for s in infra["services"]:
            if s["key"] in {"waf", "alb", "ec2", "cloudwatch"}:
                assert s["status"] == "not_connected" and not s.get("metrics"), s["key"]


@pytest.mark.skipif(not os.environ.get("DB_ADMIN_DSN"), reason="set DB_ADMIN_DSN to test the database itself")
def test_audit_log_is_append_only_even_for_the_owner():
    import psycopg

    with psycopg.connect(os.environ["DB_ADMIN_DSN"]) as conn:
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("UPDATE audit_log SET result = 'success' WHERE id = (SELECT min(id) FROM audit_log)")
        conn.rollback()
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("DELETE FROM audit_log WHERE id = (SELECT min(id) FROM audit_log)")


@pytest.mark.skipif(not os.environ.get("DB_APP_DSN"), reason="set DB_APP_DSN to test the runtime role")
def test_runtime_role_cannot_read_hashes_or_change_audit():
    import psycopg

    with psycopg.connect(os.environ["DB_APP_DSN"], autocommit=True) as conn:
        for stmt in ("SELECT password_hash FROM users", "DELETE FROM audit_log", "DROP TABLE customers",
                     "UPDATE audit_log SET result = 'success'"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(stmt)


def test_public_config_is_minimal_and_admin_config_is_protected(analyst, viewer):
    status, d = Client().call("GET", "/api/config")
    assert status == 200 and set(d) == {"waf_mode", "vulnerable_demo", "environment"}
    assert isinstance(d["vulnerable_demo"], bool)
    assert analyst.call("GET", "/api/admin/config")[0] == 403
    assert viewer.call("GET", "/api/admin/config")[0] == 403

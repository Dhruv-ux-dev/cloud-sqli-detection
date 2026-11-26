import pytest

from queryguard import detector, dlp

MALICIOUS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "1 OR 1=1",
    "' or ''='",
    "x' UNION SELECT username, password_hash, role FROM users--",
    "1; DROP TABLE customers",
    "1' AND (SELECT count(*) FROM pg_catalog.pg_tables) > 0--",
    "1' AND pg_sleep(5)--",
    "'/**/UNION/**/SELECT/**/null,null,null--",
    "%27%20OR%20%271%27%3D%271",            # URL-encoded
    "%2527%2520OR%25201%253D1--",           # double URL-encoded
    "＇ OR 1=1--",                      # full-width apostrophe
    "1' AND extractvalue(1, concat(0x7e, version()))--",
    "' UNION ALL SELECT table_name FROM information_schema.tables--",
]

BENIGN = [
    "Aarav Sharma",
    "Patiala",
    "D'Souza",
    "O'Neil",
    "Sector 17",
    "rock and roll",
    "union bank of india",
    "select a branch",
    "ishita.gill42@example.in",
    "Phase 7, Mohali",
    "100% cotton",
]


@pytest.mark.parametrize("payload", MALICIOUS)
def test_blocks_injection(payload):
    result = detector.inspect_fields([("query.q", payload)])
    assert result.verdict == "blocked", (payload, result)


@pytest.mark.parametrize("value", BENIGN)
def test_allows_normal_input(value):
    result = detector.inspect_fields([("query.q", value)])
    assert result.verdict == "normal", (value, result)


def test_trailing_comment_alone_is_only_suspicious():
    result = detector.inspect_fields([("query.q", "patiala --")])
    assert result.verdict == "suspicious"


def test_scanner_user_agent_is_suspicious():
    result = detector.inspect_fields([("header:user-agent", "sqlmap/1.8.2#stable (https://sqlmap.org)")])
    assert result.verdict == "suspicious"
    assert result.rule_ids == ["SCANNER-UA"]


def test_json_body_values_and_keys_are_inspected():
    fields = detector.flatten_json({"username": "admin' OR '1'='1", "password": "x"})
    assert detector.inspect_fields(fields).verdict == "blocked"


def test_masking():
    assert dlp.mask_email("ishita.gill42@example.in") == "i••••@example.in"
    assert dlp.mask_phone("9876543210").endswith("3210")
    assert "9876" not in dlp.mask_phone("9876543210")
    assert dlp.mask_account("123456789012").endswith("9012")
    assert dlp.escape_like("50%_off") == "50\\%\\_off"

#!/usr/bin/env python3
"""Send known SQL injection payloads (and harmless controls) to YOUR OWN
QueryGuard deployment and report which layer stopped each one.

Use only against a deployment you own, in the controlled test environment.
Standard library only, so it runs anywhere Python 3.9+ is installed.

    python3 tools/sqli_test.py                         # local, http://localhost:8000
    python3 tools/sqli_test.py --target http://<alb-dns-name>
    python3 tools/sqli_test.py --user analyst --password '...'   # also test signed-in search
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PAYLOADS = [
    ("Tautology", "' OR '1'='1"),
    ("Tautology, numeric", "1 OR 1=1"),
    ("Comment out password check", "admin'--"),
    ("Empty-string tautology", "' or ''='"),
    ("UNION extraction of hashes", "x' UNION SELECT username, password_hash, role FROM users--"),
    ("UNION extraction of PII", "x' UNION SELECT id, pan, account_no FROM customers--"),
    ("Stacked DROP", "x'; DROP TABLE customers;--"),
    ("Catalogue enumeration", "x' AND (SELECT count(*) FROM pg_catalog.pg_tables) > 0--"),
    ("Time-based blind", "x' AND pg_sleep(5)--"),
    ("Error-based", "x' AND extractvalue(1, concat(0x7e, version()))--"),
    ("Comment-obfuscated UNION", "x'/**/UNION/**/SELECT/**/null,null,null--"),
    ("Double URL-encoded", "%2527%2520OR%25201%253D1--"),
    ("Full-width apostrophe", "＇ OR 1=1--"),
    ("information_schema", "' UNION ALL SELECT table_name, null, null FROM information_schema.tables--"),
]

CONTROLS = [
    ("Plain surname", "Sharma"),
    ("Surname with apostrophe", "D'Souza"),
    ("City", "Patiala"),
    ("Words that look like SQL", "union bank"),
]


class Client:
    def __init__(self, base: str, user_agent: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.ua = user_agent

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, str]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("User-Agent", self.ua)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if method != "GET":
            req.add_header("X-Northfield-CSRF", "1")
        try:
            with self.opener.open(req, timeout=15) as res:
                return res.status, res.read().decode(errors="replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode(errors="replace")


def who_blocked(status: int, body: str) -> str:
    if status != 403:
        return ""
    try:
        data = json.loads(body)
    except ValueError:
        return "AWS WAF"
    return data.get("blocked_by", "app") if isinstance(data, dict) else "AWS WAF"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="http://localhost:8000")
    ap.add_argument("--user", help="sign in first so authenticated search is tested too")
    ap.add_argument("--password")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between requests")
    args = ap.parse_args()

    client = Client(args.target, "QueryGuard-test/1.0")
    if args.user:
        status, _ = client.request("POST", "/api/login", {"username": args.user, "password": args.password or ""})
        if status != 200:
            print(f"Sign-in as {args.user} failed with status {status}.", file=sys.stderr)
            return 2

    rows = []
    for kind, cases in (("attack", PAYLOADS), ("control", CONTROLS)):
        for name, payload in cases:
            for where, method, path, body in (
                ("search", "GET", "/api/customers?q=" + urllib.parse.quote(payload, safe="%"), None),
                ("login", "POST", "/api/login", {"username": payload, "password": "x"}),
            ):
                status, text = client.request(method, path, body)
                rows.append((kind, name, where, status, who_blocked(status, text)))
                time.sleep(args.delay)

    width = max(len(r[1]) for r in rows)
    print(f"\nTarget: {args.target}\n")
    print(f"{'':8}{'Case':<{width}}  {'Where':<7} {'Status':<7} Result")
    for kind, name, where, status, blocker in rows:
        if kind == "attack":
            result = f"blocked by {blocker}" if blocker else "NOT BLOCKED"
        else:
            result = f"FALSE POSITIVE, blocked by {blocker}" if blocker else "passed (expected)"
        print(f"{kind:<8}{name:<{width}}  {where:<7} {status:<7} {result}")

    attacks = [r for r in rows if r[0] == "attack"]
    controls = [r for r in rows if r[0] == "control"]
    blocked = sum(1 for r in attacks if r[4])
    false_pos = sum(1 for r in controls if r[4])
    print(f"\nAttacks blocked: {blocked}/{len(attacks)} ({100 * blocked / len(attacks):.0f}%)")
    print(f"False positives: {false_pos}/{len(controls)}")
    return 0 if blocked == len(attacks) and false_pos == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

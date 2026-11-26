#!/usr/bin/env python3
"""Generate demo traffic against YOUR OWN QueryGuard deployment so the
security console has something to show.

    python3 tools/traffic.py normal --user analyst --password '...' --count 60
    python3 tools/traffic.py bruteforce           # failed sign-ins -> incident + alert
    python3 tools/traffic.py bulk --user analyst --password '...'
                                                  # many record views -> lockout + alert
    python3 tools/traffic.py scanner              # repeated injections -> incident + alert

Add --target http://<alb-dns-name> for the AWS deployment.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import urllib.parse

from sqli_test import PAYLOADS, Client

SEARCHES = ["Sharma", "Gill", "Patiala", "Mohali", "Sector 17", "Kapoor", "Arora", "D'Souza",
            "Ludhiana", "Meera", "Kabir", "Sandhu", "Amritsar", "Phase 7", "Bansal"]


def sign_in(client: Client, user: str | None, password: str | None) -> None:
    if not user:
        sys.exit("This scenario needs --user and --password.")
    status, _ = client.request("POST", "/api/login", {"username": user, "password": password or ""})
    if status != 200:
        sys.exit(f"Sign-in as {user} failed with status {status}.")


def normal(client: Client, args) -> None:
    sign_in(client, args.user, args.password)
    views = 0
    for i in range(args.count):
        q = random.choice(SEARCHES)
        status, body = client.request("GET", "/api/customers?q=" + urllib.parse.quote(q))
        print(f"{i + 1:>3} search {q!r}: {status}")
        # Open a record now and then, staying under the bulk-access threshold.
        if status == 200 and views < 15 and random.random() < 0.35:
            import json
            results = json.loads(body)["results"]
            if results:
                cid = random.choice(results)["id"]
                client.request("GET", f"/api/customers/{cid}")
                views += 1
        time.sleep(args.delay)


def bruteforce(client: Client, args) -> None:
    for i in range(args.count or 8):
        status, _ = client.request("POST", "/api/login", {"username": "admin", "password": f"guess{i}"})
        print(f"{i + 1:>3} wrong password: {status}")
        time.sleep(args.delay)


def bulk(client: Client, args) -> None:
    sign_in(client, args.user, args.password)
    for cid in range(1, (args.count or 30) + 1):
        status, _ = client.request("GET", f"/api/customers/{cid}")
        print(f"{cid:>3} view customer {cid}: {status}")
        if status == 429:
            print("Access paused by the bulk-access guard, as intended.")
            break
        time.sleep(args.delay / 3)


def scanner(client: Client, args) -> None:
    client.ua = "sqlmap/1.8 (demo)"
    for i in range(args.count or 12):
        name, payload = PAYLOADS[i % len(PAYLOADS)]
        status, _ = client.request("GET", "/api/customers?q=" + urllib.parse.quote(payload, safe="%"))
        print(f"{i + 1:>3} {name}: {status}")
        time.sleep(args.delay)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", choices=["normal", "bruteforce", "bulk", "scanner"])
    ap.add_argument("--target", default="http://localhost:8000")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--delay", type=float, default=0.4)
    args = ap.parse_args()
    if args.scenario == "normal" and not args.count:
        args.count = 40
    client = Client(args.target, "Mozilla/5.0 (QueryGuard demo traffic)")
    {"normal": normal, "bruteforce": bruteforce, "bulk": bulk, "scanner": scanner}[args.scenario](client, args)


if __name__ == "__main__":
    main()

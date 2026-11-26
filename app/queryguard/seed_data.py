"""Deterministic fake customer records. Every name and number is invented."""

from __future__ import annotations

import random
import string
from datetime import date, timedelta

FIRST = [
    "Aarav", "Ishita", "Kabir", "Meera", "Rohan", "Sanya", "Vivaan", "Anaya", "Arjun",
    "Diya", "Reyansh", "Kiara", "Aditya", "Nysa", "Ayaan", "Riya", "Kunal", "Tara",
    "Nikhil", "Pooja", "Harjot", "Simran", "Gurpreet", "Navneet", "Jaspreet", "Manav",
    "Tanvi", "Yash", "Avni", "Dev", "Lakshya", "Prisha", "Rahul", "Neha", "Siddharth",
]
LAST = [
    "Sharma", "Verma", "Gill", "Sandhu", "Bansal", "Goyal", "Kapoor", "Malhotra",
    "Sidhu", "Chawla", "Arora", "Mehta", "Bhatia", "Grewal", "Dhillon", "Khanna",
    "Saini", "Jindal", "Sethi", "Ahuja", "Brar", "Kohli", "Nanda", "Puri",
]
# One O'Brien-style surname so a legitimate apostrophe search can be shown
# going through untouched.
LAST_SPECIAL = ["D'Souza", "O'Neil"]
CITIES = {
    "Patiala": ["Leela Bhawan", "Tripuri"],
    "Chandigarh": ["Sector 17", "Sector 35"],
    "Ludhiana": ["Ghumar Mandi", "Sarabha Nagar"],
    "Amritsar": ["Lawrence Road"],
    "Mohali": ["Phase 7"],
    "Bathinda": ["Mall Road"],
}


def _pan(rng: random.Random, last: str) -> str:
    letters = "".join(rng.choices(string.ascii_uppercase, k=3))
    initial = (last[0] if last[0].isalpha() else "X").upper()
    digits = f"{rng.randint(0, 9999):04d}"
    return f"{letters}P{initial}{digits}{rng.choice(string.ascii_uppercase)}"


def generate(count: int = 240) -> list[dict]:
    rng = random.Random(531)
    rows = []
    for i in range(count):
        first = rng.choice(FIRST)
        last = rng.choice(LAST_SPECIAL) if i % 37 == 5 else rng.choice(LAST)
        city = rng.choice(list(CITIES))
        email_last = last.replace("'", "").lower()
        rows.append({
            "full_name": f"{first} {last}",
            "email": f"{first.lower()}.{email_last}{rng.randint(1, 99)}@example.in",
            "phone": f"{rng.choice('6789')}{rng.randint(0, 999_999_999):09d}",
            "city": city,
            "branch": rng.choice(CITIES[city]),
            "pan": _pan(rng, last),
            "account_no": f"{rng.randint(10**11, 10**12 - 1)}",
            "balance": round(rng.lognormvariate(11, 1.1), 2),
            "opened_on": date(2012, 1, 1) + timedelta(days=rng.randint(0, 4900)),
        })
    return rows

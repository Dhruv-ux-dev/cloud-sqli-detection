"""Data leak prevention: what leaves the API, and how much of it.

* Identifiers (email, phone, PAN, account number) are masked in every list
  response and for every non-admin user.
* An admin can reveal one record's full details; each reveal is recorded.
* Searches return at most SEARCH_ROW_LIMIT rows with explicit columns.
* Bulk access (many record views or searches in a short window) locks the
  user out for a while and raises an incident.
"""

from __future__ import annotations

from decimal import Decimal

MASK = "•"  # bullet


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return MASK * 6
    return f"{local[:1]}{MASK * 4}@{domain}"


def mask_phone(phone: str) -> str:
    return MASK * max(len(phone) - 4, 4) + phone[-4:]


def mask_pan(pan: str) -> str:
    return MASK * 6 + pan[-4:]


def mask_account(account_no: str) -> str:
    return f"{MASK * 4} {MASK * 4} {account_no[-4:]}"


def balance_band(balance: Decimal | float) -> str:
    value = float(balance)
    if value < 50_000:
        return "Under ₹50k"
    if value < 2_00_000:
        return "₹50k – ₹2L"
    if value < 10_00_000:
        return "₹2L – ₹10L"
    return "Over ₹10L"


def summary_row(row: dict) -> dict:
    """Shape used in search results: always masked."""
    return {
        "id": row["id"],
        "full_name": row["full_name"],
        "city": row["city"],
        "branch": row["branch"],
        "email": mask_email(row["email"]),
        "account_no": mask_account(row["account_no"]),
    }


def detail_row(row: dict, reveal: bool) -> dict:
    if reveal:
        return {
            **{k: row[k] for k in ("id", "full_name", "city", "branch", "email", "phone",
                                   "pan", "account_no")},
            "balance": f"₹{Decimal(row['balance']):,.2f}",
            "opened_on": row["opened_on"].isoformat(),
            "masked": False,
        }
    return {
        "id": row["id"],
        "full_name": row["full_name"],
        "city": row["city"],
        "branch": row["branch"],
        "email": mask_email(row["email"]),
        "phone": mask_phone(row["phone"]),
        "pan": mask_pan(row["pan"]),
        "account_no": mask_account(row["account_no"]),
        "balance": balance_band(row["balance"]),
        "opened_on": str(row["opened_on"].year),
        "masked": True,
    }


def escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

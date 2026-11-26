"""Data Protection Center: what sensitive data was touched, by whom, and how."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import audit, db, dlp, events
from ..middleware import request_ip
from ..policy import get as policy_get
from ..security import PERMISSIONS, User, require
from .common import Page, Window, empty_series, paged, paging, window

router = APIRouter(prefix="/api/dlp", tags=["dlp"])

DETAIL_FIELDS = ["email", "phone", "pan", "account_no", "balance"]


@router.get("/overview")
def overview(w: Window = Depends(window), user: User = Depends(require("dlp:view"))):
    p = {"start": w.start, "bucket": w.bucket}
    with db.pool().connection() as conn:
        customers = conn.execute("SELECT count(*) AS n FROM customers").fetchone()["n"]
        k = conn.execute(
            """SELECT count(DISTINCT customer_id) FILTER (WHERE customer_id IS NOT NULL) AS records_accessed,
                      coalesce(sum(row_count) FILTER (WHERE access_type = 'search'), 0)
                        + count(*) FILTER (WHERE access_type IN ('masked_view', 'sample')) AS masked_responses,
                      count(*) FILTER (WHERE access_type = 'reveal') AS reveals,
                      count(*) FILTER (WHERE access_type = 'reveal_denied') AS denied,
                      count(*) AS events
               FROM dlp_access WHERE ts >= %(start)s""", p).fetchone()
        fields = {r["f"]: r for r in conn.execute(
            """SELECT f, count(*) AS n,
                      count(*) FILTER (WHERE access_type = 'reveal') AS revealed
               FROM dlp_access, unnest(fields) AS f WHERE ts >= %(start)s GROUP BY f""", p)}
        tl = conn.execute(
            """SELECT floor(extract(epoch FROM ts) / %(bucket)s)::bigint * %(bucket)s AS b, access_type, count(*) AS n
               FROM dlp_access WHERE ts >= %(start)s GROUP BY 1, 2""", p).fetchall()
        users = conn.execute(
            """SELECT username, role, count(*) AS events,
                      count(*) FILTER (WHERE access_type = 'reveal') AS reveals,
                      count(*) FILTER (WHERE access_type = 'reveal_denied') AS denied,
                      max(ts) AS last_access
               FROM dlp_access WHERE ts >= %(start)s GROUP BY 1, 2 ORDER BY events DESC LIMIT 10""", p).fetchall()
        incidents = conn.execute(
            """SELECT count(*) FILTER (WHERE kind = 'bulk_access') AS bulk,
                      count(*) FILTER (WHERE kind = 'unauthorized_action') AS unauthorized
               FROM security_event WHERE ts >= %(start)s""", p).fetchone()

    series = empty_series(w, ("search", "masked_view", "reveal", "reveal_denied", "sample"))
    for r in tl:
        if r["b"] in series:
            series[r["b"]][r["access_type"]] = r["n"]
    reveal_roles = sorted(PERMISSIONS["dlp:reveal"])
    return {
        "hours": w.hours, "bucket_seconds": w.bucket,
        "kpis": {"customers": customers, **k},
        "categories": [{"field": f, "label": label, "accesses": fields.get(f, {}).get("n", 0),
                        "revealed": fields.get(f, {}).get("revealed", 0)}
                       for f, label in dlp.SENSITIVE_FIELDS.items()],
        "timeline": list(series.values()), "users": users,
        "controls": [
            {"name": "Sensitive data masking", "status": "enforced",
             "detail": "Email, phone, PAN and account numbers are masked in every search result and for every "
                       "role without reveal permission. Balances are shown as a range."},
            {"name": "Role-based data visibility", "status": "enforced",
             "detail": f"Only {', '.join(reveal_roles)} may reveal full details. Viewers cannot open the Data "
                       f"Protection Center."},
            {"name": "Full-data reveal authorization", "status": "enforced",
             "detail": "Every reveal needs an explicit action and a stated reason; denied attempts open an "
                       "unauthorized-action incident."},
            {"name": "Access logging", "status": "enforced",
             "detail": "Each search, view and reveal is logged with user, record and field names. Values are "
                       "never logged."},
            {"name": "Bulk access rate limiting", "status": "enforced",
             "detail": f"More than {policy_get('record_view_threshold')} record views or "
                       f"{policy_get('search_threshold')} searches per {policy_get('window_seconds') // 60} min "
                       f"pauses access for {policy_get('lockout_seconds') // 60} min. "
                       f"Bulk-access incidents this period: {incidents['bulk']}."},
            {"name": "Result size limit", "status": "enforced",
             "detail": "Searches return at most 25 rows with explicit columns only."},
        ],
        "can_reveal": user.can("dlp:reveal"),
    }


@router.get("/sample")
def sample(request: Request, user: User = Depends(require("dlp:view"))):
    """A handful of real records, masked, for the masking demonstration."""
    with db.pool().connection() as conn:
        rows = conn.execute(
            """SELECT id, full_name, email, phone, city, branch, pan, account_no, balance, opened_on
               FROM customers ORDER BY id LIMIT 6""").fetchall()
    dlp.record_access(user.username, user.role, "sample", authorized=True,
                      fields=["email", "phone", "pan", "account_no"], row_count=len(rows),
                      client_ip=request_ip(request))
    return {"items": [dlp.detail_row(r, reveal=False) for r in rows], "can_reveal": user.can("dlp:reveal")}


class RevealBody(BaseModel):
    customer_id: int = Field(ge=1)
    reason: str = Field(min_length=5, max_length=300)


@router.post("/reveal")
def reveal(body: RevealBody, request: Request, user: User = Depends(require("dlp:view"))):
    ip = request_ip(request)
    if not user.can("dlp:reveal"):
        dlp.record_access(user.username, user.role, "reveal_denied", authorized=False,
                          customer_id=body.customer_id, fields=DETAIL_FIELDS, client_ip=ip)
        audit.record("dlp.reveal", actor=user.username, actor_role=user.role,
                     resource=f"customer:{body.customer_id}", client_ip=ip, result="denied",
                     detail={"reason_given": body.reason})
        events.raise_incident(
            "unauthorized_action", "medium",
            f"{user.username} ({user.role}) tried to reveal unmasked details of customer {body.customer_id}",
            client_ip=ip, username=user.username, endpoint="/api/dlp/reveal",
            detail={"customer_id": body.customer_id})
        raise HTTPException(403, "Your role cannot reveal unmasked customer data.")
    with db.pool().connection() as conn:
        row = conn.execute(
            """SELECT id, full_name, email, phone, city, branch, pan, account_no, balance, opened_on
               FROM customers WHERE id = %s""", (body.customer_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "No customer has that ID.")
    dlp.record_access(user.username, user.role, "reveal", authorized=True, customer_id=body.customer_id,
                      fields=DETAIL_FIELDS, client_ip=ip)
    audit.record("dlp.reveal", actor=user.username, actor_role=user.role,
                 resource=f"customer:{body.customer_id}", client_ip=ip,
                 detail={"fields": DETAIL_FIELDS, "reason_given": body.reason})
    events.raise_incident(
        "pii_reveal", "informational",
        f"{user.username} viewed unmasked details of customer {body.customer_id}",
        client_ip=ip, username=user.username, endpoint="/api/dlp/reveal",
        detail={"customer_id": body.customer_id, "reason": body.reason}, alert=False)
    return dlp.detail_row(row, reveal=True)


@router.get("/access")
def access_log(
    p: Page = Depends(paging),
    username: str | None = Query(None, max_length=64),
    access_type: str | None = Query(None, pattern="^(search|masked_view|reveal|reveal_denied|sample)$"),
    authorized: bool | None = None,
    user: User = Depends(require("dlp:view")),
):
    params = {"u": username, "t": access_type, "a": authorized, "limit": p.page_size, "offset": p.offset}
    where = """(%(u)s::text IS NULL OR username = %(u)s) AND (%(t)s::text IS NULL OR access_type = %(t)s)
               AND (%(a)s::boolean IS NULL OR authorized = %(a)s)"""
    with db.pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM dlp_access WHERE {where}", params).fetchone()["n"]
        rows = conn.execute(
            f"""SELECT id, ts, username, role, customer_id, fields, access_type, authorized, row_count, client_ip
                FROM dlp_access WHERE {where} ORDER BY id DESC LIMIT %(limit)s OFFSET %(offset)s""",
            params).fetchall()
    return paged(rows, total, p)

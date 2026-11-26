"""Helpers shared by the API routers."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Time range (hours) -> chart bucket size (seconds).
RANGES = {1: 120, 6: 900, 24: 3600, 168: 6 * 3600, 720: 86400}

SEVERITIES = ("critical", "high", "medium", "low", "informational")
INCIDENT_STATUSES = ("new", "investigating", "resolved", "false_positive")


class Window(BaseModel):
    hours: int
    bucket: int
    start: datetime
    end: datetime
    prev_start: datetime


def window(hours: int = Query(24)) -> Window:
    if hours not in RANGES:
        raise HTTPException(400, f"hours must be one of {sorted(RANGES)}")
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    return Window(hours=hours, bucket=RANGES[hours], start=start, end=end,
                  prev_start=start - timedelta(hours=hours))


class Page(BaseModel):
    page: int
    page_size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def paging(page: int = Query(1, ge=1, le=10000), page_size: int = Query(25, ge=5, le=100)) -> Page:
    return Page(page=page, page_size=page_size)


def paged(rows: list[dict], total: int, p: Page) -> dict:
    return {"items": rows, "total": total, "page": p.page, "page_size": p.page_size,
            "pages": max(1, -(-total // p.page_size))}


def empty_series(w: Window, keys: tuple[str, ...]) -> dict[int, dict]:
    first = int(w.start.timestamp()) // w.bucket * w.bucket
    return {b: {"t": b, **{k: 0 for k in keys}}
            for b in range(first, int(w.end.timestamp()) + 1, w.bucket)}


def csv_response(filename: str, header: list[str], rows: list[list]) -> StreamingResponse:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for row in rows:
        # Neutralise spreadsheet formula injection in exported cells.
        writer.writerow([("'" + v) if isinstance(v, str) and v[:1] in "=+-@" else v for v in row])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def incident_ref(i: int) -> str:
    return f"INC-{i:06d}"


def request_ref(i: int) -> str:
    return f"REQ-{i:07d}"


def audit_ref(i: int) -> str:
    return f"AUD-{i:07d}"

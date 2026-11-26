"""Reads AWS WAF numbers for the dashboard.

Requests that AWS WAF blocks never reach the app, so the app cannot count
them itself. In AWS mode the dashboard adds:
  * BlockedRequests / AllowedRequests from CloudWatch (namespace AWS/WAFV2);
  * the last few blocked requests from WAF's sampled-requests API
    (WAF keeps samples for 3 hours).
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from .config import settings

log = logging.getLogger("queryguard.aws")

_cache: dict[tuple, tuple[float, dict]] = {}
_cache_lock = threading.Lock()
CACHE_SECONDS = 30


def enabled() -> bool:
    return settings.waf_mode == "aws" and bool(settings.waf_web_acl_name and settings.aws_region)


def _cached(key: tuple, fn):
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    value = fn()
    with _cache_lock:
        _cache[key] = (now, value)
    return value


def waf_overview(start: datetime, end: datetime, bucket_seconds: int) -> dict:
    if not enabled():
        return {"available": False, "reason": "WAF metrics are read only when WAF_MODE=aws."}
    key = (int(start.timestamp()) // CACHE_SECONDS, int(end.timestamp()) // CACHE_SECONDS, bucket_seconds)
    return _cached(key, lambda: _load(start, end, bucket_seconds))


def _load(start: datetime, end: datetime, bucket_seconds: int) -> dict:
    import boto3

    out: dict = {"available": True, "blocked": 0, "allowed": 0, "timeline": {}, "samples": []}
    try:
        cw = boto3.client("cloudwatch", region_name=settings.aws_region)
        dims = [
            {"Name": "WebACL", "Value": settings.waf_web_acl_name},
            {"Name": "Region", "Value": settings.aws_region},
            {"Name": "Rule", "Value": "ALL"},
        ]
        period = max(60, (bucket_seconds // 60) * 60)
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": metric_id,
                    "MetricStat": {
                        "Metric": {"Namespace": "AWS/WAFV2", "MetricName": name, "Dimensions": dims},
                        "Period": period,
                        "Stat": "Sum",
                    },
                }
                for metric_id, name in (("blocked", "BlockedRequests"), ("allowed", "AllowedRequests"))
            ],
            StartTime=start,
            EndTime=end,
        )
        for series in resp["MetricDataResults"]:
            total = int(sum(series["Values"]))
            out[series["Id"]] = total
            if series["Id"] == "blocked":
                for ts, value in zip(series["Timestamps"], series["Values"]):
                    bucket = int(ts.timestamp()) // bucket_seconds * bucket_seconds
                    out["timeline"][bucket] = out["timeline"].get(bucket, 0) + int(value)
    except Exception as exc:  # permissions, throttling, no data yet
        log.warning("CloudWatch WAF metrics unavailable: %s", exc)
        out["error"] = f"CloudWatch: {exc.__class__.__name__}"

    if settings.waf_web_acl_arn and settings.waf_rule_metrics:
        try:
            waf = boto3.client("wafv2", region_name=settings.aws_region)
            now = datetime.now(timezone.utc)
            window = {"StartTime": max(start, now - timedelta(hours=3) + timedelta(seconds=30)),
                      "EndTime": now}
            for metric in settings.waf_rule_metrics:
                resp = waf.get_sampled_requests(
                    WebAclArn=settings.waf_web_acl_arn,
                    RuleMetricName=metric,
                    Scope="REGIONAL",
                    TimeWindow=window,
                    MaxItems=50,
                )
                for s in resp.get("SampledRequests", []):
                    if s.get("Action") != "BLOCK":
                        continue
                    req = s["Request"]
                    out["samples"].append({
                        "ts": s["Timestamp"].isoformat(),
                        "client_ip": req.get("ClientIP"),
                        "country": req.get("Country"),
                        "method": req.get("Method"),
                        "uri": req.get("URI"),
                        "rule": s.get("RuleNameWithinRuleGroup") or metric,
                    })
            out["samples"].sort(key=lambda s: s["ts"], reverse=True)
            out["samples"] = out["samples"][:40]
        except Exception as exc:
            log.warning("WAF sampled requests unavailable: %s", exc)
            out["samples_error"] = f"WAF: {exc.__class__.__name__}"
    return out

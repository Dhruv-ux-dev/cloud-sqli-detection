"""Live AWS integrations for the infrastructure monitor.

Every function returns what AWS actually answered, or an explicit
"not_connected" / "not_configured" / "error" state. Nothing here invents a
metric: in local mode the AWS services are reported as not connected.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from .config import settings

log = logging.getLogger("queryguard.cloud")

CACHE_SECONDS = 30
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def aws_mode() -> bool:
    return settings.waf_mode == "aws" and bool(settings.aws_region)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cached(key: str, fn) -> dict:
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    try:
        value = fn()
    except Exception as exc:  # credentials, permissions, throttling, network
        log.warning("%s check failed: %s", key, exc)
        value = {"status": "error", "error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
    value.setdefault("checked_at", _now())
    with _lock:
        _cache[key] = (now, value)
    return value


def _client(service: str):
    import boto3

    return boto3.client(service, region_name=settings.aws_region)


def _not_connected(reason: str = "Local mode: this AWS service is not connected.") -> dict:
    return {"status": "not_connected", "error": None, "reason": reason, "checked_at": _now()}


def _metric_sum(namespace: str, metric: str, dims: dict, minutes: int = 60, stat: str = "Sum",
                period: int = 300) -> float | None:
    end = datetime.now(timezone.utc)
    resp = _client("cloudwatch").get_metric_statistics(
        Namespace=namespace, MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()],
        StartTime=end - timedelta(minutes=minutes), EndTime=end, Period=period, Statistics=[stat],
    )
    points = resp.get("Datapoints", [])
    if not points:
        return None
    if stat == "Sum":
        return float(sum(p["Sum"] for p in points))
    latest = max(points, key=lambda p: p["Timestamp"])
    return float(latest[stat])


# ---------------------------------------------------------------- services

def waf() -> dict:
    if not aws_mode():
        return _not_connected("Local mode: AWS WAF is not in front of this app. The app's own filter emulates it.")
    if not (settings.waf_web_acl_arn and settings.waf_web_acl_name):
        return {"status": "not_configured", "reason": "WAF_WEB_ACL_ARN / WAF_WEB_ACL_NAME are not set."}

    def load():
        acl_id = settings.waf_web_acl_arn.rsplit("/", 1)[-1]
        acl = _client("wafv2").get_web_acl(Name=settings.waf_web_acl_name, Scope="REGIONAL", Id=acl_id)["WebACL"]
        rules = []
        for r in acl.get("Rules", []):
            st = r.get("Statement", {})
            kind = ("managed: " + st["ManagedRuleGroupStatement"]["Name"]) if "ManagedRuleGroupStatement" in st \
                else "rate-based" if "RateBasedStatement" in st else "custom"
            rules.append({"name": r["Name"], "priority": r["Priority"], "type": kind})
        dims = {"WebACL": settings.waf_web_acl_name, "Region": settings.aws_region, "Rule": "ALL"}
        return {
            "status": "healthy",
            "metrics": {
                "blocked_1h": _metric_sum("AWS/WAFV2", "BlockedRequests", dims),
                "allowed_1h": _metric_sum("AWS/WAFV2", "AllowedRequests", dims),
            },
            "config": {"web_acl": acl["Name"], "default_action": next(iter(acl.get("DefaultAction", {})), None),
                       "capacity_wcu": acl.get("Capacity"), "rules": rules},
        }

    return _cached("waf", load)


def alb() -> dict:
    if not aws_mode():
        return _not_connected()
    if not (settings.alb_arn_suffix and settings.target_group_arn_suffix):
        return {"status": "not_configured", "reason": "ALB_ARN_SUFFIX / TARGET_GROUP_ARN_SUFFIX are not set."}

    def load():
        lb = {"LoadBalancer": settings.alb_arn_suffix}
        tg = {**lb, "TargetGroup": settings.target_group_arn_suffix}
        healthy = _metric_sum("AWS/ApplicationELB", "HealthyHostCount", tg, minutes=10, stat="Minimum", period=60)
        return {
            "status": "healthy" if healthy and healthy >= 1 else "degraded",
            "metrics": {
                "requests_1h": _metric_sum("AWS/ApplicationELB", "RequestCount", lb),
                "target_5xx_1h": _metric_sum("AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", lb),
                "healthy_targets": healthy,
                "avg_response_ms": (lambda v: round(v * 1000, 1) if v is not None else None)(
                    _metric_sum("AWS/ApplicationELB", "TargetResponseTime", lb, minutes=15, stat="Average")),
            },
            "config": {"load_balancer": settings.alb_arn_suffix},
        }

    return _cached("alb", load)


def ec2() -> dict:
    if not aws_mode():
        return _not_connected("Local mode: the app runs in Docker on this machine, not on EC2.")
    if not settings.ec2_instance_id:
        return {"status": "not_configured", "reason": "EC2_INSTANCE_ID is not set."}

    def load():
        dims = {"InstanceId": settings.ec2_instance_id}
        status = _client("ec2").describe_instance_status(InstanceIds=[settings.ec2_instance_id],
                                                         IncludeAllInstances=True)["InstanceStatuses"]
        s = status[0] if status else {}
        checks_ok = s.get("InstanceStatus", {}).get("Status") == "ok" and s.get("SystemStatus", {}).get("Status") == "ok"
        return {
            "status": "healthy" if checks_ok else "degraded",
            "metrics": {
                "cpu_percent": _metric_sum("AWS/EC2", "CPUUtilization", dims, minutes=15, stat="Average"),
                "memory_percent": None,
            },
            "notes": ["Memory utilisation needs the CloudWatch agent, which this deployment does not install."],
            "config": {"instance_id": settings.ec2_instance_id, "state": s.get("InstanceState", {}).get("Name"),
                       "status_checks": "passed" if checks_ok else "not passed"},
        }

    return _cached("ec2", load)


def rds() -> dict:
    if not aws_mode():
        return _not_connected("Local mode: the database is the local PostgreSQL container.")
    if not settings.db_instance_id:
        return {"status": "not_configured", "reason": "DB_INSTANCE_ID is not set."}

    def load():
        dims = {"DBInstanceIdentifier": settings.db_instance_id}
        inst = _client("rds").describe_db_instances(DBInstanceIdentifier=settings.db_instance_id)["DBInstances"][0]
        free = _metric_sum("AWS/RDS", "FreeStorageSpace", dims, minutes=15, stat="Average")
        return {
            "status": "healthy" if inst["DBInstanceStatus"] == "available" else "degraded",
            "metrics": {
                "connections": _metric_sum("AWS/RDS", "DatabaseConnections", dims, minutes=15, stat="Average"),
                "cpu_percent": _metric_sum("AWS/RDS", "CPUUtilization", dims, minutes=15, stat="Average"),
                "free_storage_gb": round(free / 1024 ** 3, 2) if free is not None else None,
            },
            "config": {"identifier": settings.db_instance_id, "engine": f"{inst['Engine']} {inst['EngineVersion']}",
                       "class": inst["DBInstanceClass"], "status": inst["DBInstanceStatus"],
                       "encrypted": inst.get("StorageEncrypted"), "multi_az": inst.get("MultiAZ"),
                       "public": inst.get("PubliclyAccessible")},
        }

    return _cached("rds", load)


def cloudwatch() -> dict:
    if not aws_mode():
        return _not_connected("Local mode: logs go to this container's stdout and the local database.")

    def load():
        cw = _client("cloudwatch")
        kwargs = {"AlarmNamePrefix": settings.alarm_prefix} if settings.alarm_prefix else {}
        alarms = cw.describe_alarms(**kwargs).get("MetricAlarms", [])
        ingestion = None
        if settings.app_log_group:
            streams = _client("logs").describe_log_streams(
                logGroupName=settings.app_log_group, orderBy="LastEventTime", descending=True, limit=1
            ).get("logStreams", [])
            if streams and streams[0].get("lastIngestionTime"):
                ingestion = datetime.fromtimestamp(streams[0]["lastIngestionTime"] / 1000, timezone.utc).isoformat()
        in_alarm = [a for a in alarms if a["StateValue"] == "ALARM"]
        return {
            "status": "degraded" if in_alarm else "healthy",
            "metrics": {"alarms_total": len(alarms), "alarms_in_alarm": len(in_alarm)},
            "alarms": [{"name": a["AlarmName"], "state": a["StateValue"], "metric": a.get("MetricName"),
                        "updated": a["StateUpdatedTimestamp"].isoformat(),
                        "reason": a.get("StateReason", "")[:300]} for a in alarms],
            "config": {"app_log_group": settings.app_log_group, "last_log_ingestion": ingestion},
        }

    return _cached("cloudwatch", load)


def sns(last_delivery: dict) -> dict:
    if not settings.sns_topic_arn:
        return {"status": "not_configured" if aws_mode() else "not_connected",
                "reason": "SNS_TOPIC_ARN is not set: alerts are written to the log and the notification "
                          "center only.", "checked_at": _now(), "last_delivery": last_delivery}
    if not aws_mode():
        return _not_connected()

    def load():
        attrs = _client("sns").get_topic_attributes(TopicArn=settings.sns_topic_arn)["Attributes"]
        confirmed = int(attrs.get("SubscriptionsConfirmed", 0))
        pending = int(attrs.get("SubscriptionsPending", 0))
        return {
            "status": "healthy" if confirmed else "degraded",
            "metrics": {"subscriptions_confirmed": confirmed, "subscriptions_pending": pending},
            "notes": [] if confirmed else ["No confirmed subscription: open the confirmation email AWS sent."],
            "config": {"topic": settings.sns_topic_arn.rsplit(":", 1)[-1]},
        }

    result = dict(_cached("sns", load))
    result["last_delivery"] = last_delivery
    return result

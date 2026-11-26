"""AWS infrastructure monitor and component health."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import cloud, db, events, health
from ..config import settings
from ..security import User, require

router = APIRouter(prefix="/api", tags=["infra"])


@router.get("/health/components")
def components(_: User = Depends(require("dashboard:view"))):
    return {"mode": "aws" if cloud.aws_mode() else "local", "environment": settings.app_env,
            "components": health.snapshot()}


@router.get("/infra")
def infrastructure(_: User = Depends(require("infra:view"))):
    comps = health.snapshot()
    with db.pool().connection() as conn:
        local = conn.execute(
            """SELECT count(*) AS requests,
                      count(*) FILTER (WHERE verdict = 'blocked') AS blocked,
                      round(avg(latency_ms)::numeric, 1) AS avg_latency_ms,
                      count(*) FILTER (WHERE status >= 500) AS errors
               FROM request_log WHERE ts >= now() - interval '1 hour'""").fetchone()
        last_alert = conn.execute(
            """SELECT ts, title, delivery FROM security_alert
               WHERE delivery IN ('sent', 'failed', 'logged') ORDER BY ts DESC LIMIT 1""").fetchone()

    aws = cloud.aws_mode()
    db_comp = comps["database"]
    rds = cloud.rds()
    services = [
        {"key": "waf", "name": "AWS WAF", "role": "Filters SQL injection before it reaches the load balancer's "
                                                 "targets.", **comps["waf"]},
        {"key": "alb", "name": "Application Load Balancer", "role": "Single public entry point; WAF is attached here.",
         **cloud.alb()},
        {"key": "ec2", "name": "Amazon EC2", "role": "Runs the app container (FastAPI, detector, DLP).",
         **cloud.ec2(),
         "app": {"status": comps["api"]["status"], "uptime_s": comps["api"]["metrics"]["uptime_s"],
                 "requests_1h": local["requests"], "avg_latency_ms": local["avg_latency_ms"],
                 "errors_1h": local["errors"]}},
        {"key": "rds", "name": "Amazon RDS PostgreSQL" if aws else "PostgreSQL (local container)",
         "role": "Customer data and security records, private subnets only.",
         **(rds if aws else {"status": db_comp["status"], "checked_at": db_comp["checked_at"],
                             "reason": "Local mode: Amazon RDS is not connected. Figures below come from the "
                                       "local PostgreSQL container."}),
         "app_connection": db_comp},
        {"key": "cloudwatch", "name": "Amazon CloudWatch", "role": "Logs, metric filters, alarms and dashboard.",
         **comps["cloudwatch"]},
        {"key": "sns", "name": "Amazon SNS", "role": "Emails alerts to the administrator.", **comps["sns"],
         "last_notification": last_alert},
    ]
    return {
        "mode": "aws" if aws else "local",
        "environment": settings.app_env,
        "region": settings.aws_region,
        "terraform": {"managed": aws, "path": "infra/",
                      "detail": "All resources above are created by Terraform in infra/." if aws
                      else "Terraform in infra/ defines these resources; none are deployed for this local run."},
        "services": services,
        "local_metrics": {**local, "last_notification": last_alert},
        "notification_delivery": events.last_sns_delivery(),
    }

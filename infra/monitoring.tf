# CloudWatch (monitoring and logs) and SNS (alerts).
#
#   WAF metrics ---------------------------------\
#   app JSON logs -> metric filters -> metrics ---+-> alarms -> SNS -> admin email
#   RDS logs      -> metric filter  -> metric ---/
#
# The app also publishes detailed incident alerts to the same SNS topic.

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${local.name}/app"
  retention_in_days = var.log_retention_days
}

resource "aws_sns_topic" "alerts" {
  name = "${local.name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------- metric filters

locals {
  metric_namespace = "QueryGuard"

  app_metric_filters = {
    SuspiciousRequests = "{ $.event = \"request\" && $.verdict = \"suspicious\" }"
    AppBlockedRequests = "{ $.event = \"request\" && $.verdict = \"blocked\" }"
    Incidents          = "{ $.event = \"incident\" && $.severity != \"low\" }"
  }
}

resource "aws_cloudwatch_log_metric_filter" "app" {
  for_each = local.app_metric_filters

  name           = "${local.name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = each.value

  metric_transformation {
    name          = each.key
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "db_errors" {
  name           = "${local.name}-DatabaseErrors"
  log_group_name = aws_cloudwatch_log_group.rds.name
  pattern        = "?\"syntax error\" ?\"permission denied\" ?\"must be owner\" ?\"does not exist\""

  metric_transformation {
    name          = "DatabaseErrors"
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }

  depends_on = [aws_db_instance.main]
}

# ---------------------------------------------------------------- alarms

locals {
  waf_dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Region = var.region
    Rule   = "ALL"
  }
}

resource "aws_cloudwatch_metric_alarm" "waf_blocked" {
  alarm_name          = "${local.name}-waf-blocked-sqli"
  alarm_description   = "AWS WAF blocked ${var.waf_block_alarm_threshold}+ requests in 5 minutes. Likely an injection attempt or a scanner."
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  dimensions          = local.waf_dimensions
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.waf_block_alarm_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "app_suspicious" {
  alarm_name          = "${local.name}-app-suspicious"
  alarm_description   = "The application flagged ${var.suspicious_alarm_threshold}+ suspicious requests in 5 minutes."
  namespace           = local.metric_namespace
  metric_name         = "SuspiciousRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.suspicious_alarm_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "app_blocked" {
  alarm_name          = "${local.name}-app-blocked"
  alarm_description   = "Injection got past AWS WAF and was stopped by the application filter. Review WAF rules."
  namespace           = local.metric_namespace
  metric_name         = "AppBlockedRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "db_errors" {
  alarm_name          = "${local.name}-db-errors"
  alarm_description   = "PostgreSQL logged 5+ failed statements in 5 minutes (syntax or permission errors)."
  namespace           = local.metric_namespace
  metric_name         = "DatabaseErrors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "unhealthy" {
  alarm_name        = "${local.name}-app-unhealthy"
  alarm_description = "The load balancer sees no healthy app server."
  namespace         = "AWS/ApplicationELB"
  metric_name       = "HealthyHostCount"
  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.app.arn_suffix
  }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 5
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ---------------------------------------------------------------- dashboard

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = local.name

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6
        properties = {
          title   = "AWS WAF: allowed and blocked"
          region  = var.region
          stat    = "Sum"
          period  = 300
          view    = "timeSeries"
          stacked = false
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", var.region, "Rule", "ALL", { color = "#2e7a68" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", var.region, "Rule", "ALL", { color = "#c33a2e" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6
        properties = {
          title  = "AWS WAF: blocked, by rule"
          region = var.region
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
          metrics = [
            for m in values(local.waf_metrics) :
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", var.region, "Rule", m]
          ]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6
        properties = {
          title  = "Application filter and incidents"
          region = var.region
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
          metrics = [
            [local.metric_namespace, "SuspiciousRequests", { color = "#b7790b" }],
            [local.metric_namespace, "AppBlockedRequests", { color = "#c33a2e" }],
            [local.metric_namespace, "Incidents", { color = "#2b4c9b" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 6, width = 12, height = 6
        properties = {
          title  = "Database errors and load balancer responses"
          region = var.region
          stat   = "Sum"
          period = 300
          view   = "timeSeries"
          metrics = [
            [local.metric_namespace, "DatabaseErrors"],
            ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", aws_lb.main.arn_suffix],
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", aws_lb.main.arn_suffix],
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.main.arn_suffix],
          ]
        }
      },
      {
        type = "log", x = 0, y = 12, width = 24, height = 7
        properties = {
          title  = "Latest requests blocked by AWS WAF"
          region = var.region
          view   = "table"
          query  = "SOURCE '${aws_cloudwatch_log_group.waf.name}' | fields @timestamp, httpRequest.clientIp, httpRequest.httpMethod, httpRequest.uri, httpRequest.args, terminatingRuleId | filter action = 'BLOCK' | sort @timestamp desc | limit 25"
        }
      },
      {
        type = "log", x = 0, y = 19, width = 24, height = 6
        properties = {
          title  = "Latest incidents raised by the application"
          region = var.region
          view   = "table"
          query  = "SOURCE '${aws_cloudwatch_log_group.app.name}' | fields @timestamp, kind, severity, client_ip, summary, alert | filter event = 'incident' | sort @timestamp desc | limit 25"
        }
      },
    ]
  })
}

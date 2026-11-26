# AWS WAF: the first line of defence, attached to the load balancer.

resource "aws_wafv2_web_acl" "main" {
  name        = "${local.name}-web-acl"
  description = "Blocks SQL injection before requests reach the app"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  custom_response_body {
    key          = "blocked"
    content_type = "APPLICATION_JSON"
    content = jsonencode({
      error      = "Request rejected by AWS WAF: it matched SQL injection rules."
      blocked_by = "AWS WAF"
    })
  }

  # 1. Slow down scanners: too many requests from one IP in 5 minutes.
  rule {
    name     = "rate-limit-per-ip"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = local.waf_metrics.rate
      sampled_requests_enabled   = true
    }
  }

  # 2. AWS-maintained SQL injection signatures.
  rule {
    name     = "aws-managed-sqli"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = local.waf_metrics.aws_sqli
      sampled_requests_enabled   = true
    }
  }

  # 3. Our own SQLi match on every part of the request, at high sensitivity,
  #    after undoing URL and HTML-entity encoding.
  rule {
    name     = "custom-sqli-match"
    priority = 3

    action {
      block {
        custom_response {
          response_code            = 403
          custom_response_body_key = "blocked"
        }
      }
    }

    statement {
      or_statement {
        statement {
          sqli_match_statement {
            sensitivity_level = "HIGH"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE_UNI"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {
            sensitivity_level = "HIGH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE_UNI"
            }
          }
        }

        statement {
          sqli_match_statement {
            sensitivity_level = "HIGH"
            field_to_match {
              body {
                oversize_handling = "MATCH"
              }
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }

        statement {
          sqli_match_statement {
            sensitivity_level = "HIGH"
            field_to_match {
              json_body {
                match_scope               = "VALUE"
                invalid_fallback_behavior = "EVALUATE_AS_STRING"
                oversize_handling         = "MATCH"
                match_pattern {
                  all {}
                }
              }
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE_UNI"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = local.waf_metrics.custom
      sampled_requests_enabled   = true
    }
  }

  # 4. AWS-maintained known-bad inputs (exploit paths, malformed requests).
  rule {
    name     = "aws-known-bad-inputs"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = local.waf_metrics.bad_input
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-web-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# Full WAF request logs in CloudWatch Logs. The name must start with aws-waf-logs-.
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  policy_name = "${local.name}-waf-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "delivery.logs.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.waf.arn}:*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:logs:${var.region}:${local.account_id}:*" }
      }
    }]
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}

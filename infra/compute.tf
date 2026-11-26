# App server: one EC2 instance that builds and runs the app container.
# The app source is zipped from ../app and shipped through S3; any change to
# the app produces a new zip hash, which replaces the instance on apply.

resource "random_id" "suffix" {
  byte_length = 4
}

# ---------------------------------------------------------------- app bundle

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${local.name}-artifacts-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "archive_file" "app" {
  type        = "zip"
  source_dir  = "${path.module}/../app"
  output_path = "${path.module}/build/app.zip"
  excludes = [
    "tests",
    ".pytest_cache",
    ".venv",
    "queryguard/__pycache__",
    "tests/__pycache__",
  ]
}

resource "aws_s3_object" "app" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "app-${data.archive_file.app.output_md5}.zip"
  source = data.archive_file.app.output_path
  etag   = data.archive_file.app.output_md5
}

# ---------------------------------------------------------------- secrets

resource "random_password" "secret_key" {
  length  = 48
  special = false
}

# Letters and digits only, so a password can never look like SQL to a filter.
resource "random_password" "admin" {
  length      = 20
  special     = false
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
}

resource "random_password" "analyst" {
  length      = 20
  special     = false
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
}

resource "aws_ssm_parameter" "app" {
  for_each = {
    secret_key       = random_password.secret_key.result
    admin_password   = random_password.admin.result
    analyst_password = random_password.analyst.result
  }

  name  = "/${local.name}/${each.key}"
  type  = "SecureString"
  value = each.value
}

# ---------------------------------------------------------------- IAM

locals {
  create_iam       = var.existing_instance_profile_name == ""
  instance_profile = local.create_iam ? aws_iam_instance_profile.app[0].name : var.existing_instance_profile_name
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  count              = local.create_iam ? 1 : 0
  name               = "${local.name}-app"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

# Shell access through Session Manager: no SSH key, no port 22.
resource "aws_iam_role_policy_attachment" "ssm" {
  count      = local.create_iam ? 1 : 0
  role       = aws_iam_role.app[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ReadAppBundle"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    sid       = "ReadAppSecrets"
    actions   = ["ssm:GetParameter"]
    resources = [for p in aws_ssm_parameter.app : p.arn]
  }

  statement {
    sid       = "ReadDbMasterSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.main.master_user_secret[0].secret_arn]
  }

  statement {
    sid       = "SendAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "ReadWafMetrics"
    actions   = ["cloudwatch:GetMetricData"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadWafSamples"
    actions   = ["wafv2:GetSampledRequests"]
    resources = [aws_wafv2_web_acl.main.arn]
  }

  statement {
    sid       = "ShipAppLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.app.arn}:*"]
  }
}

resource "aws_iam_role_policy" "app" {
  count  = local.create_iam ? 1 : 0
  name   = "${local.name}-app"
  role   = aws_iam_role.app[0].id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_instance_profile" "app" {
  count = local.create_iam ? 1 : 0
  name  = "${local.name}-app"
  role  = aws_iam_role.app[0].name
}

# ---------------------------------------------------------------- instance

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = local.instance_profile

  # IMDSv2 only. Hop limit 2 lets the container (one network hop further)
  # reach instance credentials.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 16
    volume_type = "gp3"
    encrypted   = true
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region                 = var.region
    bucket                 = aws_s3_bucket.artifacts.id
    bundle_key             = aws_s3_object.app.key
    param_prefix           = "/${local.name}"
    log_group              = aws_cloudwatch_log_group.app.name
    db_host                = aws_db_instance.main.address
    db_secret_arn          = aws_db_instance.main.master_user_secret[0].secret_arn
    web_acl_name           = aws_wafv2_web_acl.main.name
    web_acl_arn            = aws_wafv2_web_acl.main.arn
    waf_rule_metrics       = join(",", [local.waf_metrics.aws_sqli, local.waf_metrics.custom, local.waf_metrics.rate, local.waf_metrics.bad_input])
    sns_topic_arn          = aws_sns_topic.alerts.arn
    enable_vulnerable_demo = var.enable_vulnerable_demo ? "true" : "false"
  })

  tags = { Name = "${local.name}-app" }

  depends_on = [
    aws_iam_role_policy.app,
    aws_ssm_parameter.app,
  ]
}

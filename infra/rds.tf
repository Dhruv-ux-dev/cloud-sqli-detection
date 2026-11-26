# PostgreSQL on Amazon RDS, private subnets only. The master password is
# generated and stored by RDS in Secrets Manager; the app reads it once at
# start-up to create the schema and its own least-privilege role.

resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "main" {
  name   = "${local.name}-pg16"
  family = "postgres16"

  # Failed statements are logged; injection probing produces many of them
  # (syntax errors, permission denied). A CloudWatch metric filter counts them.
  parameter {
    name         = "log_min_error_statement"
    value        = "error"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "log_connections"
    value        = "1"
    apply_method = "pending-reboot"
  }

  # Slow statements are logged too: time-based blind injection shows up here.
  parameter {
    name         = "log_min_duration_statement"
    value        = "2000"
    apply_method = "pending-reboot"
  }
}

# Created up front so Terraform owns its retention and the metric filter.
resource "aws_cloudwatch_log_group" "rds" {
  name              = "/aws/rds/instance/${local.name}-db/postgresql"
  retention_in_days = var.log_retention_days
}

resource "aws_db_instance" "main" {
  identifier     = "${local.name}-db"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = true

  db_name                     = "queryguard"
  username                    = "qgadmin"
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.main.name
  publicly_accessible    = false
  multi_az               = false

  enabled_cloudwatch_logs_exports = ["postgresql"]

  backup_retention_period    = var.db_backup_retention_days
  auto_minor_version_upgrade = true
  apply_immediately          = true
  skip_final_snapshot        = true
  deletion_protection        = false

  depends_on = [aws_cloudwatch_log_group.rds]
}

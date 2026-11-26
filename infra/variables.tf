variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Prefix for resource names. Lowercase letters, digits and hyphens."
  type        = string
  default     = "queryguard"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "Use 3-21 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "alert_email" {
  description = "Administrator email that receives SNS alerts. AWS sends a confirmation link first."
  type        = string
}

variable "allowed_cidrs" {
  description = "Who may reach the load balancer. Narrow this to your lab or home IP (x.x.x.x/32) for testing."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "instance_type" {
  description = "EC2 type for the app server."
  type        = string
  default     = "t3.micro"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_backup_retention_days" {
  description = "RDS automated backup retention. 0 keeps free-tier accounts happy; raise it for anything real."
  type        = number
  default     = 0
}

variable "existing_instance_profile_name" {
  description = <<-EOT
    Use an existing EC2 instance profile instead of creating an IAM role.
    Set to "LabInstanceProfile" in AWS Academy Learner Lab, where creating IAM roles is not allowed.
  EOT
  type        = string
  default     = ""
}

variable "waf_rate_limit" {
  description = "Requests per 5 minutes from one IP before AWS WAF blocks it."
  type        = number
  default     = 300
}

variable "waf_block_alarm_threshold" {
  description = "Alarm when AWS WAF blocks at least this many requests in 5 minutes."
  type        = number
  default     = 5
}

variable "suspicious_alarm_threshold" {
  description = "Alarm when the app flags at least this many suspicious requests in 5 minutes."
  type        = number
  default     = 10
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for app, WAF and database logs."
  type        = number
  default     = 14
}

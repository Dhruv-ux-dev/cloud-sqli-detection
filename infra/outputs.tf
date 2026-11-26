output "app_url" {
  description = "Open this in a browser. It can take 3-5 minutes after apply for the app to pass health checks."
  value       = "http://${aws_lb.main.dns_name}"
}

output "security_console_url" {
  value = "http://${aws_lb.main.dns_name}/security"
}

output "admin_password" {
  description = "Password for the 'admin' account. Show it with: terraform output -raw admin_password"
  value       = random_password.admin.result
  sensitive   = true
}

output "analyst_password" {
  description = "Password for the 'analyst' account. Show it with: terraform output -raw analyst_password"
  value       = random_password.analyst.result
  sensitive   = true
}

output "cloudwatch_dashboard_url" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "waf_console_url" {
  value = "https://${var.region}.console.aws.amazon.com/wafv2/homev2/web-acl/${aws_wafv2_web_acl.main.name}/${aws_wafv2_web_acl.main.id}/overview?region=${var.region}"
}

output "shell_on_app_server" {
  description = "Open a shell on the app server without SSH (needs the Session Manager plugin)."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.app.id}"
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "reminder" {
  value = "Confirm the SNS subscription from the email AWS sent to ${var.alert_email}, or alerts will not arrive."
}

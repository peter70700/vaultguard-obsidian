output "api_url" {
  description = "VaultGuard REST API URL"
  value       = module.apigateway.api_url
}

output "cloudfront_url" {
  description = "VaultGuard CloudFront API CDN URL (backward compat for existing plugin installs)"
  value       = module.cloudfront.distribution_url
}

output "user_pool_id" {
  description = "Cognito User Pool ID"
  value       = module.cognito.user_pool_id
}

output "user_pool_client_id" {
  description = "Cognito User Pool Client ID"
  value       = module.cognito.client_id
}

output "vault_bucket_name" {
  description = "S3 vault storage bucket name"
  value       = module.s3.bucket_name
}

output "kms_key_arn" {
  description = "Master KMS key ARN"
  value       = module.kms.key_arn
}

output "admin_sns_topic_arn" {
  description = "SNS topic ARN for admin notifications"
  value       = module.monitoring.sns_topic_arn
}

output "permissions_table_name" {
  description = "DynamoDB permissions table name"
  value       = module.dynamodb.permissions_table_name
}

output "audit_table_name" {
  description = "DynamoDB audit log table name"
  value       = module.dynamodb.audit_table_name
}

output "sessions_table_name" {
  description = "DynamoDB sessions table name"
  value       = module.dynamodb.sessions_table_name
}

output "user_keys_table_name" {
  description = "DynamoDB user keys table name"
  value       = module.dynamodb.user_keys_table_name
}

output "domain_nameservers" {
  description = "Nameservers to configure at your domain registrar (only when domain is set)"
  value       = var.domain_name != "" ? module.dns[0].nameservers : []
}

output "api_custom_domain" {
  description = "Custom API domain (e.g., api.example.com)"
  value       = var.domain_name != "" ? "https://api.${var.domain_name}" : module.apigateway.api_url
}

output "regional_certificate_arn" {
  description = "ACM certificate ARN for regional services"
  value       = var.domain_name != "" ? module.dns[0].regional_certificate_arn : ""
}

output "api_id" {
  description = "API Gateway REST API ID (used by debug scripts)"
  value       = module.apigateway.api_id
}

output "api_stage_name" {
  description = "API Gateway stage name (used by debug scripts)"
  value       = module.apigateway.api_stage_name
}

# ─────────────────────────────────────────────────────────────────────────────
# CloudFront — API CDN only
#
# Provides backward compatibility for existing plugin installs using the
# *.cloudfront.net URL. New installs use api.example.com directly.
# Static hosting (landing + admin) is handled by Amplify.
# ─────────────────────────────────────────────────────────────────────────────

variable "stage" { type = string }
variable "api_gateway_url" { type = string }
variable "api_gateway_stage" { type = string }
variable "waf_acl_arn" { type = string }

locals {
  api_domain = replace(replace(var.api_gateway_url, "https://", ""), "/${var.api_gateway_stage}", "")
}

resource "aws_cloudfront_distribution" "vaultguard" {
  comment             = "VaultGuard API CDN (${var.stage})"
  enabled             = true
  http_version        = "http2and3"
  web_acl_id          = var.waf_acl_arn
  price_class         = "PriceClass_100"
  is_ipv6_enabled     = true
  wait_for_deployment = false

  origin {
    domain_name = local.api_domain
    origin_id   = "api-gateway"
    origin_path = "/${var.api_gateway_stage}"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "api-gateway"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # CachingDisabled
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac" # AllViewerExceptHostHeader

    compress = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    # When using the default *.cloudfront.net cert, AWS forces this to TLSv1
    # and ignores higher values — declaring otherwise causes perpetual drift.
    # To enforce TLSv1.2_2021, switch to an ACM cert with a custom alias.
    minimum_protocol_version = "TLSv1"
  }

  tags = { Name = "vaultguard-api-cdn-${var.stage}" }
}

output "distribution_url" {
  value = "https://${aws_cloudfront_distribution.vaultguard.domain_name}"
}

output "distribution_id" {
  value = aws_cloudfront_distribution.vaultguard.id
}

output "distribution_domain_name" {
  value = aws_cloudfront_distribution.vaultguard.domain_name
}

output "distribution_hosted_zone_id" {
  value = aws_cloudfront_distribution.vaultguard.hosted_zone_id
}

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "stage" { type = string }

resource "aws_wafv2_web_acl" "vaultguard" {
  name        = "obsidian-vaultguard-waf-${var.stage}"
  scope       = "CLOUDFRONT"
  description = "WAF for Obsidian VaultGuard API"

  default_action {
    allow {}
  }

  # AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # This ACL fronts the legacy *.cloudfront.net distribution whose
        # origin is the API Gateway, so JSON-path file-sync PUT bodies — base64
        # ciphertext up to API Gateway's request ceiling — flow through here.
        # SizeRestrictions_BODY in block mode 403s every body over 8 KB,
        # silently breaking uploads of any note larger than ~6 KB for clients
        # still on the legacy endpoint. Count instead of block, same as the
        # REGIONAL ACL on the primary API: size stays bounded by API Gateway's
        # 10 MB cap and Lambda validation. Larger configured files transfer
        # directly to isolated S3 staging objects and bypass this request body.
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rate limiting: 2000 requests per 5 minutes per IP
  rule {
    name     = "RateLimitRule"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # Geo-restriction: Block requests from sanctioned countries
  rule {
    name     = "GeoRestriction"
    priority = 4

    action {
      block {}
    }

    statement {
      geo_match_statement {
        country_codes = ["KP", "IR", "SY", "CU"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "GeoRestriction"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "vaultguard-waf-${var.stage}"
    sampled_requests_enabled   = true
  }

  tags = { Name = "obsidian-vaultguard-waf-${var.stage}" }
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.vaultguard.arn
}

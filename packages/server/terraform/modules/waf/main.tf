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

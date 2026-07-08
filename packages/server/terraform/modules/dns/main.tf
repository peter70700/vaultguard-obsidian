# ─────────────────────────────────────────────────────────────────────────────
# DNS & Certificate Module
#
# Manages the Route53 hosted zone, ACM certificates (regional + CloudFront),
# DNS validation records, and subdomain aliases for all VaultGuard services.
#
# Domain layout:
#   example.com            → Landing page (CloudFront)
#   api.example.com        → API Gateway custom domain
#   admin.example.com      → Admin panel (CloudFront)
#   auth.example.com       → Cognito custom domain (future)
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws, aws.us_east_1]
    }
  }
}

variable "stage" { type = string }
variable "domain_name" {
  type        = string
  description = "Root domain (e.g., example.com)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Google Workspace inbound mail
# ─────────────────────────────────────────────────────────────────────────────
# Inbound mail for example.com is handled by Google Workspace. The MX
# record below points at Google. The Google site-verification TXT and DKIM
# TXT records are managed manually in the Route 53 console (Workspace's
# DKIM key rotates outside the deploy cadence, so it lives outside terraform
# to avoid drift). Outbound transactional mail (signup, password reset,
# invoices) continues to go through Amazon SES — see the SES section below.

# ─────────────────────────────────────────────────────────────────────────────
# Route53 Hosted Zone
# ─────────────────────────────────────────────────────────────────────────────

# Import the existing hosted zone (already created in AWS console)
data "aws_route53_zone" "main" {
  name         = var.domain_name
  private_zone = false
}

# ─────────────────────────────────────────────────────────────────────────────
# ACM Certificate — CloudFront (must be us-east-1)
# ─────────────────────────────────────────────────────────────────────────────

# CloudFront requires certificates in us-east-1
resource "aws_acm_certificate" "cloudfront" {
  provider = aws.us_east_1

  domain_name = var.domain_name
  subject_alternative_names = [
    "*.${var.domain_name}",
  ]
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "vaultguard-cloudfront-${var.stage}"
  }
}

# DNS validation records for the CloudFront certificate
resource "aws_route53_record" "cloudfront_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.cloudfront.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 300
  records = [each.value.record]

  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "cloudfront" {
  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.cloudfront.arn
  validation_record_fqdns = [for record in aws_route53_record.cloudfront_cert_validation : record.fqdn]
}

# ─────────────────────────────────────────────────────────────────────────────
# ACM Certificate — Regional (API Gateway, ALBs, etc.)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_acm_certificate" "regional" {
  domain_name = var.domain_name
  subject_alternative_names = [
    "*.${var.domain_name}",
  ]
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "vaultguard-regional-${var.stage}"
  }
}

# DNS validation records for the regional certificate
# The wildcard cert shares the same CNAME validation record as the apex,
# so we reuse the cloudfront validation records (same zone, same CNAME).
resource "aws_acm_certificate_validation" "regional" {
  certificate_arn         = aws_acm_certificate.regional.arn
  validation_record_fqdns = [for record in aws_route53_record.cloudfront_cert_validation : record.fqdn]
}

# ─────────────────────────────────────────────────────────────────────────────
# API Gateway Custom Domain
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_api_gateway_domain_name" "api" {
  domain_name              = "api.${var.domain_name}"
  regional_certificate_arn = aws_acm_certificate_validation.regional.certificate_arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  security_policy = "TLS_1_2"

  tags = {
    Name = "vaultguard-api-${var.stage}"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# DNS Records — Point subdomains to AWS services
# ─────────────────────────────────────────────────────────────────────────────

# api.example.com → API Gateway custom domain
resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_api_gateway_domain_name.api.regional_domain_name
    zone_id                = aws_api_gateway_domain_name.api.regional_zone_id
    evaluate_target_health = false
  }
}

# NOTE: example.com (apex), admin.example.com, and
# share.example.com DNS records are managed by Amplify Hosting via
# `aws_amplify_domain_association` set up in the AWS console (mirrors the
# landing/admin pattern). Do NOT create them here or they will conflict.

# MX record — Google Workspace handles all inbound mail.
# SES is NOT in the MX set: outbound from SES doesn't need an MX, and adding
# SES as a low-priority fallback would silently drop mail (no SES receipt rule
# is configured) whenever Google has a hiccup.
#
# IMPORTANT: no trailing dot on `SMTP.GOOGLE.COM`. Route53 stores MX targets
# without the trailing dot (it's added back when serving DNS responses), so
# `.` here causes perpetual no-op drift on every `terraform plan` against the
# terraform-provider-aws's normalization quirk. Verified live with
# `aws route53 list-resource-record-sets` returning the un-dotted form.
resource "aws_route53_record" "mx" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "MX"
  ttl     = 3600
  records = ["1 SMTP.GOOGLE.COM"]
}

# Google Workspace site-verification TXT and DKIM TXT are managed manually
# in the Route 53 console — Google rotates DKIM keys outside the terraform
# cadence, so keeping these out of state avoids spurious diffs and accidental
# destruction when applying without the matching tfvars.

# ─────────────────────────────────────────────────────────────────────────────
# SES Domain Verification (DKIM + SPF)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_ses_domain_identity" "main" {
  domain = var.domain_name
}

resource "aws_ses_domain_dkim" "main" {
  domain = aws_ses_domain_identity.main.domain
}

# DKIM CNAME records (3 records for SES DKIM verification)
resource "aws_route53_record" "ses_dkim" {
  count = 3

  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${aws_ses_domain_dkim.main.dkim_tokens[count.index]}._domainkey.${var.domain_name}"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_ses_domain_dkim.main.dkim_tokens[count.index]}.dkim.amazonses.com"]
}

# SES domain verification TXT record
resource "aws_route53_record" "ses_verification" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "_amazonses.${var.domain_name}"
  type    = "TXT"
  ttl     = 600
  records = [aws_ses_domain_identity.main.verification_token]
}

# The apex TXT RR set at `${var.domain_name}` is managed manually in the
# Route 53 console. It MUST contain (at minimum) both of:
#   "v=spf1 include:_spf.google.com include:amazonses.com -all"
#   "google-site-verification=<token from Google Workspace Admin>"
#
# Why not terraform? Route 53 collapses every TXT string at a name into one
# RR set, so terraform can't own one value and let a human own another —
# whoever writes last clobbers the other. Since the Google verification
# token is managed by hand (see comment near the MX record above), the SPF
# must be managed by hand too. Outbound SES mail will fail SPF if the
# `include:amazonses.com` term is dropped, so audit this record after any
# DNS change.

# DMARC record — email authentication policy.
# `sp=quarantine` sets the policy for any subdomain that lacks its own _dmarc
# record. The dedicated sending subdomains below publish their OWN _dmarc
# records (so this is belt-and-suspenders for them), but sp= closes the gap for
# every other subdomain so none can be spoofed under a looser default.
resource "aws_route53_record" "dmarc" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "_dmarc.${var.domain_name}"
  type    = "TXT"
  ttl     = 600
  records = ["v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@${var.domain_name}; pct=100"]
}

# ─────────────────────────────────────────────────────────────────────────────
# Dedicated sending subdomains (reputation isolation)
#
# Outbound app mail is moved OFF the apex onto dedicated SES sending subdomains
# so their reputation is isolated from (a) the apex — which carries Google
# Workspace corporate mail + the website — and (b) each other:
#   mail.<domain>  — transactional (password resets, invites, receipts). The
#                    email Lambda + Cognito send as noreply@mail.<domain>.
#   news.<domain>  — bulk/marketing blasts. The blast scripts send as
#                    hello@news.<domain>.
# A spam-complaint hit on the marketing lane can therefore never drag down
# transactional deliverability or the corporate/apex domain.
#
# Each subdomain also gets a custom MAIL FROM (Return-Path) domain
# (bounce.<subdomain>) so SPF authenticates against our domain (aligned) rather
# than the default amazonses.com — strengthening DMARC and inbox placement.
# behavior_on_mx_failure = "RejectMessage" fails CLOSED: if the MAIL FROM MX/SPF
# is ever unverified, SES rejects the send instead of silently reverting to
# amazonses.com and breaking SPF alignment. Confirm the MAIL FROM domain shows
# "Success" in SES before cutting a sender over to it.
#
# The apex SES identity above is intentionally LEFT verified during migration:
# a sender rolls back to the apex instantly by flipping var.sender_email /
# var.sender_domain — no destroy/recreate required.
# ─────────────────────────────────────────────────────────────────────────────

data "aws_region" "current" {}

locals {
  # logical key => sending subdomain FQDN
  ses_sending_subdomains = {
    transactional = "mail.${var.domain_name}"
    marketing     = "news.${var.domain_name}"
  }
  # logical key => custom MAIL FROM (Return-Path) FQDN
  ses_mail_from_domains = {
    for key, domain in local.ses_sending_subdomains : key => "bounce.${domain}"
  }
}

resource "aws_ses_domain_identity" "sending" {
  for_each = local.ses_sending_subdomains
  domain   = each.value
}

resource "aws_ses_domain_dkim" "sending" {
  for_each = aws_ses_domain_identity.sending
  domain   = each.value.domain
}

resource "aws_ses_domain_mail_from" "sending" {
  for_each               = aws_ses_domain_identity.sending
  domain                 = each.value.domain
  mail_from_domain       = local.ses_mail_from_domains[each.key]
  behavior_on_mx_failure = "RejectMessage"
}

# SES identity verification TXT — _amazonses.<subdomain>
resource "aws_route53_record" "sending_ses_verification" {
  for_each = aws_ses_domain_identity.sending

  zone_id = data.aws_route53_zone.main.zone_id
  name    = "_amazonses.${each.value.domain}"
  type    = "TXT"
  ttl     = 600
  records = [each.value.verification_token]
}

# DKIM CNAMEs (3 per subdomain). SES exposes dkim_tokens only at apply time, so
# — exactly like the apex ses_dkim block above — these use count, not for_each
# (a for_each over a computed-length list errors at plan time).
resource "aws_route53_record" "sending_dkim_transactional" {
  count = 3

  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${aws_ses_domain_dkim.sending["transactional"].dkim_tokens[count.index]}._domainkey.${local.ses_sending_subdomains["transactional"]}"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_ses_domain_dkim.sending["transactional"].dkim_tokens[count.index]}.dkim.amazonses.com"]
}

resource "aws_route53_record" "sending_dkim_marketing" {
  count = 3

  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${aws_ses_domain_dkim.sending["marketing"].dkim_tokens[count.index]}._domainkey.${local.ses_sending_subdomains["marketing"]}"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_ses_domain_dkim.sending["marketing"].dkim_tokens[count.index]}.dkim.amazonses.com"]
}

# SPF TXT on each sending subdomain — only SES sends from these names, so no
# Google include is needed here (unlike the apex, which Google Workspace shares).
resource "aws_route53_record" "sending_spf" {
  for_each = local.ses_sending_subdomains

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value
  type    = "TXT"
  ttl     = 600
  records = ["v=spf1 include:amazonses.com -all"]
}

# Custom MAIL FROM MX — routes bounces/complaints to SES's regional feedback
# endpoint. No trailing dot on the target (same Route53 normalization quirk the
# apex MX comment documents).
resource "aws_route53_record" "sending_mail_from_mx" {
  for_each = aws_ses_domain_mail_from.sending

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value.mail_from_domain
  type    = "MX"
  ttl     = 600
  records = ["10 feedback-smtp.${data.aws_region.current.name}.amazonses.com"]
}

# Custom MAIL FROM SPF TXT — authorizes SES for the Return-Path domain so SPF
# aligns to our domain.
resource "aws_route53_record" "sending_mail_from_spf" {
  for_each = aws_ses_domain_mail_from.sending

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value.mail_from_domain
  type    = "TXT"
  ttl     = 600
  records = ["v=spf1 include:amazonses.com -all"]
}

# Explicit DMARC per sending subdomain. Aggregate reports go to the same inbox
# as the apex (same org domain → no external _report._dmarc authorization
# needed).
resource "aws_route53_record" "sending_dmarc" {
  for_each = local.ses_sending_subdomains

  zone_id = data.aws_route53_zone.main.zone_id
  name    = "_dmarc.${each.value}"
  type    = "TXT"
  ttl     = 600
  records = ["v=DMARC1; p=quarantine; rua=mailto:dmarc@${var.domain_name}; pct=100"]
}

# ─────────────────────────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────────────────────────

output "zone_id" {
  value = data.aws_route53_zone.main.zone_id
}

output "cloudfront_certificate_arn" {
  description = "ACM certificate ARN for CloudFront (us-east-1)"
  value       = aws_acm_certificate_validation.cloudfront.certificate_arn
}

output "regional_certificate_arn" {
  description = "ACM certificate ARN for API Gateway and regional services"
  value       = aws_acm_certificate_validation.regional.certificate_arn
}

output "api_custom_domain" {
  description = "API Gateway custom domain name"
  value       = aws_api_gateway_domain_name.api.domain_name
}

output "api_gateway_domain_name" {
  description = "API Gateway regional target domain (for base path mapping)"
  value       = aws_api_gateway_domain_name.api.regional_domain_name
}

output "nameservers" {
  description = "Nameservers to configure at your domain registrar"
  value       = data.aws_route53_zone.main.name_servers
}

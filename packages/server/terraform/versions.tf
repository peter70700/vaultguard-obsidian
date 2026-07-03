terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # State backend. With no backend configured, Terraform stores state locally in
  # terraform.tfstate — fine for a single operator. For a team, uncomment and
  # point at an S3 bucket + DynamoDB lock table you control:
  #
  # backend "s3" {
  #   bucket         = "your-vaultguard-tfstate-bucket"
  #   key            = "vaultguard/terraform.tfstate"
  #   region         = "your-region"
  #   dynamodb_table = "your-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "ObsidianVaultGuard"
      Stage     = var.stage
      ManagedBy = "Terraform"
    }
  }
}

# CloudFront + WAF require us-east-1 for the WAF WebACL
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project   = "ObsidianVaultGuard"
      Stage     = var.stage
      ManagedBy = "Terraform"
    }
  }
}

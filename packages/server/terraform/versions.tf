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

  # Local backend for dev/testing. Switch to S3 for shared team state:
  #   backend "s3" {
  #     bucket         = "your-terraform-state-bucket"
  #     key            = "vaultguard/terraform.tfstate"
  #     region         = "us-east-1"
  #     dynamodb_table = "terraform-locks"
  #     encrypt        = true
  #   }
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

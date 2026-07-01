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

  # Remote state — versioned + encrypted S3 with DynamoDB locking.
  #
  # The bucket and lock table are created out-of-band by
  # scripts/bootstrap-tf-backend.sh (these names must match its defaults).
  # After the first `terraform init -migrate-state`, the on-disk
  # terraform.tfstate is copied here and locking is enforced.
  #
  # NOTE on the "prod" key: this single stack runs production
  # (example.com) even though its `stage` variable is "dev". The state
  # key is named prod for clarity; the `stage` var must NOT be changed —
  # renaming would recreate every resource and destroy production.
  # Backend blocks cannot reference variables, so these values are literal.
  backend "s3" {
    bucket         = "vaultguard-tfstate-eu-central-1"
    key            = "vaultguard/prod/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "vaultguard-terraform-locks"
    encrypt        = true
  }
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

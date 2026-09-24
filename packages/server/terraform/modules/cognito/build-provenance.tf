# Local-only provenance gate. Every archive uses the verified snapshot path,
# so a direct terraform plan is guarded as well as the clean planning wrapper.
terraform {
  required_providers {
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
  }
}

data "external" "lambda_build" {
  program = ["node", "${path.module}/../../../infrastructure/verify-lambda-build.mjs"]
  query = {
    infrastructure = abspath("${path.module}/../../../infrastructure")
  }
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "test"
  secret_key                  = "test"
}

# Deliberately missing an aws_s3_bucket_public_access_block — this is the fixture's whole point,
# a self-contained example of aws.storage.s3-public-access-block-missing that doesn't require
# reaching into a sibling repo to demonstrate the block. (The end-to-end tests in this repo also
# exercise local-delegate-mcp/bench/reference-iac, which was already insecure by this same rule
# before this server existed — both are worth keeping: this one for a minimal, self-contained
# example; that one for proof the check works against real, independently-authored code.)
resource "aws_s3_bucket" "this" {
  bucket = "tfguard-fixture-insecure-bucket"
}

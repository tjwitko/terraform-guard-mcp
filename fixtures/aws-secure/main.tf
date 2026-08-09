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
  access_key                  = "minioadmin"
  secret_key                  = "minioadmin"
  s3_use_path_style           = true

  # Fake credentials alone get plan/validate to succeed (pure local computation) but a real
  # apply genuinely calls the AWS API and fails on them (confirmed: a first attempt without this
  # endpoint override got a real 403 InvalidAccessKeyId from AWS). Pointing s3 at a local MinIO
  # container is what makes an actual `terraform apply` succeed without real AWS credentials.
  endpoints {
    s3 = "http://localhost:9100"
  }
}

resource "aws_s3_bucket" "this" {
  bucket = "tfguard-fixture-secure-bucket"
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

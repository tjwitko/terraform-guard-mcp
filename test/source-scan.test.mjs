import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { scanTerraformSources } from "../lib/source-scan.mjs";

function withTf(contents) {
  const dir = mkdtempSync(path.join(tmpdir(), "tfguard-scan-"));
  writeFileSync(path.join(dir, "main.tf"), contents);
  try {
    return scanTerraformSources(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const ids = (v) => v.map((x) => x.ruleId).sort();

// The exact shape that motivated this module: the policy interpolates the bucket ARN, so the
// rendered document is unknown at plan time and the plan-based engine cannot see the Principal.
test("catches an account-wildcard Principal ARN inside a jsonencode policy", () => {
  const found = withTf(`
resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::*:role/log-service-role" }
      Resource  = "\${aws_s3_bucket.b.arn}/*"
    }]
  })
}
`);
  assert.deepEqual(ids(found), ["aws.iam.principal-account-wildcard"]);
  assert.match(found[0].message, /ANY AWS account/);
});

test("catches a fully public Principal", () => {
  const found = withTf(`
resource "aws_s3_bucket_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*" }] })
}
`);
  assert.deepEqual(ids(found), ["aws.iam.principal-wildcard"]);
});

// arn:aws:iam::aws:policy/... has the literal string "aws" in the account field. Treating that as
// a wildcard would flag every managed-policy attachment in existence.
test("does NOT flag AWS-managed policy ARNs", () => {
  const found = withTf(`
resource "aws_iam_role_policy_attachment" "a" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}
`);
  assert.deepEqual(found, []);
});

test("does NOT flag a wildcard in the resource portion of a known account", () => {
  const found = withTf(`
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Principal = { AWS = "arn:aws:iam::123456789012:role/*" } }] })
}
`);
  assert.deepEqual(found, []);
});

test("ignores commented-out dangerous literals", () => {
  const found = withTf(`
# Principal = { AWS = "arn:aws:iam::*:role/old-role" }
resource "aws_s3_bucket" "b" { bucket = "x" }
`);
  assert.deepEqual(found, []);
});

test("reports a missing directory as no findings rather than throwing", () => {
  assert.deepEqual(scanTerraformSources("/nonexistent/tfguard/path"), []);
});

// The configuration this rule was written for, verbatim from a real agent run. It passed
// `terraform validate`, passed the security scan, passed the pre-commit hook, and could never
// have deployed: the hardcoded key is what let `terraform plan` succeed with no credentials at
// all, which is exactly what made the clean report worthless.
test("flags hardcoded provider credentials", () => {
  const found = withTf(`
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "AKIA_DUMMY_ACCESS_KEY"
  secret_key                  = "DUMMY_SECRET_KEY"
  skip_credentials_validation = true
}
`);
  assert.deepEqual(ids(found), [
    "provider.hardcoded-credentials",
    "provider.hardcoded-credentials",
  ]);
  assert.equal(found[0].provider, "aws");
  assert.deepEqual(
    found.map((f) => f.attribute),
    ["access_key", "secret_key"]
  );
});

// A finding whose actualValue echoed the secret would put it into tool output, agent context,
// and any log that captures either.
test("never echoes the credential value in the finding", () => {
  const found = withTf(`
provider "aws" {
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
`);
  assert.equal(found.length, 1);
  assert.equal(found[0].actualValue, "<redacted>");
  assert.ok(!JSON.stringify(found).includes("wJalrXUtnFEMI"));
});

test("flags non-AWS provider secrets too", () => {
  const found = withTf(`
provider "azurerm" {
  client_secret = "a-real-looking-client-secret"
  features {}
}

provider "postgresql" {
  host     = "db.internal"
  password = "hunter2"
}
`);
  assert.deepEqual(
    found.map((f) => f.provider),
    ["azurerm", "postgresql"]
  );
});

test("does NOT flag credentials sourced from variables or resources", () => {
  const found = withTf(`
provider "aws" {
  access_key = var.access_key
  secret_key = "\${data.aws_secretsmanager_secret_version.s.secret_string}"
  token      = ""
}
`);
  assert.deepEqual(found, []);
});

// google's `credentials` takes either the key material or a path to it; a path is normal.
test("distinguishes a google credentials file path from inline key material", () => {
  assert.deepEqual(withTf(`provider "google" { credentials = "/etc/gcp/key.json" }`), []);
  const inline = withTf(
    `provider "google" { credentials = "{\\"type\\":\\"service_account\\",\\"private_key_id\\":\\"abc\\"}" }`
  );
  assert.deepEqual(ids(inline), ["provider.hardcoded-credentials"]);
});

// This repo's own aws-secure fixture hardcodes minioadmin/minioadmin against a container on
// 127.0.0.1 so a real `terraform apply` can be tested without an AWS account. Flagging that would
// make the scanner fail on the configuration written to prove the scanner works.
test("exempts a provider aimed at a local emulator", () => {
  const found = withTf(`
provider "aws" {
  access_key = "minioadmin"
  secret_key = "minioadmin"
  endpoints {
    s3 = "http://localhost:9100"
  }
}
`);
  assert.deepEqual(found, []);
});

// ...but the exemption must not become a laundering trick for a genuine key.
test("does not let a local endpoint exempt a syntactically real AWS key id", () => {
  const found = withTf(`
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "minioadmin"
  endpoints {
    s3 = "http://localhost:9100"
  }
}
`);
  assert.deepEqual(
    found.map((f) => f.attribute),
    ["access_key"]
  );
});

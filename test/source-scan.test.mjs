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

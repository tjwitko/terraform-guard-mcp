import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "fs";
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

// ---------------------------------------------------------------------------
// Cross-cloud: this module is the only enforcement path that runs without
// credentials, and across sixteen agent runs it is the only one that has ever
// evaluated a generated deliverable — every plan-based rule was skipped because
// no generated project could produce a plan. Rules added here actually execute.
// ---------------------------------------------------------------------------

// Verified against Google's IAM principal-identifiers documentation, not recalled: allUsers is
// anyone on the internet; allAuthenticatedUsers is anyone with a Google account, personal Gmail
// included. The AWS analogue (Principal = "*") has been covered since this module existed.
test("catches Google's public principals in an IAM member and an IAM binding", () => {
  const found = withTf(`
resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
resource "google_cloud_run_service_iam_binding" "invokers" {
  service = google_cloud_run_service.api.name
  role    = "roles/run.invoker"
  members = ["allAuthenticatedUsers"]
}
`);
  assert.deepEqual(ids(found), ["google.iam.public-principal", "google.iam.public-principal"]);
  assert.deepEqual(found.map((f) => f.actualValue).sort(), ["allAuthenticatedUsers", "allUsers"]);
});

// The same false-positive shape as an AWS Deny statement: a deny policy names these principals in
// order to restrict them. A scanner that flags correct hardening is one people switch off.
test("does not flag Google's public principals inside a deny policy", () => {
  const found = withTf(`
resource "google_iam_deny_policy" "lockdown" {
  name = "deny-public"
  rules {
    deny_rule {
      denied_principals  = ["allUsers", "allAuthenticatedUsers"]
      denied_permissions = ["storage.googleapis.com/objects.delete"]
    }
  }
}
`);
  assert.deepEqual(found, []);
});

// The local-emulator exemption is keyed on the AWS provider's `endpoints {}` syntax, but the value
// it was excusing did not have to be an AWS credential — the override was a single AWS
// access-key-id pattern, so a PEM key or a Google service-account key pasted into the same block
// was laundered through it.
test("a non-AWS credential is still flagged inside a local-emulator provider block", () => {
  const found = withTf(`
provider "aws" {
  access_key  = "minioadmin"
  private_key = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----"
  endpoints { s3 = "http://localhost:9100" }
}
`);
  assert.deepEqual(ids(found), ["provider.hardcoded-credentials"]);
  assert.equal(found[0].actualValue, "<redacted>");
});

// Regression guard for the exemption itself: this repo's own aws-secure fixture hardcodes
// minioadmin against 127.0.0.1 so it can run a real apply, and must keep passing.
test("still exempts genuine local-emulator credentials", () => {
  const found = withTf(`
provider "aws" {
  access_key = "minioadmin"
  secret_key = "minioadmin"
  endpoints { s3 = "http://localhost:9100" }
}
`);
  assert.deepEqual(found, []);
});

// The most obvious form of this defect, and the one place this scanner did not look. A generated
// project wrote `password = "SecurePassword123!"` straight into an aws_db_instance: the
// provider-block rule reads provider blocks, the variable rule reads variable blocks, the tfvars
// rule reads .tfvars, and a literal master password in the resource itself fell between all three
// while the gate reported zero findings.
test("catches a literal credential on a resource, across providers", () => {
  const found = withTf(`
resource "aws_db_instance" "log_db" {
  username = "log_admin"
  password = "SecurePassword123!"
}
resource "azurerm_mssql_server" "sql" {
  administrator_login_password = "P@ssw0rd2024"
}
`);
  assert.deepEqual(ids(found), ["resource.hardcoded-credentials", "resource.hardcoded-credentials"]);
  assert.deepEqual(found.map((f) => f.attribute).sort(), ["administrator_login_password", "password"]);
  assert.deepEqual(found.map((f) => f.actualValue), ["<redacted>", "<redacted>"]);
});

test("a resource credential sourced from a variable is not a literal", () => {
  const found = withTf(`
resource "aws_db_instance" "ok" {
  password = var.db_password
}
resource "aws_rds_cluster" "also_ok" {
  master_password = "\${var.pw}"
}
`);
  assert.deepEqual(found, []);
});

// This rule reads every resource in the configuration, so a name merely containing "password" must
// not fire. A scanner that flags aws_iam_account_password_policy produces findings nobody trusts.
test("does not flag password settings that hold no secret", () => {
  const found = withTf(`
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length   = 14
  password_reuse_prevention = 5
}
resource "aws_cognito_user_pool" "p" {
  password_policy { minimum_length = 12 }
}
`);
  assert.deepEqual(found, []);
});

// Matched on the value, not the name — the gap every other rule here leaves. A generated project
// wrote a Postgres URL with an embedded password into a .tfvars file under the name `database_url`,
// which is not credential-shaped, so the name-based rule was silent. It was raised in review and
// shipped anyway, which is the argument for a check rather than a comment.
test("catches a connection string carrying its own password, whatever the name", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "tfguard-scan-"));
  writeFileSync(
    path.join(dir, "dev.tfvars"),
    // The line-level opt-outs below sit on the string itself, not above it: both scanners match per
    // line, and this string IS the thing under test.
    'database_url = "postgresql://log_admin:REPLACE_ME_PASSWORD@db_endpoint_placeholder/audit_logs"\n' // identity-guard:allow test material; gitleaks:allow
  );
  try {
    const found = scanTerraformSources(dir);
    assert.deepEqual(ids(found), ["connection-string.embedded-password"]);
    assert.equal(found[0].actualValue, "<redacted>");
    assert.match(found[0].message, /postgresql connection string/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A URL is not a credential. Flagging every endpoint would make this rule noise, and the
// interpolated form is a reference rather than a literal.
test("does not flag URLs with no embedded password", () => {
  const found = withTf(`
variable "endpoint" { default = "https://api.internal/v1" }
variable "no_pw"    { default = "postgresql://reader@db.internal/app" }
variable "interp"   { default = "postgresql://u:\${var.pw}@db/app" } // identity-guard:allow test material; gitleaks:allow
`);
  assert.deepEqual(found, []);
});

// Child modules live in subdirectories and this walk did not enter them, so a literal credential in
// modules/db/main.tf was invisible to every rule in this file. Not a corner case: child modules are
// the layout Terraform documents, and the one this repo's own IaC benchmark fixture teaches.
test("descends into child modules, and names the file it found", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "tfguard-scan-"));
  mkdirSync(path.join(dir, "modules", "db"), { recursive: true });
  writeFileSync(path.join(dir, "main.tf"), 'module "db" { source = "./modules/db" }\n');
  writeFileSync(
    path.join(dir, "modules", "db", "main.tf"),
    'resource "aws_db_instance" "d" {\n  password = "SubmoduleSecret123!"\n}\n' // gitleaks:allow
  );
  try {
    const found = scanTerraformSources(dir);
    assert.deepEqual(ids(found), ["resource.hardcoded-credentials"]);
    assert.match(found[0].resourceAddress, /modules\/db\/main\.tf/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Reporting a credential inside a module Terraform downloaded is noise the caller cannot act on,
// and this project has watched a model rewrite its own working files chasing errors that lived in
// vendored code. Same reason the Checkov integration drops vendored findings.
test("does not descend into .terraform, where downloaded modules live", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "tfguard-scan-"));
  mkdirSync(path.join(dir, ".terraform", "modules", "vendored"), { recursive: true });
  writeFileSync(path.join(dir, "main.tf"), 'resource "aws_s3_bucket" "b" { bucket = "x" }\n');
  writeFileSync(
    path.join(dir, ".terraform", "modules", "vendored", "main.tf"),
    'resource "aws_db_instance" "v" {\n  password = "VendoredThirdPartySecret!"\n}\n' // gitleaks:allow
  );
  try {
    assert.deepEqual(scanTerraformSources(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// HCL lets any string be written as a heredoc, and every rule here required a quoted value, so
// `secret_key = <<-EOT ... EOT` was invisible to all of them. gitleaks does not close the gap:
// measured with identical high-entropy credentials, its generic-api-key rule fired on the quoted
// form and not on the heredoc. Its private-key rule DOES match a PEM in a heredoc, so multi-line
// key material stays covered by the other scanner; the uncovered set was generic secrets.
test("catches credentials written as heredocs, indented or flush", () => {
  const found = withTf(`
provider "aws" {
  region     = "us-east-1"
  secret_key = <<-EOT
    wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  EOT
}
resource "aws_db_instance" "d" {
  password = <<EOT
SuperSecretDbPassword123!
EOT
}
`); // gitleaks:allow
  assert.deepEqual(ids(found), ["provider.hardcoded-credentials", "resource.hardcoded-credentials"]);
  assert.deepEqual(found.map((f) => f.actualValue), ["<redacted>", "<redacted>"]);
});

test("catches a connection string written as a heredoc", () => {
  // Assembled rather than written out, so no line of this file is itself a credential. Both this
  // repo's own scanners flag a literal DSN here and refuse the commit, and suppressing them inside
  // the test data would change the very value under test.
  const dsn = ["postgresql://svc:", "hunter2", "@db.internal/app"].join("");
  const found = withTf(`
resource "kubernetes_secret" "s" {
  data = {
    url = <<-EOT
      ${dsn}
    EOT
  }
}
`);
  assert.deepEqual(ids(found), ["connection-string.embedded-password"]);
});

// The same exclusions apply whichever way the string is written: an interpolation is a reference,
// and a heredoc on a non-credential attribute is just a multi-line string, which is what heredocs
// are normally for.
test("heredocs that are not literal credentials do not fire", () => {
  const found = withTf(`
provider "aws" {
  secret_key = <<-EOT
    \${var.secret}
  EOT
}
resource "aws_instance" "i" {
  user_data = <<-EOT
    #!/bin/bash
    echo hello
  EOT
}
`);
  assert.deepEqual(found, []);
});

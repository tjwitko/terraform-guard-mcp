import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "fs";
import { tmpdir } from "os";
import path from "path";

import {
  declaredVariables,
  syntheticValue,
  syntheticVarEnv,
  scanCredentialEnv,
  planInputs,
  writeScanOverride,
  removeScanOverride,
  SCAN_OVERRIDE_FILE,
} from "../lib/plan-inputs.mjs";

const NO_HOME = "/nonexistent-tfguard-home";

function withDir(files) {
  const dir = mkdtempSync(path.join(tmpdir(), "tfguard-inputs-"));
  for (const [name, contents] of Object.entries(files)) writeFileSync(path.join(dir, name), contents);
  return dir;
}

// The measured cause of four of eight unscanned runs. A variable with no default and no value is
// not a defect in the configuration -- a flawless project fails identically -- so the scanner
// supplies one rather than reporting the whole directory as unscannable.
test("a variable with no default and no tfvars value is synthesized", () => {
  const dir = withDir({ "v.tf": 'variable "db_password" {\n  type = string\n}\n' });
  try {
    assert.deepEqual(declaredVariables(dir), [{ name: "db_password", type: "string", satisfied: false }]);
    assert.deepEqual(Object.keys(syntheticVarEnv(dir)), ["TF_VAR_db_password"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Terraform auto-loads terraform.tfvars and *.auto.tfvars, and nothing else. A run named its file
// dummy.tfvars, believed the variable was supplied, and could not plan for the rest of the run.
test("only genuinely auto-loaded tfvars files count as supplying a value", () => {
  const decl = 'variable "a" { type = string }\nvariable "b" { type = string }\nvariable "c" { type = string }\n';
  const dir = withDir({
    "v.tf": decl,
    "terraform.tfvars": 'a = "x"\n',
    "extra.auto.tfvars": 'b = "y"\n',
    "dummy.tfvars": 'c = "z"\n',
  });
  try {
    const byName = Object.fromEntries(declaredVariables(dir).map((v) => [v.name, v.satisfied]));
    assert.deepEqual(byName, { a: true, b: true, c: false });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a variable with a default is left alone", () => {
  const dir = withDir({ "v.tf": 'variable "region" {\n  default = "us-east-1"\n}\n' });
  try {
    assert.deepEqual(syntheticVarEnv(dir), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// TF_VAR_ values are parsed as HCL for complex types, so a list has to look like one. The string
// placeholder is long enough to clear minimum-length rules such as an RDS master password.
test("synthesized values match the declared type", () => {
  assert.equal(syntheticValue("bool"), "false");
  assert.equal(syntheticValue("number"), "1");
  assert.equal(syntheticValue("list(string)"), '["tfguard-scan-a","tfguard-scan-b"]');
  assert.equal(syntheticValue("map(string)"), "{}");
  assert.ok(syntheticValue("string").length >= 8);
});

test("placeholder credentials are only supplied when nothing else can authenticate", () => {
  const dir = withDir({ "m.tf": 'provider "aws" {\n  region = "us-east-1"\n}\n' });
  try {
    assert.equal(Object.keys(scanCredentialEnv(dir, {}, NO_HOME)).length > 0, true);
    // A real account always wins: scanning under different credentials than the caller expects
    // would make the result mean something other than what it says.
    assert.deepEqual(scanCredentialEnv(dir, { AWS_PROFILE: "prod" }, NO_HOME), {});
    assert.deepEqual(scanCredentialEnv(dir, { AWS_ACCESS_KEY_ID: "real" }, NO_HOME), {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// This repo's aws-secure fixture hardcodes MinIO credentials so it can run a real apply end to
// end. Treating it as credential-less would deny it a planId and break the test that proves the
// plan->apply guarantee holds.
test("a provider that carries its own credentials is left untouched", () => {
  const dir = withDir({
    "m.tf": 'provider "aws" {\n  access_key = "minioadmin"\n  secret_key = "minioadmin"\n}\n',
  });
  try {
    const i = planInputs(dir, {}, NO_HOME);
    assert.equal(i.injectedCredentials, false);
    assert.equal(i.scanOnly, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The whole safety argument for this module. Terraform writes variable values into the plan file,
// so a plan built on placeholders must never become applyable.
test("any injection marks the plan scan-only", () => {
  const dir = withDir({
    "m.tf": 'provider "aws" {\n  region = "us-east-1"\n}\nvariable "pw" { type = string }\n',
  });
  try {
    const i = planInputs(dir, {}, NO_HOME);
    assert.equal(i.scanOnly, true);
    assert.deepEqual(i.injectedVariables, ["pw"]);
    assert.equal(i.injectedCredentials, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the scan override is written only for known providers and always removable", () => {
  const dir = withDir({ "m.tf": 'provider "aws" {}\n' });
  try {
    assert.equal(writeScanOverride(dir, new Set(["kubernetes"])), false);
    assert.equal(existsSync(path.join(dir, SCAN_OVERRIDE_FILE)), false);

    assert.equal(writeScanOverride(dir, new Set(["aws"])), true);
    assert.ok(existsSync(path.join(dir, SCAN_OVERRIDE_FILE)));

    removeScanOverride(dir);
    assert.equal(existsSync(path.join(dir, SCAN_OVERRIDE_FILE)), false);
    removeScanOverride(dir); // absent is the normal case, must not throw
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a missing directory yields no inputs rather than throwing", () => {
  const i = planInputs("/nonexistent/tfguard/dir", {}, NO_HOME);
  assert.equal(i.scanOnly, false);
  assert.deepEqual(i.injectedVariables, []);
});

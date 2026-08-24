// Makes a plan possible on a machine with no cloud account, so the rule engine has something to
// evaluate.
//
// Why this exists: across sixteen agent runs, not one generated project ever produced a plan, so
// not one plan-based security rule ever ran. The causes were counted rather than guessed — four
// runs failed on a required variable with no value, two on absent credentials, and two on genuine
// configuration errors. The first two classes are the harness's fault, not the configuration's: a
// perfectly secure project would have failed identically. This module removes them.
//
// The hard constraint that shapes everything below: **terraform bakes variable values into the
// plan file**, unlike credentials, which the provider re-resolves at apply time (verified
// separately, see CLAUDE.md). So a plan built with synthesized values must never become an
// applyable planId — applying it would deploy a database whose password is
// "tfguard-scan-placeholder". Callers get the security verdict and no plan id. That keeps the
// enforcement guarantee exactly where it was while letting the rules finally run.

import { existsSync, readdirSync, readFileSync, writeFileSync, unlinkSync } from "fs";
import path from "path";
import os from "os";

import { blockBodyAt } from "./source-scan.mjs";

const VARIABLE_BLOCK_RE = /(?:^|\n)\s*variable\s+"([^"]+)"\s*\{/g;
const TYPE_RE = /(?:^|\n)\s*type\s*=\s*([^\n]+)/;
const HAS_DEFAULT_RE = /(?:^|\n)\s*default\s*=/;

// Terraform auto-loads exactly these: terraform.tfvars, terraform.tfvars.json, and anything
// matching *.auto.tfvars(.json). A file the model happens to name dummy.tfvars is NOT loaded,
// which is precisely how one run ended up with a required variable it believed it had supplied.
function autoLoadedAssignments(dir) {
  const assigned = new Set();
  let files = [];
  try {
    files = readdirSync(dir);
  } catch {
    return assigned;
  }
  for (const f of files) {
    if (f !== "terraform.tfvars" && !f.endsWith(".auto.tfvars")) continue;
    let text = "";
    try {
      text = readFileSync(path.join(dir, f), "utf8");
    } catch {
      continue;
    }
    for (const m of text.matchAll(/(?:^|\n)\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=/g)) assigned.add(m[1]);
  }
  return assigned;
}

/** Every `variable` block in the directory, with whether it already has a value. */
export function declaredVariables(dir) {
  const out = [];
  const assigned = autoLoadedAssignments(dir);
  let files = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".tf"));
  } catch {
    return out;
  }
  for (const file of files) {
    let source = "";
    try {
      source = readFileSync(path.join(dir, file), "utf8");
    } catch {
      continue;
    }
    VARIABLE_BLOCK_RE.lastIndex = 0;
    let m;
    while ((m = VARIABLE_BLOCK_RE.exec(source))) {
      const name = m[1];
      const body = blockBodyAt(source, VARIABLE_BLOCK_RE.lastIndex - 1);
      out.push({
        name,
        type: (body.match(TYPE_RE)?.[1] || "string").trim(),
        satisfied: HAS_DEFAULT_RE.test(body) || assigned.has(name),
      });
    }
  }
  return out;
}

// TF_VAR_ values are parsed as HCL for complex types, so a list has to look like a list. The
// string placeholder is 26 characters because real resources impose minimum lengths — an RDS
// master password under 8 characters fails at plan time and would trade one blocked plan for
// another.
export function syntheticValue(type) {
  const t = type.toLowerCase();
  if (/^bool/.test(t)) return "false";
  if (/^number/.test(t)) return "1";
  if (/^(list|set|tuple)/.test(t)) return '["tfguard-scan-a","tfguard-scan-b"]';
  if (/^(map|object)/.test(t)) return "{}";
  return "tfguard-scan-placeholder-01";
}

/** TF_VAR_* entries for every variable that has no value from any other source. */
export function syntheticVarEnv(dir) {
  const env = {};
  for (const v of declaredVariables(dir)) {
    if (v.satisfied) continue;
    env[`TF_VAR_${v.name}`] = syntheticValue(v.type);
  }
  return env;
}

// Scan-only credentials, per provider. Deliberately a table rather than an AWS special case, so a
// second cloud is a data change; but only AWS is filled in, because what makes an offline plan
// succeed differs per provider and is not something to write from memory. The AWS values are
// Amazon's own documented example key pair.
//
// These never reach an apply: any injection makes the plan scan-only, and terraform_apply resolves
// credentials from the real environment.
const SCAN_CREDENTIALS = {
  aws: {
    resolvedBy: ["AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"],
    configFiles: [".aws/credentials", ".aws/config"],
    env: {
      AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
      AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      AWS_DEFAULT_REGION: "us-east-1",
    },
    // Placeholder credentials alone are not enough for any resource that needs the account id:
    // the provider calls STS GetCallerIdentity and fails with InvalidClientTokenId. There are no
    // environment-variable equivalents for skip_credentials_validation or
    // skip_requesting_account_id -- only skip_metadata_api_check has one -- so the settings have
    // to come from configuration. An override file supplies them without touching the caller's
    // source: Terraform merges `*_override.tf` into the matching block, adding these arguments
    // while leaving everything the original set (verified: `region` survives the merge).
    //
    // This is the same mechanism as the "make a plan succeed with no account" trick that
    // aws.provider.hardcoded-credentials exists to catch. The difference is where it lives and how
    // long: in a scanner-owned file, deleted before this call returns, and never on a path that
    // can produce an applyable planId.
    overrideBody:
      'provider "aws" {\n' +
      "  skip_credentials_validation = true\n" +
      "  skip_requesting_account_id  = true\n" +
      "  skip_metadata_api_check     = true\n" +
      "}\n",
  },
};

// Named to sort last and to be unmistakable if it ever survives a crash. Terraform loads any file
// matching *_override.tf, so the name also has to end that way.
export const SCAN_OVERRIDE_FILE = "zzz_tfguard_scan_override.tf";

/** Write the scan-only provider override, returning true if one was needed. */
export function writeScanOverride(dir, providers) {
  const bodies = [...providers].map((p) => SCAN_CREDENTIALS[p]?.overrideBody).filter(Boolean);
  if (bodies.length === 0) return false;
  writeFileSync(
    path.join(dir, SCAN_OVERRIDE_FILE),
    "# Written by terraform-guard for a scan-only plan, and deleted immediately after.\n" +
      "# If you are reading this in a committed repository, a scan crashed: delete it.\n" +
      bodies.join("\n"),
    "utf8"
  );
  return true;
}

/** Remove it. Safe to call when it was never written. */
export function removeScanOverride(dir) {
  try {
    unlinkSync(path.join(dir, SCAN_OVERRIDE_FILE));
  } catch {
    /* absent is the normal case */
  }
}

const PROVIDER_BLOCK_RE = /(?:^|\n)\s*provider\s+"([\w-]+)"\s*\{/g;

export function providersUsed(dir) {
  const found = new Set();
  let files = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".tf"));
  } catch {
    return found;
  }
  for (const file of files) {
    let source = "";
    try {
      source = readFileSync(path.join(dir, file), "utf8");
    } catch {
      continue;
    }
    PROVIDER_BLOCK_RE.lastIndex = 0;
    let m;
    while ((m = PROVIDER_BLOCK_RE.exec(source))) found.add(m[1]);
  }
  return found;
}

// Attributes that mean this provider block carries its own credentials. Kept deliberately broad:
// the question here is only "can this configuration authenticate on its own", and a false yes
// simply leaves the configuration untouched, which is the safe direction.
const INLINE_CREDENTIAL_ATTRS =
  /(^|[\s{])(access_key|secret_key|token|access_token|client_secret|credentials|password|private_key)\s*=/m;

/**
 * Providers that supply their own credentials in source. This repo's own aws-secure fixture is
 * exactly that shape -- it hardcodes MinIO credentials so it can run a real apply end to end --
 * and without this check it would be treated as credential-less, turned into a scan-only plan, and
 * denied a planId, breaking the test that proves the plan->apply guarantee holds.
 */
export function providersWithInlineCredentials(dir) {
  const found = new Set();
  let files = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".tf"));
  } catch {
    return found;
  }
  for (const file of files) {
    let source = "";
    try {
      source = readFileSync(path.join(dir, file), "utf8");
    } catch {
      continue;
    }
    PROVIDER_BLOCK_RE.lastIndex = 0;
    let m;
    while ((m = PROVIDER_BLOCK_RE.exec(source))) {
      const body = blockBodyAt(source, PROVIDER_BLOCK_RE.lastIndex - 1);
      if (INLINE_CREDENTIAL_ATTRS.test(body)) found.add(m[1]);
    }
  }
  return found;
}

function credentialsAlreadyResolvable(spec, baseEnv, home) {
  if (spec.resolvedBy.some((k) => baseEnv[k])) return true;
  return spec.configFiles.some((f) => existsSync(path.join(home, f)));
}

/**
 * Placeholder credentials for providers in this configuration that have none available. Returns
 * `{}` when the machine can already authenticate — a real account must always win, or the scan
 * would silently run against different credentials than the caller expects.
 */
export function scanCredentialEnv(dir, baseEnv = process.env, home = os.homedir()) {
  const env = {};
  const inline = providersWithInlineCredentials(dir);
  for (const provider of providersUsed(dir)) {
    const spec = SCAN_CREDENTIALS[provider];
    if (!spec) continue;
    if (inline.has(provider)) continue;
    if (credentialsAlreadyResolvable(spec, baseEnv, home)) continue;
    Object.assign(env, spec.env);
  }
  return env;
}

/**
 * Everything needed to make this directory plannable, plus why. An empty `injected` means nothing
 * was synthesized and the resulting plan is a real one that may be stored for apply.
 */
export function planInputs(dir, baseEnv = process.env, home = os.homedir()) {
  const vars = syntheticVarEnv(dir);
  const credentials = scanCredentialEnv(dir, baseEnv, home);
  const injectedVars = Object.keys(vars).map((k) => k.replace(/^TF_VAR_/, ""));
  return {
    env: { ...vars, ...credentials },
    injectedVariables: injectedVars,
    injectedCredentials: Object.keys(credentials).length > 0,
    providers: providersUsed(dir),
    scanOnly: injectedVars.length > 0 || Object.keys(credentials).length > 0,
  };
}

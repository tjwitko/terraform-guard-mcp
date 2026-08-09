import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";

// Mints short-lived, apply-capable AWS credentials for a single guarded terraform_apply.
//
// The point of this module is that the *ambient* environment (what a raw shell would inherit)
// holds only plan/read-level credentials, so a `terraform apply` run outside this server fails
// at AWS with AccessDenied. Apply-capable credentials exist only inside the subprocess this
// server spawns, and only for the length of one apply.
//
// Uses the AWS SDK rather than shelling out to the `aws` CLI for two reasons: the CLI is a
// second prerequisite that may not be installed, and the SDK resolves the ambient credential
// chain (env -> ~/.aws/credentials -> SSO -> IMDS) the same way Terraform itself does. That
// resolution is genuinely hard to reproduce correctly by hand and is security-critical, so it's
// worth the heavier dependency tree relative to the sibling servers in this workspace.

// STS minimum is 900s. An apply shouldn't outlive itself, so the floor is also the default —
// there's no benefit to a credential that stays valid long after the apply that needed it.
const DEFAULT_DURATION_SECONDS = 900;
const MIN_DURATION_SECONDS = 900;
const MAX_DURATION_SECONDS = 43200;

export function isScopedCredentialsConfigured() {
  return Boolean(process.env.TFGUARD_APPLY_ROLE_ARN);
}

function resolveDuration() {
  const raw = Number(process.env.TFGUARD_SESSION_DURATION);
  if (!Number.isFinite(raw)) return DEFAULT_DURATION_SECONDS;
  // Clamp rather than fail: a misconfigured duration shouldn't block an otherwise-valid apply,
  // and STS would reject an out-of-range value with a much less obvious error than this.
  return Math.min(Math.max(Math.trunc(raw), MIN_DURATION_SECONDS), MAX_DURATION_SECONDS);
}

// RoleSessionName is the audit hook, not decoration. Every legitimate apply is attributable in
// CloudTrail to a specific plan that this server scanned and stored; an out-of-band
// `aws sts assume-role` cannot name a plan id that exists in the plan store. That's what makes
// the residual bypass (ambient identity is permitted to assume the role) detectable rather than
// invisible. Constraint per the STS API: 2-64 chars matching [\w+=,.@-] — "tfguard-" plus a
// 36-char UUID is 44, and hyphens are allowed, so a plan id always fits without sanitizing.
function sessionNameFor(planId) {
  return `tfguard-${planId}`.slice(0, 64);
}

// `stsClient` is injectable purely so the failure path can be tested without AWS credentials or
// network access — production callers omit it.
export async function assumeApplyRole({ planId, stsClient } = {}) {
  const roleArn = process.env.TFGUARD_APPLY_ROLE_ARN;
  if (!roleArn) {
    throw new Error("TFGUARD_APPLY_ROLE_ARN is not set");
  }

  const client = stsClient || new STSClient({});
  const input = {
    RoleArn: roleArn,
    RoleSessionName: sessionNameFor(planId),
    DurationSeconds: resolveDuration(),
  };
  if (process.env.TFGUARD_EXTERNAL_ID) {
    input.ExternalId = process.env.TFGUARD_EXTERNAL_ID;
  }

  const response = await client.send(new AssumeRoleCommand(input));
  const creds = response?.Credentials;
  if (!creds?.AccessKeyId || !creds?.SecretAccessKey || !creds?.SessionToken) {
    // A 200 response with incomplete credentials would otherwise produce a subprocess env with
    // undefined values, which fails much later and much more confusingly than failing here.
    throw new Error("STS returned a response without complete credentials");
  }

  return {
    accessKeyId: creds.AccessKeyId,
    secretAccessKey: creds.SecretAccessKey,
    sessionToken: creds.SessionToken,
    expiration: creds.Expiration ? new Date(creds.Expiration).toISOString() : null,
    roleSessionName: input.RoleSessionName,
  };
}

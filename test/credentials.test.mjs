import test from "node:test";
import assert from "node:assert/strict";
import { buildApplyEnv } from "../lib/terraform-cli.mjs";
import { assumeApplyRole, isScopedCredentialsConfigured } from "../lib/aws-credentials.mjs";

const FAKE_CREDS = {
  accessKeyId: "ASIAFAKEACCESSKEY",
  secretAccessKey: "fake-secret",
  sessionToken: "fake-session-token",
};

test("buildApplyEnv injects the three credential variables", () => {
  const env = buildApplyEnv({ PATH: "/usr/bin" }, FAKE_CREDS);
  assert.equal(env.AWS_ACCESS_KEY_ID, "ASIAFAKEACCESSKEY");
  assert.equal(env.AWS_SECRET_ACCESS_KEY, "fake-secret");
  assert.equal(env.AWS_SESSION_TOKEN, "fake-session-token");
  assert.equal(env.PATH, "/usr/bin", "unrelated variables must be preserved");
});

// The bug this guards against: a profile in the ambient environment wins over static credentials
// in the AWS credential chain, so leaving it set would silently run the apply under the ambient
// (plan-only) identity while this server reported that it had scoped the credentials.
test("buildApplyEnv removes AWS_PROFILE and AWS_DEFAULT_PROFILE", () => {
  const env = buildApplyEnv(
    { AWS_PROFILE: "personal", AWS_DEFAULT_PROFILE: "work", PATH: "/usr/bin" },
    FAKE_CREDS
  );
  assert.equal("AWS_PROFILE" in env, false);
  assert.equal("AWS_DEFAULT_PROFILE" in env, false);
  assert.equal(env.AWS_ACCESS_KEY_ID, "ASIAFAKEACCESSKEY");
});

test("buildApplyEnv does not mutate the environment object it was given", () => {
  const base = { AWS_PROFILE: "personal", PATH: "/usr/bin" };
  buildApplyEnv(base, FAKE_CREDS);
  assert.equal(base.AWS_PROFILE, "personal", "process.env must not be modified in place");
  assert.equal(base.AWS_ACCESS_KEY_ID, undefined);
});

test("isScopedCredentialsConfigured reflects TFGUARD_APPLY_ROLE_ARN", () => {
  const original = process.env.TFGUARD_APPLY_ROLE_ARN;
  try {
    delete process.env.TFGUARD_APPLY_ROLE_ARN;
    assert.equal(isScopedCredentialsConfigured(), false);
    process.env.TFGUARD_APPLY_ROLE_ARN = "arn:aws:iam::123456789012:role/terraform-guard-apply";
    assert.equal(isScopedCredentialsConfigured(), true);
  } finally {
    if (original === undefined) delete process.env.TFGUARD_APPLY_ROLE_ARN;
    else process.env.TFGUARD_APPLY_ROLE_ARN = original;
  }
});

test("assumeApplyRole throws when no role is configured", async () => {
  const original = process.env.TFGUARD_APPLY_ROLE_ARN;
  try {
    delete process.env.TFGUARD_APPLY_ROLE_ARN;
    await assert.rejects(() => assumeApplyRole({ planId: "abc" }), /TFGUARD_APPLY_ROLE_ARN is not set/);
  } finally {
    if (original === undefined) delete process.env.TFGUARD_APPLY_ROLE_ARN;
    else process.env.TFGUARD_APPLY_ROLE_ARN = original;
  }
});

test("assumeApplyRole surfaces an STS failure instead of returning unusable credentials", async () => {
  const original = process.env.TFGUARD_APPLY_ROLE_ARN;
  process.env.TFGUARD_APPLY_ROLE_ARN = "arn:aws:iam::123456789012:role/terraform-guard-apply";
  const failingClient = {
    send: async () => {
      throw new Error("AccessDenied: not authorized to perform sts:AssumeRole");
    },
  };
  try {
    await assert.rejects(
      () => assumeApplyRole({ planId: "abc", stsClient: failingClient }),
      /AccessDenied/
    );
  } finally {
    if (original === undefined) delete process.env.TFGUARD_APPLY_ROLE_ARN;
    else process.env.TFGUARD_APPLY_ROLE_ARN = original;
  }
});

// A 200 response with missing fields would otherwise produce a subprocess env containing
// "undefined" strings, failing far later and far less legibly than failing right here.
test("assumeApplyRole rejects a success response with incomplete credentials", async () => {
  const original = process.env.TFGUARD_APPLY_ROLE_ARN;
  process.env.TFGUARD_APPLY_ROLE_ARN = "arn:aws:iam::123456789012:role/terraform-guard-apply";
  const partialClient = {
    send: async () => ({ Credentials: { AccessKeyId: "ASIA", SecretAccessKey: "s" } }), // no SessionToken
  };
  try {
    await assert.rejects(
      () => assumeApplyRole({ planId: "abc", stsClient: partialClient }),
      /without complete credentials/
    );
  } finally {
    if (original === undefined) delete process.env.TFGUARD_APPLY_ROLE_ARN;
    else process.env.TFGUARD_APPLY_ROLE_ARN = original;
  }
});

test("assumeApplyRole builds an auditable, spec-conformant session name", async () => {
  const original = process.env.TFGUARD_APPLY_ROLE_ARN;
  const originalExternalId = process.env.TFGUARD_EXTERNAL_ID;
  process.env.TFGUARD_APPLY_ROLE_ARN = "arn:aws:iam::123456789012:role/terraform-guard-apply";
  process.env.TFGUARD_EXTERNAL_ID = "shared-secret";

  let captured;
  const capturingClient = {
    send: async (command) => {
      captured = command.input;
      return {
        Credentials: {
          AccessKeyId: "ASIA",
          SecretAccessKey: "s",
          SessionToken: "t",
          Expiration: new Date("2030-01-01T00:00:00Z"),
        },
      };
    },
  };

  try {
    const planId = "6b5c1a61-e51b-4985-843a-5d4ba34649bb"; // a real UUID shape
    const result = await assumeApplyRole({ planId, stsClient: capturingClient });

    assert.equal(captured.RoleSessionName, `tfguard-${planId}`);
    // STS constraints, verified against the API reference: 2-64 chars, [\w+=,.@-] only.
    assert.ok(captured.RoleSessionName.length <= 64, "session name must fit the 64-char limit");
    assert.match(captured.RoleSessionName, /^[\w+=,.@-]+$/);
    assert.equal(captured.ExternalId, "shared-secret");
    assert.equal(captured.DurationSeconds, 900);
    assert.equal(result.roleSessionName, `tfguard-${planId}`);
  } finally {
    if (original === undefined) delete process.env.TFGUARD_APPLY_ROLE_ARN;
    else process.env.TFGUARD_APPLY_ROLE_ARN = original;
    if (originalExternalId === undefined) delete process.env.TFGUARD_EXTERNAL_ID;
    else process.env.TFGUARD_EXTERNAL_ID = originalExternalId;
  }
});

test("session duration is clamped to the STS-permitted range", async () => {
  const original = process.env.TFGUARD_APPLY_ROLE_ARN;
  const originalDuration = process.env.TFGUARD_SESSION_DURATION;
  process.env.TFGUARD_APPLY_ROLE_ARN = "arn:aws:iam::123456789012:role/terraform-guard-apply";

  let captured;
  const capturingClient = {
    send: async (command) => {
      captured = command.input;
      return { Credentials: { AccessKeyId: "A", SecretAccessKey: "s", SessionToken: "t" } };
    },
  };

  try {
    process.env.TFGUARD_SESSION_DURATION = "10"; // below the 900s STS minimum
    await assumeApplyRole({ planId: "abc", stsClient: capturingClient });
    assert.equal(captured.DurationSeconds, 900);

    process.env.TFGUARD_SESSION_DURATION = "999999"; // above the 43200s STS maximum
    await assumeApplyRole({ planId: "abc", stsClient: capturingClient });
    assert.equal(captured.DurationSeconds, 43200);
  } finally {
    if (original === undefined) delete process.env.TFGUARD_APPLY_ROLE_ARN;
    else process.env.TFGUARD_APPLY_ROLE_ARN = original;
    if (originalDuration === undefined) delete process.env.TFGUARD_SESSION_DURATION;
    else process.env.TFGUARD_SESSION_DURATION = originalDuration;
  }
});

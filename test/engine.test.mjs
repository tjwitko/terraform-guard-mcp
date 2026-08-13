import test from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../rules/engine.mjs";
import { PROVIDER_PACKS } from "../rules/index.mjs";

// Minimal hand-authored resource_changes entries matching the real terraform show -json shape
// confirmed against a live `terraform plan` this session: {address, module_address, mode, type,
// name, provider_name, change: {actions, before, after, after_unknown}}. Equivalent to a
// captured fixture for unit-test purposes, simpler to keep next to the assertions that use them.
const AWS_PROVIDER = "registry.terraform.io/hashicorp/aws";

function resource(overrides) {
  return {
    address: overrides.address,
    module_address: overrides.module_address ?? "",
    mode: overrides.mode ?? "managed",
    type: overrides.type,
    name: overrides.name ?? "this",
    provider_name: AWS_PROVIDER,
    change: {
      actions: overrides.actions ?? ["create"],
      before: null,
      after: overrides.after ?? {},
      after_unknown: overrides.after_unknown ?? {},
    },
  };
}

function planOf(...resources) {
  return { resource_changes: resources };
}

function ruleIds(violations) {
  return violations.map((v) => v.ruleId).sort();
}

test("s3-public-access-block-missing: flags a bucket with no PAB", () => {
  const plan = planOf(resource({ address: "aws_s3_bucket.this", type: "aws_s3_bucket", module_address: "module.storage" }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.storage.s3-public-access-block-missing"]);
});

test("s3-public-access-block-missing: flags a PAB with one attribute false", () => {
  const plan = planOf(
    resource({ address: "aws_s3_bucket.this", type: "aws_s3_bucket", module_address: "module.storage" }),
    resource({
      address: "aws_s3_bucket_public_access_block.this",
      type: "aws_s3_bucket_public_access_block",
      module_address: "module.storage",
      after: { block_public_acls: true, block_public_policy: true, ignore_public_acls: true, restrict_public_buckets: false },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.storage.s3-public-access-block-missing"]);
});

test("s3-public-access-block-missing: passes with a correctly-configured PAB", () => {
  const plan = planOf(
    resource({ address: "aws_s3_bucket.this", type: "aws_s3_bucket", module_address: "module.storage" }),
    resource({
      address: "aws_s3_bucket_public_access_block.this",
      type: "aws_s3_bucket_public_access_block",
      module_address: "module.storage",
      after: { block_public_acls: true, block_public_policy: true, ignore_public_acls: true, restrict_public_buckets: true },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("s3-public-access-block-missing: a bucket whose PAB is being deleted is still flagged", () => {
  const plan = planOf(
    resource({ address: "aws_s3_bucket.this", type: "aws_s3_bucket", module_address: "module.storage", actions: ["no-op"] }),
    resource({
      address: "aws_s3_bucket_public_access_block.this",
      type: "aws_s3_bucket_public_access_block",
      module_address: "module.storage",
      actions: ["delete"],
      after: { block_public_acls: true, block_public_policy: true, ignore_public_acls: true, restrict_public_buckets: true },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.storage.s3-public-access-block-missing"]);
});

test("sg-open-ingress: flags inline ingress open to 0.0.0.0/0 on port 22", () => {
  const plan = planOf(
    resource({
      address: "aws_security_group.web",
      type: "aws_security_group",
      after: { ingress: [{ cidr_blocks: ["0.0.0.0/0"], from_port: 22, to_port: 22, protocol: "tcp" }] },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.network.sg-open-ingress-sensitive-port"]);
});

test("sg-open-ingress: passes inline ingress restricted to a known CIDR", () => {
  const plan = planOf(
    resource({
      address: "aws_security_group.web",
      type: "aws_security_group",
      after: { ingress: [{ cidr_blocks: ["10.0.0.0/8"], from_port: 22, to_port: 22, protocol: "tcp" }] },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("sg-open-ingress: flags the newer per-rule resource open on port 3389", () => {
  const plan = planOf(
    resource({
      address: "aws_vpc_security_group_ingress_rule.rdp",
      type: "aws_vpc_security_group_ingress_rule",
      after: { cidr_ipv4: "0.0.0.0/0", from_port: 3389, to_port: 3389, ip_protocol: "tcp" },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.network.sg-open-ingress-sensitive-port"]);
});

test("sg-open-ingress: open CIDR on a non-sensitive port is not flagged", () => {
  const plan = planOf(
    resource({
      address: "aws_vpc_security_group_ingress_rule.http",
      type: "aws_vpc_security_group_ingress_rule",
      after: { cidr_ipv4: "0.0.0.0/0", from_port: 8080, to_port: 8080, ip_protocol: "tcp" },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("iam-wildcard: flags Action: \"*\" in an aws_iam_policy", () => {
  const plan = planOf(
    resource({
      address: "aws_iam_policy.admin",
      type: "aws_iam_policy",
      after: { policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }) },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.iam.wildcard-action-or-principal"]);
});

test("iam-wildcard: passes a scoped policy", () => {
  const plan = planOf(
    resource({
      address: "aws_iam_policy.reader",
      type: "aws_iam_policy",
      after: { policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::example/*" }] }) },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("iam-wildcard: unresolved policy (after_unknown) is skipped, not blocked", () => {
  const plan = planOf(
    resource({
      address: "aws_iam_policy.dynamic",
      type: "aws_iam_policy",
      after: {},
      after_unknown: { policy: true },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

// The exact policy a local model shipped on an audit-log bucket. It reads like a scoped ARN, but
// the wildcard is in the account field, so any AWS account with a role of that name gets access.
test("iam-wildcard: flags a Principal ARN whose ACCOUNT field is a wildcard", () => {
  const plan = planOf(
    resource({
      address: "aws_s3_bucket_policy.logs",
      type: "aws_s3_bucket_policy",
      after: {
        policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: { AWS: "arn:aws:iam::*:role/log-service-role" },
              Action: ["s3:PutObject"],
              Resource: "arn:aws:s3:::logs/*",
            },
          ],
        }),
      },
    })
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.iam.wildcard-action-or-principal"]);
  assert.match(violations[0].message, /ACCOUNT field/);
});

// A wildcard scoped to a known account is an ordinary pattern, not a cross-account hole.
test("iam-wildcard: does NOT flag a wildcard in the resource part of a known-account ARN", () => {
  const plan = planOf(
    resource({
      address: "aws_s3_bucket_policy.logs",
      type: "aws_s3_bucket_policy",
      after: {
        policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            { Effect: "Allow", Principal: { AWS: "arn:aws:iam::123456789012:role/*" }, Action: ["s3:GetObject"] },
          ],
        }),
      },
    })
  );
  assert.deepEqual(evaluate(plan, PROVIDER_PACKS), []);
});

// A wildcard inside a Deny restricts access rather than granting it.
test("iam-wildcard: does NOT flag a wildcard inside a Deny statement", () => {
  const plan = planOf(
    resource({
      address: "aws_iam_policy.deny_all",
      type: "aws_iam_policy",
      after: {
        policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [{ Effect: "Deny", Action: "*", Resource: "*" }],
        }),
      },
    })
  );
  assert.deepEqual(evaluate(plan, PROVIDER_PACKS), []);
});

test("iam-wildcard: covers resource-based policy types, not just IAM resources", () => {
  for (const type of ["aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_ecr_repository_policy"]) {
    const plan = planOf(
      resource({
        address: `${type}.x`,
        type,
        after: {
          policy: JSON.stringify({ Statement: [{ Effect: "Allow", Principal: "*", Action: ["x:Y"] }] }),
        },
      })
    );
    assert.deepEqual(ruleIds(evaluate(plan, PROVIDER_PACKS)), ["aws.iam.wildcard-action-or-principal"], type);
  }
});

test("rds-publicly-accessible: flags explicit true", () => {
  const plan = planOf(resource({ address: "aws_db_instance.main", type: "aws_db_instance", after: { publicly_accessible: true, storage_encrypted: true } }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.database.rds-publicly-accessible"]);
});

test("rds-publicly-accessible: passes when absent (safe default)", () => {
  const plan = planOf(resource({ address: "aws_db_instance.main", type: "aws_db_instance", after: { storage_encrypted: true } }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("rds-unencrypted: flags absence (unsafe default)", () => {
  const plan = planOf(resource({ address: "aws_db_instance.main", type: "aws_db_instance", after: {} }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.database.rds-unencrypted"]);
});

test("rds-unencrypted: passes when explicitly true", () => {
  const plan = planOf(resource({ address: "aws_db_instance.main", type: "aws_db_instance", after: { storage_encrypted: true } }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("kms-rotation-disabled: flags absence (unsafe default)", () => {
  const plan = planOf(resource({ address: "aws_kms_key.main", type: "aws_kms_key", after: {} }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.secrets.kms-rotation-disabled"]);
});

test("kms-rotation-disabled: passes when explicitly true", () => {
  const plan = planOf(resource({ address: "aws_kms_key.main", type: "aws_kms_key", after: { enable_key_rotation: true } }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("imdsv1-allowed: flags explicit \"optional\"", () => {
  const plan = planOf(resource({ address: "aws_instance.web", type: "aws_instance", after: { metadata_options: [{ http_tokens: "optional" }] } }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.compute.imdsv1-allowed"]);
});

test("imdsv1-allowed: passes when explicitly \"required\"", () => {
  const plan = planOf(resource({ address: "aws_instance.web", type: "aws_instance", after: { metadata_options: [{ http_tokens: "required" }] } }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("imdsv1-allowed: does NOT flag absence — no stated Terraform-level default, account-dependent", () => {
  const plan = planOf(resource({ address: "aws_instance.web", type: "aws_instance", after: {} }));
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

test("a resource from an unrelated provider is ignored entirely", () => {
  const plan = {
    resource_changes: [
      {
        address: "google_storage_bucket.this",
        module_address: "",
        mode: "managed",
        type: "google_storage_bucket",
        name: "this",
        provider_name: "registry.terraform.io/hashicorp/google",
        change: { actions: ["create"], before: null, after: {}, after_unknown: {} },
      },
    ],
  };
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(violations, []);
});

// ---------------------------------------------------------------------------
// Long-lived credentials — rules that refuse a resource type outright
// ---------------------------------------------------------------------------

// Unlike every other rule in the pack, these check nothing about the attributes. There is no
// secure way to configure a resource whose entire purpose is minting a permanent credential, so
// the resource itself is the finding.
test("refuses aws_iam_access_key outright", () => {
  const v = evaluate(planOf(resource({ address: "aws_iam_access_key.ci", type: "aws_iam_access_key" })), PROVIDER_PACKS);
  assert.deepEqual(v.map((x) => x.ruleId), ["aws.iam.access-key-created"]);
  assert.equal(v[0].severity, "critical");
  assert.match(v[0].message, /Terraform state/);
});

test("flags aws_iam_user as a credential-bearing principal", () => {
  const v = evaluate(planOf(resource({ address: "aws_iam_user.svc", type: "aws_iam_user" })), PROVIDER_PACKS);
  assert.deepEqual(v.map((x) => x.ruleId), ["aws.iam.user-as-service-identity"]);
});

// A role assumed through federation is the thing these rules are steering toward, so it must not
// itself trip them.
test("does not flag an IAM role", () => {
  const v = evaluate(
    planOf(resource({ address: "aws_iam_role.irsa", type: "aws_iam_role", after: { name: "irsa" } })),
    PROVIDER_PACKS
  );
  assert.deepEqual(v, []);
});

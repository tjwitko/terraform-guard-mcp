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

// ---------------------------------------------------------------------------
// Resource census — the warning must outlive the call that produced it
// ---------------------------------------------------------------------------
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import nodePath from "path";
import { findRemovedResources, pendingRemovals, clearPendingRemovals } from "../lib/resource-census.mjs";

function tfDir(contents) {
  const dir = mkdtempSync(nodePath.join(tmpdir(), "tfguard-census-"));
  writeFileSync(nodePath.join(dir, "main.tf"), contents);
  return dir;
}
const BUCKET = 'resource "aws_s3_bucket" "logs" {}\nresource "aws_s3_bucket_versioning" "v" {}\n';

// The bug this pins: findRemovedResources saves the new census on every call, so the second call
// diffed empty against empty and said nothing. The warning fired exactly once, inside one tool
// response, and afterwards the stored state claimed no resources had ever existed — which is how
// a real run deleted three resources and left no way to establish whether the guardrail fired.
test("a removal stays visible after the call that detected it", () => {
  const dir = tfDir(BUCKET);
  try {
    assert.deepEqual(findRemovedResources(dir), [], "first scan has no prior record");

    writeFileSync(nodePath.join(dir, "main.tf"), 'provider "aws" {}\n');
    assert.deepEqual(findRemovedResources(dir).sort(), ["aws_s3_bucket.logs", "aws_s3_bucket_versioning.v"]);

    // The call that used to forget everything.
    assert.deepEqual(findRemovedResources(dir), [], "nothing newly removed on the next scan");
    assert.deepEqual([...pendingRemovals(dir)].sort(), ["aws_s3_bucket.logs", "aws_s3_bucket_versioning.v"],
      "but the removal is still on the record");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("restoring a resource clears it, with no dismissal mechanism needed", () => {
  const dir = tfDir(BUCKET);
  try {
    findRemovedResources(dir);
    writeFileSync(nodePath.join(dir, "main.tf"), 'provider "aws" {}\n');
    findRemovedResources(dir);
    assert.equal(pendingRemovals(dir).size, 2);

    writeFileSync(nodePath.join(dir, "main.tf"), BUCKET);
    findRemovedResources(dir);
    assert.equal(pendingRemovals(dir).size, 0, "putting it back is the way out");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pendingRemovals does not mutate state, and can be cleared deliberately", () => {
  const dir = tfDir(BUCKET);
  try {
    findRemovedResources(dir);
    writeFileSync(nodePath.join(dir, "main.tf"), 'provider "aws" {}\n');
    findRemovedResources(dir);

    assert.equal(pendingRemovals(dir).size, 2);
    assert.equal(pendingRemovals(dir).size, 2, "reading it twice must give the same answer");

    clearPendingRemovals(dir);
    assert.equal(pendingRemovals(dir).size, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Duplicate policy attachments
// ---------------------------------------------------------------------------

// Found in a real generated project: three differently-named resources attaching
// AmazonEKS_CNI_Policy to the same node role. `terraform validate` reported "Success!" — the
// syntax is fine — and the duplicates were the fingerprint of a model guessing policy ARNs it
// could not look up. Nothing in the stack caught it.
function attachment(name, role, policyArn, overrides = {}) {
  return resource({
    address: `aws_iam_role_policy_attachment.${name}`,
    type: "aws_iam_role_policy_attachment",
    name,
    after: { role, policy_arn: policyArn },
    ...overrides,
  });
}

const CNI = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy";
const ECR = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly";

test("duplicate-policy-attachment: flags the same policy attached twice to one role", () => {
  const plan = planOf(
    attachment("eks_nodes_cni", "nodes-role", CNI),
    attachment("eks_nodes_cgroup", "nodes-role", CNI)
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.deepEqual(ruleIds(violations), ["aws.iam.duplicate-policy-attachment"]);
  // One finding per duplicate group, naming every member — not one per resource, which would
  // report the same defect twice and bury which resources are actually involved.
  assert.match(violations[0].message, /eks_nodes_cgroup/);
  assert.match(violations[0].message, /eks_nodes_cni/);
});

test("duplicate-policy-attachment: reports one finding for a group of three", () => {
  const plan = planOf(
    attachment("a", "nodes-role", CNI),
    attachment("b", "nodes-role", CNI),
    attachment("c", "nodes-role", CNI)
  );
  const violations = evaluate(plan, PROVIDER_PACKS);
  assert.equal(violations.length, 1);
  assert.match(violations[0].message, /^3 aws_iam_role_policy_attachment/);
});

test("duplicate-policy-attachment: different policies on one role are fine", () => {
  const plan = planOf(
    attachment("cni", "nodes-role", CNI),
    attachment("ecr", "nodes-role", ECR)
  );
  assert.deepEqual(evaluate(plan, PROVIDER_PACKS), []);
});

test("duplicate-policy-attachment: the same policy on different roles is fine", () => {
  const plan = planOf(
    attachment("nodes", "nodes-role", CNI),
    attachment("other", "other-role", CNI)
  );
  assert.deepEqual(evaluate(plan, PROVIDER_PACKS), []);
});

// A rule that blocks an apply must never guess. When the principal is computed, two attachments
// that look identical may well name different roles — so an unresolved value is not a duplicate.
test("duplicate-policy-attachment: never flags on values unresolved at plan time", () => {
  const plan = planOf(
    attachment("a", null, CNI, { after: { policy_arn: CNI }, after_unknown: { role: true } }),
    attachment("b", null, CNI, { after: { policy_arn: CNI }, after_unknown: { role: true } })
  );
  assert.deepEqual(evaluate(plan, PROVIDER_PACKS), []);
});

// ---------------------------------------------------------------------------
// Security groups: protocol "-1" covers every port
// ---------------------------------------------------------------------------

// A real generated project shipped protocol="-1" with from_port/to_port both 0 — the documented
// way to write "all traffic", since AWS ignores the port fields entirely when protocol is -1.
// The gate approved it: 0/0 fails the 0..65535 test and contains no sensitive port. SSH from
// anywhere was caught while allow-everything-from-anywhere was not.
function sgWith(ingress) {
  return planOf(
    resource({
      address: "aws_security_group.eks_sg",
      type: "aws_security_group",
      after: { ingress },
    })
  );
}

test("sg-open-ingress: flags protocol -1 from anywhere, ports written as 0/0", () => {
  const v = evaluate(
    sgWith([{ protocol: "-1", from_port: 0, to_port: 0, cidr_blocks: ["0.0.0.0/0"] }]),
    PROVIDER_PACKS
  );
  assert.deepEqual(ruleIds(v), ["aws.network.sg-open-ingress-sensitive-port"]);
  assert.match(v[0].message, /every port and every protocol/);
});

test("sg-open-ingress: still flags a sensitive port on a named protocol", () => {
  const v = evaluate(
    sgWith([{ protocol: "tcp", from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] }]),
    PROVIDER_PACKS
  );
  assert.deepEqual(ruleIds(v), ["aws.network.sg-open-ingress-sensitive-port"]);
  assert.match(v[0].message, /port 22-22/);
});

// Deliberately not flagged: the rule is scoped to sensitive ports, and a public app port behind a
// LoadBalancer is ordinary. Pinned so "-1" support does not quietly widen this into noise.
test("sg-open-ingress: a benign public app port stays unflagged", () => {
  assert.deepEqual(
    evaluate(sgWith([{ protocol: "tcp", from_port: 8000, to_port: 8000, cidr_blocks: ["0.0.0.0/0"] }]), PROVIDER_PACKS),
    []
  );
});

test("sg-open-ingress: protocol -1 restricted to a known CIDR is not flagged", () => {
  assert.deepEqual(
    evaluate(sgWith([{ protocol: "-1", from_port: 0, to_port: 0, cidr_blocks: ["10.0.0.0/16"] }]), PROVIDER_PACKS),
    []
  );
});

test("sg-open-ingress: covers ip_protocol on the newer per-rule resource", () => {
  const plan = planOf(
    resource({
      address: "aws_vpc_security_group_ingress_rule.open",
      type: "aws_vpc_security_group_ingress_rule",
      after: { cidr_ipv4: "0.0.0.0/0", ip_protocol: "-1", from_port: null, to_port: null },
    })
  );
  assert.deepEqual(ruleIds(evaluate(plan, PROVIDER_PACKS)), ["aws.network.sg-open-ingress-sensitive-port"]);
});

// ---------------------------------------------------------------------------
// S3 Object Lock must be enabled on the bucket itself
// ---------------------------------------------------------------------------

// Object Lock can only be turned on at bucket creation. Two separate generated projects declared
// an object lock configuration against a bucket without it: `terraform validate` passed, the plan
// passed, every rule passed, and the apply would fail — while the configuration read as though
// the audit log were immutable. The one control the whole project existed for.
function bucketAndLock({ objectLockEnabled, withConfig = true }) {
  const rs = [
    resource({
      address: "aws_s3_bucket.logs",
      type: "aws_s3_bucket",
      after: objectLockEnabled === undefined ? {} : { object_lock_enabled: objectLockEnabled },
    }),
  ];
  if (withConfig) {
    rs.push(
      resource({
        address: "aws_s3_bucket_object_lock_configuration.logs_lock",
        type: "aws_s3_bucket_object_lock_configuration",
        after: {},
      })
    );
  }
  return planOf(...rs);
}

const LOCK_RULE = "aws.storage.s3-object-lock-not-enabled-on-bucket";
const has = (v, id) => v.some((x) => x.ruleId === id);

test("object-lock: flags a lock configuration on a bucket missing object_lock_enabled", () => {
  const v = evaluate(bucketAndLock({ objectLockEnabled: undefined }), PROVIDER_PACKS);
  assert.ok(has(v, LOCK_RULE), `expected ${LOCK_RULE}, got ${ruleIds(v).join(", ")}`);
});

test("object-lock: flags an explicit false just as it flags absence", () => {
  const v = evaluate(bucketAndLock({ objectLockEnabled: false }), PROVIDER_PACKS);
  assert.ok(has(v, LOCK_RULE));
});

test("object-lock: a correctly enabled bucket is not flagged", () => {
  const v = evaluate(bucketAndLock({ objectLockEnabled: true }), PROVIDER_PACKS);
  assert.ok(!has(v, LOCK_RULE), `unexpected ${LOCK_RULE}`);
});

// Without a lock configuration there is no claim of immutability to contradict, and demanding
// Object Lock on every bucket in every project would be false positives on ordinary storage.
test("object-lock: a bucket with no lock configuration is not this rule's business", () => {
  const v = evaluate(bucketAndLock({ objectLockEnabled: undefined, withConfig: false }), PROVIDER_PACKS);
  assert.ok(!has(v, LOCK_RULE));
});

// ---------------------------------------------------------------------------
// Object Lock: retention mode, and permissions that defeat it
// ---------------------------------------------------------------------------

// Nested blocks arrive as arrays and an unset attribute is null, not absent — verified against a
// real `terraform show -json`: rule = [{ default_retention: [{ days: 365, mode: null }] }].
function lockConfig(defaultRetention) {
  return resource({
    address: "aws_s3_bucket_object_lock_configuration.lock",
    type: "aws_s3_bucket_object_lock_configuration",
    after: defaultRetention === null ? {} : { rule: [{ default_retention: [defaultRetention] }] },
  });
}
const MODE_RULE = "aws.storage.s3-object-lock-retention-mode-missing";
const UNDERMINED = "aws.storage.s3-object-lock-undermined-by-permissions";

test("object-lock mode: flags a retention period with no mode", () => {
  const v = evaluate(planOf(lockConfig({ days: 365, mode: null, years: null })), PROVIDER_PACKS);
  assert.ok(has(v, MODE_RULE), ruleIds(v).join(", "));
  assert.match(v.find((x) => x.ruleId === MODE_RULE).message, /365 days/);
});

test("object-lock mode: COMPLIANCE and GOVERNANCE both satisfy the rule", () => {
  for (const mode of ["COMPLIANCE", "GOVERNANCE"]) {
    const v = evaluate(planOf(lockConfig({ days: 30, mode, years: null })), PROVIDER_PACKS);
    assert.ok(!has(v, MODE_RULE), `${mode} should not be flagged by this rule`);
  }
});

// GOVERNANCE on its own is a legitimate choice — it protects against accident and is meant to be
// overridable. It only becomes a finding when the bypass permission is also granted, which is the
// undermined-by-permissions rule's job, not this one's.
test("object-lock mode: no retention period declared is not this rule's business", () => {
  assert.ok(!has(evaluate(planOf(lockConfig(null)), PROVIDER_PACKS), MODE_RULE));
});

function lockedBucketPlus(...extra) {
  return planOf(
    resource({
      address: "aws_s3_bucket.audit_logs",
      type: "aws_s3_bucket",
      after: { object_lock_enabled: true },
    }),
    resource({
      address: "aws_s3_bucket_public_access_block.pab",
      type: "aws_s3_bucket_public_access_block",
      after: {
        block_public_acls: true,
        block_public_policy: true,
        ignore_public_acls: true,
        restrict_public_buckets: true,
      },
    }),
    ...extra
  );
}

function attach(name, policyArn) {
  return resource({
    address: `aws_iam_role_policy_attachment.${name}`,
    type: "aws_iam_role_policy_attachment",
    after: { role: "svc", policy_arn: policyArn },
  });
}

test("undermined: AmazonS3FullAccess alongside an Object Lock bucket", () => {
  const v = evaluate(lockedBucketPlus(attach("s3", "arn:aws:iam::aws:policy/AmazonS3FullAccess")), PROVIDER_PACKS);
  assert.ok(has(v, UNDERMINED), ruleIds(v).join(", "));
});

test("undermined: AdministratorAccess counts too", () => {
  const v = evaluate(lockedBucketPlus(attach("admin", "arn:aws:iam::aws:policy/AdministratorAccess")), PROVIDER_PACKS);
  assert.ok(has(v, UNDERMINED));
});

test("undermined: a read-only managed policy is fine", () => {
  const v = evaluate(lockedBucketPlus(attach("ro", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")), PROVIDER_PACKS);
  assert.ok(!has(v, UNDERMINED));
});

// The scoped bucket policy the generated project wrote alongside AmazonS3FullAccess. On its own it
// is exactly right, and must not be flagged — the finding belongs to the broad grant, not this.
test("undermined: a correctly scoped policy document is not flagged", () => {
  const scoped = resource({
    address: "aws_s3_bucket_policy.scoped",
    type: "aws_s3_bucket_policy",
    after: {
      policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::1:role/svc" }, Action: ["s3:PutObject", "s3:GetObject", "s3:ListBucket"], Resource: ["arn:aws:s3:::b/*"] }],
      }),
    },
  });
  assert.ok(!has(evaluate(lockedBucketPlus(scoped), PROVIDER_PACKS), UNDERMINED));
});

test("undermined: an inline policy granting s3:DeleteObject is flagged", () => {
  const del = resource({
    address: "aws_iam_role_policy.inline",
    type: "aws_iam_role_policy",
    after: {
      policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Action: ["s3:PutObject", "s3:DeleteObjectVersion"], Resource: "*" }],
      }),
    },
  });
  assert.ok(has(evaluate(lockedBucketPlus(del), PROVIDER_PACKS), UNDERMINED));
});

// Deny restricts; it cannot grant. Flagging it would report the safest possible configuration.
test("undermined: the same actions inside a Deny are not a grant", () => {
  const deny = resource({
    address: "aws_iam_role_policy.deny",
    type: "aws_iam_role_policy",
    after: {
      policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Deny", Action: ["s3:DeleteObject", "s3:BypassGovernanceRetention"], Resource: "*" }],
      }),
    },
  });
  assert.ok(!has(evaluate(lockedBucketPlus(deny), PROVIDER_PACKS), UNDERMINED));
});

// Without Object Lock there is no immutability claim to undermine, and flagging every broad S3
// grant in every project is a different rule with a much higher false-positive cost.
test("undermined: broad S3 access with no Object Lock anywhere is out of scope", () => {
  const plan = planOf(
    resource({ address: "aws_s3_bucket.plain", type: "aws_s3_bucket", after: {} }),
    attach("s3", "arn:aws:iam::aws:policy/AmazonS3FullAccess")
  );
  assert.ok(!has(evaluate(plan, PROVIDER_PACKS), UNDERMINED));
});

// ---------------------------------------------------------------------------
// Credential-shaped variable defaults, and module argument hints
// ---------------------------------------------------------------------------
import { scanVariableDefaults } from "../lib/source-scan.mjs";
import { rejectedArgumentNames, moduleArgumentHint } from "../lib/module-interface.mjs";

const varIds = (f) => f.map((x) => x.ruleId);

// The one that fell through all three scanners in this workspace: gitleaks does not match a
// generic password, scanProviderCredentials only reads provider blocks, and identity-guard does
// not read .tf files at all.
test("variable defaults: flags a credential-shaped variable with a literal default", () => {
  const f = scanVariableDefaults(
    'variable "db_password" {\n  type    = string\n  default = "SecurePassword123!"\n}',
    "variables.tf"
  );
  assert.deepEqual(varIds(f), ["variable.credential-default"]);
  assert.equal(f[0].actualValue, "<redacted>", "a finding must never echo the credential");
});

// A default is supplied without prompting, so the value deploys whether or not it looks real.
test("variable defaults: a placeholder default is still the deployed value", () => {
  assert.equal(scanVariableDefaults('variable "api_token" {\n  default = "changeme"\n}', "v.tf").length, 1);
});

test("variable defaults: no default is the correct pattern and is not flagged", () => {
  assert.deepEqual(scanVariableDefaults('variable "db_password" {\n  type = string\n}', "v.tf"), []);
});

test("variable defaults: empty and interpolated defaults are not literals", () => {
  assert.deepEqual(scanVariableDefaults('variable "db_password" {\n  default = ""\n}', "v.tf"), []);
  assert.deepEqual(scanVariableDefaults('variable "db_password" {\n  default = "${var.x}"\n}', "v.tf"), []);
});

// Names that reference a credential rather than carrying one. A rule that fires on every variable
// containing "key" produces findings nobody trusts.
test("variable defaults: identifiers and public keys are not credentials", () => {
  for (const decl of [
    'variable "kms_key_id" {\n  default = "arn:aws:kms:us-east-1:1:key/abc"\n}',
    'variable "ssh_public_key" {\n  default = "ssh-rsa AAAAB3"\n}',
    'variable "db_secret_arn" {\n  default = "arn:aws:secretsmanager:::secret:x"\n}',
    'variable "s3_bucket_name" {\n  default = "audit-logs"\n}',
  ]) {
    assert.deepEqual(scanVariableDefaults(decl, "v.tf"), [], decl.split("\n")[0]);
  }
});

test("module hints: extracts the rejected argument names Terraform reported", () => {
  assert.deepEqual(
    rejectedArgumentNames(
      'eks.tf:9 — Unsupported argument: An argument named "cluster_subnet_ids" is not expected here.\n' +
        'eks.tf:11 — Unsupported argument: An argument named "cluster_arn" is not expected here.'
    ),
    ["cluster_subnet_ids", "cluster_arn"]
  );
});

// Silence unless there is something real to say: no unsupported-argument error, or no installed
// module to read, means no hint rather than a guessed one.
test("module hints: silent when nothing was rejected or nothing is installed", () => {
  assert.equal(moduleArgumentHint("/nonexistent", "some unrelated error"), "");
  assert.equal(moduleArgumentHint("/nonexistent", 'An argument named "x" is not expected here'), "");
});

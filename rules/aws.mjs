import { makeViolation } from "./engine.mjs";

// AWS rule pack — 9 rules. (Seeded with 7, not the 8 originally planned; The 8th (flag S3 buckets with no
// aws_s3_bucket_server_side_encryption_configuration) was dropped after checking the real
// provider docs at implementation time: AWS applies default SSE-S3 encryption to every new
// bucket automatically since 2023, with or without this resource declared (confirmed via
// terraform-provider-aws's own docs: "Destroying an
// aws_s3_bucket_server_side_encryption_configuration resource resets the bucket to Amazon S3
// bucket default encryption" — implying a default already exists). Flagging its absence would
// have been a false positive on every ordinary bucket, not a real finding.)
//
// Rules 8 and 9 are a different shape from the rest: they refuse a resource TYPE rather than
// checking its attributes, because aws_iam_access_key and aws_iam_user exist to create durable
// credentials and have no secure configuration.

const SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 6379, 27017, 9200];

// "-1" means every protocol on every port, and AWS ignores from_port/to_port entirely when it is
// set — the documented convention is to write them as 0/0. That form was invisible here: 0/0 fails
// the "0..65535" test and contains no sensitive port, so the single most permissive security group
// AWS allows (all protocols, all ports, 0.0.0.0/0) passed clean while SSH-from-anywhere was caught.
// Found in a real generated project whose plan the gate approved.
function coversEverything(protocol) {
  if (protocol == null) return false;
  const p = String(protocol).toLowerCase();
  return p === "-1" || p === "all";
}

function portRangeCoversSensitive(fromPort, toPort, protocol) {
  if (coversEverything(protocol)) return true;
  if (fromPort == null || toPort == null) return true; // unbounded/unresolved — treat conservatively as open
  if (fromPort <= 0 && toPort >= 65535) return true;
  return SENSITIVE_PORTS.some((p) => p >= fromPort && p <= toPort);
}

function isOpenIpv4(cidrs) {
  return Array.isArray(cidrs) && cidrs.includes("0.0.0.0/0");
}
function isOpenIpv6(cidrs) {
  return Array.isArray(cidrs) && cidrs.includes("::/0");
}

// policy/json attributes hold a JSON *string* — pure functions of already-known config resolve
// at plan time and land in `after`; anything depending on a not-yet-applied value lands in
// after_unknown instead, where there's no string to parse at all.
function extractPolicyJson(resource) {
  const after = resource.change.after || {};
  const raw = after.policy ?? after.json;
  if (typeof raw !== "string") return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// An IAM ARN is arn:partition:service:region:ACCOUNT:resource. A wildcard in the account field
// means "this principal in ANY AWS account on earth" — e.g. arn:aws:iam::*:role/log-service-role
// grants access to anyone who creates a role with that name in their own account. It reads like a
// scoped ARN, which is exactly why it slips through review; a real generated config in this
// workspace shipped precisely that on an audit-log bucket.
//
// Deliberately NOT flagged: a wildcard in the resource portion of a known account, such as
// arn:aws:iam::123456789012:role/* — that stays inside one account and is a normal pattern.
function principalHasAccountWildcard(value) {
  if (typeof value !== "string" || !value.startsWith("arn:")) return false;
  const account = value.split(":")[4];
  return account !== undefined && account.includes("*");
}

// Returns a description of what matched, so the violation names the actual offending value rather
// than a generic "contains a wildcard".
function findPolicyWildcard(doc) {
  const rawStatements = doc?.Statement;
  const statements = Array.isArray(rawStatements) ? rawStatements : rawStatements ? [rawStatements] : [];
  for (const stmt of statements) {
    if (stmt?.Effect === "Deny") continue; // a wildcard inside a Deny is restrictive, not permissive

    const actions = Array.isArray(stmt?.Action) ? stmt.Action : stmt?.Action ? [stmt.Action] : [];
    if (actions.includes("*")) return 'a wildcard Action ("*")';

    const principal = stmt?.Principal;
    if (principal === "*") return 'a wildcard Principal ("*")';
    if (principal && typeof principal === "object") {
      for (const raw of Object.values(principal)) {
        const values = Array.isArray(raw) ? raw : [raw];
        if (values.includes("*")) return 'a wildcard Principal ("*")';
        const accountWildcard = values.find(principalHasAccountWildcard);
        if (accountWildcard) {
          return `a Principal ARN with a wildcard in the ACCOUNT field ("${accountWildcard}") — this grants access to that role name in ANY AWS account, not just yours`;
        }
      }
    }
  }
  return null;
}

const rules = [
  {
    id: "aws.storage.s3-public-access-block-missing",
    category: "storage.public-access",
    severity: "critical",
    provider: "aws",
    kind: "aggregate",
    resourceTypes: ["aws_s3_bucket"],
    description:
      "Every S3 bucket must have a companion aws_s3_bucket_public_access_block with all four " +
      "block/ignore/restrict attributes true — blocking public access is not an attribute on " +
      "aws_s3_bucket itself.",
    check(index) {
      const buckets = index.byType("aws_s3_bucket");
      const pabs = index.byType("aws_s3_bucket_public_access_block");
      const required = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"];

      return buckets
        .filter((bucket) => {
          // Matched by module_address, not by resolved bucket id/reference: a newly-created
          // bucket's `id` is unresolved at plan time (after_unknown.id === true), so the PAB's
          // `bucket = aws_s3_bucket.this.id` reference is unresolved too — there's no literal
          // value to match on for the common "brand new bucket" case. Same-module is a
          // deliberate, documented simplification: it can miss a PAB declared in a different
          // module than its bucket (a rare pattern), but it will never wrongly flag a
          // correctly-configured same-module setup, which is the safer failure direction for a
          // blocking tool.
          const pab = pabs.find((p) => p.module_address === bucket.module_address);
          if (!pab) return true;
          const after = pab.change.after || {};
          return required.some((attr) => after[attr] !== true);
        })
        .map((bucket) =>
          makeViolation(rules[0], bucket, {
            message: "no aws_s3_bucket_public_access_block resource protects this bucket (or one exists with an attribute not set to true)",
            remediation:
              "add an aws_s3_bucket_public_access_block in the same module with block_public_acls, " +
              "block_public_policy, ignore_public_acls, and restrict_public_buckets all set to true",
          })
        );
    },
  },
  {
    id: "aws.network.sg-open-ingress-sensitive-port",
    category: "network.open-ingress",
    severity: "critical",
    provider: "aws",
    kind: "single",
    resourceTypes: ["aws_security_group", "aws_vpc_security_group_ingress_rule"],
    description:
      "Flags ingress rules open to 0.0.0.0/0 or ::/0 on a sensitive port (SSH/RDP/common " +
      "database ports) or with no port restriction at all. Covers both the classic inline " +
      "aws_security_group ingress block and the newer per-rule aws_vpc_security_group_ingress_rule " +
      "resource (AWS provider v5+) — a plan using only one shape would be invisible to a rule " +
      "checking only the other.",
    check(resource) {
      const after = resource.change.after || {};
      const violations = [];

      if (resource.type === "aws_security_group") {
        (after.ingress || []).forEach((block, i) => {
          const openV4 = isOpenIpv4(block.cidr_blocks);
          const openV6 = isOpenIpv6(block.ipv6_cidr_blocks);
          if ((openV4 || openV6) && portRangeCoversSensitive(block.from_port, block.to_port, block.protocol)) {
            violations.push(
              makeViolation(rules[1], resource, {
                message:
                  `ingress[${i}] allows ${openV4 ? "0.0.0.0/0" : "::/0"} on ` +
                  (coversEverything(block.protocol)
                    ? `every port and every protocol`
                    : `port ${block.from_port}-${block.to_port}`),
                remediation: "restrict cidr_blocks/ipv6_cidr_blocks to a known range, or remove the rule if unneeded",
                attribute: `ingress[${i}]`,
                actualValue: openV4 ? block.cidr_blocks : block.ipv6_cidr_blocks,
              })
            );
          }
        });
      } else if (resource.type === "aws_vpc_security_group_ingress_rule") {
        const openV4 = after.cidr_ipv4 === "0.0.0.0/0";
        const openV6 = after.cidr_ipv6 === "::/0";
        if ((openV4 || openV6) && portRangeCoversSensitive(after.from_port, after.to_port, after.ip_protocol)) {
          violations.push(
            makeViolation(rules[1], resource, {
              message:
              `allows ${openV4 ? after.cidr_ipv4 : after.cidr_ipv6} on ` +
              (coversEverything(after.ip_protocol)
                ? `every port and every protocol`
                : `port ${after.from_port}-${after.to_port}`),
              remediation: "restrict cidr_ipv4/cidr_ipv6 to a known range, or remove the rule if unneeded",
              attribute: openV4 ? "cidr_ipv4" : "cidr_ipv6",
              actualValue: openV4 ? after.cidr_ipv4 : after.cidr_ipv6,
            })
          );
        }
      }
      return violations;
    },
  },
  {
    id: "aws.iam.wildcard-action-or-principal",
    category: "iam.wildcard",
    severity: "critical",
    provider: "aws",
    kind: "single",
    // Resource-based policies belong here as much as identity-based ones — arguably more, since
    // they are what grants OUTSIDE principals access. The list originally covered only IAM
    // resources, so a wide-open aws_s3_bucket_policy was invisible to this rule no matter how
    // permissive it was.
    resourceTypes: [
      "aws_iam_policy",
      "aws_iam_role_policy",
      "aws_iam_policy_document",
      "aws_s3_bucket_policy",
      "aws_sqs_queue_policy",
      "aws_sns_topic_policy",
      "aws_ecr_repository_policy",
      "aws_secretsmanager_secret_policy",
    ],
    description:
      'Flags policy documents containing Action: "*", Principal: "*", or a Principal ARN whose ' +
      "account field is a wildcard (which grants access to any AWS account). Covers identity-based " +
      "and resource-based policies. Wildcards inside Deny statements are ignored — those restrict.",
    check(resource) {
      const doc = extractPolicyJson(resource);
      // Deliberate deviation from the original plan wording ("surface as a lower-confidence
      // warning"): a policy string that's genuinely unresolved at plan time (after_unknown) is
      // extremely common for legitimate dynamic policies (e.g. jsonencode(local.foo) depending
      // on a not-yet-applied resource), and a hard-block tool that flags "can't verify" as a
      // finding would be a constant false-positive source on ordinary code — worse than the gap
      // it closes. Skip silently instead; this only weakens coverage for policies that are both
      // dynamic AND insecure, not for the common case.
      const finding = doc ? findPolicyWildcard(doc) : null;
      if (!finding) return [];
      return [
        makeViolation(rules[2], resource, {
          message: `policy document contains ${finding}`,
          remediation: "scope Action/Principal to the specific actions and principals actually needed",
        }),
      ];
    },
  },
  {
    id: "aws.database.rds-publicly-accessible",
    category: "database.public-access",
    severity: "critical",
    provider: "aws",
    kind: "single",
    resourceTypes: ["aws_db_instance", "aws_rds_cluster_instance"],
    description: 'Flags publicly_accessible = true. Verified default is false (safe) — absence is NOT flagged.',
    check(resource) {
      const after = resource.change.after || {};
      if (after.publicly_accessible !== true) return [];
      return [
        makeViolation(rules[3], resource, {
          message: "publicly_accessible is explicitly set to true",
          remediation: "set publicly_accessible = false (the default) unless a public endpoint is genuinely required",
          attribute: "publicly_accessible",
          actualValue: true,
        }),
      ];
    },
  },
  {
    id: "aws.database.rds-unencrypted",
    category: "database.unencrypted",
    severity: "critical",
    provider: "aws",
    kind: "single",
    resourceTypes: ["aws_db_instance"],
    description: "Flags storage_encrypted !== true. Verified default is false (unsafe) — absence IS flagged.",
    check(resource) {
      const after = resource.change.after || {};
      if (after.storage_encrypted === true) return [];
      return [
        makeViolation(rules[4], resource, {
          message: `storage_encrypted is ${after.storage_encrypted === false ? "explicitly false" : "not set (defaults to false)"}`,
          remediation: "set storage_encrypted = true",
          attribute: "storage_encrypted",
          actualValue: after.storage_encrypted ?? null,
        }),
      ];
    },
  },
  {
    id: "aws.secrets.kms-rotation-disabled",
    category: "secrets.key-rotation",
    severity: "medium",
    provider: "aws",
    kind: "single",
    resourceTypes: ["aws_kms_key"],
    description: "Flags enable_key_rotation !== true. Verified default is false — absence IS flagged.",
    check(resource) {
      const after = resource.change.after || {};
      if (after.enable_key_rotation === true) return [];
      return [
        makeViolation(rules[5], resource, {
          message: `enable_key_rotation is ${after.enable_key_rotation === false ? "explicitly false" : "not set (defaults to false)"}`,
          remediation: "set enable_key_rotation = true",
          attribute: "enable_key_rotation",
          actualValue: after.enable_key_rotation ?? null,
        }),
      ];
    },
  },
  {
    id: "aws.compute.imdsv1-allowed",
    category: "compute.imds-hardening",
    severity: "high",
    provider: "aws",
    kind: "single",
    resourceTypes: ["aws_instance"],
    description:
      'Flags metadata_options.http_tokens explicitly set to "optional". Unlike its sibling ' +
      "attributes, the provider docs state no Terraform-level default for http_tokens — the " +
      "effective default depends on AWS account-level instance-metadata-defaults settings not " +
      "visible in a plan, so omission is NOT flagged, only an explicit unsafe value.",
    check(resource) {
      const after = resource.change.after || {};
      const metadataOptions = Array.isArray(after.metadata_options) ? after.metadata_options[0] : after.metadata_options;
      const httpTokens = metadataOptions?.http_tokens;
      if (httpTokens !== "optional") return [];
      return [
        makeViolation(rules[6], resource, {
          message: 'metadata_options.http_tokens is explicitly set to "optional", allowing IMDSv1',
          remediation: 'set metadata_options { http_tokens = "required" } to require IMDSv2',
          attribute: "metadata_options.http_tokens",
          actualValue: "optional",
        }),
      ];
    },
  },
  {
    id: "aws.iam.access-key-created",
    category: "iam.long-lived-credential",
    severity: "critical",
    provider: "aws",
    kind: "single",
    resourceTypes: ["aws_iam_access_key"],
    description:
      "Flags creation of an aws_iam_access_key. This resource exists only to mint a permanent " +
      "credential — there is no secure configuration of it, so unlike every other rule here it " +
      "checks nothing about the attributes and refuses the resource itself. The secret also " +
      "lands in Terraform state in plaintext, so the state file becomes credential material too.",
    check(resource) {
      return [
        makeViolation(rules[7], resource, {
          message:
            "creates a long-lived IAM access key; the secret is written to Terraform state in " +
            "plaintext and never expires on its own",
          remediation:
            "use a role instead of a key — IRSA or EKS Pod Identity for Kubernetes workloads, an " +
            "instance or task role on EC2/ECS, and OIDC federation for CI. If a key is genuinely " +
            "unavoidable, it does not belong in Terraform.",
          attribute: null,
          actualValue: "aws_iam_access_key",
        }),
      ];
    },
  },
  {
    id: "aws.iam.user-as-service-identity",
    category: "iam.long-lived-credential",
    severity: "high",
    provider: "aws",
    kind: "single",
    resourceTypes: ["aws_iam_user"],
    description:
      "Flags aws_iam_user. An IAM user is a durable principal authenticated by something it " +
      "holds — a password or an access key — which is what workload identity replaces. Human " +
      "access should come from SSO federation, and workloads should assume roles.",
    check(resource) {
      return [
        makeViolation(rules[8], resource, {
          message: "declares an IAM user, a principal that authenticates with a stored credential",
          remediation:
            "federate humans through SSO/OIDC and give workloads roles they assume. An IAM user " +
            "is only appropriate where a service genuinely cannot assume a role, and that should " +
            "be a deliberate, documented exception.",
          attribute: null,
          actualValue: "aws_iam_user",
        }),
      ];
    },
  },
  {
    id: "aws.iam.duplicate-policy-attachment",
    category: "iam.duplicate-attachment",
    severity: "medium",
    provider: "aws",
    kind: "aggregate",
    resourceTypes: [
      "aws_iam_role_policy_attachment",
      "aws_iam_user_policy_attachment",
      "aws_iam_group_policy_attachment",
    ],
    description:
      "Flags two or more attachment resources binding the same managed policy to the same " +
      "principal. No correct configuration does this: the duplicates fight over one piece of " +
      "real state, so destroying either detaches the policy while the others still believe it " +
      "is attached. AttachRolePolicy is idempotent, so AWS accepts it silently and the defect " +
      "only surfaces later.",
    check(index) {
      // Attribute naming the principal differs per attachment type; the duplicate test is
      // otherwise identical, so the types are driven from this table rather than copied.
      const PRINCIPAL_ATTR = {
        aws_iam_role_policy_attachment: "role",
        aws_iam_user_policy_attachment: "user",
        aws_iam_group_policy_attachment: "group",
      };
      const violations = [];

      for (const [type, principalAttr] of Object.entries(PRINCIPAL_ATTR)) {
        const groups = new Map();

        for (const resource of index.byType(type)) {
          const after = resource.change.after || {};
          const unknown = resource.change.after_unknown || {};
          // Never compare values Terraform has not resolved. Two attachments whose principal is
          // computed may well name different principals, and a rule that blocks an apply has to
          // be certain — the same discipline the S3/PAB rule follows. Verified against real plan
          // JSON that both fields resolve to literals in the ordinary case, so skipping the
          // unknown ones costs almost nothing.
          if (unknown[principalAttr] === true || unknown.policy_arn === true) continue;
          const principal = after[principalAttr];
          const policyArn = after.policy_arn;
          if (typeof principal !== "string" || typeof policyArn !== "string") continue;

          const key = `${principal} ${policyArn}`;
          if (!groups.has(key)) groups.set(key, { principal, policyArn, members: [] });
          groups.get(key).members.push(resource);
        }

        for (const { principal, policyArn, members } of groups.values()) {
          if (members.length < 2) continue;
          const addresses = members.map((m) => m.address).sort();
          violations.push(
            makeViolation(rules[9], null, {
              message:
                `${members.length} ${type} resources attach the same policy to ${principal}: ` +
                addresses.join(", "),
              remediation:
                `keep one attachment and delete the others. Duplicates under different resource ` +
                `names usually mean the policy ARNs were guessed rather than looked up — check ` +
                `that ${policyArn} is a real managed policy and that the attachments this was ` +
                `meant to be were not lost in the process.`,
              attribute: "policy_arn",
              actualValue: policyArn,
            })
          );
        }
      }

      return violations;
    },
  },
  {
    id: "aws.storage.s3-object-lock-not-enabled-on-bucket",
    category: "storage.immutability",
    severity: "critical",
    provider: "aws",
    kind: "aggregate",
    resourceTypes: ["aws_s3_bucket"],
    description:
      "Flags an aws_s3_bucket_object_lock_configuration whose bucket was not created with " +
      "object_lock_enabled = true. Object Lock can only be turned on at bucket creation, so this " +
      "combination fails at apply — and until it does, the configuration reads as though the " +
      "objects are immutable when nothing is enforcing it.",
    check(index) {
      const buckets = index.byType("aws_s3_bucket");
      const configs = index.byType("aws_s3_bucket_object_lock_configuration");
      if (configs.length === 0) return [];

      return buckets
        // Same module_address matching as the public-access-block rule, and for the same reason:
        // a new bucket's id is unresolved at plan time, so the configuration's
        // `bucket = aws_s3_bucket.this.id` reference has no literal value to match on.
        .filter((bucket) => configs.some((c) => c.module_address === bucket.module_address))
        .filter((bucket) => (bucket.change.after || {}).object_lock_enabled !== true)
        .map((bucket) =>
          makeViolation(rules[10], bucket, {
            message:
              "an object lock configuration targets this bucket, but the bucket is not created " +
              "with object_lock_enabled = true",
            remediation:
              "add `object_lock_enabled = true` to the aws_s3_bucket. It can only be set at " +
              "creation, so a bucket that already exists without it must be replaced — and give " +
              "the lock configuration a depends_on the bucket's versioning resource, which " +
              "Object Lock requires and Terraform will not order on its own.",
            attribute: "object_lock_enabled",
            actualValue: (bucket.change.after || {}).object_lock_enabled ?? null,
          })
        );
    },
  },
];

export default rules;

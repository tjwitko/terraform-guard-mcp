# Candidate rules — advisory findings not yet promoted to blocking

A running list of exposures that Checkov (or another advisory scanner) reports but that no
terraform-guard rule blocks on. Kept because the benchmark work keeps surfacing the same shape of
gap, and because the decision "should this block?" is a real one with a cost on both sides:

- **Advisory findings do not get acted on.** Measured repeatedly across the audit-log and webhook
  benchmark runs — an advisory finding is ignored, a blocking one gets fixed, usually in one round.
- **A false positive in a blocking gate destroys work.** Also measured: webhook-3 failed a whole
  run (4 rounds, 1.85M tokens) rewriting a file six times to satisfy an immutability condition it
  already met, because the check matched `ConditionExpression =` but not `:`.

So nothing gets promoted here by default. Each entry needs its defaults verified against real
provider docs (not recollection — see the standing rule in CLAUDE.md), and a deliberate call that
the exposure is worth blocking on.

---

## Resolved

### EKS public API endpoint → `aws.kubernetes.eks-public-api-open`

Promoted to blocking. Recorded here because it is the worked example the entries below should
follow: the argument that carried it was **verdict inconsistency**, not severity in the abstract.
`aws.network.sg-open-ingress-sensitive-port` blocks on a security group open to `0.0.0.0/0`, while
an EKS control plane open to the same `0.0.0.0/0` only advised — the same risk class getting two
different verdicts depending on which tool happened to notice it.

Evidence at the time of promotion — every `aws_eks_cluster` across the preserved deliverables:

| deliverable | `endpoint_public_access` | `public_access_cidrs` | effective exposure |
|---|---|---|---|
| audit-adv17 | unset (default `true`) | unset | `0.0.0.0/0` |
| audit-adv18 | unset (default `true`) | unset | `0.0.0.0/0` |
| audit-adv19 | unset (default `true`) | unset | `0.0.0.0/0` |
| audit-adv22 | unset (default `true`) | unset | `0.0.0.0/0` |
| webhook-1   | unset (default `true`) | unset | `0.0.0.0/0` |
| webhook-3   | explicit `true`        | unset | `0.0.0.0/0` |

6/6 internet-open, 6/6 passed the blocking gate clean.

---

## Open

The three below came from the same review that surfaced the EKS gap. None is promoted yet.

### 1. EKS control-plane logging disabled — category `kubernetes.control-plane-logging` (reserved)

`enabled_cluster_log_types` unset means no API/audit/authenticator logs reach CloudWatch, so
control-plane activity is unreconstructable after the fact.

- **Reserved in `rules/taxonomy.mjs`, no rule implements it.**
- Deliverable evidence is mixed, which is what makes this worth measuring rather than assuming:
  audit-adv18 sets all five log types unprompted; the other five clusters set none.
- **Open question.** Absence-of-logging is a different argument from open-to-the-internet: it
  degrades forensics rather than granting access. Blocking on it is defensible for a task whose
  own requirement is a tamper-evident audit trail, and much less so as a universal rule.
- **Verify before writing:** the real default for `enabled_cluster_log_types` when the attribute
  is omitted, and whether an empty list and an absent attribute are distinguishable in plan JSON.

### 2. EKS secrets encryption not configured — category `kubernetes.secrets-encryption` (reserved)

No `encryption_config` block means Kubernetes Secrets are stored in etcd under the AWS-managed
default rather than a customer-managed KMS key — no envelope encryption.

- **Reserved in `rules/taxonomy.mjs`, no rule implements it.**
- **Open question.** Closer to the KMS-CMK entry below than to the EKS endpoint one: this is key
  custody, not reachability.
- **Verify before writing:** whether etcd is encrypted at rest by default with an AWS-managed key
  when `encryption_config` is absent. If it is, "absent" is a custody preference, not an
  unencrypted-secrets finding — and the rule's framing has to say so honestly. This is exactly the
  check that killed the originally-planned 8th S3 rule (default SSE-S3 since 2023), so do it first.

### 3. No customer-managed KMS key on Secrets Manager / DynamoDB

- **No taxonomy category reserved.** Would fit `storage.encryption` or `secrets.kms-policy`.
- **Weakest of the three.** Both services encrypt at rest by default with AWS-managed keys, so the
  finding is about who controls the key and can revoke access — a real concern for separation of
  duties, but not the "reachable from the entire internet" risk class that made the EKS endpoint
  clear-cut. Flagging every table and secret without a CMK would fire on ordinary configurations.
- **If pursued,** scope it to resources the task itself designates as sensitive rather than
  applying it universally — otherwise it is the S3-default-encryption false positive again.

---

## Note on Checkov IDs

The review that raised these named `CKV_AWS_38` for the public endpoint. IDs for the other checks
were not independently verified and are deliberately not recorded here — look them up against
Checkov's own registry if they are needed, rather than trusting a remembered mapping.

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

The companion file `local-delegate-mcp/docs/candidate-rules.md` tracks the mirror-image problem in
the agent-loop gates: where those checks are *wrong* rather than merely advisory, and what they do
not check yet.

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

None. The three entries below were worked on 12 September 2026 and all three were closed without
promotion. Each was closed on verified provider behaviour rather than on judgement, and the evidence
is recorded so that none of them gets re-opened from recollection.

---

## Closed without promotion

### 1. EKS control-plane logging — closed: models already do it, and the task does not require it

Verified against the provider docs, and the default is as suspected:

> "By default, cluster control plane logs aren't sent to CloudWatch Logs. You must enable each log
> type individually to send logs for your cluster."
> — *Send control plane logs to CloudWatch Logs*, AWS EKS User Guide

So absence really does mean no API/audit/authenticator record. The exposure is real. It is not worth
a blocking rule here, for three reasons, in descending order of weight:

**The evidence in this file was stale and pointed the wrong way.** It recorded "audit-adv18 sets all
five log types unprompted; the other five clusters set none." Across the webhook deliverables the
distribution is the opposite:

| deliverable | `enabled_cluster_log_types` |
|---|---|
| webhook-claude | all five |
| webhook-sonnet-3 | all five |
| webhook-haiku-4 | all five |
| webhook-haiku-6 | all five |
| webhook-haiku-9 | all five |
| webhook-haiku-12 | **none** |

5 of 6 comply without being asked. Compare the EKS endpoint rule that this file holds up as the
worked example: 6 of 6 were internet-open and 6 of 6 passed clean. That rule changed behaviour
because the behaviour was universally wrong. This one would codify a norm the models already follow
and catch one deliverable in six.

**The task's own requirement does not imply it.** The webhook task asks that a chargeback dispute
weeks later "can be settled by what we actually received at the time" — a property of the *records*.
Control-plane logging is a record of who changed the *cluster*. Related, not the same, and this file
already says the promotion argument has to be verdict inconsistency rather than severity in the
abstract. There is no inconsistency here: no other terraform-guard rule blocks on absent telemetry.

**It is already detected.** Checkov reports `CKV_AWS_37` on exactly the one deliverable that lacks
it. A blocking duplicate would add enforcement, not detection — and enforcement is the part the
evidence above does not support.

Reconsider if a task's stated requirement is control-plane forensics rather than record integrity.
The taxonomy category stays reserved.

### 2. EKS secrets encryption — closed: the exposure does not exist at these versions

This is the entry the file warned to verify first, on the grounds that it was "exactly the check that
killed the originally-planned 8th S3 rule". It died the same way.

> "Amazon EKS provides default envelope encryption for all Kubernetes API data in EKS clusters
> running Kubernetes version 1.28 or higher. […] By default, this KEK is owned by AWS, but you can
> optionally bring your own from AWS KMS. […] you don't have to take any action."
> — *Default envelope encryption for all Kubernetes API Data*, AWS EKS User Guide

And, for clusters below that version:

> "All of the data stored in the etcd are encrypted at the disk level for every EKS cluster,
> irrespective of the Kubernetes version being run."

So an absent `encryption_config` is not unencrypted secrets. It is an AWS-owned KEK instead of a
customer-managed one — key custody, precisely as this entry suspected. The same page also records
that the `resources` field of `EncryptionConfig` is **deprecated** and no longer affects what is
encrypted, which is worth knowing before writing any rule that reads it.

Versions across the deliverables:

| deliverable | K8s version | `encryption_config` | envelope encryption |
|---|---|---|---|
| webhook-claude | 1.31 | yes | CMK |
| webhook-sonnet-3 | 1.30 | yes | CMK |
| webhook-haiku-4 | 1.28 | no | **default, AWS-owned key** |
| webhook-haiku-6 | 1.28 | no | **default, AWS-owned key** |
| webhook-haiku-9 | 1.28 | no | **default, AWS-owned key** |
| webhook-haiku-12 | 1.27 | no | disk-level only |

Checkov's `CKV_AWS_58` fires on four of these, and for three of the four the finding is moot at the
version they run. A blocking rule built on it would have blocked correct configurations — the exact
failure this file exists to prevent. The one cluster where the finding has any force is on 1.27,
which is separately flagged by `CKV_AWS_339` for running an unsupported version, and fixing *that*
resolves this as a side effect.

The taxonomy category stays reserved. If it is ever implemented it must be framed as key custody and
gated on the cluster version, never as "secrets are unencrypted".

### 3. Customer-managed KMS key on Secrets Manager / DynamoDB — closed: partly covered, and unscopable

Closed on the reasoning already written in this entry, which survives review: both services encrypt
at rest by default with AWS-managed keys, so the finding is about who can revoke access rather than
whether the data is readable. Flagging every table and secret without a CMK fires on ordinary
configurations.

One part of it has since been covered from the other direction. `local-delegate-mcp`'s retention
durability check reports a KMS key that the configuration can schedule for deletion when the records
depend on it — "ciphertext without its key is not a record". That is the custody concern where it has
teeth, scoped to a store the task designates as needing seven-year retention, which is exactly the
scoping this entry said would be required.

No taxonomy category is reserved and none should be until a task exists whose stated requirement is
separation of duties over key material.

---

## Note on Checkov IDs

The review that raised these named `CKV_AWS_38` for the public endpoint. The IDs now recorded above
— `CKV_AWS_37`, `CKV_AWS_58`, `CKV_AWS_339` — were observed in Checkov's own output against
webhook-haiku-12 on 12 September 2026, not looked up from memory. Anything added later should be
obtained the same way.

## What closing these cost, and what it bought

Two of the three were closed on provider documentation that contradicted the assumption behind the
entry, and the third on evidence in this file that had gone stale and pointed the wrong way. Nothing
was built.

That is the intended outcome of the rule in the header — each entry needs its defaults verified
against real provider docs, not recollection — and it is the second time that rule has prevented a
rule from being written. The first was the S3 default-encryption check, killed by SSE-S3 becoming
default in 2023. This time it was EKS envelope encryption becoming default at Kubernetes 1.28.

Both would have blocked correct configurations. A gate that does that gets switched off, and then
protects nothing.

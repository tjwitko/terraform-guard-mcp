# terraform-guard-mcp

An MCP server that blocks an LLM agent from applying insecure Terraform infrastructure. Not an
advisory linter that reports findings for the calling model to ignore or act on — a real block,
enforced by controlling the only path from "plan" to "apply" that goes through this server.

Grew out of a real incident earlier in this session: a delegated Terraform generation shipped an
S3 bucket policy granting public `s3:GetObject` to anyone (`Principal: "*"`), caught only by
manual review. This exists to catch that class of mistake automatically, before it's ever applied.

## Architecture

```
                    ┌─────────────────┐
 LLM agent ───────▶ │  terraform_plan  │ ──▶ terraform init/plan/show -json (real binary)
                    └────────┬─────────┘            │
                             │                       ▼
                    ┌────────▼─────────┐   rule engine (rules/engine.mjs + rules/aws.mjs)
                    │ violations found?│
                    └────┬────────┬────┘
                       yes│        │no
                          ▼        ▼
                  refuse, itemized   plan copied into plan-store,
                  list of what/why,  planId issued, tmp file deleted
                  no planId issued          │
                                             ▼
                                   ┌──────────────────┐
                        LLM agent │ terraform_apply   │ ──▶ look up planId in plan-store
                     (with planId)│ (plan_id, dir)     │      (ONLY way to get a plan file —
                                  └──────────────────┘       no parameter accepts one directly)
                                             │
                                             ▼
                                   terraform apply <stored file>
                                   (Terraform's own staleness check
                                    is a second, independent layer)
                                             │
                                             ▼
                                   plan-store entry deleted —
                                   single-use, no replay
```

## The tools

**`terraform_plan(working_dir, var_file?)`** — runs a real `terraform plan` against
`working_dir` (contained under `TF_WORKING_ROOT`), scans the result, and either:
- refuses with `isError: true` and a JSON body containing both a human-readable itemized
  `message` and a machine-parseable `violations[]` array (ruleId, severity, category, resource
  address, what's wrong, how to fix it) — no `planId` is issued, and the scanned plan file is
  deleted, not left lying around; or
- approves and returns a `planId`, a short-TTL token (default 15 minutes) that's the only thing
  `terraform_apply` will accept.

**`terraform_apply(plan_id, working_dir)`** — looks up `plan_id` in a server-side plan store and
runs `terraform apply` against exactly that file. Refuses if the id is unknown, expired, already
consumed, or was scanned against a different `working_dir`. Single-use: the entry is deleted the
moment this call resolves, success or failure, so a `planId` can never be replayed.

## What it checks (AWS only, this version)

| Rule | What it flags |
|---|---|
| `aws.storage.s3-public-access-block-missing` | An S3 bucket with no `aws_s3_bucket_public_access_block` (or one with any of the four block/ignore/restrict attributes not `true`) |
| `aws.network.sg-open-ingress-sensitive-port` | Ingress open to `0.0.0.0/0`/`::/0` on SSH/RDP/common database ports, or with no port restriction — both the classic inline `aws_security_group` shape and the newer per-rule `aws_vpc_security_group_ingress_rule` |
| `aws.iam.wildcard-action-or-principal` | `Action: "*"` or `Principal: "*"` in an IAM policy document |
| `aws.database.rds-publicly-accessible` | `publicly_accessible = true` on an RDS instance |
| `aws.database.rds-unencrypted` | `storage_encrypted` not explicitly `true` on an RDS instance |
| `aws.secrets.kms-rotation-disabled` | `enable_key_rotation` not explicitly `true` on a KMS key |
| `aws.compute.imdsv1-allowed` | `metadata_options.http_tokens` explicitly `"optional"` on an EC2 instance |

Each rule's "absence is/isn't a violation" direction was individually verified against real
`terraform-provider-aws` docs before being written, not assumed — see `CLAUDE.md`'s "Things to
know" for the two cases (S3 encryption, IMDS hardening) where that verification changed the rule
from what was originally planned. GCP and Azure are not implemented yet; the engine and rule
taxonomy are provider-agnostic by design specifically so adding them later is additive, not a
rewrite.

## Security & guardrails

- **Path containment**: `working_dir` must resolve within `TF_WORKING_ROOT` (default: this
  server's startup cwd), same pattern as `dep-audit-mcp`'s `SCAN_ROOT`.
- **No `shell: true`** anywhere; every `terraform` invocation is a direct argv array.
- **The plan store is on disk**, under `~/Library/Application Support/terraform-guard-mcp/`, not
  in-memory — an MCP stdio server can be restarted by its client mid-session, and losing an
  approved-but-unapplied plan on restart would be a correctness bug.
- **Env sanitization is prefix-based** (`AWS_*`, `ARM_*`/`AZURE_*`, `GOOGLE_*`/`GCLOUD_*`,
  `TF_*`, plus exact `PATH`/`HOME`), not the exact-name allowlist the sibling MCP servers in this
  workspace use — deliberate, since `terraform` genuinely needs whatever cloud credentials the
  user's setup relies on and those can't be fully enumerated in advance. This server passes
  cloud credentials through to `terraform` by design; the point of sanitizing at all is to stop
  *unrelated* secrets from the parent process leaking through, not to deny `terraform` what it
  needs to function.
- **The rule engine never reads credentials** — only `resource_changes[].change.{after,
  after_unknown}` structural attributes (booleans, CIDRs, policy JSON).

**The one limitation this can't engineer around**: it only governs actions taken *through*
`terraform_plan`/`terraform_apply`. An agent with a raw shell available can always run
`terraform apply` directly and bypass this server entirely. That's not a gap in this
implementation — it's the honest edge of what any MCP server can enforce, stated here rather
than left for someone to discover the hard way.

## Known gotchas

- **Terraform's own "Saved plan is stale" check protects against concurrent state changes, not
  against editing `.tf` source after planning.** Verified directly: editing a resource's config
  between `terraform_plan` and `terraform_apply` did nothing — the saved plan file is a
  self-contained snapshot and gets applied exactly as computed, ignoring the later edit. Only a
  genuine concurrent state change (a separate `terraform apply` run against the same state
  outside this server) triggered the real staleness error. Useful defense-in-depth against races
  with another apply, not a substitute for re-scanning after every config change — always get a
  fresh `planId` if the config might have changed since the last scan.
- **MinIO (used for local end-to-end testing) doesn't fully support `PutPublicAccessBlock`** — a
  bucket applies fine, its companion `aws_s3_bucket_public_access_block` fails with a MinIO-side
  `MalformedXML` error. Confirmed as a MinIO API-compatibility gap, not a bug here, since the
  bucket creation itself (same `terraform apply` invocation, same code path) succeeded. Use real
  AWS credentials or LocalStack if you need that specific resource to fully apply in a test.
- **`terraform` isn't in Homebrew's core anymore.** `brew install terraform` will fail after
  HashiCorp's license change moved it to their own tap — use
  `brew install hashicorp/tap/terraform`.

## Setup

```sh
npm install
terraform version   # confirm the prerequisite is installed
```

Register with an MCP client:
```json
{"command": "node", "args": ["/absolute/path/to/terraform-guard-mcp/index.mjs"]}
```

Optional env vars: `TF_WORKING_ROOT` (containment root, default: server's startup cwd),
`TF_PLAN_TTL_SECONDS` (default 900).

## Status

AWS rule pack (7 rules) implemented and verified end-to-end against real `terraform` — a
deliberately-insecure fixture blocks with the exact expected violation, a compliant fixture gets
approved and genuinely applies against a local MinIO backend, and the single-use/replay,
staleness, and TTL-expiry protections were each proven with a real Terraform run, not just
asserted. GCP and Azure rule packs are the natural next addition, using the same engine.

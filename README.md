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

Two checks run **without cloud credentials**, before and alongside the plan-based rules:
`terraform validate` (catches schema errors — hallucinated resource types, misspelled arguments)
and a source scan for dangerous literals that plan JSON cannot represent at all. A policy built
with `jsonencode()` that also interpolates a not-yet-created ARN is unknown at plan time — its
text appears nowhere in `after`, `after_unknown`, or `configuration` — so an
`arn:aws:iam::*:role/x` Principal (access from *any* AWS account, not just yours) is invisible to
the engine and is caught by the source scan instead.

**A failed plan is never reported as clean.** If `terraform plan` can't authenticate, the response
says outright that the plan-based rules did not run and the result is partial, not passing.

**Stale `.terraform` directories are re-initialized automatically.** Adding a module or provider
after the first `init` leaves it uninstalled, and the resulting error looks like a defect in your
configuration rather than in the tooling. The server detects Terraform's own init-required signals
and retries once.

**Removed resources are reported.** Each scan records what a directory declared; if resources
present last time have since vanished, the response says which ones. Advisory, not blocking —
deleting resources is legitimate, but doing it silently while fixing something else is how an
agent loop quietly deletes the thing the project exists for.

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

## Credential scoping

By default this server governs only actions taken *through* its two tools — an agent with a raw
shell could run `terraform apply` directly and bypass it. Credential scoping closes that at the
layer that can actually hold it: **AWS IAM**. Rather than trying to stop the agent from *running*
`terraform apply`, it makes a raw invocation powerless.

Set two environment variables and the server mints short-lived, apply-capable credentials via STS
for each guarded apply:

```sh
export TFGUARD_APPLY_ROLE_ARN="arn:aws:iam::<account>:role/terraform-guard-apply"
export TFGUARD_EXTERNAL_ID="<a shared secret matching the role's trust policy>"   # optional
export TFGUARD_SESSION_DURATION=900                                              # optional, 900–43200
```

The intended setup is two identities:

1. **Ambient identity** — whatever your shell and `~/.aws` already resolve. Give it read/plan
   permissions plus `sts:AssumeRole` on the apply role, and nothing that can mutate
   infrastructure. This is what `terraform plan` uses, and what a raw `terraform apply` would
   get — hence `AccessDenied` from AWS itself.
2. **Apply role** — the permissions an apply actually needs, with a trust policy trusting the
   ambient principal (gated on `sts:ExternalId` if you set one).

The server deliberately does not create these roles. Provisioning IAM would require the ambient
identity to hold IAM write permissions, which is exactly what this design removes.

Every apply reports which mode was in force — `[scopedCredentials: true|false]` — on both success
and failure, so an unconfigured server says so plainly rather than looking identical to a
configured one, and a permissions-shaped failure can be read against the identity that produced
it. Successful scoped applies also report the CloudTrail `RoleSessionName`.

**If STS fails, the apply is refused — never retried with ambient credentials.** A silent
fallback would run the apply at a different privilege level than configured while still
reporting success, which is the precise failure this mechanism exists to prevent.

### What this does and doesn't buy you

**Does**: a raw `terraform apply` — from any shell, wrapper, or tool, bypassing this server
entirely — fails at AWS with `AccessDenied`. That property holds regardless of what the agent
can execute locally, because it's enforced by IAM rather than by anything on your machine.

**Doesn't**: the ambient identity is *permitted* to assume the apply role, so a determined agent
could call `sts:AssumeRole` itself and obtain the same credentials. That path is not prevented —
but it is **attributable**: legitimate applies carry `RoleSessionName = tfguard-<planId>` naming a
plan this server actually scanned and stored, which an out-of-band assume-role cannot forge.
Deliberate bypass becomes visible in CloudTrail rather than invisible.

Closing that residual entirely requires either MFA on the apply role's trust policy (real
prevention, at the cost of a TOTP prompt on every apply) or moving the privileged half into a
daemon running as a separate OS user (real prevention, no prompt, considerably more machinery).
Both were considered and deliberately deferred — on a single-user machine where the agent's shell
runs as the same OS user as this server, anything the server can read the shell can read too, so
there is no local secret that constitutes a boundary.

### The local-sandbox hook

A Claude Code permission deny-rule blocking `Bash(terraform apply*)` is a useful *additional*
layer, but only that: it's a text matcher, and testing confirmed `bash -c "terraform apply"`
defeats it. It stops the accidental bypass; credential scoping is what stops the effective one.

A static deny-rule also blocks legitimate local sandbox work, which is why this workspace uses a
`PreToolUse` hook (`.claude/hooks/terraform-local-guard.mjs`) instead. The hook inspects the
target directory's `.tf` files and allows `apply`/`destroy` only when every cloud-reaching
provider block declares a localhost endpoint — MinIO/LocalStack work runs freely; anything that
could reach a real cloud is denied and pushed through `terraform_plan`/`terraform_apply`. It
fails closed on anything it can't positively prove local, including an unresolvable directory, a
cloud resource with no provider block at all, and `cd`/`-chdir=` redirection to a cloud config.

Two things worth knowing if you replicate this:

- **A static `deny` rule always beats a hook's `allow`** — verified empirically. Keeping both
  means the hook's allow can never fire, so the deny entries have to be removed for the bypass to
  work at all. The hook is strictly stronger than what it replaces: it inspects what a config
  actually targets rather than pattern-matching command text.
- **Keying on the config rather than a marker file or path list is deliberate.** Faking a
  localhost endpoint to get past the check actually redirects Terraform to localhost, so it can't
  be used to sneak a real-cloud apply through — the check and the effect are the same fact.

The tradeoff, stated plainly: with no deny rule, if hooks are ever disabled nothing at this layer
blocks a raw apply. That's acceptable precisely because this layer only ever stopped careless
applies; credential scoping above is the boundary that doesn't depend on local machinery.

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
`TF_PLAN_TTL_SECONDS` (default 900), and the `TFGUARD_*` credential-scoping vars documented above.

## Status

AWS rule pack (7 rules) implemented and verified end-to-end against real `terraform` — a
deliberately-insecure fixture blocks with the exact expected violation, a compliant fixture gets
approved and genuinely applies against a local MinIO backend, and the single-use/replay,
staleness, and TTL-expiry protections were each proven with a real Terraform run, not just
asserted.

Credential scoping is implemented and its local-testable paths are verified: the unconfigured
path applies and reports `scopedCredentials: false`; a configured path whose STS call fails
refuses rather than falling back. The full configured path (assume role → apply succeeds → raw
apply gets `AccessDenied`) needs a real AWS account to exercise — MinIO cannot serve STS — and
has not been run here.

GCP and Azure rule packs are the natural next addition, using the same engine.

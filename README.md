# terraform-guard-mcp

[![release](https://img.shields.io/github/v/release/tjwitko/terraform-guard-mcp)](https://github.com/tjwitko/terraform-guard-mcp/releases/latest)
[![license](https://img.shields.io/github/license/tjwitko/terraform-guard-mcp)](LICENSE)

An MCP server that **stops insecure Terraform from being applied** — not a linter that reports
findings for the caller to weigh, a refusal.

It works by owning the only route from plan to apply that runs through it:

```
terraform_plan  ──▶ terraform init / plan / show -json ──▶ rule engine
                                                              │
                        violations ──▶ refused, itemised, no planId issued
                        clean      ──▶ plan stored server-side, planId returned
                                                              │
terraform_apply(planId) ──▶ applies exactly that stored plan, once, then deletes it
```

There is no parameter that accepts a plan file, and no way to re-plan from inside
`terraform_apply`. A plan that was never scanned clean cannot be applied through this server.

It exists because a generated Terraform config shipped an S3 bucket policy granting public
`s3:GetObject` to `Principal: "*"`, and only manual review caught it.

---

## Getting started

### Requirements

- **Node.js 20 or newer**
- **Terraform**:

  ```bash
  brew install hashicorp/tap/terraform
  ```

  Not `brew install terraform` — HashiCorp moved it out of homebrew-core after their licence
  change.

### Install

```bash
npm install --save-dev github:tjwitko/terraform-guard-mcp#v1.1.0
```

### Register it with an MCP client

```json
{
  "mcpServers": {
    "terraform-guard": {
      "command": "node",
      "args": ["/absolute/path/to/terraform-guard-mcp/index.mjs"],
      "env": { "TF_WORKING_ROOT": "/absolute/path/to/your/infrastructure" }
    }
  }
}
```

---

## The tools

### `terraform_plan(working_dir, var_file?)`

Runs a real `terraform plan`, scans the result, and either:

- **refuses** — `isError: true`, with a human-readable itemised `message` and a machine-readable
  `violations[]` (rule id, severity, category, resource address, what is wrong, how to fix it). No
  `planId` is issued and the plan file is deleted rather than left on disk; or
- **approves** — returns a `planId`, a short-TTL token (default 15 minutes) that is the only thing
  `terraform_apply` accepts.

### `terraform_apply(plan_id, working_dir)`

Applies exactly the stored plan. Refuses an id that is unknown, expired, already consumed, or
scanned against a different `working_dir`. **Single-use**: the entry is deleted the moment the call
resolves, success or failure, so a `planId` can never be replayed.

---

## What it checks

Fourteen AWS rules, each verified against the real `terraform-provider-aws` documentation before it
was written:

| rule | severity | flags |
|---|---|---|
| `aws.storage.s3-public-access-block-missing` | critical | a bucket with no public-access block, or one whose four attributes are not all `true` |
| `aws.storage.s3-object-lock-not-enabled-on-bucket` | critical | an Object Lock configuration on a bucket that was not created with it — it cannot be turned on afterwards |
| `aws.storage.s3-object-lock-retention-mode-missing` | critical | a default retention block setting a period but no mode |
| `aws.storage.s3-object-lock-undermined-by-permissions` | critical | Object Lock enabled while a principal is granted the permissions that defeat it |
| `aws.network.sg-open-ingress-sensitive-port` | critical | ingress from `0.0.0.0/0` / `::/0` on SSH, RDP or common database ports, or with no port restriction |
| `aws.iam.wildcard-action-or-principal` | critical | `Action: "*"` or `Principal: "*"` — including a wildcard in an ARN's **account** field, which looks scoped and is not |
| `aws.iam.access-key-created` | critical | an `aws_iam_access_key` at all. It exists only to mint a permanent credential, so there is no secure configuration to check — and the secret lands in Terraform state in plaintext |
| `aws.iam.user-as-service-identity` | high | an `aws_iam_user` standing in for a workload identity |
| `aws.iam.duplicate-policy-attachment` | medium | two attachments binding the same managed policy to the same principal |
| `aws.database.rds-publicly-accessible` | critical | `publicly_accessible = true` |
| `aws.database.rds-unencrypted` | critical | `storage_encrypted` not explicitly `true` |
| `aws.kubernetes.eks-public-api-open` | critical | an EKS API server reachable from `0.0.0.0/0` |
| `aws.secrets.kms-rotation-disabled` | medium | `enable_key_rotation` not explicitly `true` |
| `aws.compute.imdsv1-allowed` | high | `metadata_options.http_tokens` explicitly `"optional"` |

Two of these are a different shape from the rest. `aws.iam.access-key-created` and
`aws.iam.user-as-service-identity` refuse a resource *type* rather than inspecting attributes,
because a resource whose purpose is minting a permanent credential has no secure configuration.

`aws.kubernetes.eks-public-api-open` is the one worth knowing about if you write EKS configs: a
control plane is open to the internet unless **two separate attributes** say otherwise.
`endpoint_public_access` defaults to `true`, and EKS defaults `public_access_cidrs` to
`0.0.0.0/0` — so a `vpc_config` block setting only `subnet_ids`, which is the shape most generated
configs produce, is a Kubernetes API server reachable from anywhere with nothing in the source text
to notice.

Whether *absence* of an attribute is a violation was verified per rule rather than assumed. Two
attributes with the identical shape need opposite handling: `publicly_accessible` defaults to
`false`, so absence is safe; `storage_encrypted` also defaults to `false`, so absence is not.

**A rule deliberately absent:** flagging buckets with no server-side encryption configuration. AWS
has applied default SSE-S3 to every new bucket since 2023, so that rule would fire on every ordinary
bucket. A false positive in a blocking gate destroys work rather than merely missing a finding.

### Two checks that need no cloud credentials

- **`terraform validate`** — schema errors, hallucinated resource types, misspelled arguments.
- **A source scan** for dangerous literals that plan JSON cannot represent. A policy built with
  `jsonencode()` that interpolates a not-yet-created ARN is unknown at plan time — the literal text
  appears in neither `after`, `after_unknown` nor `configuration` — so an
  `arn:aws:iam::*:role/x` principal is invisible to the engine and is caught here instead.

The source scan also refuses **hardcoded provider credentials**. Two reasons, and the second is the
one people miss: a credential in a `.tf` file gets committed, *and* a fake one is the standard way
to make `terraform plan` succeed without credentials — producing a clean plan for a configuration
that could never deploy. A real generated project did exactly that, passing validate, every security
rule and a pre-commit hook, having bought its clean plan with a dummy access key. Findings never
echo the value.

Provider blocks declaring a **local endpoint** (`localhost`, `127.0.0.1`, `host.docker.internal`)
are exempt, so MinIO and LocalStack work runs freely. The exemption does not cover a real-shaped
`AKIA…`/`ASIA…` key, so an `endpoints` block cannot launder a genuine credential.

### A failed plan is never reported as clean

If `terraform plan` cannot authenticate, the response says outright that the plan-based rules did
not run and the result is partial. Before that existed, a project sailed through with a wide-open
bucket policy because every security rule had silently been skipped.

---

## Scanning without a cloud account

Across sixteen agent runs, not one generated project ever produced a plan — so not one plan-based
rule ever ran. The causes were counted rather than guessed: four blocked on a required variable with
no value, two on the machine having no cloud account, two on real configuration errors. Only the
last class is the configuration's fault.

So when nothing else supplies them, the server provides `TF_VAR_*` values, placeholder credentials,
and a scanner-owned override carrying the offline `skip_*` settings, deleted before the call
returns. Three rules keep it honest:

1. **Real inputs always win.** A machine with a real account, a `terraform.tfvars`, or a provider
   block carrying its own credentials is left untouched.
2. **Any injection makes the plan scan-only** — `planId` is `null`, `applyable` is `false`.
   Terraform writes variable *values* into the plan file, so applying one would deploy a database
   whose password is literally a placeholder. The chokepoint stays exactly as strict.
3. **Only `terraform.tfvars` and `*.auto.tfvars` count** as supplying a value.

Measured effect: a config with an unencrypted, publicly-accessible RDS instance now returns both
findings on a machine with no AWS account at all.

---

## Credential scoping

By default this server governs only what goes through its two tools — a raw shell can run
`terraform apply` directly. Credential scoping closes that at the layer that can actually hold it:
**AWS IAM**. Rather than stopping the agent from running apply, it makes a raw invocation powerless.

```bash
export TFGUARD_APPLY_ROLE_ARN="arn:aws:iam::<account>:role/terraform-guard-apply"
export TFGUARD_EXTERNAL_ID="<shared secret matching the role's trust policy>"   # optional
export TFGUARD_SESSION_DURATION=900                                            # optional, 900–43200
```

Two identities:

1. **Ambient** — your shell and `~/.aws`. Read and plan permissions plus `sts:AssumeRole` on the
   apply role, and nothing that can mutate infrastructure. This is what a raw `terraform apply`
   would get, hence `AccessDenied` from AWS itself.
2. **Apply role** — the permissions an apply needs, trusting the ambient principal.

The server does not create these roles. Provisioning IAM would require the ambient identity to hold
IAM write permissions, which is exactly what this removes.

**If STS fails, the apply is refused — never retried with ambient credentials.** A silent fallback
would run at a different privilege level than configured while reporting success. Every apply reports
`scopedCredentials: true|false` on success *and* failure, so an unconfigured server says so plainly
and a permissions-shaped failure can be read against the identity that produced it.

**What it does and does not buy you.** A raw `terraform apply` from any shell fails at AWS,
regardless of what the agent can execute locally. What it does not do is prevent a determined agent
from calling `sts:AssumeRole` itself — but that becomes *attributable*: legitimate applies carry
`RoleSessionName = tfguard-<planId>`, naming a plan this server actually scanned, which an
out-of-band assume-role cannot forge. Closing the residual entirely needs MFA on the trust policy or
a daemon running as a separate OS user; on a single-user machine, anything this server can read the
agent's shell can read too.

---

## Configuration

| variable | default | purpose |
|---|---|---|
| `TF_WORKING_ROOT` | the process's working directory at startup | `working_dir` must resolve inside it |
| `TF_PLAN_TTL_SECONDS` | `900` | how long a `planId` stays valid |
| `TFGUARD_APPLY_ROLE_ARN` | — | enables credential scoping |
| `TFGUARD_EXTERNAL_ID` | — | matched against the role's trust policy |
| `TFGUARD_SESSION_DURATION` | `900` | STS session length |

Environment sanitization here is **prefix-based** (`AWS_*`, `ARM_*`, `AZURE_*`, `GOOGLE_*`,
`GCLOUD_*`, `TF_*`, `TFGUARD_*`, plus `PATH` and `HOME`) rather than the exact-name allowlist the
sibling servers use. Terraform genuinely needs whatever cloud credentials your setup relies on, and
those cannot be enumerated in advance. The point is to stop *unrelated* secrets from the parent
process leaking through, not to deny Terraform what it needs.

The plan store lives on disk under `~/Library/Application Support/terraform-guard-mcp/`, because an
MCP stdio server can be restarted by its client mid-session and losing an approved-but-unapplied
plan would be a correctness bug. **The rule engine never reads credentials** — only structural
attributes from `resource_changes[]`.

---

## Two behaviours worth knowing

**Stale `.terraform` directories are re-initialised automatically.** Adding a module or provider
after the first `init` leaves it uninstalled, and the error reads like a defect in your
configuration. In a real run a model read "Module not installed" as its own fault and rewrote the
file twice, deleting working resources on the way. When a tool's error message is wrong, the caller
does not get to find that out.

**Removed resources are reported.** Each scan records what a directory declared; if something has
since vanished, the response says which. Advisory, never blocking — deleting resources is
legitimate, but a model fixing a validation error once rewrote `main.tf` three times and silently
dropped the S3 bucket the project existed for. Every individual response looked reasonable; only the
sequence showed it.

---

## Limitations

- **A raw shell bypasses the tools.** Credential scoping is the answer to that; a local permission
  rule is not — `bash -c "terraform apply"` defeats a text matcher.
- **Terraform's own staleness check guards concurrent state changes, not source edits.** Verified
  directly: editing a `.tf` file between plan and apply does *not* trigger it, because the saved plan
  is a self-contained snapshot. Always take a fresh `planId` if the config may have changed.
- **AWS only.** The engine and taxonomy are provider-agnostic by design — adding `rules/gcp.mjs` and
  a line in `rules/index.mjs` is the whole integration surface — but no GCP or Azure attribute
  defaults have been verified yet, and writing them from memory is how false positives get shipped.
- **MinIO does not fully support `PutPublicAccessBlock`**, so that one resource cannot complete a
  local end-to-end apply. Use LocalStack or real credentials if you need it.

---

## Development

```bash
npm install
npm test            # unit tests over real `terraform show -json` shapes; no terraform binary needed
terraform version
```

`fixtures/aws-insecure` and `fixtures/aws-secure` are real configurations, not fake JSON. The secure
fixture applies for real against a local MinIO container:

```bash
docker run -d --name minio-tfguard -p 9100:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data
```

Candidate rules not yet promoted to the blocking pack are tracked in `docs/candidate-rules.md`.
Nothing is promoted without verifying the attribute's real default first.

---

## Part of agent-gate

This is one of four control servers behind
[agent-gate](https://github.com/tjwitko/agent-gate), which runs them together and fails a build on
what they find. It works standalone with any MCP client.

## License

[Apache License 2.0](LICENSE) © 2026 Tom Witkowski

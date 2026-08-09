# CLAUDE.md

An MCP server that blocks an LLM agent from applying insecure Terraform infrastructure — not
an advisory linter, a real block. Exposes two tools, `terraform_plan` and `terraform_apply`,
that together are the only way to get from a working directory to applied infrastructure through
this server: `terraform_apply` can only apply a plan that was just scanned clean and issued a
`planId` by `terraform_plan`. There is no parameter to pass a plan file directly and no way to
re-plan internally from inside `terraform_apply`.

## Architecture

Calling model → `terraform_plan` → `terraform init`/`plan`/`show -json` (real `terraform`
binary, real provider) → rule engine (`rules/engine.mjs` + `rules/aws.mjs`) → clean plans get
copied into a server-side plan store (`lib/plan-store.mjs`, keyed by a random UUID) and the tmp
plan file is deleted; violating plans never get a `planId` and are refused with an itemized
list. `terraform_apply` looks up a `planId` in that store — nowhere else — and runs
`terraform apply <that exact file>`.

**Honest limitation, not a bug to fix**: this only governs actions taken *through* these two
tools. An agent with a raw shell available can always run `terraform apply` directly, bypassing
this server entirely — the same boundary `local-delegate-mcp` has around delegation calls that
don't go through its own tool.

## Key files

- `index.mjs` — server bootstrap, env sanitization, the two tool registrations
- `lib/paths.mjs` — `resolveWorkingDir()`, `TF_WORKING_ROOT` containment (same shape as
  dep-audit-mcp's `resolveScanPath`)
- `lib/terraform-cli.mjs` — `spawnSync` wrappers for `terraform version/init/plan/show/apply`,
  no `shell: true` anywhere
- `lib/plan-store.mjs` — **the enforcement-critical file.** Plan-id issuance, on-disk storage
  under `~/Library/Application Support/terraform-guard-mcp/plans/`, TTL, single-use consumption.
  This is what makes "block insecure applies" a real guarantee instead of an advisory check —
  read this file before touching anything else if you're auditing the security model.
- `lib/aws-credentials.mjs` — STS AssumeRole for credential scoping (see "Things to know")
- `rules/engine.mjs` — `buildIndex()`/`evaluate()`, provider routing by `provider_name`'s final
  path segment (not `type` prefix — deliberate, see "Things to know")
- `rules/aws.mjs` — the only provider pack implemented so far, 7 rules
- `rules/taxonomy.mjs` — shared category-id list, includes categories reserved for GCP/Azure
  packs that don't exist yet
- `fixtures/aws-insecure/`, `fixtures/aws-secure/` — real Terraform configs for end-to-end
  testing (not fake JSON), see "Common commands"
- `test/engine.test.mjs` — unit tests over hand-authored `resource_changes[]` fixtures matching
  the real `terraform show -json` shape, no `terraform` binary required to run these

## Common commands

```sh
npm install
node --check index.mjs
node --test                      # unit tests, no terraform binary needed
terraform version                # confirm the prerequisite is installed (brew install hashicorp/tap/terraform —
                                  # NOT `brew install terraform`, HashiCorp pulled it from homebrew-core
                                  # after their license change; it now lives in their own tap)
```

No build step. Run directly by an MCP client via:
```json
{"command": "node", "args": ["/absolute/path/to/terraform-guard-mcp/index.mjs"]}
```

**End-to-end testing** (proves the block is real, not just unit-tested logic) needs a local
MinIO container for the `aws-secure` fixture's `terraform_apply` step to actually succeed —
fake `access_key`/`secret_key` alone gets `plan`/`validate` to pass (pure local computation) but
a real `apply` genuinely calls the AWS API and gets a real 403 without a reachable endpoint:
```sh
docker run -d --name minio-tfguard -p 9100:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data
```
`fixtures/aws-secure/main.tf` already points its `endpoints { s3 = "http://localhost:9100" }`
at this. `fixtures/aws-insecure/` needs no backing service — it's rejected by `terraform_plan`
before any real API call happens.

## Things to know

- **`provider_name`'s final path segment routes to a rule pack, not `type` prefix matching.**
  `"registry.terraform.io/hashicorp/aws"` → `aws`. Deliberate: a community/wrapped provider using
  a non-`aws_`-prefixed type naming convention would silently miss every rule under prefix
  matching; `provider_name` is Terraform's own authoritative statement of which provider produced
  a resource change.
- **Four cases per checked attribute, not three**: present-safe, present-unsafe, present-but-
  `after_unknown` (config sets it to something not yet resolvable), and genuinely absent from
  both. The last two get the same `absentBehavior`, but that behavior must be verified per
  attribute against real docs, not assumed uniformly — `aws_db_instance.publicly_accessible`
  defaults to `false` (absence is safe) while `storage_encrypted` also defaults to `false`
  (absence is unsafe). Same shape, opposite correct handling.
- **A rule this repo does NOT have, on purpose**: flagging S3 buckets with no
  `aws_s3_bucket_server_side_encryption_configuration`. Checked the real provider docs before
  writing it — AWS has applied default SSE-S3 encryption to every new bucket automatically since
  2023, with or without this resource declared. That would have been a false positive on every
  ordinary bucket, not a real finding. Worth re-checking before ever adding an "encryption
  missing" rule for any resource type: verify the resource genuinely has no default, don't assume.
- **`aws.compute.imdsv1-allowed` only flags an explicit `"optional"` value, never absence.**
  Unlike its sibling `metadata_options` attributes (which each state a documented default),
  `http_tokens` has none in the provider docs — the effective default depends on AWS
  account-level instance-metadata-defaults settings that aren't visible in a plan at all. Flagging
  absence here would be guessing, not verifying.
- **S3 bucket ↔ public-access-block matching is by `module_address`, not by resolved value.** A
  newly-created bucket's `id` is unresolved at plan time (`after_unknown.id === true`), so a PAB's
  `bucket = aws_s3_bucket.this.id` reference is unresolved too — there's no literal value to
  match on for the common case. Same-module is a deliberate simplification: it can miss a PAB
  declared in a different module than its bucket (rare in practice), but it will never wrongly
  clear a bucket that's actually unprotected — the safer failure direction for a blocking tool.
- **Terraform's own "Saved plan is stale" check fires on state changes, not on editing the `.tf`
  source after planning.** Verified directly this session, not assumed: editing a resource's
  config between `terraform_plan` and `terraform_apply` did NOT trigger it — the saved plan file
  is a self-contained snapshot of intended actions and gets applied as originally computed,
  silently ignoring the edit. Only a genuine concurrent state change (a real `terraform apply`
  run outside this server, advancing the state serial) triggered the real error. The defense
  this buys is against races with a concurrent apply on the same state, not against someone
  editing config after a plan was approved — don't oversell it as the latter.
- **MinIO doesn't fully support `PutPublicAccessBlock`.** `fixtures/aws-secure`'s bucket creates
  fine against a local MinIO container; the accompanying `aws_s3_bucket_public_access_block`
  fails with a MinIO-side `MalformedXML` error on `apply`. This is a MinIO API-compatibility
  gap, confirmed by getting the bucket itself created successfully first — not a defect in this
  server's plan/apply plumbing, which was proven correct by every other end-to-end test
  (violation detection, clean approval, fabricated-id rejection, single-use/replay, staleness,
  TTL expiry all passed for real). If you need a fully-succeeding PAB apply for some future test,
  you'll need real AWS credentials or LocalStack instead of MinIO for that specific resource.
- **Env sanitization here is prefix-based (`/^(AWS_|ARM_|AZURE_|GOOGLE_|GCLOUD_|TF_)/`), not the
  exact-name allowlist both sibling servers use.** `terraform plan`/`apply` genuinely needs
  whatever cloud credentials the user's setup relies on, which can't be fully enumerated in
  advance — an exact-name list would silently break the first time a new provider or `TF_VAR_*`
  shows up. This server passes cloud credentials through to `terraform` by design; sanitization
  here is about not leaking *unrelated* secrets from the parent process, not about denying
  `terraform` what it needs.
- **`TFGUARD_` is its own sanitization prefix, and it has to be.** `/^TF_/` does NOT match
  `TFGUARD_` — that regex requires the underscore immediately after `TF`. Before this was
  explicitly added to `PREFIX_ALLOWLIST`, every `TFGUARD_*` var would have been silently deleted
  at startup and credential scoping would have looked broken for completely non-obvious reasons.
  If you add more config vars, keep them on this prefix and don't assume `TF_` covers it.
- **`buildApplyEnv()` deletes `AWS_PROFILE`/`AWS_DEFAULT_PROFILE`, deliberately.** A profile set
  in the ambient environment wins over static credentials in the AWS credential chain, so leaving
  it would silently run the apply under the ambient (plan-only) identity while this server
  reported it had scoped the credentials. There's a unit test pinning this; don't "simplify" it
  back into an inline object spread.
- **Terraform re-resolves env-sourced credentials at apply time, and does not object to them
  differing from plan time.** Verified four ways before the feature was built, since the whole
  injection design depends on it: the plan JSON's `provider_config` contains no credential
  fields when they come from the environment; `strings` over the binary plan file finds no
  credential material (which also matters because the plan store persists these files to disk);
  applying a stored plan with deliberately-invalid credentials fails with `InvalidAccessKeyId`
  (proving re-resolution rather than pinning); and applying with *different valid* credentials
  succeeds. If you ever move credentials into the provider block literally, all of that stops
  holding — keep them env-sourced.
- **An STS failure refuses the apply and never falls back to ambient credentials.** A fallback
  would run at a different privilege level than configured while reporting success. The plan is
  consumed on that path too, so a failed assume-role can't be retried against the same planId.
- **`scopedCredentials` is reported on failures as well as successes.** This was originally
  success-only and testing caught it — a permissions-shaped apply failure is exactly when
  "which identity ran this?" is the first question worth asking.
- **The AWS SDK dependency is a deliberate divergence from the siblings**, which carry only
  `@modelcontextprotocol/sdk` + `zod`. `@aws-sdk/client-sts` (24 packages) is used instead of
  shelling out to the `aws` CLI because the CLI is a second prerequisite that may not be
  installed, and the SDK resolves the ambient credential chain (env → `~/.aws` → SSO → IMDS) the
  same way Terraform does — security-critical logic not worth reimplementing.
- **GCP/Azure are not implemented.** The engine and taxonomy are provider-agnostic by design —
  adding `rules/gcp.mjs`/`rules/azure.mjs` and a line in `rules/index.mjs` is the entire
  integration surface, no engine changes needed — but no attribute defaults for either cloud have
  been verified against real docs yet. Don't write GCP/Azure rules from memory; verify each one
  the same way the AWS pack's defaults were verified (real provider doc fetch, not recollection).

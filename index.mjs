#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import path from "path";
import os from "os";
import { existsSync } from "fs";
import { randomUUID } from "crypto";

import { resolveWorkingDir } from "./lib/paths.mjs";
import {
  checkTerraformInstalled,
  needsInit,
  terraformInit,
  terraformValidate,
  classifyValidationErrors,
  looksLikeInitRequired,
  terraformPlan,
  terraformShowJson,
  terraformApply,
  buildApplyEnv,
  safeUnlink,
} from "./lib/terraform-cli.mjs";
import { assumeApplyRole, isScopedCredentialsConfigured } from "./lib/aws-credentials.mjs";
import { scanTerraformSources } from "./lib/source-scan.mjs";
import { planInputs, writeScanOverride, removeScanOverride } from "./lib/plan-inputs.mjs";
import { findRemovedResources } from "./lib/resource-census.mjs";
import { moduleArgumentHint } from "./lib/module-interface.mjs";
import { storePlan, lookupPlan, consumePlan } from "./lib/plan-store.mjs";
import { formatRefusalMessage, worstSeverity } from "./lib/format.mjs";
import { evaluate } from "./rules/engine.mjs";
import { PROVIDER_PACKS } from "./rules/index.mjs";

// A stdio MCP server inherits its entire parent environment by default — drop everything not
// needed, same guardrail as the sibling servers. This one diverges from their exact-name
// allowlist on purpose: `terraform plan`/`apply` genuinely needs whatever cloud credentials the
// user's setup relies on (AWS_*, ARM_*/AZURE_*, GOOGLE_*/GCLOUD_*, TF_VAR_*), and an exact-name
// list would silently break the first time a new provider or TF_VAR_* is introduced. This
// server passes cloud credentials through to `terraform` by design — sanitization here is about
// not leaking *unrelated* secrets from the parent process, not about denying terraform what it
// needs to function.
// TFGUARD_ needs its own entry: /^TF_/ does NOT match "TFGUARD_" (it requires the underscore
// directly after TF), so this server's own config vars would be silently deleted at startup and
// credential scoping would appear broken for entirely non-obvious reasons. Kept as a distinct
// prefix rather than renaming to TF_GUARD_* so this server's config never sits inside
// Terraform's own TF_ namespace.
const EXACT_ALLOWLIST = ["PATH", "HOME"];
const PREFIX_ALLOWLIST = [/^AWS_/, /^ARM_/, /^AZURE_/, /^GOOGLE_/, /^GCLOUD_/, /^TF_/, /^TFGUARD_/];

function sanitizeEnv() {
  for (const key in process.env) {
    if (EXACT_ALLOWLIST.includes(key)) continue;
    if (PREFIX_ALLOWLIST.some((re) => re.test(key))) continue;
    delete process.env[key];
  }
}
sanitizeEnv();

// Sole allowed root for working_dir, same containment pattern as dep-audit-mcp's SCAN_ROOT /
// local-delegate-mcp's CONTEXT_ROOT.
const WORKING_ROOT = path.resolve(process.env.TF_WORKING_ROOT || process.cwd());

const server = new McpServer({
  name: "terraform-guard",
  version: "0.1.0",
});

server.tool(
  "terraform_plan",
  "Run `terraform plan` against a working directory, scan the resulting plan for insecure " +
    "configurations (AWS only in this version — public S3 buckets, open security-group ingress " +
    "on sensitive ports, wildcard IAM policies, publicly-accessible/unencrypted RDS instances, " +
    "disabled KMS key rotation, IMDSv1 allowed), and either refuse with an itemized list of " +
    "violations, or approve the plan and return a planId. A clean plan is NOT applied by this " +
    "tool — call terraform_apply with the returned planId to actually apply it. This is the " +
    "only way to get a planId: there is no way to skip scanning and go straight to apply.",
  {
    working_dir: z
      .string()
      .describe(
        "Path to the Terraform root module to plan, relative to this server's working root " +
          "(TF_WORKING_ROOT env var, default: server's startup cwd) or absolute within it."
      ),
    var_file: z
      .string()
      .optional()
      .describe("Optional .tfvars file path, relative to working_dir, passed as -var-file."),
  },
  async ({ working_dir, var_file }) => {
    let resolvedDir;
    try {
      resolvedDir = resolveWorkingDir(working_dir, WORKING_ROOT);
    } catch (error) {
      return { content: [{ type: "text", text: `Refusing to plan: ${error.message}` }], isError: true };
    }

    if (!checkTerraformInstalled()) {
      return {
        content: [
          {
            type: "text",
            text: "terraform is not installed or not on PATH. Install it with `brew install hashicorp/tap/terraform` and retry.",
          },
        ],
        isError: true,
      };
    }

    if (needsInit(resolvedDir)) {
      const init = terraformInit(resolvedDir);
      if (init.status !== 0) {
        return {
          content: [{ type: "text", text: `terraform init failed:\n${(init.stderr || init.stdout || "").slice(0, 4000)}` }],
          isError: true,
        };
      }
    }

    // `validate` runs before `plan` because it needs no cloud credentials. Schema errors — a
    // hallucinated resource type, a misspelled argument — are the most common generated-Terraform
    // defect, and without this they were only reachable in environments that could authenticate.
    // Any resource that vanished since the last scan of this directory. Advisory, not blocking —
    // deleting resources is legitimate. It's deleting them *silently while fixing something else*
    // that isn't, and that pattern is invisible in any single tool response.
    const removed = findRemovedResources(resolvedDir);
    const regressionWarning = removed.length
      ? `\n\n[REGRESSION WARNING] These resources were present the last time this directory was ` +
        `scanned and are now gone: ${removed.join(", ")}. If you removed them on purpose, ignore ` +
        `this. If they disappeared while you were fixing something else, you have deleted working ` +
        `infrastructure — restore it before continuing.`
      : "";

    let validate = terraformValidate(resolvedDir);
    // A stale .terraform directory (a module or provider added after the first init) surfaces as
    // a validation error that looks like the caller's fault. Re-initialize and retry once rather
    // than reporting a problem this server created.
    if (validate.status !== 0 && looksLikeInitRequired(validate.stdout || validate.stderr || "")) {
      const reinit = terraformInit(resolvedDir);
      if (reinit.status === 0) validate = terraformValidate(resolvedDir);
    }
    if (validate.status !== 0) {
      // Errors inside a downloaded module are not the caller's to fix. Saying "fix these schema
      // errors" when every error is in vendored code sends a caller rewriting its own files
      // forever — observed for real, ten rewrites deep, against terraform-aws-modules/eks pinned
      // incompatibly with the provider.
      const { parsed, own, vendored } = classifyValidationErrors(resolvedDir);
      const raw = (validate.stdout || validate.stderr || "").slice(0, 4000);

      if (parsed && own.length === 0 && vendored.length > 0) {
        return {
          content: [
            {
              type: "text",
              text:
                `Refusing to plan-approve: validation failed, but every error is inside a ` +
                `downloaded module under .terraform/modules — NOT in your own configuration. Do ` +
                `not rewrite your files; they are not the problem. This almost always means the ` +
                `module version and the provider version are incompatible. Pin a module release ` +
                `that supports your provider version, or constrain the provider to one the module ` +
                `supports.\n\n${vendored.slice(0, 8).join("\n")}${regressionWarning}`,
            },
          ],
          isError: true,
        };
      }

      const moduleHint = moduleArgumentHint(resolvedDir, raw);
      const detail = parsed && own.length
        ? own.slice(0, 10).join("\n") +
          (vendored.length ? `\n\n(${vendored.length} further error(s) are inside downloaded modules and are not yours to fix.)` : "")
        : raw;
      return {
        content: [
          {
            type: "text",
            text:
              `Refusing to plan-approve: the configuration is not valid Terraform. No security ` +
              `scan was performed — fix these schema errors first.\n\n${detail}${moduleHint}${regressionWarning}`,
          },
        ],
        isError: true,
      };
    }

    const tmpPlanPath = path.join(os.tmpdir(), `tfguard-${randomUUID()}.tfplan`);
    const varFileArg = var_file ? path.join(resolvedDir, var_file) : undefined;
    // Supply whatever this configuration needs in order to plan at all, and remember that we did.
    // Sixteen agent runs produced sixteen unscanned deliverables: four blocked on a required
    // variable with no value, two on the machine having no cloud account. Neither is a property of
    // the configuration -- a flawless project failed identically -- and neither was the model's to
    // fix. Real credentials and real variable values always win; this only fills genuine gaps.
    const inputs = planInputs(resolvedDir);
    const planEnv = inputs.scanOnly ? { ...process.env, ...inputs.env } : undefined;
    // Only when we supplied the credentials ourselves: a machine with a real account plans against
    // it, unmodified. The override is removed in `finally` so a throw between here and there
    // cannot leave a provider-weakening file behind in someone's repository.
    let plan;
    try {
      if (inputs.injectedCredentials) writeScanOverride(resolvedDir, inputs.providers);
      plan = terraformPlan(resolvedDir, tmpPlanPath, varFileArg, planEnv);
    } finally {
      removeScanOverride(resolvedDir);
    }
    if (plan.status !== 0 || !existsSync(tmpPlanPath)) {
      safeUnlink(tmpPlanPath);
      const output = (plan.stderr || plan.stdout || "").slice(0, 4000);
      // A credentials failure is not a clean bill of health, and it used to read like one: the
      // caller saw "plan failed", treated it as an environment problem, and moved on believing
      // nothing had been flagged — when in fact no security rule had run at all. Say so outright.
      const looksLikeCredentials =
        /credential|InvalidClientTokenId|GetCallerIdentity|AuthFailure|ExpiredToken|no valid provider/i.test(output);
      // The source scan needs no credentials, so it still produces real findings here. Without it
      // this path returned zero security signal, which is how a wide-open bucket policy sailed
      // through unnoticed in a real generated project.
      const sourceFindings = scanTerraformSources(resolvedDir);
      const preamble = looksLikeCredentials
        ? `Refusing to plan-approve: terraform plan could not authenticate to the cloud provider, ` +
          `so THE PLAN-BASED SECURITY RULES DID NOT RUN. Schema validation passed and the ` +
          `credential-free source scan did run, but this is a PARTIAL result, not a clean one. For ` +
          `a full scan, either supply working credentials, or add skip_credentials_validation, ` +
          `skip_requesting_account_id and skip_metadata_api_check to the provider block with dummy ` +
          `keys (there are no environment-variable equivalents for the first two).`
        : `Refusing to plan-approve: terraform plan failed, so the plan-based security rules did not run.`;
      const findingsText = sourceFindings.length
        ? `\n\nThe source scan DID find ${sourceFindings.length} issue(s):\n${formatRefusalMessage(sourceFindings)}`
        : `\n\nThe source scan found no issues in the patterns it can check without a plan.`;
      // Structured, like the other two exit paths, and for a specific reason: the caller used to
      // have to decide from prose whether this was "the plan could not run" or "the plan found
      // something", and the only available signal was a regex over the whole blob. A source-scan
      // finding whose text contains the word "credential" -- which every credential finding does --
      // was therefore classified as an authentication failure and demoted to advisory. A
      // hardcoded credential shipped that way in a real run while validation reported PASSED.
      // `planScanned` and `violations` answer both questions without reading the message.
      const report = {
        ok: false,
        workingDir: resolvedDir,
        planScanned: false,
        unscannableReason: looksLikeCredentials ? "provider-authentication" : "plan-failed",
        violationCount: sourceFindings.length,
        worstSeverity: sourceFindings.length ? worstSeverity(sourceFindings) : null,
        violations: sourceFindings,
        message: `${preamble}${findingsText}\n\n${output}${regressionWarning}`,
      };
      return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }], isError: true };
    }

    let planJson;
    try {
      planJson = terraformShowJson(resolvedDir, tmpPlanPath);
    } catch (error) {
      safeUnlink(tmpPlanPath);
      return { content: [{ type: "text", text: `Refusing to plan-approve: ${error.message}` }], isError: true };
    }

    const resourceChanges = planJson.resource_changes || [];
    const resourceSummary = {
      toAdd: resourceChanges.filter((r) => r.change.actions.includes("create")).length,
      toChange: resourceChanges.filter((r) => r.change.actions.includes("update")).length,
      toDestroy: resourceChanges.filter((r) => r.change.actions.includes("delete")).length,
    };

    // Source findings are merged with plan-based ones: they catch literals the plan JSON cannot
    // represent at all (a Principal inside a jsonencode() that also references an unresolved ARN
    // is absent from `after`, `after_unknown` and `configuration` alike — verified directly).
    const violations = [...evaluate(planJson, PROVIDER_PACKS), ...scanTerraformSources(resolvedDir)];

    if (violations.length > 0) {
      // Never persisted for apply — the whole enforcement guarantee rests on there being no
      // path from "scan found violations" to "a plan file exists that terraform_apply could
      // reach," not even a stale/unused one left on disk.
      safeUnlink(tmpPlanPath);
      const report = {
        ok: false,
        workingDir: resolvedDir,
        planScanned: true,
        violationCount: violations.length,
        worstSeverity: worstSeverity(violations),
        message: formatRefusalMessage(violations) + regressionWarning,
        violations,
        removedSinceLastScan: removed,
      };
      return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }], isError: true };
    }

    // A plan built on synthesized inputs is a scan result, not something to apply. Terraform
    // writes variable values INTO the plan file -- unlike credentials, which the provider
    // re-resolves at apply time -- so applying this one would deploy a database whose password is
    // literally "tfguard-scan-placeholder-01". No planId is issued, which leaves the plan->apply
    // chokepoint exactly as strict as it was while letting every rule finally run.
    if (inputs.scanOnly) {
      safeUnlink(tmpPlanPath);
      const supplied = [
        inputs.injectedVariables.length
          ? `values for ${inputs.injectedVariables.length} variable(s) with no value of their own ` +
            `(${inputs.injectedVariables.join(", ")})`
          : null,
        inputs.injectedCredentials ? "placeholder cloud credentials" : null,
      ].filter(Boolean);
      const report = {
        ok: true,
        planId: null,
        applyable: false,
        planScanned: true,
        workingDir: resolvedDir,
        resourceSummary,
        resourcesScanned: resourceChanges.length,
        removedSinceLastScan: removed,
        scanOnlyInputs: { variables: inputs.injectedVariables, credentials: inputs.injectedCredentials },
        message:
          `Scanned clean: 0 violations across ${resourceChanges.length} resource change(s). ` +
          `Every plan-based rule ran.\n\nNo planId was issued, because this plan was only ` +
          `possible after supplying ${supplied.join(" and ")}. Terraform stores variable values in ` +
          `the plan file, so applying this one would deploy those placeholders. To get an ` +
          `applyable plan, give the variables real values (terraform.tfvars, *.auto.tfvars, or ` +
          `TF_VAR_*) and make real credentials available, then plan again.` + regressionWarning,
      };
      return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
    }

    const meta = storePlan({ planFilePath: tmpPlanPath, workingDir: resolvedDir, resourceSummary });
    safeUnlink(tmpPlanPath); // storePlan copies it into the store; the tmp original is redundant now

    const report = {
      ok: true,
      planId: meta.planId,
      workingDir: resolvedDir,
      planScanned: true,
      expiresAt: meta.expiresAt,
      resourceSummary,
      resourcesScanned: resourceChanges.length,
      removedSinceLastScan: removed,
      message:
        `Plan is clean: 0 violations across ${resourceChanges.length} resource change(s). ` +
        `Call terraform_apply with planId "${meta.planId}" before ${meta.expiresAt} to apply exactly this plan.` +
        regressionWarning,
    };
    return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
  }
);

server.tool(
  "terraform_apply",
  "Apply a previously plan_id-approved Terraform plan. This tool can ONLY apply a plan that " +
    "was just scanned clean by terraform_plan and issued a planId — there is no parameter to " +
    "pass a plan file directly, no way to re-plan internally, and no way to apply anything that " +
    "wasn't scanned. A planId is single-use (consumed on this call, success or failure) and " +
    "expires after a short TTL. Terraform's own plan-file staleness check also refuses if the " +
    "working directory changed since the plan was generated, as a second layer of defense.",
  {
    plan_id: z.string().describe("planId returned by a prior clean terraform_plan call."),
    working_dir: z
      .string()
      .describe("Must match the working_dir used for the terraform_plan call that produced plan_id."),
  },
  async ({ plan_id, working_dir }) => {
    let resolvedDir;
    try {
      resolvedDir = resolveWorkingDir(working_dir, WORKING_ROOT);
    } catch (error) {
      return { content: [{ type: "text", text: `Refusing to apply: ${error.message}` }], isError: true };
    }

    const found = lookupPlan(plan_id);
    if (!found) {
      return {
        content: [
          {
            type: "text",
            text:
              `Refusing to apply: no stored plan found for planId "${plan_id}" (expired, already ` +
              `applied, or never scanned). Run terraform_plan again — a fresh plan must be scanned ` +
              `before it can be applied; there is no way to apply an unscanned or stale plan through this tool.`,
          },
        ],
        isError: true,
      };
    }

    if (found.meta.workingDir !== resolvedDir) {
      return {
        content: [
          {
            type: "text",
            text:
              `Refusing to apply: planId "${plan_id}" was scanned against "${found.meta.workingDir}", ` +
              `not "${resolvedDir}". Re-run terraform_plan against the directory you actually want to apply.`,
          },
        ],
        isError: true,
      };
    }

    // Mint short-lived apply-capable credentials, so that the ambient environment (what a raw
    // shell inherits) can stay plan/read-only. See lib/aws-credentials.mjs.
    let applyEnv;
    let scopedCredentials = false;
    let roleSessionName = null;
    if (isScopedCredentialsConfigured()) {
      try {
        const credentials = await assumeApplyRole({ planId: plan_id });
        applyEnv = buildApplyEnv(process.env, credentials);
        scopedCredentials = true;
        roleSessionName = credentials.roleSessionName;
      } catch (error) {
        // Deliberately never falls back to ambient credentials. A silent fallback would run the
        // apply at a different privilege level than configured while still reporting success —
        // the exact failure this whole mechanism exists to prevent.
        consumePlan(plan_id);
        return {
          content: [
            {
              type: "text",
              text:
                `Refusing to apply: could not assume the configured apply role ` +
                `(TFGUARD_APPLY_ROLE_ARN=${process.env.TFGUARD_APPLY_ROLE_ARN}). ${error.message}\n\n` +
                `Not falling back to ambient credentials — those are meant to be plan-only, and ` +
                `applying with them would run at a different privilege level than configured. ` +
                `Fix the role/trust policy and run terraform_plan again (this planId is now consumed).`,
            },
          ],
          isError: true,
        };
      }
    }

    const apply = terraformApply(resolvedDir, found.planFilePath, applyEnv);
    consumePlan(plan_id); // single-use regardless of outcome — no replay even if apply itself fails

    // scopedCredentials is reported on every apply — including failures — so the caller can never
    // assume a guarantee that isn't actually in force, and so a permissions-shaped failure can be
    // read against the credential mode that produced it. Reporting it only on success would hide
    // it in exactly the case where "which identity ran this?" is the first question worth asking.
    const note = scopedCredentials
      ? `\n\n[scopedCredentials: true — applied with short-lived credentials from the configured ` +
        `apply role, CloudTrail RoleSessionName "${roleSessionName}"]`
      : `\n\n[scopedCredentials: false — TFGUARD_APPLY_ROLE_ARN is not set, so this applied with ` +
        `ambient credentials. A raw \`terraform apply\` outside this server would have the same ` +
        `power. See README "Credential scoping" to close that gap.]`;

    if (apply.status !== 0) {
      return {
        content: [
          {
            type: "text",
            text: `terraform apply failed:\n${(apply.stderr || apply.stdout || "").slice(0, 4000)}${note}`,
          },
        ],
        isError: true,
      };
    }

    return { content: [{ type: "text", text: (apply.stdout || "Apply completed.") + note }] };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("terraform-guard MCP server running on stdio");
}
main().catch(console.error);

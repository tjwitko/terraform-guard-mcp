import { spawnSync } from "child_process";
import { existsSync, unlinkSync } from "fs";
import path from "path";

// No shell:true — args-array invocation only, same reasoning as dep-audit-mcp's osv-scanner
// spawn (Node flags shell:true+args as unsafe in general, DEP0190, even without a concrete
// injection path here). ENOENT surfaces as spawnSync's own .error, not a shell exit code.
export function checkTerraformInstalled() {
  const which = spawnSync("terraform", ["version"], { encoding: "utf8" });
  return !which.error;
}

export function terraformInit(cwd) {
  return spawnSync("terraform", ["init", "-input=false", "-no-color"], { cwd, encoding: "utf8" });
}

// Init for validation only. `-backend=false` skips backend configuration entirely, so a config
// naming an S3 backend it has no credentials for can still be checked — validation needs the
// provider and module schemas and nothing else. This is what makes a validate-only path cheap
// enough to call repeatedly while iterating.
export function terraformInitNoBackend(cwd) {
  return spawnSync("terraform", ["init", "-backend=false", "-input=false", "-no-color"], {
    cwd,
    encoding: "utf8",
  });
}

export function needsInit(cwd) {
  return !existsSync(path.join(cwd, ".terraform"));
}

// `.terraform` existing is not the same as `.terraform` being current. Adding a module or
// provider after the first init leaves the directory in place but the new dependency
// uninstalled, and every subsequent validate/plan fails with an init-required error.
//
// This is not hypothetical: a real agent run hit "Module not installed" here, read it as a defect
// in its own configuration, and rewrote the file twice more trying to fix a problem this server
// had manufactured — deleting working resources in the process. Detect Terraform's own signal and
// re-initialize instead of blaming the caller's code.
const INIT_REQUIRED_RE =
  /Module not installed|Missing required provider|required providers? .*not installed|please run "?terraform init|run:? "?terraform init/i;

export function looksLikeInitRequired(output) {
  return INIT_REQUIRED_RE.test(output || "");
}

// `validate` needs no cloud credentials — it checks the configuration against the provider
// schemas already downloaded by `init`. That matters because `plan` requires working credentials
// for most providers, so without this a credential-less environment gets no signal at all.
export function terraformValidate(cwd) {
  return spawnSync("terraform", ["validate", "-no-color"], { cwd, encoding: "utf8" });
}

// Splits validation errors by whose file they are in. A third-party module downloaded into
// .terraform/modules can be incompatible with the selected provider version, and its errors are
// not the caller's to fix.
//
// This is not hypothetical: a real agent run pinned terraform-aws-modules/eks against AWS provider
// 6.x, got told "the configuration is not valid Terraform — fix these schema errors first", and
// rewrote its own main.tf ten times chasing errors inside a vendored file it never wrote. Telling
// someone to fix code they do not own is worse than saying nothing.
export function classifyValidationErrors(cwd) {
  const r = spawnSync("terraform", ["validate", "-json"], { cwd, encoding: "utf8" });
  let parsed;
  try {
    parsed = JSON.parse(r.stdout || "{}");
  } catch {
    return { parsed: false, own: [], vendored: [] };
  }
  const own = [];
  const vendored = [];
  for (const d of parsed.diagnostics || []) {
    if (d.severity !== "error") continue;
    const file = d.range?.filename || "";
    const line = `${file}${d.range?.start?.line ? `:${d.range.start.line}` : ""} — ${d.summary}${d.detail ? `: ${d.detail}` : ""}`;
    (file.includes(`.terraform${path.sep}modules`) || file.includes(".terraform/modules") ? vendored : own).push(line);
  }
  return { parsed: true, own, vendored };
}

// `env`, when given, fully replaces the child environment (callers build it from process.env plus
// their additions). Used to supply scan-only variable values and placeholder credentials so the
// rule engine has a plan to evaluate on a machine with no cloud account -- see lib/plan-inputs.mjs
// for why a plan produced that way must never be stored for apply.
export function terraformPlan(cwd, planFilePath, varFile, env) {
  const args = ["plan", "-input=false", "-no-color", `-out=${planFilePath}`];
  if (varFile) args.push(`-var-file=${varFile}`);
  return spawnSync("terraform", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
    ...(env ? { env } : {}),
  });
}

export function terraformShowJson(cwd, planFilePath) {
  const result = spawnSync("terraform", ["show", "-json", planFilePath], {
    cwd,
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`terraform show -json failed: ${result.stderr || result.stdout}`);
  }
  return JSON.parse(result.stdout);
}

// Builds the environment for a credential-scoped apply. Pure and exported so the AWS_PROFILE
// behaviour below can be unit-tested without spawning anything.
//
// Deleting AWS_PROFILE / AWS_DEFAULT_PROFILE is the non-obvious part and the reason this is a
// named function rather than an inline spread: a profile set in the ambient environment takes
// precedence in the AWS credential chain and would silently override the injected static
// credentials. The failure mode is nasty — the apply would run under the ambient (plan-only)
// identity and fail with a confusing AccessDenied, or under some other profile entirely, while
// this server reported that it had scoped the credentials.
export function buildApplyEnv(baseEnv, credentials) {
  const env = { ...baseEnv };
  env.AWS_ACCESS_KEY_ID = credentials.accessKeyId;
  env.AWS_SECRET_ACCESS_KEY = credentials.secretAccessKey;
  env.AWS_SESSION_TOKEN = credentials.sessionToken;
  delete env.AWS_PROFILE;
  delete env.AWS_DEFAULT_PROFILE;
  return env;
}

// `env` omitted => inherit this process's environment, i.e. the pre-credential-scoping
// behaviour, which is still the correct path when no apply role is configured.
export function terraformApply(cwd, planFilePath, env) {
  return spawnSync("terraform", ["apply", "-input=false", "-no-color", planFilePath], {
    cwd,
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
    ...(env ? { env } : {}),
  });
}

export function safeUnlink(filePath) {
  try {
    if (existsSync(filePath)) unlinkSync(filePath);
  } catch {
    // best-effort cleanup of a temp/scanned plan file — a leftover file here is a disk-space
    // nit, not a correctness or security issue, so a failed unlink shouldn't fail the caller
  }
}

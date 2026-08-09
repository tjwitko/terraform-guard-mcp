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

export function needsInit(cwd) {
  return !existsSync(path.join(cwd, ".terraform"));
}

// `validate` needs no cloud credentials — it checks the configuration against the provider
// schemas already downloaded by `init`. That matters because `plan` requires working credentials
// for most providers, so without this a credential-less environment gets no signal at all.
export function terraformValidate(cwd) {
  return spawnSync("terraform", ["validate", "-no-color"], { cwd, encoding: "utf8" });
}

export function terraformPlan(cwd, planFilePath, varFile) {
  const args = ["plan", "-input=false", "-no-color", `-out=${planFilePath}`];
  if (varFile) args.push(`-var-file=${varFile}`);
  return spawnSync("terraform", args, { cwd, encoding: "utf8", maxBuffer: 50 * 1024 * 1024 });
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

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

export function terraformApply(cwd, planFilePath) {
  return spawnSync("terraform", ["apply", "-input=false", "-no-color", planFilePath], {
    cwd,
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
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

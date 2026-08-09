import { randomUUID } from "crypto";
import { mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, copyFileSync } from "fs";
import path from "path";

// This file is the enforcement-critical piece of the whole server: terraform_apply can ONLY
// apply a plan file it looks up here by id, never one passed to it directly. That's what makes
// "block insecure applies" a real guarantee rather than an advisory check the LLM could route
// around by re-planning and applying without asking for another scan.
//
// Same base-directory convention as local-delegate-mcp's ledger — ~/Library/Application
// Support/<server-name>/ — not repo-relative or /tmp, so an approved-but-unapplied plan
// survives independently of any one working directory and is never accidentally git-tracked.
const STORE_DIR = path.join(
  process.env.HOME || "/tmp",
  "Library",
  "Application Support",
  "terraform-guard-mcp",
  "plans"
);

const DEFAULT_TTL_SECONDS = 15 * 60;

function ttlSeconds() {
  const raw = Number(process.env.TF_PLAN_TTL_SECONDS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TTL_SECONDS;
}

function entryDir(planId) {
  return path.join(STORE_DIR, planId);
}

// On-disk, not in-memory: an MCP stdio server isn't guaranteed to stay alive across an entire
// client session, and losing an approved-but-unapplied plan on a restart would silently force a
// confusing re-plan, not just be an inconvenience.
//
// No background timer — a lazy sweep (delete anything expired) runs at the start of every
// store()/lookup() call instead, matching both sibling servers, neither of which runs one.
function sweepExpired() {
  if (!existsSync(STORE_DIR)) return;
  const now = Date.now();
  for (const id of readdirSync(STORE_DIR)) {
    const metaPath = path.join(entryDir(id), "meta.json");
    if (!existsSync(metaPath)) continue;
    try {
      const meta = JSON.parse(readFileSync(metaPath, "utf8"));
      if (new Date(meta.expiresAt).getTime() <= now) {
        rmSync(entryDir(id), { recursive: true, force: true });
      }
    } catch {
      // an unreadable meta.json means this entry is unusable either way — remove it rather
      // than leaving an orphaned directory that sweepExpired trips over on every future call
      rmSync(entryDir(id), { recursive: true, force: true });
    }
  }
}

export function storePlan({ planFilePath, workingDir, resourceSummary }) {
  sweepExpired();
  mkdirSync(STORE_DIR, { recursive: true });

  const planId = randomUUID();
  const dir = entryDir(planId);
  mkdirSync(dir, { recursive: true });

  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + ttlSeconds() * 1000);

  copyFileSync(planFilePath, path.join(dir, "plan.tfplan"));
  const meta = {
    planId,
    workingDir,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    resourceSummary,
  };
  writeFileSync(path.join(dir, "meta.json"), JSON.stringify(meta, null, 2));

  return meta;
}

// Returns { meta, planFilePath } or null if the id doesn't exist, is expired, or was already
// consumed. Does NOT delete the entry — that's consumePlan()'s job, called only after apply
// actually runs, so a lookup alone (e.g. for a future "inspect this plan" tool) stays read-only.
export function lookupPlan(planId) {
  sweepExpired();
  const dir = entryDir(planId);
  const metaPath = path.join(dir, "meta.json");
  const planFilePath = path.join(dir, "plan.tfplan");
  if (!existsSync(metaPath) || !existsSync(planFilePath)) return null;

  const meta = JSON.parse(readFileSync(metaPath, "utf8"));
  if (new Date(meta.expiresAt).getTime() <= Date.now()) {
    rmSync(dir, { recursive: true, force: true });
    return null;
  }
  return { meta, planFilePath };
}

// Single-use: called after terraform_apply resolves (success OR failure) so a plan_id can never
// be replayed, regardless of how much TTL remained.
export function consumePlan(planId) {
  rmSync(entryDir(planId), { recursive: true, force: true });
}

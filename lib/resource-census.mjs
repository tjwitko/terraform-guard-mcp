import { createHash } from "crypto";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "fs";
import { terraformFilesUnder } from "./source-scan.mjs";
import path from "path";

// Tracks which resources a configuration declared last time it was scanned, so that a rewrite
// which silently drops resources can be called out.
//
// Motivation, from a real agent run: a model hit a validation error, rewrote main.tf three times
// trying to satisfy the tool, and in the process deleted the S3 bucket and Object Lock
// configuration — the entire point of the project — without ever mentioning it. Each individual
// response looked like a reasonable fix. Only the trajectory revealed the regression, and nothing
// in the tooling was watching the trajectory.
//
// Deliberately advisory rather than blocking: removing resources is a legitimate thing to do.
// What matters is that it never happens *silently*.

const CENSUS_DIR = path.join(
  process.env.HOME || "/tmp",
  "Library",
  "Application Support",
  "terraform-guard-mcp",
  "census"
);

// Matches `resource "aws_s3_bucket" "logs" {` — enough to identify what a configuration declares
// without parsing HCL properly. Module blocks count too, since swapping a module for inline
// resources (or losing one) is exactly the pattern this exists to notice.
const RESOURCE_RE = /(?:^|\s)resource\s+"([^"]+)"\s+"([^"]+)"/g;
const MODULE_RE = /(?:^|\s)module\s+"([^"]+)"/g;

function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)(#|\/\/).*$/gm, "$1");
}

export function censusOf(dir) {
  const found = new Set();
  if (!existsSync(dir)) return found;
  // Descends into child modules, sharing source-scan's walk so the two cannot disagree about what
  // counts as part of a configuration. Without this the census could not see a resource declared in
  // modules/*, which is the layout Terraform documents -- so a model deleting the one bucket the
  // project exists for would go unreported precisely when the project was structured conventionally.
  // The walk skips .terraform, so vendored modules never enter the baseline.
  const files = terraformFilesUnder(dir).filter((f) => f.endsWith(".tf"));
  for (const file of files) {
    let raw;
    try {
      raw = readFileSync(path.join(dir, file), "utf8");
    } catch {
      continue;
    }
    const source = stripComments(raw);
    RESOURCE_RE.lastIndex = 0;
    let m;
    while ((m = RESOURCE_RE.exec(source))) found.add(`${m[1]}.${m[2]}`);
    MODULE_RE.lastIndex = 0;
    while ((m = MODULE_RE.exec(source))) found.add(`module.${m[1]}`);
  }
  return found;
}

function censusPath(dir) {
  return path.join(CENSUS_DIR, `${createHash("sha256").update(dir).digest("hex").slice(0, 16)}.json`);
}

function readRecord(dir) {
  const file = censusPath(dir);
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

export function loadPreviousCensus(dir) {
  const record = readRecord(dir);
  return record ? new Set(record.resources || []) : null;
}

function writeRecord(dir, census, pending) {
  try {
    mkdirSync(CENSUS_DIR, { recursive: true });
    writeFileSync(
      censusPath(dir),
      JSON.stringify(
        { dir, savedAt: new Date().toISOString(), resources: [...census], pendingRemovals: [...pending] },
        null,
        2
      )
    );
  } catch {
    // Census tracking must never fail a scan by failing to persist.
  }
}

export function saveCensus(dir, census) {
  writeRecord(dir, census, pendingRemovals(dir));
}

// Removals seen since they were last acknowledged, without disturbing anything.
//
// This exists because the warning used to erase its own evidence. findRemovedResources saves the
// new census on every call, so the sequence was: call 1 diffs [3 resources] against [0], warns,
// and stores [0]; call 2 diffs [0] against [0] and says nothing. The warning fired exactly once,
// inside one tool response, and by the time anyone asked "did the guardrail fire?" the only
// surviving state said no resources had ever existed. Verified against a real run: fourteen
// terraform_plan calls, three deleted resources, and no way to establish after the fact whether
// it had fired at all.
export function pendingRemovals(dir) {
  const record = readRecord(dir);
  return new Set(record?.pendingRemovals || []);
}

// Cleared deliberately, by a human or a test. Not exposed as a tool: a run that can dismiss its
// own regression warning is back to deleting infrastructure silently.
export function clearPendingRemovals(dir) {
  writeRecord(dir, censusOf(dir), new Set());
}

// Returns the addresses present last time but gone now, or [] when there's no prior record.
// Removals accumulate into pendingRemovals so a later check can still see them.
export function findRemovedResources(dir) {
  const previous = loadPreviousCensus(dir);
  const current = censusOf(dir);
  const pending = pendingRemovals(dir);
  const removed = previous ? [...previous].filter((address) => !current.has(address)) : [];

  for (const address of removed) pending.add(address);
  // A resource that came back is no longer missing, whatever happened in between.
  for (const address of [...pending]) if (current.has(address)) pending.delete(address);

  writeRecord(dir, current, pending);
  return removed;
}

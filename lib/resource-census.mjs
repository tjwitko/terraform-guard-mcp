import { createHash } from "crypto";
import { readFileSync, readdirSync, existsSync, mkdirSync, writeFileSync } from "fs";
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
  let files;
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".tf"));
  } catch {
    return found;
  }
  for (const file of files) {
    const source = stripComments(readFileSync(path.join(dir, file), "utf8"));
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

export function loadPreviousCensus(dir) {
  const file = censusPath(dir);
  if (!existsSync(file)) return null;
  try {
    return new Set(JSON.parse(readFileSync(file, "utf8")).resources || []);
  } catch {
    return null;
  }
}

export function saveCensus(dir, census) {
  try {
    mkdirSync(CENSUS_DIR, { recursive: true });
    writeFileSync(censusPath(dir), JSON.stringify({ dir, savedAt: new Date().toISOString(), resources: [...census] }, null, 2));
  } catch {
    // Census tracking is advisory; failing to persist it must never fail a scan.
  }
}

// Returns the addresses present last time but gone now, or [] when there's no prior record.
export function findRemovedResources(dir) {
  const previous = loadPreviousCensus(dir);
  const current = censusOf(dir);
  saveCensus(dir, current);
  if (!previous) return [];
  return [...previous].filter((address) => !current.has(address));
}

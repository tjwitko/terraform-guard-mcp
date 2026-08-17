// Reads the real argument list of an installed Terraform module, so an "Unsupported argument"
// error can name the arguments that ARE accepted instead of leaving the caller to guess.
//
// Why this exists: three consecutive agent runs failed on exactly this, against the same module.
// `node_groups` vs `eks_managed_node_groups`, then `cluster_arn`, then `cluster_subnet_ids` —
// each a plausible-sounding name recalled rather than looked up, each costing a validation round
// to discover and often several more to guess again. A model has no reliable sense of when its
// own knowledge of a versioned interface is stale, and giving it internet access to check is the
// wrong fix (see local-delegate-mcp's CLAUDE.md on why the local model must not fetch).
//
// It does not need to be. `terraform init` downloads the module's complete source into
// .terraform/modules, so the pinned version's authoritative interface is already sitting on disk
// next to the configuration. This reads it from there: no network, no recall, no guessing — the
// same reason this server reads `terraform show -json` instead of parsing HCL.
import { readFileSync, existsSync } from "fs";
import path from "path";

function installedModules(dir) {
  const manifest = path.join(dir, ".terraform", "modules", "modules.json");
  if (!existsSync(manifest)) return [];
  try {
    const parsed = JSON.parse(readFileSync(manifest, "utf8"));
    // Sub-modules carry a dotted Key ("eks.fargate_profile"); only the top-level ones correspond
    // to a `module "x"` block the caller actually wrote.
    return (parsed.Modules || []).filter((m) => m.Key && !m.Key.includes("."));
  } catch {
    return [];
  }
}

// Every variables.tf-style declaration in the module root. Terraform allows variables in any .tf
// file, but the convention is universal enough that scanning the root's variables.tf plus main.tf
// covers real modules; a miss here degrades to "no hint", never to a wrong hint.
function declaredVariables(moduleDir) {
  const names = new Set();
  for (const file of ["variables.tf", "main.tf"]) {
    const full = path.join(moduleDir, file);
    if (!existsSync(full)) continue;
    try {
      for (const m of readFileSync(full, "utf8").matchAll(/^variable\s+"([^"]+)"/gm)) names.add(m[1]);
    } catch {
      /* unreadable module file — no hint rather than a wrong one */
    }
  }
  return [...names].sort();
}

// Cheap edit distance, only ever run over one module's variable list against a handful of
// rejected names. Good enough to turn "cluster_subnet_ids" into "did you mean subnet_ids?".
function distance(a, b) {
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let carry = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const next = Math.min(prev[j] + 1, prev[j - 1] + 1, carry + (a[i - 1] === b[j - 1] ? 0 : 1));
      carry = prev[j];
      prev[j] = next;
    }
  }
  return prev[b.length];
}

function nearest(name, candidates) {
  let best = null;
  let bestScore = Infinity;
  for (const c of candidates) {
    const d = distance(name.toLowerCase(), c.toLowerCase());
    if (d < bestScore) {
      bestScore = d;
      best = c;
    }
  }
  // Only offer a suggestion that is genuinely close; an unrelated nearest match is worse than
  // none, because it reads as authoritative.
  return bestScore <= Math.max(3, Math.floor(name.length / 3)) ? best : null;
}

export function rejectedArgumentNames(validateOutput) {
  return [...new Set([...String(validateOutput).matchAll(/An argument named "([^"]+)" is not expected here/g)].map((m) => m[1]))];
}

/**
 * Given a working directory and Terraform's validation output, returns a human-readable note
 * listing what the installed modules really accept — or "" when there is nothing useful to add.
 */
export function moduleArgumentHint(dir, validateOutput) {
  const rejected = rejectedArgumentNames(validateOutput);
  if (rejected.length === 0) return "";

  const modules = installedModules(dir);
  if (modules.length === 0) return "";

  const sections = [];
  for (const mod of modules) {
    const names = declaredVariables(path.join(dir, mod.Dir));
    if (names.length === 0) continue;

    // Only report a module that actually rejects one of these names; otherwise every unrelated
    // module in the configuration would be dumped into the error.
    const relevant = rejected.filter((r) => !names.includes(r));
    if (relevant.length === 0) continue;

    const suggestions = relevant
      .map((r) => {
        const near = nearest(r, names);
        return near ? `  "${r}" is not accepted — did you mean "${near}"?` : `  "${r}" is not accepted.`;
      })
      .join("\n");

    sections.push(
      `module "${mod.Key}" (${mod.Source}) accepts these arguments:\n` +
        `  ${names.join(", ")}\n${suggestions}`
    );
  }

  if (sections.length === 0) return "";
  return (
    `\n\nThe argument list below was read from the module source that \`terraform init\` installed ` +
    `under .terraform/modules — it is the pinned version's real interface, not a guess. Use these ` +
    `names rather than recalling them.\n\n${sections.join("\n\n")}`
  );
}

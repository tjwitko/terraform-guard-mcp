import { readFileSync, readdirSync, existsSync } from "fs";
import path from "path";

// A narrow source-text scan for dangerous literals that are STRUCTURALLY INVISIBLE in
// `terraform show -json`.
//
// Why this exists rather than being a normal engine rule: a policy built with
// jsonencode({... Principal = {AWS = "arn:aws:iam::*:role/x"} ...}) that also interpolates a
// not-yet-created resource ARN is unknown at plan time. Verified directly against real plan
// output — `after.policy` is null, `after_unknown.policy` is true, and the `configuration`
// section records only the expression's *references*, never the literal text. The Principal
// simply is not present in the plan JSON in any form. Since a bucket policy nearly always
// references its own bucket's ARN, that is the common case, not an edge case.
//
// Deliberately kept to a handful of unambiguous literal patterns rather than becoming an HCL
// parser: this is a safety net for things the real engine cannot see, not a second rule system.
// It also runs without cloud credentials, so it is the only security signal available when
// `terraform plan` cannot authenticate.

function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)(#|\/\/).*$/gm, "$1");
}

// arn:PARTITION:SERVICE:REGION:ACCOUNT:RESOURCE — a "*" in the ACCOUNT field means any AWS
// account on earth. Note arn:aws:iam::aws:policy/... has the literal string "aws" in that field
// (AWS-managed policies) and must not be confused for a wildcard.
function arnHasAccountWildcard(arn) {
  const parts = arn.split(":");
  return parts.length >= 6 && parts[4].includes("*");
}

const ARN_RE = /arn:aws[\w-]*:[^"'\s,}\]]*/g;
// Principal = "*"  |  Principal = { AWS = "*" }  |  "Principal": {"AWS": "*"}
const PRINCIPAL_STAR_RE = /"?Principal"?\s*[:=]\s*(\{[^}]*\}|"\*")/g;

// A wildcard inside a Deny statement restricts access rather than granting it —
// `Effect = "Deny", Principal = "*"` on s3:DeleteObject is a hardening pattern, and flagging it
// as critical is a false positive on correct code. Caught by running this scanner against a
// deliberately well-written configuration; a security tool that cries wolf on good practice is
// worse than no tool, because people switch it off.
//
// The plan-based rule in rules/aws.mjs already skips Deny by reading parsed JSON. This scanner
// works on raw text, so it has to find the enclosing statement block itself: walk backwards to
// the opening brace of the object containing the match, forward to its close, and look for the
// Effect inside that span.
function enclosingStatementIsDeny(source, index) {
  let depth = 0;
  let start = -1;
  for (let i = index; i >= 0; i--) {
    const ch = source[i];
    if (ch === "}") depth++;
    else if (ch === "{") {
      if (depth === 0) {
        start = i;
        break;
      }
      depth--;
    }
  }
  if (start === -1) return false;

  depth = 1;
  let end = source.length;
  for (let i = start + 1; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  return /"?Effect"?\s*[:=]\s*"Deny"/i.test(source.slice(start, end));
}

export function scanTerraformSources(dir) {
  const violations = [];
  if (!existsSync(dir)) return violations;

  let files;
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".tf"));
  } catch {
    return violations;
  }

  for (const file of files) {
    const source = stripComments(readFileSync(path.join(dir, file), "utf8"));

    const seen = new Set();
    for (const match of source.match(ARN_RE) || []) {
      if (!arnHasAccountWildcard(match) || seen.has(match)) continue;
      if (enclosingStatementIsDeny(source, source.indexOf(match))) continue;
      seen.add(match);
      violations.push({
        ruleId: "aws.iam.principal-account-wildcard",
        severity: "critical",
        category: "iam.public-principal",
        provider: "aws",
        resourceAddress: `${file} (source scan)`,
        resourceType: null,
        attribute: null,
        actualValue: match,
        message:
          `"${match}" has a wildcard in the ARN's ACCOUNT field, granting access to that ` +
          `resource name in ANY AWS account rather than only yours`,
        remediation: "replace the wildcard account with your own account id, or reference the role resource directly",
      });
    }

    PRINCIPAL_STAR_RE.lastIndex = 0;
    let m;
    while ((m = PRINCIPAL_STAR_RE.exec(source))) {
      if (!/"\*"/.test(m[1])) continue;
      if (enclosingStatementIsDeny(source, m.index)) continue;
      violations.push({
        ruleId: "aws.iam.principal-wildcard",
        severity: "critical",
        category: "iam.public-principal",
        provider: "aws",
        resourceAddress: `${file} (source scan)`,
        resourceType: null,
        attribute: "Principal",
        actualValue: "*",
        message: 'a policy in this file grants access to Principal "*" (anyone, unauthenticated)',
        remediation: "scope the Principal to the specific roles or accounts that need access",
      });
    }
  }

  return violations;
}

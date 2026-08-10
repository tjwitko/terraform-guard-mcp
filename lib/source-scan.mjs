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

// Credential attributes that take a literal secret in a provider block. Cross-cloud on purpose:
// `access_key`/`secret_key`/`token` (aws), `client_secret`/`client_certificate_password`
// (azurerm), `access_token` (google), `password`/`private_key` (kubernetes, postgresql, and
// friends). `credentials` (google) is handled separately since it legitimately takes a *file
// path* as well as inline JSON.
const CREDENTIAL_ATTRS = [
  "access_key",
  "secret_key",
  "token",
  "access_token",
  "client_secret",
  "client_certificate_password",
  "password",
  "private_key",
];

const PROVIDER_BLOCK_RE = /provider\s+"([\w-]+)"\s*\{/g;

// A real AWS access key id. Deliberately NOT the only trigger — the case this rule was written
// for used "AKIA_DUMMY_ACCESS_KEY", which fails this pattern — but it is what overrides the
// local-emulator exemption below.
const REAL_AWS_KEY_ID_RE = /^(AKIA|ASIA)[A-Z0-9]{16}$/;

// Hardcoding minioadmin/minioadmin against a container on 127.0.0.1 is not a leaked cloud
// credential, and this repo's own aws-secure fixture does exactly that in order to run a real
// `terraform apply` end-to-end without an AWS account. Flagging it would make the scanner fail on
// the configuration written to prove the scanner works.
//
// The exemption is scoped to the provider block that declares the local endpoint, and it does not
// apply to a value that is a syntactically real AWS key id — otherwise adding an `endpoints`
// block would launder a genuine credential.
const LOCAL_ENDPOINT_RE =
  /endpoints\s*\{[^}]*(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|minio)/i;

function blockBodyAt(source, openBraceIndex) {
  let depth = 1;
  for (let i = openBraceIndex + 1; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return source.slice(openBraceIndex + 1, i);
    }
  }
  return source.slice(openBraceIndex + 1);
}

// `credentials` in the google provider takes either the JSON key material itself or a path to a
// file holding it. A path is normal practice; the key material is a service-account private key
// pasted into version control.
function isInlineServiceAccountJson(value) {
  return /"?(private_key|private_key_id)"?\s*:/.test(value) || value.trim().startsWith("{");
}

export function scanProviderCredentials(source, file) {
  const violations = [];
  PROVIDER_BLOCK_RE.lastIndex = 0;
  let block;
  while ((block = PROVIDER_BLOCK_RE.exec(source))) {
    const providerName = block[1];
    const body = blockBodyAt(source, PROVIDER_BLOCK_RE.lastIndex - 1);
    const localEmulator = LOCAL_ENDPOINT_RE.test(body);

    const attrRe = new RegExp(
      `(^|[\\s{])(${[...CREDENTIAL_ATTRS, "credentials"].join("|")})\\s*=\\s*"([^"]*)"`,
      "gm"
    );
    let m;
    while ((m = attrRe.exec(body))) {
      const [, , attr, value] = m;
      // An interpolation is a reference to a variable or another resource, not a literal.
      if (value === "" || value.includes("${")) continue;
      if (attr === "credentials" && !isInlineServiceAccountJson(value)) continue;
      if (localEmulator && !REAL_AWS_KEY_ID_RE.test(value)) continue;

      violations.push({
        ruleId: "provider.hardcoded-credentials",
        severity: "critical",
        category: "secrets.hardcoded-credentials",
        provider: providerName,
        resourceAddress: `${file} (source scan)`,
        resourceType: null,
        attribute: attr,
        actualValue: "<redacted>",
        message:
          `provider "${providerName}" sets ${attr} to a literal value in source. A credential in ` +
          `a .tf file is committed to version control, and hardcoding one is also how a ` +
          `configuration that cannot actually deploy still produces a clean plan`,
        remediation:
          "remove the attribute and let the provider resolve credentials from the environment " +
          "(env vars, ~/.aws, SSO, IMDS, workload identity), or pass it through a variable " +
          "sourced from a secret store",
      });
    }
  }
  return violations;
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

    violations.push(...scanProviderCredentials(source, file));
  }

  return violations;
}

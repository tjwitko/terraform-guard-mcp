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

// Google Cloud's two public principals. Verified against Google's IAM principal-identifiers
// documentation rather than recalled: `allUsers` is "anyone who is on the internet, including
// authenticated and unauthenticated users", and `allAuthenticatedUsers` is anyone with a Google
// account — explicitly including personal Gmail accounts unconnected to the organization. The
// second one is the trap: it reads like a restriction and is public in every sense that matters.
// These are the direct analogue of Principal = "*" in an AWS policy, and they are unambiguous —
// neither string means anything else in Google Cloud configuration.
const GOOGLE_PUBLIC_MEMBER_RE = /"(allUsers|allAuthenticatedUsers)"/g;

// Google's deny policies list the same principals in order to *restrict* them, so a match inside
// `denied_principals` grants nothing. Same false-positive shape as an AWS Deny statement, and the
// same reasoning applies: a scanner that flags correct hardening gets switched off. Walks back to
// the nearest attribute name rather than parsing HCL, which is all this text-level scan can do.
function insideDeniedPrincipals(source, index) {
  const before = source.slice(Math.max(0, index - 400), index);
  const lastAttr = [...before.matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[?/g)].pop();
  return Boolean(lastAttr && /^denied_principals$/.test(lastAttr[1]));
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

// Values that are recognizably real credential material, whatever cloud issued them. Deliberately
// NOT the only trigger for the rule — the case it was written for used "AKIA_DUMMY_ACCESS_KEY",
// which matches none of these — but it is what overrides the local-emulator exemption below.
//
// Cross-cloud on purpose. This was a single AWS access-key-id pattern, which meant a GCP
// service-account key or a PEM private key pasted into a provider block that happened to declare
// a localhost endpoint was exempted: the exemption is keyed on AWS `endpoints {}` syntax, but the
// value it was laundering did not have to be an AWS credential.
const REAL_AWS_KEY_ID_RE = /^(AKIA|ASIA)[A-Z0-9]{16}$/;
const GOOGLE_API_KEY_RE = /^AIza[0-9A-Za-z_-]{35}$/;
const PEM_PRIVATE_KEY_RE = /-----BEGIN[ A-Z]*PRIVATE KEY-----/;

function looksLikeRealCredential(value) {
  return (
    REAL_AWS_KEY_ID_RE.test(value) ||
    GOOGLE_API_KEY_RE.test(value) ||
    PEM_PRIVATE_KEY_RE.test(value) ||
    isInlineServiceAccountJson(value)
  );
}

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

export function blockBodyAt(source, openBraceIndex) {
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
      if (localEmulator && !looksLikeRealCredential(value)) continue;

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

// A credential-shaped `variable` with a literal default. Found in a real generated project:
//
//   variable "db_password" { type = string, default = "SecurePassword123!" }
//
// It fell through all three scanners in this workspace. gitleaks does not match a generic
// password with no structured prefix; scanProviderCredentials only reads provider blocks; and
// identity-guard does not read .tf files at all. The value was in the repository and, because a
// default means `terraform apply` never prompts, it was the credential the deployment would
// actually use rather than a placeholder.
//
// That last point is why the value's realism is not considered: "changeme" as a default deploys
// exactly as readily as a strong-looking string. The mechanism is the finding — the same call
// identity-guard's connection-string rule makes about placeholder DSNs.
const VARIABLE_BLOCK_RE = /(?:^|\n)\s*variable\s+"([^"]+)"\s*\{/g;

// Names that read as credential material. Deliberately narrow: a rule that fires on every
// variable with "key" in its name produces findings nobody trusts.
const CREDENTIAL_VAR_RE =
  /(password|passwd|^pwd$|_pwd$|secret|token|credential|passphrase|private_key|access_key|api_?key)/i;

// Names that merely reference a credential rather than carrying one. `kms_key_id`, `secret_arn`
// and `key_name` are identifiers; a public key is public. Checked before the match above, since
// several of these contain the words it looks for.
const NOT_A_CREDENTIAL_RE = /(public_key|_arn$|_id$|_name$|_names$|key_pair|rotation|enabled|^kms_key$)/i;

export function scanVariableDefaults(source, file) {
  const violations = [];
  VARIABLE_BLOCK_RE.lastIndex = 0;
  let match;
  while ((match = VARIABLE_BLOCK_RE.exec(source))) {
    const name = match[1];
    if (NOT_A_CREDENTIAL_RE.test(name) || !CREDENTIAL_VAR_RE.test(name)) continue;

    const body = blockBodyAt(source, VARIABLE_BLOCK_RE.lastIndex - 1);
    const def = /(^|[\s{])default\s*=\s*"([^"]*)"/m.exec(body);
    // No default is the correct pattern — apply prompts, or CI supplies it. Nothing to report.
    if (!def) continue;
    const value = def[2];
    // Empty defaults and interpolations are not literal credentials.
    if (value === "" || value.includes("${")) continue;

    violations.push({
      ruleId: "variable.credential-default",
      severity: "critical",
      category: "secrets.hardcoded-credentials",
      provider: null,
      resourceAddress: `${file} (source scan)`,
      resourceType: null,
      attribute: `variable.${name}.default`,
      actualValue: "<redacted>",
      message:
        `variable "${name}" carries a literal default. Because a default is supplied without ` +
        `prompting, this is the value the deployment uses — not a placeholder — and it is ` +
        `committed to version control and written to Terraform state in plaintext`,
      remediation:
        `remove the default so a missing value fails loudly, and add sensitive = true so the ` +
        `value is kept out of Terraform's own output. Better still, do not pass a credential at ` +
        `all: use IAM/OIDC authentication so the workload proves an identity instead of holding ` +
        `a secret.`,
    });
  }
  return violations;
}

// A credential assigned in a .tfvars file. Found immediately after the variable-default rule
// shipped: the generated project moved its `variables.tf` to the correct shape — `sensitive = true`,
// no default — and put the actual secret in `terraform.tfvars` instead. Every scanner in this
// workspace returned zero, for three independent reasons: scanTerraformSources filtered to `.tf`
// so the file was never opened, the variable rule only inspects `variable "x" {}` blocks rather
// than assignments, and gitleaks does not match a generic password.
//
// .tfvars is committed by default — it is not gitignored by `terraform init`, and Terraform's own
// docs tell you to keep secrets out of it precisely because people do not.
const TFVARS_ASSIGNMENT_RE = /(?:^|\n)\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"([^"]*)"/g;

export function scanTfvarsAssignments(source, file) {
  const violations = [];
  TFVARS_ASSIGNMENT_RE.lastIndex = 0;
  let match;
  while ((match = TFVARS_ASSIGNMENT_RE.exec(source))) {
    const [, name, value] = match;
    // Same notion of "credential-shaped" as the variable-default rule, deliberately shared: two
    // definitions would drift, and a name excluded in one place must be excluded in both.
    if (NOT_A_CREDENTIAL_RE.test(name) || !CREDENTIAL_VAR_RE.test(name)) continue;
    if (value === "" || value.includes("${")) continue;

    violations.push({
      ruleId: "tfvars.credential-value",
      severity: "critical",
      category: "secrets.hardcoded-credentials",
      provider: null,
      resourceType: null,
      resourceAddress: `${file} (source scan)`,
      attribute: name,
      actualValue: "<redacted>",
      message:
        `${file} assigns a value to "${name}". .tfvars files are committed by default, so this ` +
        `is a credential in version control — and it is the value the deployment uses, whether or ` +
        `not it looks like a placeholder`,
      remediation:
        `remove the assignment and supply the value at apply time (TF_VAR_${name}, a secret store, ` +
        `or a CI variable). Note that adding *.tfvars to .gitignore afterwards fixes nothing on ` +
        `its own: an ignore rule does not untrack a file git is already tracking, and does not ` +
        `remove the value from history — use \`git rm --cached\` and rotate the credential.`,
    });
  }
  return violations;
}

export function scanTerraformSources(dir) {
  const violations = [];
  if (!existsSync(dir)) return violations;

  let files;
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".tf") || f.endsWith(".tfvars"));
  } catch {
    return violations;
  }

  for (const file of files) {
    const source = stripComments(readFileSync(path.join(dir, file), "utf8"));

    // .tfvars holds values, not configuration: there are no provider blocks, resources or policy
    // documents in it, so only the credential-assignment rule applies.
    if (file.endsWith(".tfvars")) {
      violations.push(...scanTfvarsAssignments(source, file));
      continue;
    }

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

    GOOGLE_PUBLIC_MEMBER_RE.lastIndex = 0;
    let g;
    const seenPublic = new Set();
    while ((g = GOOGLE_PUBLIC_MEMBER_RE.exec(source))) {
      const member = g[1];
      if (insideDeniedPrincipals(source, g.index) || seenPublic.has(member)) continue;
      seenPublic.add(member);
      violations.push({
        ruleId: "google.iam.public-principal",
        severity: "critical",
        category: "iam.public-principal",
        provider: "google",
        resourceAddress: `${file} (source scan)`,
        resourceType: null,
        attribute: "member",
        actualValue: member,
        message:
          member === "allUsers"
            ? 'this file grants a role to "allUsers", which is anyone on the internet, authenticated or not'
            : 'this file grants a role to "allAuthenticatedUsers", which is anyone with a Google ' +
              "account — including personal Gmail accounts outside your organization. It restricts " +
              "nothing in practice",
        remediation:
          "grant the role to the specific service account, group or domain that needs it. Note " +
          "organizations created on or after 2024-05-03 block these principals by default via the " +
          "iam.managed.allowedPolicyMembers constraint, so this may also simply fail to apply",
      });
    }

    violations.push(...scanProviderCredentials(source, file));
    violations.push(...scanVariableDefaults(source, file));
  }

  return violations;
}

// Resolves which resource a companion resource actually names.
//
// A rule like "every bucket has a public access block" has to pair two resources, and the obvious
// key -- the `bucket` attribute's value -- is unusable: for a bucket being created, its `id` is
// unknown at plan time, so `bucket = aws_s3_bucket.this.id` has no literal value in
// `resource_changes`. Both S3 companion rules worked around that by pairing anything in the same
// module, which is wrong in both directions. The object-lock rule flagged a bucket no lock
// configuration named. Worse, the public-access-block rule let a bucket with no block of its own
// inherit a sibling's and pass -- a critical blocking rule returning clean for an unprotected
// bucket, found only by deriving it from the visible false positive.
//
// `terraform show -json` answers this directly. Alongside `resource_changes` it emits
// `configuration`, which records what each attribute was *written as* rather than what it will
// evaluate to:
//
//   "aws_s3_bucket_public_access_block.protected": {
//     "expressions": { "bucket": { "references": [
//       "aws_s3_bucket.protected.id", "aws_s3_bucket.protected" ] } }
//   }
//
// The reference survives the value being unknown, which is the whole point. Terraform emits both
// the attribute reference and the bare resource address; `referencesOf` keeps them as written and
// `referenceMatches` accepts either.
//
// Nothing in this project read `plan.configuration` before -- only `resource_changes` -- so this is
// the plumbing that has to exist before either rule can be correct.

// `resource_changes` addresses carry count/for_each keys (`aws_s3_bucket.this[0]`,
// `aws_s3_bucket.this["logs"]`); `configuration` addresses never do, because configuration is
// per-declaration rather than per-instance. Every address is compared with the key stripped, so an
// expanded resource pairs with the declaration it came from.
export function stripIndex(address) {
  return typeof address === "string" ? address.replace(/\[[^\]]*\]/g, "") : address;
}

// Addresses inside a module's configuration block are module-relative: a resource that
// `resource_changes` calls `module.storage.aws_s3_bucket.this` is `aws_s3_bucket.this` there, and
// so are the references in its expressions. Both get the module prefix applied so every address in
// the returned index is absolute and directly comparable to a resource's `address`.
function qualify(moduleAddress, address) {
  return moduleAddress ? `${moduleAddress}.${address}` : address;
}

function walkModule(module, moduleAddress, out) {
  for (const resource of module?.resources || []) {
    const attributes = new Map();
    for (const [attribute, expression] of Object.entries(resource.expressions || {})) {
      if (!Array.isArray(expression?.references)) continue;
      attributes.set(attribute, expression.references.map((r) => qualify(moduleAddress, stripIndex(r))));
    }
    out.set(qualify(moduleAddress, stripIndex(resource.address)), attributes);
  }
  for (const [name, call] of Object.entries(module?.module_calls || {})) {
    walkModule(call.module, qualify(moduleAddress, `module.${name}`), out);
  }
}

// Returns a Map of absolute resource address -> Map of attribute name -> absolute references,
// or `null` when the plan carries no configuration at all.
//
// `null` means "this plan cannot answer the question", and callers must treat it differently from
// an empty result, which means "asked, and this attribute references nothing". Conflating the two
// is how the retention rule reports a parameterised period as no retention: a value it could not
// read became a value it decided was absent.
export function buildReferenceIndex(configuration) {
  if (!configuration?.root_module) return null;
  const out = new Map();
  walkModule(configuration.root_module, "", out);
  return out;
}

// True when `references` names `address` -- either as the bare resource (`aws_s3_bucket.this`) or
// through one of its attributes (`aws_s3_bucket.this.id`). The `.` guard keeps
// `aws_s3_bucket.this_other` from matching `aws_s3_bucket.this`, the same prefix trap
// `resolveWorkingDir` guards with `path.sep`.
export function referenceMatches(references, address) {
  const target = stripIndex(address);
  return (references || []).some((r) => r === target || r.startsWith(`${target}.`));
}

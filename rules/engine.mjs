import { sortBySeverity } from "../lib/format.mjs";

// A resource whose ONLY action is "delete" won't exist after apply, so it can't be protecting
// anything — excluding it from the index is what makes "the companion resource that protects
// this bucket is being removed while the bucket stays" fall out for free from an aggregate rule,
// with no special-casing: from the index's point of view, a bucket whose public-access-block is
// being deleted looks identical to a bucket that never had one.
function existsAfterApply(change) {
  return !(change.actions.length === 1 && change.actions[0] === "delete");
}

// provider_name looks like "registry.terraform.io/hashicorp/aws" — take the final path segment
// as the routing key. Deliberately not `type`-prefix matching (`aws_`/`google_`/`azurerm_`),
// since that breaks for any community/wrapped provider using a different type-name convention;
// provider_name is Terraform's own authoritative statement of which provider produced a
// resource. "google-beta" is a distinct provider binary but the same conceptual cloud/rule set.
export function providerKey(providerName) {
  if (!providerName) return null;
  const last = providerName.split("/").pop();
  return last === "google-beta" ? "google" : last;
}

export function buildIndex(resourceChanges) {
  const all = resourceChanges.filter((r) => existsAfterApply(r.change));

  return {
    all,
    byType(type) {
      return all.filter((r) => r.type === type);
    },
    byProvider(key) {
      return all.filter((r) => providerKey(r.provider_name) === key);
    },
    // For aggregate/companion-resource rules: find resources of `type` where `predicate` holds,
    // typically matching a reference back to some other resource (e.g. an
    // aws_s3_bucket_public_access_block whose `bucket` attribute names a specific bucket).
    findRelated(type, predicate) {
      return all.filter((r) => r.type === type && predicate(r));
    },
  };
}

// Shared shape every rule's check() should build via this helper, so callers never have to
// repeat ruleId/severity/category/provider by hand and risk them drifting from the rule
// definition they came from.
export function makeViolation(rule, resource, { message, remediation, attribute = null, actualValue = null }) {
  return {
    ruleId: rule.id,
    severity: rule.severity,
    category: rule.category,
    provider: rule.provider,
    resourceAddress: resource?.address ?? "(multiple resources)",
    resourceType: resource?.type ?? null,
    attribute,
    actualValue,
    message,
    remediation,
  };
}

export function evaluate(planJson, providerPacks) {
  const index = buildIndex(planJson.resource_changes || []);
  const violations = [];

  for (const [key, pack] of Object.entries(providerPacks)) {
    const relevant = index.byProvider(key);
    if (relevant.length === 0) continue; // skip clouds absent from this plan entirely

    for (const rule of pack) {
      if (rule.kind === "aggregate") {
        violations.push(...rule.check(index));
      } else {
        const matches = relevant.filter((r) => rule.resourceTypes.includes(r.type));
        for (const resource of matches) {
          violations.push(...rule.check(resource, index));
        }
      }
    }
  }

  return sortBySeverity(violations);
}

// Fixed category-id list, shared across every provider pack, so results stay comparable across
// clouds even though the underlying resource types are unrelated. A rule inventing a category
// string outside this list is a bug, not a new category — extend this file deliberately instead.
//
// Only AWS rules exist as of this list's introduction; several categories below are reserved,
// not yet used by any rule, for the GCP/Azure packs planned as a follow-on addition using this
// same engine. Reserving them now means those packs slot into an existing taxonomy instead of
// each inventing its own naming later.
export const CATEGORIES = [
  "storage.public-access",
  "storage.encryption",
  "storage.immutability",
  "network.open-ingress",
  "network.flow-logs-disabled",
  "iam.wildcard",
  "iam.long-lived-credential",
  "iam.public-principal",
  "iam.duplicate-attachment",
  "compute.public-ip",
  "compute.unencrypted-disk",
  "compute.imds-hardening",
  "kubernetes.public-api",
  "kubernetes.control-plane-logging",
  "kubernetes.secrets-encryption",
  "database.public-access",
  "database.unencrypted",
  "database.no-backups",
  "secrets.hardcoded-credentials",
  "secrets.kms-policy",
  "secrets.key-rotation",
  "logging.disabled",
  "logging.unencrypted",
  "messaging.unencrypted",
  "messaging.public",
  "registry.no-scanning",
  "registry.mutable-tags",
  "registry.public",
];

export function isKnownCategory(category) {
  return CATEGORIES.includes(category);
}

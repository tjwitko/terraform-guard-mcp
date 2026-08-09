const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

export function sortBySeverity(violations) {
  return [...violations].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
}

export function worstSeverity(violations) {
  if (violations.length === 0) return null;
  return sortBySeverity(violations)[0].severity;
}

// Itemized-by-name prose, matching the sibling servers' refusal convention (name the specific
// offending thing, don't summarize) — but this is additive to a structured violations[] array
// in the caller's response, not the only representation. A blocking security tool's caller
// needs to reliably parse "what exactly failed" to fix and retry; that's a parse task as much
// as a read task, which the siblings never needed since their refusals end the interaction
// rather than expecting a corrected retry against specific named resources.
export function formatRefusalMessage(violations) {
  const sorted = sortBySeverity(violations);
  const items = sorted
    .map(
      (v, i) =>
        `[${i + 1}] ${v.severity.toUpperCase()} ${v.category} ${v.resourceAddress} (${v.provider}): ` +
        `${v.message} ${v.remediation}`
    )
    .join(" ");
  return (
    `Refusing to plan-approve: ${violations.length} violation(s) found blocking this Terraform ` +
    `change. ${items}`
  );
}

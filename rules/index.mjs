import awsRules from "./aws.mjs";

// Only AWS is implemented this pass. Adding GCP/Azure later means adding rules/gcp.mjs and
// rules/azure.mjs and a line here — the engine (rules/engine.mjs) needs no changes, since it
// already routes generically by provider_name's final path segment.
export const PROVIDER_PACKS = {
  aws: awsRules,
};

import type { State } from "../state.ts";

export type DenyReason =
  | "unknown_asset"
  | "disabled"
  | "revoked"
  | "not_owner"
  | "integrity_failure"
  | "request_id_reused"
  | "quarantined";
export type Decision =
  | { decision: "allow"; reason: "owner" }
  | { decision: "deny"; reason: DenyReason };

/**
 * Zero-trust check for every request: the asset must exist, the actor must be
 * neither disabled nor revoked, and the actor must own the asset. Anything
 * else is denied. Order matters only for the recorded reason.
 */
export function decide(state: State, actor: string, asset: string): Decision {
  const owner = state.owners.get(asset);
  if (owner === undefined || !state.assets.has(asset)) return { decision: "deny", reason: "unknown_asset" };
  if (state.disabled.has(actor)) return { decision: "deny", reason: "disabled" };
  if (state.revoked.has(actor)) return { decision: "deny", reason: "revoked" };
  if (owner !== actor) return { decision: "deny", reason: "not_owner" };
  return { decision: "allow", reason: "owner" };
}

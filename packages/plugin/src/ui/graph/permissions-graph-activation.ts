/**
 * Pure Phase H eligibility decision. This module evaluates sanitized evidence
 * only; it does not activate, import, persist, or render the hybrid graph.
 */

export const PERMISSIONS_GRAPH_ACTIVATION_EVIDENCE_PHASE_H_MARKER =
  "vg-permissions-graph-activation-evidence-phase-h-v1";

export const REQUIRED_PERMISSIONS_GRAPH_ACTIVATION_GATES = Object.freeze([
  "determinism-privacy",
  "renderer-fallback-teardown",
  "interaction-drag-cancellation",
  "stress-boundedness",
  "reference-desktop-performance",
  "physical-obsidian-accessibility-lifecycle-privacy",
  "authenticated-real-graph-development",
  "production-isolation-legacy-compatibility",
] as const);

export type PermissionsGraphActivationGateId =
  (typeof REQUIRED_PERMISSIONS_GRAPH_ACTIVATION_GATES)[number];

export type PermissionsGraphActivationGateStatus =
  | "passed"
  | "failed"
  | "blocked"
  | "skipped"
  | "missing"
  | "stale";

export interface PermissionsGraphActivationGateEvidence {
  readonly gateId: string;
  readonly status: PermissionsGraphActivationGateStatus;
  readonly evidenceRevision: string;
}

export interface PermissionsGraphActivationApproval {
  readonly approved: boolean;
  readonly revision: string | null;
}

export interface PermissionsGraphActivationEvidenceInput {
  readonly candidateRevision: string;
  readonly gates: readonly PermissionsGraphActivationGateEvidence[];
  readonly approval: PermissionsGraphActivationApproval;
}

export type PermissionsGraphActivationDenialReason =
  | Readonly<{ code: "invalid-candidate-revision" }>
  | Readonly<{ code: "unknown-gate" }>
  | Readonly<{ code: "gate-missing"; gateId: PermissionsGraphActivationGateId }>
  | Readonly<{ code: "duplicate-gate"; gateId: PermissionsGraphActivationGateId }>
  | Readonly<{ code: "unknown-status"; gateId: PermissionsGraphActivationGateId }>
  | Readonly<{
      code: "gate-not-passed";
      gateId: PermissionsGraphActivationGateId;
      status: Exclude<PermissionsGraphActivationGateStatus, "passed">;
    }>
  | Readonly<{ code: "gate-revision-mismatch"; gateId: PermissionsGraphActivationGateId }>
  | Readonly<{ code: "approval-missing" }>
  | Readonly<{ code: "approval-revision-mismatch" }>;

export interface PermissionsGraphActivationDecision {
  readonly marker: typeof PERMISSIONS_GRAPH_ACTIVATION_EVIDENCE_PHASE_H_MARKER;
  readonly decision: "eligible" | "denied";
  readonly candidateRevision: string;
  readonly reasons: readonly PermissionsGraphActivationDenialReason[];
  readonly blockingGateIds: readonly PermissionsGraphActivationGateId[];
}

const REQUIRED_GATE_SET = new Set<string>(REQUIRED_PERMISSIONS_GRAPH_ACTIVATION_GATES);
const KNOWN_STATUSES = new Set<string>([
  "passed",
  "failed",
  "blocked",
  "skipped",
  "missing",
  "stale",
]);
const SAFE_REVISION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function evaluatePermissionsGraphActivationEvidence(
  input: PermissionsGraphActivationEvidenceInput,
): PermissionsGraphActivationDecision {
  if (!SAFE_REVISION.test(input.candidateRevision)) {
    return freezeDecision("denied", "invalid", [
      Object.freeze({ code: "invalid-candidate-revision" as const }),
    ]);
  }

  const reasons: PermissionsGraphActivationDenialReason[] = [];
  const evidenceByGate = new Map<PermissionsGraphActivationGateId, PermissionsGraphActivationGateEvidence[]>();
  let unknownGateFound = false;
  for (const evidence of input.gates) {
    if (!REQUIRED_GATE_SET.has(evidence.gateId)) {
      unknownGateFound = true;
      continue;
    }
    const gateId = evidence.gateId as PermissionsGraphActivationGateId;
    const entries = evidenceByGate.get(gateId) ?? [];
    entries.push(evidence);
    evidenceByGate.set(gateId, entries);
  }

  for (const gateId of REQUIRED_PERMISSIONS_GRAPH_ACTIVATION_GATES) {
    const entries = evidenceByGate.get(gateId) ?? [];
    if (entries.length === 0) {
      reasons.push(Object.freeze({ code: "gate-missing" as const, gateId }));
      continue;
    }
    if (entries.length > 1) {
      reasons.push(Object.freeze({ code: "duplicate-gate" as const, gateId }));
    }
    const evidence = entries[0] as PermissionsGraphActivationGateEvidence;
    if (!KNOWN_STATUSES.has(evidence.status)) {
      reasons.push(Object.freeze({ code: "unknown-status" as const, gateId }));
    } else if (evidence.status !== "passed") {
      reasons.push(Object.freeze({
        code: "gate-not-passed" as const,
        gateId,
        status: evidence.status as Exclude<PermissionsGraphActivationGateStatus, "passed">,
      }));
    }
    if (evidence.evidenceRevision !== input.candidateRevision) {
      reasons.push(Object.freeze({ code: "gate-revision-mismatch" as const, gateId }));
    }
  }

  if (unknownGateFound) reasons.push(Object.freeze({ code: "unknown-gate" as const }));
  if (input.approval.approved !== true) {
    reasons.push(Object.freeze({ code: "approval-missing" as const }));
  } else if (input.approval.revision !== input.candidateRevision) {
    reasons.push(Object.freeze({ code: "approval-revision-mismatch" as const }));
  }

  return freezeDecision(
    reasons.length === 0 ? "eligible" : "denied",
    input.candidateRevision,
    reasons,
  );
}

function freezeDecision(
  decision: PermissionsGraphActivationDecision["decision"],
  candidateRevision: string,
  reasons: readonly PermissionsGraphActivationDenialReason[],
): PermissionsGraphActivationDecision {
  const blocking = new Set<PermissionsGraphActivationGateId>();
  for (const reason of reasons) {
    if ("gateId" in reason) blocking.add(reason.gateId);
  }
  const blockingGateIds = REQUIRED_PERMISSIONS_GRAPH_ACTIVATION_GATES.filter((gateId) =>
    blocking.has(gateId)
  );
  return Object.freeze({
    marker: PERMISSIONS_GRAPH_ACTIVATION_EVIDENCE_PHASE_H_MARKER,
    decision,
    candidateRevision,
    reasons: Object.freeze([...reasons]),
    blockingGateIds: Object.freeze(blockingGateIds),
  });
}

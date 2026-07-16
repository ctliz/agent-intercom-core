import type { AuthorizationContext, PolicyAction, PolicyPrincipal, PolicyState } from "./policy.ts";

export interface PolicyVector {
  name: string;
  principals: PolicyPrincipal[];
  actorId: string;
  action: PolicyAction;
  targetId: string;
  context?: AuthorizationContext;
  expectedAllowed: boolean;
  expectedReasonOrCode: string;
}

const localRoot: PolicyPrincipal = {
  id: "local-root",
  kind: "local",
  state: "active",
  generation: 1,
  policy: "local-public",
  rootSessionId: "local-root",
};
const localPeer: PolicyPrincipal = {
  id: "local-peer",
  kind: "local",
  state: "active",
  generation: 1,
  policy: "local-public",
  rootSessionId: "local-peer",
};
const remoteManager: PolicyPrincipal = {
  id: "remote-manager",
  kind: "remote",
  state: "active",
  generation: 1,
  policy: "remote-parent",
  parentSessionId: "local-root",
  rootSessionId: "local-root",
};
const remoteChild: PolicyPrincipal = {
  id: "remote-child",
  kind: "remote",
  state: "active",
  generation: 1,
  policy: "remote-parent",
  parentSessionId: "remote-manager",
  rootSessionId: "local-root",
};
const remoteSibling: PolicyPrincipal = {
  id: "remote-sibling",
  kind: "remote",
  state: "active",
  generation: 1,
  policy: "remote-parent",
  parentSessionId: "remote-manager",
  rootSessionId: "local-root",
};

export const POLICY_VECTORS: PolicyVector[] = [
  {
    name: "local sessions remain public",
    principals: [localRoot, localPeer],
    actorId: "local-root",
    action: "send",
    targetId: "local-peer",
    expectedAllowed: true,
    expectedReasonOrCode: "local-public",
  },
  {
    name: "remote manager can reach direct local parent",
    principals: [localRoot, remoteManager],
    actorId: "remote-manager",
    action: "send",
    targetId: "local-root",
    expectedAllowed: true,
    expectedReasonOrCode: "direct-parent",
  },
  {
    name: "local parent can reach direct remote child",
    principals: [localRoot, remoteManager],
    actorId: "local-root",
    action: "ask",
    targetId: "remote-manager",
    expectedAllowed: true,
    expectedReasonOrCode: "direct-parent",
  },
  {
    name: "remote child cannot skip its direct parent in phase zero",
    principals: [localRoot, remoteManager, remoteChild],
    actorId: "remote-child",
    action: "send",
    targetId: "local-root",
    expectedAllowed: false,
    expectedReasonOrCode: "POLICY_DENIED",
  },
  {
    name: "remote siblings cannot communicate in phase zero",
    principals: [localRoot, remoteManager, remoteChild, remoteSibling],
    actorId: "remote-child",
    action: "discover",
    targetId: "remote-sibling",
    expectedAllowed: false,
    expectedReasonOrCode: "POLICY_DENIED",
  },
  {
    name: "unrelated local session cannot discover remote principal",
    principals: [localRoot, localPeer, remoteManager],
    actorId: "local-peer",
    action: "discover",
    targetId: "remote-manager",
    expectedAllowed: false,
    expectedReasonOrCode: "POLICY_DENIED",
  },
  {
    name: "remote principal cannot reach unrelated local session",
    principals: [localRoot, localPeer, remoteManager],
    actorId: "remote-manager",
    action: "send",
    targetId: "local-peer",
    expectedAllowed: false,
    expectedReasonOrCode: "POLICY_DENIED",
  },
  {
    name: "revoked principal cannot communicate",
    principals: [localRoot, { ...remoteManager, state: "revoked" }],
    actorId: "remote-manager",
    action: "send",
    targetId: "local-root",
    expectedAllowed: false,
    expectedReasonOrCode: "REVOKED_PRINCIPAL",
  },
  {
    name: "stale actor generation cannot send",
    principals: [localRoot, { ...remoteManager, generation: 2 }],
    actorId: "remote-manager",
    action: "send",
    targetId: "local-root",
    context: { actorGeneration: 1 },
    expectedAllowed: false,
    expectedReasonOrCode: "STALE_GENERATION",
  },
];

export function stateForVector(vector: PolicyVector): PolicyState {
  return { principals: Object.fromEntries(vector.principals.map((principal) => [principal.id, structuredClone(principal)])) };
}

export const POLICY_VECTOR_SCHEMA_VERSION = 1;
export const POLICY_SEMANTICS_HASH = "78178a5fd57c353342642968d3a27262ed02cb236927723675d875959413dce3";

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  adoptSubtree,
  authorize,
  isAncestor,
  POLICY_SEMANTICS_VERSION,
  revokeSubtree,
  type PolicyPrincipal,
  type PolicyState,
} from "../src/policy.ts";
import { POLICY_SEMANTICS_HASH, POLICY_VECTORS, POLICY_VECTOR_SCHEMA_VERSION, stateForVector } from "../src/policy-vectors.ts";

function decisionLabel(decision: ReturnType<typeof authorize>): string {
  return decision.allowed ? decision.reason : decision.code;
}

for (const vector of POLICY_VECTORS) {
  test(`policy vector: ${vector.name}`, () => {
    const decision = authorize(stateForVector(vector), vector.actorId, vector.action, vector.targetId, vector.context);
    assert.equal(decision.allowed, vector.expectedAllowed);
    assert.equal(decisionLabel(decision), vector.expectedReasonOrCode);
  });
}

test("policy semantic hash covers the complete golden vector corpus", () => {
  const payload = JSON.stringify({ version: POLICY_VECTOR_SCHEMA_VERSION, vectors: POLICY_VECTORS });
  assert.equal(createHash("sha256").update(payload).digest("hex"), POLICY_SEMANTICS_HASH);
  assert.equal(POLICY_SEMANTICS_VERSION, 2);
});

function principal(input: Partial<PolicyPrincipal> & Pick<PolicyPrincipal, "id">): PolicyPrincipal {
  return {
    kind: "remote",
    state: "active",
    generation: 1,
    policy: "remote-tree",
    rootSessionId: "root",
    ...input,
  };
}

function hierarchy(): PolicyState {
  const principals = [
    principal({ id: "root", kind: "local", policy: "local-public", rootSessionId: "root" }),
    principal({ id: "manager", parentSessionId: "root" }),
    principal({ id: "lead", parentSessionId: "manager" }),
    principal({ id: "worker", parentSessionId: "lead" }),
  ];
  return { principals: Object.fromEntries(principals.map((entry) => [entry.id, entry])) };
}

test("ancestor traversal is cycle-safe and identifies the ownership chain", () => {
  const state = hierarchy();
  assert.equal(isAncestor(state, "root", "worker"), true);
  assert.equal(isAncestor(state, "manager", "worker"), true);
  assert.equal(isAncestor(state, "worker", "root"), false);
  state.principals.root.parentSessionId = "worker";
  assert.equal(isAncestor(state, "unrelated", "worker"), false);
});

test("subtree revocation increments every affected generation without mutating input", () => {
  const state = hierarchy();
  const result = revokeSubtree(state, "manager");
  assert.deepEqual(result.changedPrincipalIds, ["manager", "lead", "worker"]);
  assert.equal(state.principals.manager.state, "active");
  for (const id of result.changedPrincipalIds) {
    assert.equal(result.state.principals[id].state, "revoked");
    assert.equal(result.state.principals[id].generation, 2);
  }
  assert.equal(result.state.principals.root.state, "active");
});

test("adoption rewrites the subtree root and fences every old generation", () => {
  const state = hierarchy();
  state.principals.otherRoot = principal({ id: "otherRoot", kind: "local", policy: "local-public", rootSessionId: "otherRoot" });
  const result = adoptSubtree(state, "lead", "otherRoot", "otherRoot");
  assert.deepEqual(result.changedPrincipalIds, ["lead", "worker"]);
  assert.equal(result.state.principals.lead.parentSessionId, "otherRoot");
  assert.equal(result.state.principals.lead.rootSessionId, "otherRoot");
  assert.equal(result.state.principals.worker.rootSessionId, "otherRoot");
  assert.equal(result.state.principals.lead.generation, 2);
  assert.equal(result.state.principals.worker.generation, 2);
  assert.equal(state.principals.lead.parentSessionId, "manager");
});

test("adoption refuses ownership cycles", () => {
  const state = hierarchy();
  assert.throws(() => adoptSubtree(state, "manager", "worker", "root"), /ownership cycle/);
});

test("phase-one communication is symmetric across the ancestor chain", () => {
  const state = hierarchy();
  const ids = Object.keys(state.principals);
  for (const left of ids) {
    for (const right of ids) {
      const forward = authorize(state, left, "send", right);
      const reverse = authorize(state, right, "send", left);
      assert.equal(forward.allowed, reverse.allowed, `${left} ↔ ${right}`);
    }
  }
  assert.equal(authorize(state, "root", "send", "worker").allowed, true);
  assert.equal(authorize(state, "worker", "send", "root").allowed, true);
  assert.equal(authorize(state, "manager", "revoke", "worker").allowed, true);
  assert.equal(authorize(state, "worker", "revoke", "manager").allowed, false);
});

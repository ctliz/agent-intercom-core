import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  bossBindingEpoch,
  brokerRevision,
  canonicalHash,
  canonicalJson,
  controllerGeneration,
  ContractValidationError,
  journalGeneration,
  participantBindingEpoch,
  schedulerGeneration,
  transitionVersion,
  workerGeneration,
  type BossBindingEpoch,
  type ParticipantBindingEpoch,
} from "../src/canonical.ts";
import { type PolicyPrincipal } from "../src/policy.ts";
import {
  POLICY_SEMANTICS_HASH,
  POLICY_VECTORS,
  POLICY_VECTOR_SCHEMA_VERSION,
} from "../src/policy-vectors.ts";
import {
  authorizeBossPolicy,
  BOSS_POLICY_PRINCIPAL_VERSION,
  type BossPrivatePrincipal,
  type BossPolicyRole,
  type BossPolicyPrincipal,
  type BossPolicyState,
} from "../src/boss-policy.ts";
import { BOSS_POLICY_SEMANTICS_HASH } from "../src/boss-policy-vectors.ts";
import {
  authorizeLegacyBoundary,
  authorizeFeatureAware,
  parseFeatureAwareAuthorizationRequest,
  parseFeatureRegistration,
  type BossFeatureRegistration,
  type FeatureAwarePolicyState,
  type FeatureRegistrationState,
  type OrdinaryFeatureRegistration,
} from "../src/feature-policy.ts";
import {
  BOSS_CONTROL_ENVELOPE_VERSION,
  BOSS_CAPABILITY_FEATURE_DIGEST,
  BOSS_RUN_FEATURE_CONTRACT,
  BOSS_RUN_FEATURE_SEMANTICS_CORPUS,
  BOSS_RUN_PROTOCOL_FEATURE_CONTRACT_HASH,
  BOSS_RUN_FEATURE_SEMANTICS_HASH,
  AUTHORITY_TRANSITION_VERSION,
  deliveryGroupId,
  parseAuthorityTransitionRecord,
  parseBossControlEnvelope,
  type DeliveryEquivalenceKey,
} from "../src/boss-wire.ts";
import {
  FEATURE_ROUTING_SEMANTICS_HASH,
  FEATURE_ROUTING_VECTOR_SCHEMA_VERSION,
  FEATURE_ROUTING_VECTORS,
} from "../src/feature-routing-vectors.ts";
import { authorizeSupervisorSubscription } from "../src/supervision.ts";
import { SUPERVISOR_ACL_VECTORS, stateForSupervisorAclVector } from "../src/supervision-vectors.ts";

const LEGACY_POLICY_HASH = "f3b00e503631bc91123aedfbcf1df72cc9913e1893c09728b2c598f3dcdfdfe0";

test("legacy remote-access-v1 corpus remains schema 2 with its literal frozen hash", () => {
  assert.equal(POLICY_VECTOR_SCHEMA_VERSION, 2);
  assert.equal(POLICY_SEMANTICS_HASH, LEGACY_POLICY_HASH);
  const bytes = JSON.stringify({ version: POLICY_VECTOR_SCHEMA_VERSION, vectors: POLICY_VECTORS });
  assert.equal(createHash("sha256").update(bytes).digest("hex"), LEGACY_POLICY_HASH);
});

function legacyPrincipal(id: string, policy: PolicyPrincipal["policy"]): PolicyPrincipal {
  return {
    id,
    kind: "local",
    state: "active",
    generation: 1,
    policy,
    rootSessionId: id,
  };
}

function ordinaryRegistration(
  principalId: string,
  state: OrdinaryFeatureRegistration["state"] = "active",
): OrdinaryFeatureRegistration {
  return { principalId, principalClass: "ordinary", state };
}

function bossRegistration(
  principalId: string,
  overrides: Partial<BossFeatureRegistration> = {},
): BossFeatureRegistration {
  return {
    principalId,
    principalClass: "boss-bound",
    state: "active",
    bossRunId: "run-a",
    participantId: principalId,
    bindingEpoch: participantBindingEpoch(1),
    featureContract: structuredClone(BOSS_RUN_FEATURE_CONTRACT),
    policySemanticsHash: BOSS_POLICY_SEMANTICS_HASH,
    capabilityDigest: BOSS_CAPABILITY_FEATURE_DIGEST,
    brokerIdentityVerified: true,
    ...overrides,
  };
}

function featureState(): FeatureAwarePolicyState {
  return {
    legacy: {
      principals: {
        public: legacyPrincipal("public", "local-public"),
        publicPeer: legacyPrincipal("publicPeer", "local-public"),
      },
    },
    boss: {
      principals: {
        boss: bossPrincipal("boss", "boss"),
        manager: bossPrincipal("manager", "manager"),
      },
    },
    registrations: {
      public: ordinaryRegistration("public"),
      publicPeer: ordinaryRegistration("publicPeer"),
      boss: bossRegistration("boss"),
      manager: bossRegistration("manager"),
    },
  };
}

test("authoritative registrations route ordinary peers through frozen legacy policy and Boss peers through Boss policy", () => {
  const state = featureState();
  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: true, reason: "local-public" });
  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "boss",
    targetId: "manager",
    action: "send",
    bossContext: { actorBindingEpoch: participantBindingEpoch(1), targetBindingEpoch: participantBindingEpoch(1) },
  }), { allowed: true, reason: "communication-profile" });
});

test("feature-aware state containers require exact own enumerable data descriptors", () => {
  const ordinaryRequest = { actorId: "public", targetId: "publicPeer", action: "send" };
  const denied = { allowed: false, code: "FEATURE_ATTESTATION_DENIED" } as const;
  const assertDenied = (state: FeatureAwarePolicyState, request = ordinaryRequest): void => {
    assert.deepEqual(authorizeFeatureAware(state, request), denied);
  };

  const accessorState = featureState();
  const legacy = accessorState.legacy;
  let getterCalls = 0;
  Object.defineProperty(accessorState, "legacy", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return legacy;
    },
  });
  assertDenied(accessorState);
  assert.equal(getterCalls, 0);

  const inheritedState = featureState();
  const inherited = Object.create({ legacy: inheritedState.legacy }) as FeatureAwarePolicyState;
  Object.defineProperties(inherited, {
    boss: { configurable: true, enumerable: true, value: inheritedState.boss, writable: true },
    registrations: { configurable: true, enumerable: true, value: inheritedState.registrations, writable: true },
  });
  assertDenied(inherited);

  const nonEnumerableState = featureState();
  Object.defineProperty(nonEnumerableState, "legacy", {
    configurable: true,
    enumerable: false,
    value: nonEnumerableState.legacy,
    writable: true,
  });
  assertDenied(nonEnumerableState);

  const symbolState = featureState();
  Object.defineProperty(symbolState, Symbol("extra"), { enumerable: true, value: true });
  assertDenied(symbolState);

  const unknownState = { ...featureState(), unexpected: true } as FeatureAwarePolicyState & { unexpected: boolean };
  assertDenied(unknownState);

  const arrayState = [{ legacy: featureState().legacy }, { boss: featureState().boss }] as unknown as FeatureAwarePolicyState;
  assertDenied(arrayState, { actorId: "0", targetId: "1", action: "send" });

  const registrationArrayState = featureState();
  registrationArrayState.registrations = [
    ordinaryRegistration("0"),
    ordinaryRegistration("1"),
  ] as never;
  assertDenied(registrationArrayState, { actorId: "0", targetId: "1", action: "send" });

  const customRegistrationMapState = featureState();
  customRegistrationMapState.registrations = Object.assign(
    Object.create(null),
    customRegistrationMapState.registrations,
  ) as never;
  assertDenied(customRegistrationMapState);
});

test("legacy and Boss state/principal maps are validated before selected entry semantics", () => {
  const request = { actorId: "public", targetId: "publicPeer", action: "send" };
  const denied = { allowed: false, code: "FEATURE_ATTESTATION_DENIED" } as const;
  const assertDenied = (state: FeatureAwarePolicyState): void => {
    assert.deepEqual(authorizeFeatureAware(state, request), denied);
  };

  const legacyStateArray = featureState();
  legacyStateArray.legacy = [{ principals: legacyStateArray.legacy.principals }] as never;
  assertDenied(legacyStateArray);

  const bossStateArray = featureState();
  bossStateArray.boss = [{ principals: bossStateArray.boss.principals }] as never;
  assertDenied(bossStateArray);

  const legacyPrincipalArray = featureState();
  legacyPrincipalArray.legacy = {
    principals: [
      legacyPrincipal("0", "local-public"),
      legacyPrincipal("1", "local-public"),
    ],
  } as never;
  assertDenied(legacyPrincipalArray);

  const bossPrincipalArray = featureState();
  bossPrincipalArray.boss = {
    principals: [
      bossPrincipal("0", "boss"),
      bossPrincipal("1", "manager"),
    ],
  } as never;
  assertDenied(bossPrincipalArray);

  const nestedAccessorState = featureState();
  const principals = nestedAccessorState.legacy.principals;
  let getterCalls = 0;
  Object.defineProperty(nestedAccessorState.legacy, "principals", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return principals;
    },
  });
  assertDenied(nestedAccessorState);
  assert.equal(getterCalls, 0);

  const nestedInheritedMapState = featureState();
  const inheritedMap = Object.create({ public: nestedInheritedMapState.legacy.principals.public });
  Object.defineProperty(inheritedMap, "publicPeer", {
    configurable: true,
    enumerable: true,
    value: nestedInheritedMapState.legacy.principals.publicPeer,
    writable: true,
  });
  nestedInheritedMapState.legacy = { principals: inheritedMap } as never;
  assertDenied(nestedInheritedMapState);

  const nestedSymbolMapState = featureState();
  Object.defineProperty(nestedSymbolMapState.legacy.principals, Symbol("extra"), {
    enumerable: true,
    value: true,
  });
  assertDenied(nestedSymbolMapState);

  const nestedNonEnumerableState = featureState();
  Object.defineProperty(nestedNonEnumerableState.boss, "principals", {
    configurable: true,
    enumerable: false,
    value: nestedNonEnumerableState.boss.principals,
    writable: true,
  });
  assertDenied(nestedNonEnumerableState);
});

test("authoritative registration and routing request parsers are exact and discriminated", () => {
  assert.deepEqual(parseFeatureRegistration(ordinaryRegistration("public")), ordinaryRegistration("public"));
  assert.deepEqual(parseFeatureRegistration(bossRegistration("boss")), bossRegistration("boss"));
  assert.deepEqual(parseFeatureAwareAuthorizationRequest({
    actorId: "boss",
    targetId: "manager",
    action: "control",
    bossContext: {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      controlKind: "decision",
      correlated: true,
    },
  }), {
    actorId: "boss",
    targetId: "manager",
    action: "control",
    bossContext: {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      controlKind: "decision",
      correlated: true,
    },
  });

  for (const registration of [
    { ...ordinaryRegistration("public"), bossRunId: "run-a" },
    { ...ordinaryRegistration("public"), bindingEpoch: participantBindingEpoch(1) },
    { ...bossRegistration("boss"), unknownBossMetadata: true },
    { ...bossRegistration("boss"), principalClass: "ordinary" },
  ]) assert.throws(() => parseFeatureRegistration(registration), ContractValidationError);

  for (const request of [
    { actorId: "public", targetId: "publicPeer", action: "send", principalClass: "ordinary" },
    { actorId: "public", targetId: "publicPeer", action: "send", legacyContext: { bossBindingEpoch: 1 } },
    { actorId: "boss", targetId: "manager", action: "send", bossContext: { bindingEpoch: 1 } },
  ]) {
    assert.throws(() => parseFeatureAwareAuthorizationRequest(request), ContractValidationError);
    assert.throws(() => authorizeFeatureAware(featureState(), request), ContractValidationError);
  }
});

test("folded or unknown registration metadata cannot downgrade authoritative routing", () => {
  const malformedRegistrations = [
    { ...ordinaryRegistration("public"), bossRunId: "run-a", participantId: "public" },
    { ...bossRegistration("boss"), unknownBossMetadata: true },
  ];
  for (const registration of malformedRegistrations) {
    const state = featureState();
    state.registrations[registration.principalId] = registration as never;
    const targetId = registration.principalClass === "ordinary" ? "publicPeer" : "manager";
    assert.deepEqual(authorizeFeatureAware(state, {
      actorId: registration.principalId,
      targetId,
      action: "send",
    }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
  }
});

test("authoritative registration lookup rejects accessor and non-enumerable map entries without invoking getters", () => {
  const accessorState = featureState();
  const publicRegistration = accessorState.registrations.public;
  let getterCalls = 0;
  Object.defineProperty(accessorState.registrations, "public", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return publicRegistration;
    },
  });
  assert.deepEqual(authorizeFeatureAware(accessorState, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
  assert.equal(getterCalls, 0);

  const nonEnumerableState = featureState();
  Object.defineProperty(nonEnumerableState.registrations, "public", {
    configurable: true,
    enumerable: false,
    value: nonEnumerableState.registrations.public,
    writable: true,
  });
  assert.deepEqual(authorizeFeatureAware(nonEnumerableState, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });

  const dataState = featureState();
  Object.defineProperty(dataState.registrations, "public", {
    configurable: true,
    enumerable: true,
    value: dataState.registrations.public,
    writable: true,
  });
  assert.deepEqual(authorizeFeatureAware(dataState, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: true, reason: "local-public" });
});

test("registration map keys, policy identities, and policy state are bound before routing", () => {
  const registrationMismatch = featureState();
  registrationMismatch.registrations.public = ordinaryRegistration("publicPeer");
  assert.deepEqual(authorizeFeatureAware(registrationMismatch, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });

  const ordinaryPolicyMismatch = featureState();
  ordinaryPolicyMismatch.legacy.principals.public.id = "publicPeer";
  assert.deepEqual(authorizeFeatureAware(ordinaryPolicyMismatch, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });

  const ordinaryPolicyStateMismatch = featureState();
  ordinaryPolicyStateMismatch.legacy.principals.public.state = "revoked";
  assert.deepEqual(authorizeFeatureAware(ordinaryPolicyStateMismatch, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });

  const bossPolicyMismatch = featureState();
  bossPolicyMismatch.boss.principals.boss.state = "revoked";
  assert.deepEqual(authorizeFeatureAware(bossPolicyMismatch, {
    actorId: "boss",
    targetId: "manager",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
});

test("live ordinary routing requires two local-public policies for the local-kind shortcut", () => {
  const state = featureState();
  state.legacy.principals.remoteRoot = legacyPrincipal("remoteRoot", "remote-tree");
  state.legacy.principals.remoteChild = {
    ...legacyPrincipal("remoteChild", "remote-tree"),
    parentSessionId: "remoteRoot",
    rootSessionId: "remoteRoot",
  };
  state.registrations.remoteRoot = ordinaryRegistration("remoteRoot");
  state.registrations.remoteChild = ordinaryRegistration("remoteChild");

  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "remoteRoot",
    targetId: "public",
    action: "send",
  }), { allowed: false, code: "POLICY_DENIED" });
  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "remoteRoot",
    targetId: "remoteChild",
    action: "send",
  }), { allowed: true, reason: "direct-parent" });
});

test("feature-aware legacy boundary rejects a policy getter without invoking it", () => {
  const state = featureState();
  let getterCalls = 0;
  Object.defineProperty(state.legacy.principals.public, "policy", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return "local-public";
    },
  });

  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
  assert.equal(getterCalls, 0);
  assert.throws(() => authorizeLegacyBoundary(state, "public", "send", "publicPeer"), ContractValidationError);
  assert.equal(getterCalls, 0);

  assert.deepEqual(authorizeFeatureAware(featureState(), {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: true, reason: "local-public" });
});

test("feature-aware legacy boundary requires own enumerable data descriptors", () => {
  const fields = [
    "id",
    "kind",
    "state",
    "generation",
    "policy",
    "parentSessionId",
    "rootSessionId",
  ] as const;
  for (const field of fields) {
    const state = featureState();
    const principal = state.legacy.principals.public;
    if (field === "parentSessionId") principal.parentSessionId = "publicPeer";
    const fieldValue = principal[field];
    let getterCalls = 0;
    Object.defineProperty(principal, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return fieldValue;
      },
    });
    assert.deepEqual(authorizeFeatureAware(state, {
      actorId: "public",
      targetId: "publicPeer",
      action: "send",
    }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" }, field);
    assert.equal(getterCalls, 0, field);
  }

  const entryAccessorState = featureState();
  const publicPrincipal = entryAccessorState.legacy.principals.public;
  let entryGetterCalls = 0;
  Object.defineProperty(entryAccessorState.legacy.principals, "public", {
    configurable: true,
    enumerable: true,
    get() {
      entryGetterCalls += 1;
      return publicPrincipal;
    },
  });
  assert.deepEqual(authorizeFeatureAware(entryAccessorState, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
  assert.equal(entryGetterCalls, 0);

  const inheritedFieldState = featureState();
  const inheritedId = Object.create({ id: "public" }) as PolicyPrincipal;
  Object.assign(inheritedId, inheritedFieldState.legacy.principals.public);
  Reflect.deleteProperty(inheritedId, "id");
  inheritedFieldState.legacy.principals.public = inheritedId;
  assert.deepEqual(authorizeFeatureAware(inheritedFieldState, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });

  const symbolState = featureState();
  Object.defineProperty(symbolState.legacy.principals.public, Symbol("extra"), {
    enumerable: true,
    value: true,
  });
  assert.deepEqual(authorizeFeatureAware(symbolState, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
  }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
});

function legacyChainState(intermediary: "own" | "inherited" | "identity-mismatch"): FeatureAwarePolicyState {
  const state = featureState();
  const root = { ...legacyPrincipal("remoteRoot", "remote-tree"), kind: "remote" as const };
  const mid = {
    ...legacyPrincipal(intermediary === "identity-mismatch" ? "substitutedMid" : "remoteMid", "remote-tree"),
    kind: "remote" as const,
    parentSessionId: "remoteRoot",
    rootSessionId: "remoteRoot",
  };
  const leaf = {
    ...legacyPrincipal("remoteLeaf", "remote-tree"),
    kind: "remote" as const,
    parentSessionId: "remoteMid",
    rootSessionId: "remoteRoot",
  };
  const prototype = intermediary === "inherited" ? { remoteMid: mid } : null;
  const principals = Object.assign(Object.create(prototype), state.legacy.principals, {
    remoteRoot: root,
    remoteLeaf: leaf,
    ...(intermediary === "inherited" ? {} : { remoteMid: mid }),
  }) as FeatureAwarePolicyState["legacy"]["principals"];
  state.legacy = { principals };
  state.registrations.remoteRoot = ordinaryRegistration("remoteRoot");
  state.registrations.remoteLeaf = ordinaryRegistration("remoteLeaf");
  return state;
}

test("legacy ancestor routing uses only own identity-bound intermediary records", () => {
  const own = legacyChainState("own");
  assert.deepEqual(authorizeFeatureAware(own, {
    actorId: "remoteRoot",
    targetId: "remoteLeaf",
    action: "send",
  }), { allowed: true, reason: "ancestor-chain" });
  assert.deepEqual(authorizeFeatureAware(own, {
    actorId: "remoteRoot",
    targetId: "remoteLeaf",
    action: "inspect_tree",
  }), { allowed: true, reason: "ancestor-control" });

  for (const intermediary of ["inherited", "identity-mismatch"] as const) {
    const state = legacyChainState(intermediary);
    for (const action of ["send", "inspect_tree"] as const) {
      assert.deepEqual(authorizeFeatureAware(state, {
        actorId: "remoteRoot",
        targetId: "remoteLeaf",
        action,
      }), { allowed: false, code: "POLICY_DENIED" }, `${intermediary}: ${action}`);
    }
  }
});

test("feature-aware routing denies missing, mixed, unknown-action, and opposite-context requests", () => {
  const state = featureState();
  assert.deepEqual(authorizeFeatureAware(state, { actorId: "missing", targetId: "public", action: "discover" }), {
    allowed: false,
    code: "UNKNOWN_REGISTRATION",
  });
  assert.deepEqual(authorizeFeatureAware(state, { actorId: "public", targetId: "boss", action: "discover" }), {
    allowed: false,
    code: "FEATURE_CLASS_DENIED",
  });
  assert.deepEqual(authorizeFeatureAware(state, { actorId: "boss", targetId: "public", action: "discover" }), {
    allowed: false,
    code: "FEATURE_CLASS_DENIED",
  });
  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "public",
    targetId: "publicPeer",
    action: "unknown-action" as never,
  }), { allowed: false, code: "ACTION_NAMESPACE_DENIED" });
  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "public",
    targetId: "publicPeer",
    action: "send",
    bossContext: { actorBindingEpoch: participantBindingEpoch(1), targetBindingEpoch: participantBindingEpoch(1) },
  }), { allowed: false, code: "CONTEXT_NAMESPACE_DENIED" });
  assert.deepEqual(authorizeFeatureAware(state, {
    actorId: "boss",
    targetId: "manager",
    action: "send",
    bossContext: { actorBindingEpoch: participantBindingEpoch(1), targetBindingEpoch: participantBindingEpoch(1) },
    legacyContext: { actorGeneration: 1, targetGeneration: 1 },
  }), { allowed: false, code: "CONTEXT_NAMESPACE_DENIED" });
});

function bossPrincipal(
  principalId: string,
  role: BossPolicyRole,
  bossRunId = "run-a",
): BossPrivatePrincipal {
  return {
    version: BOSS_POLICY_PRINCIPAL_VERSION,
    principalId,
    principalClass: "boss-private",
    state: "active",
    bossRunId,
    participantId: principalId,
    role,
    bindingEpoch: participantBindingEpoch(1),
    ...(role === "manager" ? { assignedParticipantIds: ["worker-a", "worker-b", "scout-a"] } : {}),
    ...(role === "worker" || role === "scout" ? { assignedManagerParticipantId: "manager" } : {}),
    ...(role === "council" ? { requestingPrincipalId: "boss" } : {}),
  };
}

test("inactive or credential-only Boss registrations never authorize", () => {
  for (const stateName of ["credential_only", "unbound", "revoked", "replaced", "ended"] as readonly FeatureRegistrationState[]) {
    const state = featureState();
    state.registrations.boss = bossRegistration("boss", { state: stateName });
    assert.deepEqual(authorizeFeatureAware(state, {
      actorId: "boss",
      targetId: "manager",
      action: "send",
      bossContext: { actorBindingEpoch: participantBindingEpoch(1), targetBindingEpoch: participantBindingEpoch(1) },
    }), { allowed: false, code: "BINDING_INACTIVE" });
  }
});

test("missing, mismatched, or unverified Boss feature attestation fails closed", () => {
  const invalidRegistrations: BossFeatureRegistration[] = [
    bossRegistration("boss", { featureContract: undefined as never }),
    bossRegistration("boss", { featureContract: { ...BOSS_RUN_FEATURE_CONTRACT, version: 2 as never } }),
    bossRegistration("boss", { featureContract: { ...BOSS_RUN_FEATURE_CONTRACT, semanticsHash: "0".repeat(64) } }),
    bossRegistration("boss", { policySemanticsHash: "0".repeat(64) }),
    bossRegistration("boss", { capabilityDigest: "0".repeat(64) }),
    bossRegistration("boss", { brokerIdentityVerified: false }),
  ];
  for (const registration of invalidRegistrations) {
    const state = featureState();
    state.registrations.boss = registration;
    assert.deepEqual(authorizeFeatureAware(state, {
      actorId: "boss",
      targetId: "manager",
      action: "send",
      bossContext: { actorBindingEpoch: participantBindingEpoch(1), targetBindingEpoch: participantBindingEpoch(1) },
    }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
  }
});

test("authenticated Boss registration identity must match the routed policy binding", () => {
  for (const mismatch of [
    { bossRunId: "run-b" },
    { participantId: "different-participant" },
    { bindingEpoch: participantBindingEpoch(2) },
  ] satisfies Array<Partial<BossFeatureRegistration>>) {
    const state = featureState();
    state.registrations.boss = bossRegistration("boss", mismatch);
    assert.deepEqual(authorizeFeatureAware(state, {
      actorId: "boss",
      targetId: "manager",
      action: "send",
      bossContext: { actorBindingEpoch: participantBindingEpoch(1), targetBindingEpoch: participantBindingEpoch(1) },
    }), { allowed: false, code: "FEATURE_ATTESTATION_DENIED" });
  }
});

test("feature-aware authorization rejects inherited sparse assignments while preserving dense assignments", () => {
  const sparseState = featureState();
  const sparseAssignments = Array<string>(1);
  sparseState.boss.principals.manager = {
    ...bossPrincipal("manager", "manager"),
    assignedParticipantIds: sparseAssignments,
  };
  sparseState.boss.principals["worker-a"] = bossPrincipal("worker-a", "worker");
  sparseState.registrations["worker-a"] = bossRegistration("worker-a");

  const denseState = featureState();
  denseState.boss.principals.manager = {
    ...bossPrincipal("manager", "manager"),
    assignedParticipantIds: ["worker-a"],
  };
  denseState.boss.principals["worker-a"] = bossPrincipal("worker-a", "worker");
  denseState.registrations["worker-a"] = bossRegistration("worker-a");

  const request = {
    actorId: "manager",
    targetId: "worker-a",
    action: "send",
    bossContext: {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
    },
  } as const;
  const originalIndexDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  try {
    Object.defineProperty(Array.prototype, "0", {
      configurable: true,
      enumerable: false,
      value: "worker-a",
      writable: true,
    });
    assert.equal(Object.hasOwn(sparseAssignments, 0), false);
    assert.equal(sparseAssignments[0], "worker-a");
    assert.deepEqual(authorizeFeatureAware(sparseState, request), {
      allowed: false,
      code: "FEATURE_ATTESTATION_DENIED",
    });
    assert.deepEqual(authorizeFeatureAware(denseState, request), {
      allowed: true,
      reason: "communication-profile",
    });
  } finally {
    if (originalIndexDescriptor === undefined) {
      Reflect.deleteProperty(Array.prototype, "0");
    } else {
      Object.defineProperty(Array.prototype, "0", originalIndexDescriptor);
    }
  }
});

test("Boss registrations cannot cross the frozen legacy authorization boundary", () => {
  const state = featureState();
  assert.throws(() => authorizeLegacyBoundary(state, "boss", "send", "public"), ContractValidationError);
  assert.throws(() => authorizeLegacyBoundary(state, "public", "send", "manager"), ContractValidationError);
});

test("inactive or inexact ordinary registrations cannot cross the frozen legacy authorization boundary", () => {
  for (const stateName of ["revoked", "ended"] as const) {
    const state = featureState();
    state.registrations.public = ordinaryRegistration("public", stateName);
    assert.throws(() => authorizeLegacyBoundary(state, "public", "send", "publicPeer"), ContractValidationError);
  }

  const inexact = featureState();
  inexact.registrations.public = { ...ordinaryRegistration("public"), bossRunId: "run-a" } as never;
  assert.throws(() => authorizeLegacyBoundary(inexact, "public", "send", "publicPeer"), ContractValidationError);

  const identityMismatch = featureState();
  identityMismatch.legacy.principals.public.id = "publicPeer";
  assert.throws(() => authorizeLegacyBoundary(identityMismatch, "public", "send", "publicPeer"), ContractValidationError);

  const policyStateMismatch = featureState();
  policyStateMismatch.legacy.principals.public.state = "revoked";
  assert.throws(() => authorizeLegacyBoundary(policyStateMismatch, "public", "send", "publicPeer"), ContractValidationError);

  assert.throws(() => authorizeLegacyBoundary(
    featureState(),
    "public",
    "send",
    "publicPeer",
    { bossBindingEpoch: 1 } as never,
  ), ContractValidationError);
  assert.throws(() => authorizeLegacyBoundary(
    featureState(),
    "public",
    "future_action" as never,
    "publicPeer",
  ), ContractValidationError);
});

test("every allowed supervisor ACL edge is a strict subset of dispatcher discovery", () => {
  const supervisorState = stateForSupervisorAclVector();
  const runId = "boss-run-a";
  const state: FeatureAwarePolicyState = {
    legacy: {
      principals: {
        "owner-local": legacyPrincipal("owner-local", "local-public"),
        "local-worker-a": legacyPrincipal("local-worker-a", "local-public"),
      },
    },
    boss: {
      principals: {
        "boss-a": bossPrincipal("boss-a", "boss", runId),
        "manager-a": {
          ...bossPrincipal("manager-a", "manager", runId),
          participantId: "manager-participant-a",
          assignedParticipantIds: ["worker-participant-a", "scout-participant-a"],
        },
        "worker-participant-a": {
          ...bossPrincipal("worker-participant-a", "worker", runId),
          assignedManagerParticipantId: "manager-participant-a",
        },
        "worker-participant-a-2": {
          ...bossPrincipal("worker-participant-a-2", "worker", runId),
          assignedManagerParticipantId: "manager-participant-a",
        },
        "unregistered-worker-participant-a": {
          ...bossPrincipal("unregistered-worker-participant-a", "worker", runId),
          assignedManagerParticipantId: "manager-participant-a",
        },
        "scout-participant-a": {
          ...bossPrincipal("scout-participant-a", "scout", runId),
          assignedManagerParticipantId: "manager-participant-a",
        },
        "scout-participant-a-2": {
          ...bossPrincipal("scout-participant-a-2", "scout", runId),
          assignedManagerParticipantId: "manager-participant-a",
        },
        "controller-a": bossPrincipal("controller-a", "controller", runId),
      },
    },
    registrations: {
      "owner-local": ordinaryRegistration("owner-local"),
      "local-worker-a": ordinaryRegistration("local-worker-a"),
      "boss-a": bossRegistration("boss-a", { bossRunId: runId }),
      "manager-a": bossRegistration("manager-a", { bossRunId: runId, participantId: "manager-participant-a" }),
      "worker-participant-a": bossRegistration("worker-participant-a", { bossRunId: runId }),
      "worker-participant-a-2": bossRegistration("worker-participant-a-2", { bossRunId: runId }),
      "unregistered-worker-participant-a": bossRegistration("unregistered-worker-participant-a", { bossRunId: runId }),
      "scout-participant-a": bossRegistration("scout-participant-a", { bossRunId: runId }),
      "scout-participant-a-2": bossRegistration("scout-participant-a-2", { bossRunId: runId }),
      "controller-a": bossRegistration("controller-a", { bossRunId: runId }),
    },
  };
  for (const vector of SUPERVISOR_ACL_VECTORS.filter((entry) => entry.expected.allowed)) {
    assert.equal(authorizeSupervisorSubscription(supervisorState, vector.request).allowed, true, vector.name);
    const target = vector.request.target;
    const targetWorkers = target.kind === "worker"
      ? [supervisorState.workers[target.workerId]].filter((worker) => worker !== undefined)
      : target.role === "manager"
        ? Object.values(supervisorState.workers).filter((worker) => {
          const managerPrincipalId = supervisorState.currentManagerByRun[target.bossRunId];
          const managerParticipantId = supervisorState.principals[managerPrincipalId]?.participantId;
          return worker.bossRunId === target.bossRunId
            && worker.role === "manager"
            && worker.participantId === managerParticipantId
            && worker.active;
        })
        : Object.values(supervisorState.workers).filter((worker) =>
          worker.bossRunId === target.bossRunId && worker.role === target.role && worker.active);
    assert.notEqual(targetWorkers.length, 0, vector.name);
    for (const targetWorker of targetWorkers) {
      const targetRegistration = targetWorker.participantId === undefined
        ? undefined
        : Object.values(state.registrations).find((registration) =>
          registration.principalClass === "boss-bound"
          && registration.bossRunId === targetWorker.bossRunId
          && registration.participantId === targetWorker.participantId);
      const targetId = targetRegistration?.principalId ?? targetWorker.workerId;
      const actorRegistration = state.registrations[vector.request.actorPrincipalId];
      const decision = authorizeFeatureAware(state, {
        actorId: vector.request.actorPrincipalId,
        targetId,
        action: "discover",
        ...(actorRegistration.principalClass === "boss-bound"
          ? { bossContext: { actorBindingEpoch: participantBindingEpoch(1), targetBindingEpoch: participantBindingEpoch(1) } }
          : {}),
      });
      assert.equal(decision.allowed, true, `${vector.name}: ${targetWorker.workerId}`);
    }
  }
});

test("Boss-private isolation is bidirectional for discover/send and known cross-run targets", () => {
  const boss = bossPrincipal("boss", "boss");
  const legacy: BossPolicyPrincipal = {
    version: BOSS_POLICY_PRINCIPAL_VERSION,
    principalId: "legacy",
    principalClass: "legacy-local-public",
    state: "active",
  };
  const state: BossPolicyState = { principals: { boss, legacy } };
  for (const action of ["discover", "send"] as const) {
    assert.deepEqual(authorizeBossPolicy(state, "boss", action, "legacy"), {
      allowed: false,
      code: "BOSS_LEGACY_ISOLATION",
    });
    assert.deepEqual(authorizeBossPolicy(state, "legacy", action, "boss"), {
      allowed: false,
      code: "BOSS_LEGACY_ISOLATION",
    });
  }

  const crossRun: BossPolicyState = {
    principals: {
      manager: bossPrincipal("manager", "manager"),
      "known-boss": bossPrincipal("known-boss", "boss", "run-b"),
    },
  };
  assert.deepEqual(authorizeBossPolicy(crossRun, "manager", "send", "known-boss", {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
  }), { allowed: false, code: "CROSS_RUN_DENIED" });
});

test("distinct Workers cannot discover or send to one another in either direction", () => {
  const state: BossPolicyState = {
    principals: {
      "worker-a": bossPrincipal("worker-a", "worker"),
      "worker-b": bossPrincipal("worker-b", "worker"),
    },
  };
  for (const [actorId, targetId] of [["worker-a", "worker-b"], ["worker-b", "worker-a"]] as const) {
    for (const action of ["discover", "send"] as const) {
      assert.deepEqual(authorizeBossPolicy(state, actorId, action, targetId, {
        actorBindingEpoch: participantBindingEpoch(1),
        targetBindingEpoch: participantBindingEpoch(1),
      }), { allowed: false, code: "POLICY_DENIED" });
    }
  }
});

test("canonical values distinguish absence, null, and string and reject explicit undefined", () => {
  const absent = canonicalHash("opus/collision/optional", {});
  const nullValue = canonicalHash("opus/collision/optional", { value: null });
  const stringValue = canonicalHash("opus/collision/optional", { value: "null" });
  assert.equal(absent, "6923c30778a95aadb4a48781c294174342e5a3fdd0efa5bd88e716da28044ca6");
  assert.equal(nullValue, "1be647c18f1f3f2c71b42cc2ccdea5294b3194abeb9d94a744aa20dbb12abfa3");
  assert.equal(stringValue, "3a6ca0e7529bc33145d6f94ce794f9a133839e14c334f67ec4cae29518595e98");
  assert.equal(new Set([absent, nullValue, stringValue]).size, 3);
  assert.throws(() => canonicalJson({ value: undefined }), ContractValidationError);
});

test("canonical numeric domain is safe integers only and does not alias negative zero", () => {
  for (const value of [-0, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => canonicalJson(value), ContractValidationError);
  }
  assert.equal(canonicalJson(Number.MAX_SAFE_INTEGER), String(Number.MAX_SAFE_INTEGER));
  assert.throws(() => brokerRevision(-0), ContractValidationError);
});

test("canonical objects and arrays cannot collide through special keys or sparse holes", () => {
  const protoKey = Object.fromEntries([["__proto__", null]]);
  assert.equal(canonicalJson(protoKey), '{"__proto__":null}');
  assert.notEqual(canonicalJson(protoKey), canonicalJson({}));
  assert.throws(() => canonicalJson(Array(1)), ContractValidationError);

  const customArray: unknown[] & { extra?: string } = ["entry"];
  customArray.extra = "not-a-json-array-member";
  assert.throws(() => canonicalJson(customArray), ContractValidationError);
  assert.throws(() => canonicalJson(Object.fromEntries([["\ud800", "invalid-key"]])), ContractValidationError);
});

test("canonical Unicode policy preserves exact code points without normalization", () => {
  const nfc = "\u00e9";
  const nfd = "e\u0301";
  assert.notEqual(canonicalJson(nfc), canonicalJson(nfd));
  assert.equal(canonicalHash("opus/unicode", nfc), "5504366fe25fa0a854cdcf7a277270c2199665c2e898f24649ed550db393cb93");
  assert.equal(canonicalHash("opus/unicode", nfd), "8fa223da4c3c3a7d205efdde92fc457efa6ed76da801429aa28e19072a52701e");
});

test("canonical hash framing resists domain and embedded-control collision attempts", () => {
  const vectors = [
    canonicalHash("opus/frame", { value: "a\u0000b" }),
    canonicalHash("opus/frame", { value: "a", suffix: "b" }),
    canonicalHash("opus/frame-a", { value: "b" }),
  ];
  assert.equal(new Set(vectors).size, vectors.length);
  assert.throws(() => canonicalHash("opus/frame\u0000a", { value: "b" }), ContractValidationError);
});

function equivalenceKey(sourceAuthorityId: DeliveryEquivalenceKey["sourceAuthorityId"]): DeliveryEquivalenceKey {
  return {
    recipientPrincipalId: "manager",
    recipientBindingEpoch: 1,
    sourceAuthorityId,
    ...(sourceAuthorityId.kind === "controller" ? { bossRunId: sourceAuthorityId.bossRunId } : {}),
    sourceEventId: "event-1",
    workerId: "worker-1",
    workerGeneration: workerGeneration(1),
    transitionId: "transition-1",
    transitionVersion: transitionVersion(1),
  };
}

test("tagged source-authority identities remain disjoint and required IDs reject empty strings", () => {
  const ids = [
    deliveryGroupId(equivalenceKey({ kind: "worker_store", workerStoreId: "authority", journalGeneration: journalGeneration(1) })),
    deliveryGroupId(equivalenceKey({ kind: "controller", bossRunId: "authority", controllerGeneration: controllerGeneration(1) })),
    deliveryGroupId(equivalenceKey({ kind: "orc_scheduler", ownerUid: 1, schedulerGeneration: schedulerGeneration(1) })),
  ];
  assert.deepEqual(ids, [
    "4b406e560e6aaf2c44cbe13fd042f241edb977eab580d530286ac521ba6bcada",
    "abdd8505f7e4233142db8e3049ef0c0c33f0f8f039764a3aeed554602dbbb748",
    "e60277cc3344ebd07a041095daed3e663b383970ca6e8881c4f8b622ac9eece5",
  ]);
  assert.equal(new Set(ids).size, ids.length);
  assert.throws(() => deliveryGroupId({ ...equivalenceKey({
    kind: "worker_store",
    workerStoreId: "authority",
    journalGeneration: journalGeneration(1),
  }), recipientPrincipalId: "" }), ContractValidationError);

  const valid = equivalenceKey({ kind: "controller", bossRunId: "run-a", controllerGeneration: controllerGeneration(1) });
  for (const invalidId of [" ", "event\u0000id", "event\nid", "event\u007fid", "\ud800"]) {
    assert.throws(() => deliveryGroupId({ ...valid, sourceEventId: invalidId }), ContractValidationError);
  }
  const missingSourceEventId = { ...valid } as Partial<DeliveryEquivalenceKey>;
  delete missingSourceEventId.sourceEventId;
  assert.throws(() => deliveryGroupId(missingSourceEventId as DeliveryEquivalenceKey), ContractValidationError);
  assert.throws(() => deliveryGroupId({ ...valid, bossRunId: undefined }), ContractValidationError);
});

test("policy, protocol feature, and control envelope identities are independently visible", () => {
  assert.notEqual(BOSS_POLICY_SEMANTICS_HASH, BOSS_RUN_FEATURE_SEMANTICS_HASH);
  assert.notEqual(BOSS_POLICY_SEMANTICS_HASH, BOSS_RUN_PROTOCOL_FEATURE_CONTRACT_HASH);
  assert.notEqual(BOSS_RUN_PROTOCOL_FEATURE_CONTRACT_HASH, BOSS_CAPABILITY_FEATURE_DIGEST);
  assert.equal(BOSS_RUN_FEATURE_CONTRACT.semanticsHash, BOSS_RUN_FEATURE_SEMANTICS_HASH);
  assert.equal(BOSS_RUN_FEATURE_CONTRACT.controlEnvelopeVersion, BOSS_CONTROL_ENVELOPE_VERSION);
});

test("folded feature-routing corpus commits every R2-R7 fail-closed class", () => {
  assert.equal(FEATURE_ROUTING_VECTOR_SCHEMA_VERSION, 1);
  assert.equal(FEATURE_ROUTING_SEMANTICS_HASH, canonicalHash(
    "agent-intercom-core/boss-run-v1/feature-routing-vectors",
    { version: FEATURE_ROUTING_VECTOR_SCHEMA_VERSION, vectors: FEATURE_ROUTING_VECTORS },
  ));
  assert.equal(FEATURE_ROUTING_SEMANTICS_HASH, "e8ddde569a188a122b6ba0e257e23ba203bbf0897dcb3c84994be3390e26e63f");
  assert.equal(BOSS_RUN_FEATURE_SEMANTICS_CORPUS.featureRoutingVectorVersion, FEATURE_ROUTING_VECTOR_SCHEMA_VERSION);
  assert.equal(BOSS_RUN_FEATURE_SEMANTICS_CORPUS.featureRoutingSemanticsHash, FEATURE_ROUTING_SEMANTICS_HASH);
  const names = new Set<string>(FEATURE_ROUTING_VECTORS.map((vector) => vector.name));
  for (const required of [
    "ordinary peers stay legacy when Boss is advertised",
    "local kind shortcut requires two local-public policies",
    "local remote-tree parent edge remains authorized",
    "own identity-bound legacy intermediary preserves ancestor chain",
    "inherited legacy intermediary cannot authorize ancestor chain",
    "inherited legacy intermediary cannot authorize ancestor control",
    "legacy intermediary key identity mismatch denied",
    "unbound Boss denied",
    "missing Boss feature contract denied",
    "unknown Boss feature version denied",
    "Boss feature semantics mismatch denied",
    "Boss policy semantics mismatch denied",
    "Boss capability digest mismatch denied",
    "registration run mismatch denied",
    "registration participant mismatch denied",
    "registration epoch mismatch denied",
    "folded Boss fields on ordinary registration denied",
    "unknown Boss registration metadata denied",
    "registration map key substitution denied",
    "ordinary policy identity substitution denied",
    "ordinary registration and policy state mismatch denied",
    "Boss registration and policy state mismatch denied",
    "unknown top-level routing metadata rejected",
    "folded Boss epoch in legacy context rejected",
    "Boss direct use of frozen legacy boundary throws",
    "inactive ordinary direct use of frozen legacy boundary throws",
    "unknown action direct use of frozen legacy boundary throws",
    "Controller participant supervision implies dispatcher discovery",
  ]) assert.ok(names.has(required), required);
});

test("Boss and participant binding epochs are branded and validated as non-interchangeable counters", () => {
  const acceptsBossEpoch = (_value: BossBindingEpoch): void => undefined;
  const acceptsParticipantEpoch = (_value: ParticipantBindingEpoch): void => undefined;
  const bossEpoch = bossBindingEpoch(1);
  const participantEpoch = participantBindingEpoch(1);
  acceptsBossEpoch(bossEpoch);
  acceptsParticipantEpoch(participantEpoch);
  // @ts-expect-error boss authority epochs cannot be used as participant binding epochs
  acceptsParticipantEpoch(bossEpoch);
  // @ts-expect-error participant binding epochs cannot be used as Boss authority epochs
  acceptsBossEpoch(participantEpoch);
  assert.throws(() => bossBindingEpoch(0), ContractValidationError);
  assert.throws(() => participantBindingEpoch(0), ContractValidationError);
});

test("authority epoch zero is reserved for initial bind prior state, never rebind or proposed state", () => {
  const base = {
    version: AUTHORITY_TRANSITION_VERSION,
    authorityTransitionId: "transition-1",
    expectedBrokerRevision: 0,
    brokerRevision: 1,
    target: { bossRunId: "run-a", participantId: "worker-a" },
    idempotencyKey: "idempotency-1",
    state: "prepared",
    prepareToken: "prepare-1",
    preparedAt: "2026-07-28T12:00:00.000Z",
  } as const;
  assert.equal(parseAuthorityTransitionRecord({
    ...base,
    operation: "bind_participant",
    prior: { participantBindingEpoch: 0 },
    proposed: { participantBindingEpoch: 1 },
  }).operation, "bind_participant");
  assert.throws(() => parseAuthorityTransitionRecord({
    ...base,
    operation: "rebind_participant",
    prior: { participantBindingEpoch: 0 },
    proposed: { participantBindingEpoch: 1 },
  }), ContractValidationError);
  assert.throws(() => parseAuthorityTransitionRecord({
    ...base,
    operation: "bind_participant",
    prior: { participantBindingEpoch: 0 },
    proposed: { participantBindingEpoch: 0 },
  }), ContractValidationError);
});

test("generic control bindingEpoch cannot be substituted with bossBindingEpoch metadata", () => {
  const control = {
    type: "boss.assignment.accepted",
    version: BOSS_CONTROL_ENVELOPE_VERSION,
    messageId: "message-1",
    bossRunId: "run-a",
    participantId: "worker-a",
    bindingEpoch: 3,
    idempotencyKey: "idempotency-1",
    payload: {},
  } as const;
  assert.equal(parseBossControlEnvelope(control).bindingEpoch, 3);
  assert.throws(() => parseBossControlEnvelope({ ...control, bossBindingEpoch: 3 }), ContractValidationError);
});

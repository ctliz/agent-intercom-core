import assert from "node:assert/strict";
import test from "node:test";
import { ContractValidationError, participantBindingEpoch } from "../src/canonical.ts";
import {
  authorizeBossPolicy,
  BOSS_POLICY_ACTIONS,
  BOSS_CONTROL_KINDS,
  BOSS_POLICY_PRINCIPAL_VERSION,
  BOSS_POLICY_ROLES,
  BOSS_POLICY_SEMANTICS_VERSION,
  parseBossPolicyPrincipal,
  type BossAuthorizationContext,
  type BossControlKind,
  type BossPrivatePrincipal,
  type BossPolicyAction,
  type BossPolicyState,
} from "../src/boss-policy.ts";
import {
  BOSS_CONTROL_EDGE_VECTORS,
  BOSS_POLICY_SEMANTICS_HASH,
  BOSS_POLICY_VECTORS,
  BOSS_ROLE_EDGE_VECTORS,
  bossPolicyStateForVector,
} from "../src/boss-policy-vectors.ts";

for (const vector of BOSS_POLICY_VECTORS) {
  test(`Boss policy vector: ${vector.name}`, () => {
    const decision = authorizeBossPolicy(bossPolicyStateForVector(vector), vector.actorId, vector.action, vector.targetId, vector.context);
    assert.equal(decision.allowed, vector.expectedAllowed);
    assert.equal(decision.allowed ? decision.reason : decision.code, vector.expectedReasonOrCode);
  });
}

test("Boss policy corpus has an independent frozen hash", () => {
  assert.equal(BOSS_POLICY_SEMANTICS_VERSION, 1);
  assert.equal(BOSS_ROLE_EDGE_VECTORS.length, 49);
  assert.equal(BOSS_CONTROL_EDGE_VECTORS.length, 441);
  assert.equal(BOSS_POLICY_SEMANTICS_HASH, "5fe94cc2c81bba8b50c6d6cd31487231ebfa10ee2d05495c2b088b12e2958dfa");
});

test("Boss control vectors exhaust every ordered role pair and control kind exactly once", () => {
  assert.deepEqual(BOSS_POLICY_ROLES, ["boss", "manager", "adversary", "scout", "worker", "council", "controller"]);
  assert.deepEqual(BOSS_CONTROL_KINDS, [
    "assignment_request", "assignment_response", "health", "staffing", "review_request",
    "review_result", "proof", "lifecycle", "decision",
  ]);

  const tuples = new Set(BOSS_CONTROL_EDGE_VECTORS.map((vector) =>
    `${vector.actorRole}\u0000${vector.targetRole}\u0000${vector.context.controlKind}`
  ));
  assert.equal(tuples.size, BOSS_CONTROL_EDGE_VECTORS.length);
  for (const actorRole of BOSS_POLICY_ROLES) {
    for (const targetRole of BOSS_POLICY_ROLES) {
      BOSS_CONTROL_KINDS.forEach((kind: BossControlKind) => {
        assert.equal(tuples.has(`${actorRole}\u0000${targetRole}\u0000${kind}`), true);
      });
    }
  }
});

test("communication permission never implies Worker control permission", () => {
  const state = bossPolicyStateForVector(BOSS_POLICY_VECTORS[0]!);
  const bindingContext = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
  };
  assert.deepEqual(authorizeBossPolicy(state, "worker", "send", "manager", bindingContext), {
    allowed: true,
    reason: "communication-profile",
  });
  for (const controlKind of ["decision", "staffing", "review_result"] as const) {
    assert.deepEqual(authorizeBossPolicy(state, "worker", "control", "manager", {
      ...bindingContext,
      correlated: true,
      controlKind,
    }), { allowed: false, code: "CONTROL_KIND_DENIED" }, controlKind);
  }
});

function legacyLocalPublicState(): BossPolicyState {
  return {
    principals: {
      "local-a": {
        version: BOSS_POLICY_PRINCIPAL_VERSION,
        principalId: "local-a",
        principalClass: "legacy-local-public",
        state: "active",
      },
      "local-b": {
        version: BOSS_POLICY_PRINCIPAL_VERSION,
        principalId: "local-b",
        principalClass: "legacy-local-public",
        state: "active",
      },
    },
  };
}

test("legacy local public authorization is exhaustive and communication-only", () => {
  const expectedByAction = {
    discover: { allowed: true, reason: "legacy-local-public" },
    send: { allowed: true, reason: "legacy-local-public" },
    ask: { allowed: true, reason: "legacy-local-public" },
    reply: { allowed: true, reason: "legacy-local-public" },
    control: { allowed: false, code: "BOSS_LEGACY_ISOLATION" },
  } as const;

  assert.deepEqual(BOSS_POLICY_ACTIONS, ["discover", "send", "ask", "reply", "control"]);
  for (const action of BOSS_POLICY_ACTIONS) {
    assert.deepEqual(
      authorizeBossPolicy(
        legacyLocalPublicState(),
        "local-a",
        action,
        "local-b",
        action === "control" ? { correlated: true, controlKind: "decision" } : {},
      ),
      expectedByAction[action],
      action,
    );
  }
});

test("legacy local public control is isolated whether correlated or uncorrelated", () => {
  for (const correlated of [false, true]) {
    assert.deepEqual(authorizeBossPolicy(
      legacyLocalPublicState(),
      "local-a",
      "control",
      "local-b",
      { correlated, controlKind: "decision" },
    ), { allowed: false, code: "BOSS_LEGACY_ISOLATION" }, `correlated=${correlated}`);
  }
});

test("runtime action membership fails closed before context parsing or any allow branch", () => {
  const state = bossPolicyStateForVector(BOSS_POLICY_VECTORS[0]!);
  const bindingContext = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
  };
  const wouldAllow = [
    { name: "self", actorId: "boss", targetId: "boss", context: bindingContext },
    { name: "legacy local public", actorId: "local-a", targetId: "local-b", context: {} },
    { name: "communication edge", actorId: "boss", targetId: "manager", context: bindingContext },
    { name: "Controller discovery", actorId: "controller", targetId: "council", context: bindingContext },
  ] as const;

  let actionGetterCalls = 0;
  let actionCoercionCalls = 0;
  const coercibleControl = Object.defineProperties({}, {
    [Symbol.toPrimitive]: {
      get() {
        actionGetterCalls += 1;
        return () => {
          actionCoercionCalls += 1;
          return "control";
        };
      },
    },
    toString: {
      get() {
        actionGetterCalls += 1;
        return () => {
          actionCoercionCalls += 1;
          return "control";
        };
      },
    },
    valueOf: {
      get() {
        actionGetterCalls += 1;
        return () => {
          actionCoercionCalls += 1;
          return "control";
        };
      },
    },
  });
  const hostileActions: readonly (readonly [name: string, value: unknown])[] = [
    ["unknown string", "unknown"],
    ["symbol", Symbol("send")],
    ["coercible object", coercibleControl],
    ["undefined", undefined],
    ["NUL-suffixed control lookalike", "control\u0000"],
    ["boxed control lookalike", new String("control")],
  ];

  let contextTrapCalls = 0;
  for (const scenario of wouldAllow) {
    for (const [actionName, action] of hostileActions) {
      const context = new Proxy(scenario.context, {
        getPrototypeOf() {
          contextTrapCalls += 1;
          throw new Error("authorization context must not be parsed");
        },
        ownKeys() {
          contextTrapCalls += 1;
          throw new Error("authorization context must not be parsed");
        },
      }) as BossAuthorizationContext;
      assert.deepEqual(authorizeBossPolicy(
        state,
        scenario.actorId,
        action as BossPolicyAction,
        scenario.targetId,
        context,
      ), { allowed: false, code: "POLICY_DENIED" }, `${scenario.name}: ${actionName}`);
    }
  }
  assert.equal(actionGetterCalls, 0);
  assert.equal(actionCoercionCalls, 0);
  assert.equal(contextTrapCalls, 0);
});

test("all exact Boss policy actions retain their representative allow semantics", () => {
  const state = bossPolicyStateForVector(BOSS_POLICY_VECTORS[0]!);
  const bindingContext = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
  };
  const validCases = [
    {
      action: "discover",
      actorId: "controller",
      targetId: "council",
      context: bindingContext,
      expected: { allowed: true, reason: "communication-profile" },
    },
    {
      action: "send",
      actorId: "boss",
      targetId: "boss",
      context: bindingContext,
      expected: { allowed: true, reason: "self" },
    },
    {
      action: "ask",
      actorId: "local-a",
      targetId: "local-b",
      context: {},
      expected: { allowed: true, reason: "legacy-local-public" },
    },
    {
      action: "reply",
      actorId: "boss",
      targetId: "manager",
      context: bindingContext,
      expected: { allowed: true, reason: "communication-profile" },
    },
    {
      action: "control",
      actorId: "boss",
      targetId: "manager",
      context: { ...bindingContext, correlated: true, controlKind: "lifecycle" },
      expected: { allowed: true, reason: "structured-control" },
    },
  ] as const satisfies readonly {
    action: BossPolicyAction;
    actorId: string;
    targetId: string;
    context: BossAuthorizationContext;
    expected: ReturnType<typeof authorizeBossPolicy>;
  }[];

  assert.deepEqual(validCases.map(({ action }) => action), BOSS_POLICY_ACTIONS);
  for (const { action, actorId, targetId, context, expected } of validCases) {
    assert.deepEqual(authorizeBossPolicy(state, actorId, action, targetId, context), expected, action);
  }
});

test("Boss policy principal parser rejects unknown versions, metadata, and incomplete assignment bindings", () => {
  const worker = {
    version: BOSS_POLICY_PRINCIPAL_VERSION,
    principalId: "worker",
    principalClass: "boss-private",
    state: "active",
    bossRunId: "run-a",
    participantId: "worker",
    role: "worker",
    bindingEpoch: 1,
    assignedManagerParticipantId: "manager",
  };
  assert.deepEqual(parseBossPolicyPrincipal(worker), worker);
  assert.throws(() => parseBossPolicyPrincipal({ ...worker, version: "boss.policy-principal.v2" }), ContractValidationError);
  assert.throws(() => parseBossPolicyPrincipal({ ...worker, ignored: true }), ContractValidationError);
  const { assignedManagerParticipantId: _omitted, ...unassigned } = worker;
  assert.throws(() => parseBossPolicyPrincipal(unassigned), /required exactly/);
});

function councilState(requestingPrincipalId: string): BossPolicyState {
  const boss: BossPrivatePrincipal = {
    version: BOSS_POLICY_PRINCIPAL_VERSION,
    principalId: "boss-principal",
    principalClass: "boss-private",
    state: "active",
    bossRunId: "run-a",
    participantId: "boss-participant",
    role: "boss",
    bindingEpoch: participantBindingEpoch(1),
  };
  const council: BossPrivatePrincipal = {
    version: BOSS_POLICY_PRINCIPAL_VERSION,
    principalId: "council-principal",
    principalClass: "boss-private",
    state: "active",
    bossRunId: "run-a",
    participantId: "council-participant",
    role: "council",
    bindingEpoch: participantBindingEpoch(1),
    requestingPrincipalId,
  };
  return { principals: { [boss.principalId]: boss, [council.principalId]: council } };
}

function councilStateWithInheritedPrincipal(
  inheritedPrincipalId: "boss-principal" | "council-principal",
): BossPolicyState {
  const state = councilState("boss-principal");
  const principals = Object.create({
    [inheritedPrincipalId]: state.principals[inheritedPrincipalId],
  }) as BossPolicyState["principals"];
  for (const [principalId, principal] of Object.entries(state.principals)) {
    if (principalId !== inheritedPrincipalId) principals[principalId] = principal;
  }
  return { principals };
}

test("the top-level principals container must be an own enumerable data plain record", () => {
  const source = councilState("boss-principal");
  const context = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
    correlated: true,
    controlKind: "review_result" as const,
  };
  const inherited = Object.create({ principals: source.principals }) as BossPolicyState;
  const hidden = Object.defineProperty({}, "principals", {
    enumerable: false,
    value: source.principals,
  }) as BossPolicyState;
  let getterCalls = 0;
  const accessor = Object.defineProperty({}, "principals", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return source.principals;
    },
  }) as BossPolicyState;
  const nonPlainMap = Object.create(null) as BossPolicyState["principals"];
  nonPlainMap["boss-principal"] = source.principals["boss-principal"];
  const nonPlain = { principals: nonPlainMap };

  for (const [name, state] of Object.entries({ inherited, hidden, accessor, nonPlain })) {
    assert.deepEqual(authorizeBossPolicy(
      state,
      "council-principal",
      "control",
      "boss-principal",
      context,
    ), { allowed: false, code: "UNKNOWN_PRINCIPAL" }, name);
  }
  assert.equal(getterCalls, 0);
});

test("the policy state is an exact plain sole-principals record", () => {
  const source = councilState("boss-principal");
  const context = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
    correlated: true,
    controlKind: "review_result" as const,
  };
  const authorize = (state: BossPolicyState) => authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    context,
  );

  assert.deepEqual(authorize(source), { allowed: true, reason: "structured-control" });

  const enumerable = { ...source, metadata: true } as unknown as BossPolicyState;
  const hidden = Object.defineProperty({ ...source }, "metadata", {
    enumerable: false,
    value: true,
  }) as BossPolicyState;
  let getterCalls = 0;
  const accessor = Object.defineProperty({ ...source }, "metadata", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return true;
    },
  }) as BossPolicyState;
  const symbol = { ...source } as BossPolicyState & Record<PropertyKey, unknown>;
  symbol[Symbol("metadata")] = true;
  const inherited = Object.create({ principals: source.principals }) as BossPolicyState;
  const customPrototype = Object.create({ metadata: true }) as BossPolicyState;
  Object.defineProperty(customPrototype, "principals", {
    enumerable: true,
    value: source.principals,
  });
  const nullPrototype = Object.create(null) as BossPolicyState;
  Object.defineProperty(nullPrototype, "principals", {
    enumerable: true,
    value: source.principals,
  });
  const array = Object.assign([], { principals: source.principals }) as unknown as BossPolicyState;

  for (const [name, state] of [
    ["enumerable metadata", enumerable],
    ["hidden metadata", hidden],
    ["accessor metadata", accessor],
    ["symbol metadata", symbol],
    ["inherited principals", inherited],
    ["custom prototype", customPrototype],
    ["null prototype", nullPrototype],
    ["array", array],
  ] as const) {
    assert.deepEqual(authorize(state), { allowed: false, code: "UNKNOWN_PRINCIPAL" }, name);
  }
  assert.equal(getterCalls, 0);
});

test("an array principals container cannot authorize an array id", () => {
  const principal = legacyLocalPublicState().principals["local-a"];
  const state = { principals: [principal] } as unknown as BossPolicyState;
  assert.deepEqual(authorizeBossPolicy(state, "0", "send", "0"), {
    allowed: false,
    code: "UNKNOWN_PRINCIPAL",
  });
});

test("symbol-bearing policy state and principal maps are rejected without invoking getters", () => {
  const state = councilState("boss-principal");
  let containerGetterCalls = 0;
  Object.defineProperty(state, Symbol("metadata"), {
    enumerable: true,
    get() {
      containerGetterCalls += 1;
      return "untrusted";
    },
  });
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
  assert.equal(containerGetterCalls, 0);

  const mapState = councilState("boss-principal");
  let mapGetterCalls = 0;
  Object.defineProperty(mapState.principals, Symbol("metadata"), {
    enumerable: true,
    get() {
      mapGetterCalls += 1;
      return "untrusted";
    },
  });
  assert.deepEqual(authorizeBossPolicy(
    mapState,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
  assert.equal(mapGetterCalls, 0);
});

test("Council control authorizes the requesting principal when principal and participant IDs differ", () => {
  assert.deepEqual(authorizeBossPolicy(
    councilState("boss-principal"),
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: true, reason: "structured-control" });
});

test("Council control rejects an inherited authorization context", () => {
  const context = Object.create({
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
    correlated: true,
    controlKind: "review_result",
  }) as NonNullable<Parameters<typeof authorizeBossPolicy>[4]>;
  assert.equal(Object.hasOwn(context, "controlKind"), false);
  assert.deepEqual(authorizeBossPolicy(
    councilState("boss-principal"),
    "council-principal",
    "control",
    "boss-principal",
    context,
  ), { allowed: false, code: "POLICY_DENIED" });
});

test("Council control rejects own context accessors without invoking them", () => {
  let getterCalls = 0;
  const getter = () => {
    getterCalls += 1;
    return participantBindingEpoch(1);
  };
  const context = Object.defineProperties({}, {
    actorBindingEpoch: { enumerable: true, get: getter },
    targetBindingEpoch: { enumerable: true, get: getter },
    correlated: { enumerable: true, get: getter },
    controlKind: { enumerable: true, get: getter },
  }) as NonNullable<Parameters<typeof authorizeBossPolicy>[4]>;
  assert.deepEqual(authorizeBossPolicy(
    councilState("boss-principal"),
    "council-principal",
    "control",
    "boss-principal",
    context,
  ), { allowed: false, code: "POLICY_DENIED" });
  assert.equal(getterCalls, 0);
});

test("Council control accepts the equivalent valid own data context", () => {
  const context = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
    correlated: true,
    controlKind: "review_result" as const,
  };
  for (const key of Object.keys(context)) {
    const descriptor = Object.getOwnPropertyDescriptor(context, key);
    assert.equal(descriptor?.enumerable, true);
    assert.equal(Object.hasOwn(descriptor ?? {}, "value"), true);
  }
  assert.deepEqual(authorizeBossPolicy(
    councilState("boss-principal"),
    "council-principal",
    "control",
    "boss-principal",
    context,
  ), { allowed: true, reason: "structured-control" });
});

test("authorization context rejects hidden, symbol, extra, and operation-inapplicable fields", () => {
  const bindingContext = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
  };
  const hidden = { ...bindingContext };
  Object.defineProperty(hidden, "metadata", { value: true });
  const symbol = { ...bindingContext } as typeof bindingContext & Record<PropertyKey, unknown>;
  symbol[Symbol("metadata")] = true;
  const extra = { ...bindingContext, metadata: true };
  const controlFieldsOnSend = { ...bindingContext, correlated: true, controlKind: "review_result" as const };
  for (const context of [hidden, symbol, extra, controlFieldsOnSend]) {
    assert.deepEqual(authorizeBossPolicy(
      councilState("boss-principal"),
      "boss-principal",
      "send",
      "boss-principal",
      context,
    ), { allowed: false, code: "POLICY_DENIED" });
  }
});

test("an own actor map entry with inherited principal fields is unknown even when it would authorize", () => {
  const state = councilState("boss-principal");
  state.principals["council-principal"] = Object.create(state.principals["council-principal"]) as BossPrivatePrincipal;
  assert.equal(Object.hasOwn(state.principals, "council-principal"), true);
  assert.equal(Object.hasOwn(state.principals["council-principal"], "principalId"), false);
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
});

test("an own target map entry with inherited principal fields is unknown even when it would authorize", () => {
  const state = councilState("boss-principal");
  state.principals["boss-principal"] = Object.create(state.principals["boss-principal"]) as BossPrivatePrincipal;
  assert.equal(Object.hasOwn(state.principals, "boss-principal"), true);
  assert.equal(Object.hasOwn(state.principals["boss-principal"], "principalId"), false);
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
});

test("Council control denies substitution of the requester's participant ID for its principal ID", () => {
  assert.deepEqual(authorizeBossPolicy(
    councilState("boss-participant"),
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "CONTROL_KIND_DENIED" });
});

test("an inherited actor principal is unknown even when its prototype entry would authorize", () => {
  const state = councilStateWithInheritedPrincipal("council-principal");
  assert.equal(Object.hasOwn(state.principals, "council-principal"), false);
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
});

test("an inherited target principal is unknown even when its prototype entry would authorize", () => {
  const state = councilStateWithInheritedPrincipal("boss-principal");
  assert.equal(Object.hasOwn(state.principals, "boss-principal"), false);
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
});

test("own principal map accessors are unknown without being invoked for self and structured edges", () => {
  const cases = [
    { actorId: "boss-principal", targetId: "boss-principal", action: "send" as const, entryId: "boss-principal" },
    { actorId: "council-principal", targetId: "boss-principal", action: "control" as const, entryId: "council-principal" },
    { actorId: "council-principal", targetId: "boss-principal", action: "control" as const, entryId: "boss-principal" },
  ];
  for (const { actorId, targetId, action, entryId } of cases) {
    const state = councilState("boss-principal");
    const principal = state.principals[entryId];
    let getterCalls = 0;
    Object.defineProperty(state.principals, entryId, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return principal;
      },
    });

    assert.deepEqual(authorizeBossPolicy(
      state,
      actorId,
      action,
      targetId,
      action === "control"
        ? {
            actorBindingEpoch: participantBindingEpoch(1),
            targetBindingEpoch: participantBindingEpoch(1),
            correlated: true,
            controlKind: "review_result",
          }
        : {
            actorBindingEpoch: participantBindingEpoch(1),
            targetBindingEpoch: participantBindingEpoch(1),
          },
    ), { allowed: false, code: "UNKNOWN_PRINCIPAL" }, `${action}: ${entryId}`);
    assert.equal(getterCalls, 0, `${action}: ${entryId}`);
  }
});

test("non-enumerable principal map entries are unknown for self and structured edges", () => {
  const cases = [
    { actorId: "boss-principal", targetId: "boss-principal", action: "send" as const, entryId: "boss-principal" },
    { actorId: "council-principal", targetId: "boss-principal", action: "control" as const, entryId: "council-principal" },
    { actorId: "council-principal", targetId: "boss-principal", action: "control" as const, entryId: "boss-principal" },
  ];
  for (const { actorId, targetId, action, entryId } of cases) {
    const state = councilState("boss-principal");
    Object.defineProperty(state.principals, entryId, {
      configurable: true,
      enumerable: false,
      value: state.principals[entryId],
    });

    assert.deepEqual(authorizeBossPolicy(
      state,
      actorId,
      action,
      targetId,
      action === "control"
        ? {
            actorBindingEpoch: participantBindingEpoch(1),
            targetBindingEpoch: participantBindingEpoch(1),
            correlated: true,
            controlKind: "review_result",
          }
        : {
            actorBindingEpoch: participantBindingEpoch(1),
            targetBindingEpoch: participantBindingEpoch(1),
          },
    ), { allowed: false, code: "UNKNOWN_PRINCIPAL" }, `${action}: ${entryId}`);
  }
});

test("symbol principal map entries are never read or used as authority", () => {
  const state = councilState("boss-principal");
  const boss = state.principals["boss-principal"];
  Reflect.deleteProperty(state.principals, "boss-principal");
  let getterCalls = 0;
  Object.defineProperty(state.principals, Symbol("boss-principal"), {
    enumerable: true,
    get() {
      getterCalls += 1;
      return boss;
    },
  });

  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
  assert.equal(getterCalls, 0);
});

test("symbol metadata makes the principal map unauthorized without invoking it", () => {
  const state = councilState("boss-principal");
  let getterCalls = 0;
  Object.defineProperty(state.principals, Symbol("metadata"), {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "untrusted";
    },
  });
  for (const principalId of ["boss-principal", "council-principal"]) {
    const descriptor = Object.getOwnPropertyDescriptor(state.principals, principalId);
    assert.equal(descriptor?.enumerable, true);
    assert.equal(Object.hasOwn(descriptor ?? {}, "value"), true);
  }

  assert.deepEqual(authorizeBossPolicy(
    state,
    "boss-principal",
    "send",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
  assert.equal(getterCalls, 0);
});

test("an actor entry whose embedded principal ID differs from its map key is unknown", () => {
  const state = councilState("boss-principal");
  state.principals["council-principal"] = {
    ...state.principals["council-principal"],
    principalId: "substituted-council-principal",
  };
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
});

test("a target entry whose embedded principal ID differs from its map key is unknown", () => {
  const state = councilState("substituted-boss-principal");
  state.principals["boss-principal"] = {
    ...state.principals["boss-principal"],
    principalId: "substituted-boss-principal",
  };
  assert.deepEqual(authorizeBossPolicy(
    state,
    "council-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "review_result",
    },
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
});

test("self control requires both correlation and a control kind", () => {
  const state = councilState("boss-principal");
  const bindingContext = {
    actorBindingEpoch: participantBindingEpoch(1),
    targetBindingEpoch: participantBindingEpoch(1),
  };
  assert.deepEqual(authorizeBossPolicy(
    state,
    "boss-principal",
    "control",
    "boss-principal",
    { ...bindingContext, controlKind: "decision" },
  ), { allowed: false, code: "CONTROL_REQUIRES_CORRELATION" });
  assert.deepEqual(authorizeBossPolicy(
    state,
    "boss-principal",
    "control",
    "boss-principal",
    { ...bindingContext, correlated: true },
  ), { allowed: false, code: "CONTROL_REQUIRES_CORRELATION" });
});

test("correlated self control must satisfy the structured control edge", () => {
  assert.deepEqual(authorizeBossPolicy(
    councilState("boss-principal"),
    "boss-principal",
    "control",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "decision",
    },
  ), { allowed: false, code: "CONTROL_KIND_DENIED" });
});

test("non-control self access remains allowed", () => {
  assert.deepEqual(authorizeBossPolicy(
    councilState("boss-principal"),
    "boss-principal",
    "send",
    "boss-principal",
    {
      actorBindingEpoch: participantBindingEpoch(1),
      targetBindingEpoch: participantBindingEpoch(1),
    },
  ), { allowed: true, reason: "self" });
});

function stateWithDuplicateActiveParticipant(
  principalId: string,
  duplicatePrincipalId: string,
  overrides: Partial<BossPrivatePrincipal> = {},
): BossPolicyState {
  const state = bossPolicyStateForVector(BOSS_POLICY_VECTORS[0]!);
  const original = state.principals[principalId];
  assert.equal(original?.principalClass, "boss-private");
  state.principals[duplicatePrincipalId] = {
    ...structuredClone(original as BossPrivatePrincipal),
    principalId: duplicatePrincipalId,
    ...overrides,
  };
  return state;
}

const activeIdentityEpoch = {
  actorBindingEpoch: participantBindingEpoch(1),
  targetBindingEpoch: participantBindingEpoch(1),
} as const;

test("active Worker and Scout participant identities must be unique for reciprocal Manager edges", () => {
  const cases = [
    {
      role: "Worker",
      state: stateWithDuplicateActiveParticipant("worker", "worker-duplicate"),
      participantId: "worker",
      actorId: "worker",
      targetId: "manager",
      controlKind: "assignment_response",
    },
    {
      role: "Scout",
      state: stateWithDuplicateActiveParticipant("scout", "scout-duplicate"),
      participantId: "scout",
      actorId: "scout",
      targetId: "manager",
      controlKind: "assignment_response",
    },
  ] as const;

  for (const { role, state, participantId, actorId, targetId, controlKind } of cases) {
    assert.deepEqual(authorizeBossPolicy(
      state,
      actorId,
      "send",
      targetId,
      activeIdentityEpoch,
    ), { allowed: false, code: "AMBIGUOUS_PARTICIPANT_IDENTITY" }, `${role} -> Manager communication`);
    assert.deepEqual(authorizeBossPolicy(
      state,
      actorId,
      "control",
      targetId,
      { ...activeIdentityEpoch, correlated: true, controlKind },
    ), { allowed: false, code: "AMBIGUOUS_PARTICIPANT_IDENTITY" }, `${role} -> Manager control`);
    assert.deepEqual(authorizeBossPolicy(
      state,
      targetId,
      "send",
      actorId,
      activeIdentityEpoch,
    ), { allowed: false, code: "AMBIGUOUS_PARTICIPANT_IDENTITY" }, `Manager -> ${role} communication`);
    assert.deepEqual(authorizeBossPolicy(
      state,
      targetId,
      "control",
      actorId,
      { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_request" },
    ), { allowed: false, code: "AMBIGUOUS_PARTICIPANT_IDENTITY" }, `Manager -> ${role} control`);
    assert.equal(state.principals[actorId]?.principalClass === "boss-private"
      ? state.principals[actorId].participantId
      : undefined, participantId);
  }
});

test("participant identity ambiguity spans Worker and Scout roles and binding epochs", () => {
  const state = stateWithDuplicateActiveParticipant("worker", "scout-sharing-worker-identity", {
    role: "scout",
    bindingEpoch: participantBindingEpoch(2),
    assignedManagerParticipantId: "manager",
  });
  assert.deepEqual(authorizeBossPolicy(
    state,
    "manager",
    "control",
    "worker",
    { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_request" },
  ), { allowed: false, code: "AMBIGUOUS_PARTICIPANT_IDENTITY" });
  assert.deepEqual(authorizeBossPolicy(
    state,
    "scout-sharing-worker-identity",
    "control",
    "manager",
    {
      actorBindingEpoch: participantBindingEpoch(2),
      targetBindingEpoch: participantBindingEpoch(1),
      correlated: true,
      controlKind: "assignment_response",
    },
  ), { allowed: false, code: "AMBIGUOUS_PARTICIPANT_IDENTITY" });
});

test("active Manager and Controller participant identities must be unique for allow edges", () => {
  const managerState = stateWithDuplicateActiveParticipant("manager", "manager-duplicate");
  for (const [name, actorId, action, targetId, context] of [
    ["Manager communication actor", "manager", "send", "worker", activeIdentityEpoch],
    ["Manager communication target", "worker", "send", "manager", activeIdentityEpoch],
    ["Manager control actor", "manager", "control", "worker", { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_request" }],
    ["Manager control target", "worker", "control", "manager", { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_response" }],
  ] as const) {
    assert.deepEqual(authorizeBossPolicy(managerState, actorId, action, targetId, context), {
      allowed: false,
      code: "AMBIGUOUS_PARTICIPANT_IDENTITY",
    }, name);
  }

  const controllerState = stateWithDuplicateActiveParticipant("controller", "controller-duplicate");
  for (const [name, actorId, action, targetId, context] of [
    ["Controller broad discovery actor", "controller", "discover", "council", activeIdentityEpoch],
    ["Controller control actor", "controller", "control", "worker", { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_request" }],
    ["Controller control target", "worker", "control", "controller", { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_response" }],
  ] as const) {
    assert.deepEqual(authorizeBossPolicy(controllerState, actorId, action, targetId, context), {
      allowed: false,
      code: "AMBIGUOUS_PARTICIPANT_IDENTITY",
    }, name);
  }
});

test("unique active participant identities retain communication, assignment, discovery, and control allows", () => {
  const state = bossPolicyStateForVector(BOSS_POLICY_VECTORS[0]!);
  const validCases = [
    ["Worker communication", "worker", "send", "manager", activeIdentityEpoch],
    ["Scout assignment", "manager", "control", "scout", { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_request" }],
    ["Manager assignment", "worker", "control", "manager", { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_response" }],
    ["Controller discovery", "controller", "discover", "council", activeIdentityEpoch],
    ["Controller control", "controller", "control", "worker", { ...activeIdentityEpoch, correlated: true, controlKind: "assignment_request" }],
  ] as const;
  for (const [name, actorId, action, targetId, context] of validCases) {
    assert.equal(authorizeBossPolicy(state, actorId, action, targetId, context).allowed, true, name);
  }
});

test("revoked, replaced, and other-run participant records do not create active identity ambiguity", () => {
  for (const [name, overrides] of [
    ["revoked", { state: "revoked" }],
    ["replaced", { state: "replaced" }],
    ["other run", { bossRunId: "run-b" }],
  ] as const) {
    const state = stateWithDuplicateActiveParticipant("worker", `worker-${name}`, overrides);
    assert.deepEqual(authorizeBossPolicy(state, "worker", "send", "manager", activeIdentityEpoch), {
      allowed: true,
      reason: "communication-profile",
    }, name);
  }
});

test("malformed unrelated principal entries are ignored during uniqueness checks without traps", () => {
  const state = bossPolicyStateForVector(BOSS_POLICY_VECTORS[0]!);
  let trapCalls = 0;
  const trapped = new Proxy({}, {
    get() {
      trapCalls += 1;
      throw new Error("principal value must not be read");
    },
    getOwnPropertyDescriptor() {
      trapCalls += 1;
      throw new Error("principal value descriptor must not be read");
    },
    getPrototypeOf() {
      trapCalls += 1;
      throw new Error("principal value prototype must not be read");
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error("principal value keys must not be read");
    },
  });
  state.principals["unrelated-proxy"] = trapped as BossPrivatePrincipal;

  let getterCalls = 0;
  state.principals["unrelated-accessor"] = Object.defineProperty({}, "participantId", {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error("principal accessor must not be invoked");
    },
  }) as BossPrivatePrincipal;

  const nestedArrayProxy = new Proxy(["worker"], {
    getOwnPropertyDescriptor() {
      trapCalls += 1;
      throw new Error("assignment array descriptor must not be read");
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error("assignment array keys must not be read");
    },
  });
  state.principals["unrelated-manager"] = {
    ...(state.principals.manager as BossPrivatePrincipal),
    principalId: "unrelated-manager",
    participantId: "unrelated-manager",
    assignedParticipantIds: nestedArrayProxy,
  };

  assert.deepEqual(authorizeBossPolicy(state, "worker", "send", "manager", activeIdentityEpoch), {
    allowed: true,
    reason: "communication-profile",
  });
  assert.equal(trapCalls, 0);
  assert.equal(getterCalls, 0);
});

test("proxied policy containers and coercible principal IDs fail closed without traps or coercion", () => {
  const source = bossPolicyStateForVector(BOSS_POLICY_VECTORS[0]!);
  let trapCalls = 0;
  const trappedState = new Proxy(source, {
    getPrototypeOf() {
      trapCalls += 1;
      throw new Error("state proxy must not be reflected");
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error("state proxy must not be reflected");
    },
  });
  assert.deepEqual(authorizeBossPolicy(trappedState, "worker", "send", "manager", activeIdentityEpoch), {
    allowed: false,
    code: "UNKNOWN_PRINCIPAL",
  });

  const trappedPrincipals = new Proxy(source.principals, {
    getPrototypeOf() {
      trapCalls += 1;
      throw new Error("principal map proxy must not be reflected");
    },
    ownKeys() {
      trapCalls += 1;
      throw new Error("principal map proxy must not be reflected");
    },
  });
  assert.deepEqual(authorizeBossPolicy({ principals: trappedPrincipals }, "worker", "send", "manager", activeIdentityEpoch), {
    allowed: false,
    code: "UNKNOWN_PRINCIPAL",
  });

  let coercionCalls = 0;
  const coercibleId = Object.defineProperty({}, Symbol.toPrimitive, {
    get() {
      coercionCalls += 1;
      return () => {
        coercionCalls += 1;
        return "worker";
      };
    },
  });
  assert.deepEqual(authorizeBossPolicy(
    source,
    coercibleId as unknown as string,
    "send",
    "manager",
    activeIdentityEpoch,
  ), { allowed: false, code: "UNKNOWN_PRINCIPAL" });
  assert.equal(trapCalls, 0);
  assert.equal(coercionCalls, 0);
});

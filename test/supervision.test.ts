import assert from "node:assert/strict";
import test from "node:test";
import { ContractValidationError, canonicalHash, triggerGeneration, workerGeneration } from "../src/canonical.ts";
import type { DeliveryIntent } from "../src/boss-wire.ts";
import {
  ACTIVE_OPERATION_LEASE_VERSION,
  ACTIVITY_RECORD_VERSION,
  EXTERNAL_WAIT_LEASE_VERSION,
  LIFECYCLE_SUBSCRIPTION_VERSION,
  LIFECYCLE_TRIGGER_SCHEMA_VERSION,
  LIFECYCLE_TRIGGER_VERSION,
  MAX_EXTERNAL_WAIT_LEASE_MS_DEFAULT,
  SUBSCRIBER_REBIND_MIGRATION_VERSION,
  aggregateDeliveryIntent,
  authorizeSupervisorSubscription,
  inactivityTransitionId,
  isSmartInactivitySuppressed,
  parseActiveOperationLease,
  parseAuthenticatedActivity,
  parseExternalWaitLease,
  parseInactivityEdgeKey,
  parseLifecycleSubscription,
  parseLifecycleTarget,
  parseLifecycleTrigger,
  parseSubscriberRebindMigration,
  rebindMigrationEvidenceDigest,
  validateLifecycleSubscriptionStore,
  validateActiveOperationLeaseRenewal,
  validateExternalWaitLeaseRenewal,
  type LifecycleTarget,
  type SupervisorAuthorizationRequest,
} from "../src/supervision.ts";
import {
  ACTIVE_OPERATION_LEASE_VECTOR,
  AUTHENTICATED_ACTIVITY_VECTOR,
  BLOCKED_REBIND_MIGRATION_VECTOR,
  BOSS_MANAGER_SUBSCRIPTION_VECTOR,
  COMMITTED_REBIND_MIGRATION_VECTOR,
  EXTERNAL_WAIT_LEASE_VECTOR,
  INACTIVITY_EDGE_VECTORS,
  LIFECYCLE_TRIGGER_VECTOR,
  LIFECYCLE_SUBSCRIPTION_SCHEDULER_NEGATIVE_VECTORS,
  MANAGER_WORKER_SUBSCRIPTION_VECTOR,
  REBIND_MIGRATION_NEGATIVE_VECTORS,
  SUPERVISION_VECTOR_CORPUS,
  SUPERVISION_VECTOR_HASH_DOMAIN,
  SUPERVISION_VECTORS_HASH,
  SUPERVISOR_ACL_VECTORS,
  stateForSupervisorAclVector,
} from "../src/supervision-vectors.ts";

const MANAGER_PRINCIPAL_ID = "manager-a";
const MANAGER_PARTICIPANT_ID = "manager-participant-a";

function withInheritedField<T extends object>(record: T, field: keyof T): T {
  const ownFields = { ...record } as Record<PropertyKey, unknown>;
  Reflect.deleteProperty(ownFields, field);
  return Object.assign(Object.create({ [field]: record[field] }), ownFields) as T;
}

function withOwnGetter<T extends object>(record: T, field: keyof T, onGet: () => void): T {
  const value = record[field];
  return Object.defineProperty({ ...record }, field, {
    configurable: true,
    enumerable: true,
    get() {
      onGet();
      return value;
    },
  });
}

function withInheritedGetter<T extends object>(record: T, field: keyof T, onGet: () => void): T {
  const value = record[field];
  const ownFields = { ...record } as Record<PropertyKey, unknown>;
  Reflect.deleteProperty(ownFields, field);
  const prototype = Object.defineProperty({}, field, {
    configurable: true,
    enumerable: true,
    get() {
      onGet();
      return value;
    },
  });
  return Object.assign(Object.create(prototype), ownFields) as T;
}

const AUTHORITATIVE_SUPERVISOR_MAP_FIELDS = ["principals", "workers", "currentManagerByRun"] as const;
type AuthoritativeSupervisorMapField = (typeof AUTHORITATIVE_SUPERVISOR_MAP_FIELDS)[number];

function authoritativeSupervisorMap(
  state: ReturnType<typeof stateForSupervisorAclVector>,
  field: AuthoritativeSupervisorMapField,
): Record<string, unknown> {
  const descriptor = Object.getOwnPropertyDescriptor(state, field);
  assert.ok(descriptor !== undefined && Object.hasOwn(descriptor, "value"));
  return descriptor.value as Record<string, unknown>;
}

function assertMalformedSupervisorMapsFailClosed(
  request: SupervisorAuthorizationRequest,
): void {
  for (const field of AUTHORITATIVE_SUPERVISOR_MAP_FIELDS) {
    const denial = field === "principals" ? "UNKNOWN_SUBSCRIBER" : "UNKNOWN_TARGET";
    for (const shape of ["inherited", "non-enumerable", "accessor"] as const) {
      const state = stateForSupervisorAclVector();
      const map = authoritativeSupervisorMap(state, field);
      let getterCalls = 0;
      if (shape === "inherited") {
        Reflect.deleteProperty(state, field);
        Object.setPrototypeOf(state, { [field]: map });
      } else if (shape === "non-enumerable") {
        Object.defineProperty(state, field, { configurable: true, enumerable: false, value: map });
      } else {
        Object.defineProperty(state, field, {
          configurable: true,
          enumerable: true,
          get() {
            getterCalls += 1;
            return map;
          },
        });
      }
      assert.deepEqual(
        authorizeSupervisorSubscription(state, request),
        { allowed: false, code: denial },
        `${shape} top-level ${field} map must fail closed`,
      );
      assert.equal(getterCalls, 0, `${shape} top-level ${field} getter must not be invoked`);
    }

    for (const shape of ["inherited", "array id 0", "symbol-bearing", "non-enumerable"] as const) {
      const state = stateForSupervisorAclVector();
      const map = authoritativeSupervisorMap(state, field);
      let malformedMap: object;
      if (shape === "inherited") {
        malformedMap = Object.create(map);
      } else if (shape === "array id 0") {
        malformedMap = ["id-0"];
      } else if (shape === "symbol-bearing") {
        malformedMap = { ...map };
        Reflect.set(malformedMap, Symbol("metadata"), true);
      } else {
        malformedMap = { ...map };
        Object.defineProperty(malformedMap, "metadata", { enumerable: false, value: true });
      }
      Object.defineProperty(state, field, { configurable: true, enumerable: true, value: malformedMap });
      assert.deepEqual(
        authorizeSupervisorSubscription(state, request),
        { allowed: false, code: denial },
        `${shape} ${field} map must fail closed`,
      );
    }
  }
}

function invalidArrayShapes<T>(entry: T): Array<{ name: string; value: T[]; accessorCalls?: () => number }> {
  const sparse = new Array<T>(1);

  const inherited = new Array<T>(1);
  const inheritedPrototype = Object.create(Array.prototype) as Record<PropertyKey, unknown>;
  Object.defineProperty(inheritedPrototype, "0", { enumerable: true, value: entry });
  Object.setPrototypeOf(inherited, inheritedPrototype);

  let accessorCallCount = 0;
  const accessor = Object.defineProperty([entry], "0", {
    enumerable: true,
    get() {
      accessorCallCount += 1;
      return entry;
    },
  });

  const symbolProperty = [entry];
  Reflect.set(symbolProperty, Symbol("metadata"), true);

  const nonIndexProperty = Object.assign([entry], { metadata: true });

  const nonEnumerableIndex = [entry];
  Object.defineProperty(nonEnumerableIndex, "0", { enumerable: false, value: entry });

  return [
    { name: "sparse", value: sparse },
    { name: "inherited index", value: inherited },
    { name: "accessor index", value: accessor, accessorCalls: () => accessorCallCount },
    { name: "symbol property", value: symbolProperty },
    { name: "non-index property", value: nonIndexProperty },
    { name: "non-enumerable index", value: nonEnumerableIndex },
  ];
}

test("supervision contract and vector schema versions are frozen", () => {
  assert.equal(LIFECYCLE_SUBSCRIPTION_VERSION, "orc.lifecycle-subscription.v1");
  assert.equal(ACTIVITY_RECORD_VERSION, "orc.activity-record.v1");
  assert.equal(ACTIVE_OPERATION_LEASE_VERSION, "orc.active-operation-lease.v1");
  assert.equal(EXTERNAL_WAIT_LEASE_VERSION, "orc.external-wait-lease.v1");
  assert.equal(SUBSCRIBER_REBIND_MIGRATION_VERSION, "orc.subscriber-rebind-migration.v1");
  assert.equal(LIFECYCLE_TRIGGER_SCHEMA_VERSION, 1);
  assert.equal(LIFECYCLE_TRIGGER_VERSION, "orc.lifecycle-trigger.v1");
  assert.equal(MAX_EXTERNAL_WAIT_LEASE_MS_DEFAULT, 7_200_000);
});

test("supervision golden corpus has a deterministic domain-separated hash", () => {
  assert.equal(canonicalHash(SUPERVISION_VECTOR_HASH_DOMAIN, SUPERVISION_VECTOR_CORPUS), SUPERVISION_VECTORS_HASH);
  assert.equal(inactivityTransitionId(INACTIVITY_EDGE_VECTORS[0]), LIFECYCLE_TRIGGER_VECTOR.transitionId);
  assert.equal(inactivityTransitionId(INACTIVITY_EDGE_VECTORS[1]), "768332ad37f3ff0884788581fc2ef60ef4c744b45f1f2b1b0cc2e1fd47c68c60");
  assert.notEqual(inactivityTransitionId(INACTIVITY_EDGE_VECTORS[0]), inactivityTransitionId(INACTIVITY_EDGE_VECTORS[1]));
});

test("golden subscription, activity, lease, trigger, and migration records parse exactly", () => {
  assert.deepEqual(parseLifecycleSubscription(MANAGER_WORKER_SUBSCRIPTION_VECTOR), MANAGER_WORKER_SUBSCRIPTION_VECTOR);
  assert.deepEqual(parseLifecycleSubscription(BOSS_MANAGER_SUBSCRIPTION_VECTOR), BOSS_MANAGER_SUBSCRIPTION_VECTOR);
  assert.deepEqual(parseAuthenticatedActivity(AUTHENTICATED_ACTIVITY_VECTOR), AUTHENTICATED_ACTIVITY_VECTOR);
  assert.deepEqual(parseActiveOperationLease(ACTIVE_OPERATION_LEASE_VECTOR), ACTIVE_OPERATION_LEASE_VECTOR);
  assert.deepEqual(parseExternalWaitLease(EXTERNAL_WAIT_LEASE_VECTOR), EXTERNAL_WAIT_LEASE_VECTOR);
  assert.deepEqual(parseLifecycleTrigger(LIFECYCLE_TRIGGER_VECTOR), LIFECYCLE_TRIGGER_VECTOR);
  assert.deepEqual(parseSubscriberRebindMigration(COMMITTED_REBIND_MIGRATION_VECTOR), COMMITTED_REBIND_MIGRATION_VECTOR);
  assert.deepEqual(parseSubscriberRebindMigration(BLOCKED_REBIND_MIGRATION_VECTOR), BLOCKED_REBIND_MIGRATION_VECTOR);
});

test("every versioned supervision schema rejects unknown versions and every schema rejects unknown keys", () => {
  const versioned: Array<[unknown, (value: unknown) => unknown]> = [
    [{ ...MANAGER_WORKER_SUBSCRIPTION_VECTOR, version: "orc.lifecycle-subscription.v2" }, parseLifecycleSubscription],
    [{ ...AUTHENTICATED_ACTIVITY_VECTOR, version: "orc.activity-record.v2" }, parseAuthenticatedActivity],
    [{ ...ACTIVE_OPERATION_LEASE_VECTOR, version: "orc.active-operation-lease.v2" }, parseActiveOperationLease],
    [{ ...EXTERNAL_WAIT_LEASE_VECTOR, version: "orc.external-wait-lease.v2" }, parseExternalWaitLease],
    [{ ...LIFECYCLE_TRIGGER_VECTOR, version: "orc.lifecycle-trigger.v2" }, parseLifecycleTrigger],
    [{ ...COMMITTED_REBIND_MIGRATION_VECTOR, version: "orc.subscriber-rebind-migration.v2" }, parseSubscriberRebindMigration],
  ];
  for (const [value, parse] of versioned) assert.throws(() => parse(value), /unsupported version/);

  const strict: Array<[unknown, (value: unknown) => unknown]> = [
    [{ ...MANAGER_WORKER_SUBSCRIPTION_VECTOR, unknown: true }, parseLifecycleSubscription],
    [{ ...AUTHENTICATED_ACTIVITY_VECTOR, unknown: true }, parseAuthenticatedActivity],
    [{ ...ACTIVE_OPERATION_LEASE_VECTOR, unknown: true }, parseActiveOperationLease],
    [{ ...EXTERNAL_WAIT_LEASE_VECTOR, unknown: true }, parseExternalWaitLease],
    [{ ...LIFECYCLE_TRIGGER_VECTOR, unknown: true }, parseLifecycleTrigger],
    [{ ...INACTIVITY_EDGE_VECTORS[0], unknown: true }, parseInactivityEdgeKey],
    [{ ...COMMITTED_REBIND_MIGRATION_VECTOR, unknown: true }, parseSubscriberRebindMigration],
  ];
  for (const [value, parse] of strict) assert.throws(() => parse(value), /is not supported/);
});

test("subscription predicates and inactivity configuration are strict and normalized", () => {
  const base = MANAGER_WORKER_SUBSCRIPTION_VECTOR;
  const invalid: unknown[] = [
    { ...base, predicates: [] },
    { ...base, predicates: [{ kind: "failed" }, { kind: "failed" }] },
    { ...base, predicates: [{ kind: "state_in", states: [] }] },
    { ...base, predicates: [{ kind: "state_in", states: ["ready", "ready"] }] },
    { ...base, predicates: [{ kind: "unknown" }] },
    { ...base, inactivityMode: undefined },
    { ...base, inactiveAfterMs: undefined },
    { ...base, activityBasis: undefined },
    { ...base, target: { kind: "worker", workerId: "worker-a", workerGeneration: 7 }, followReplacement: true },
    { ...BOSS_MANAGER_SUBSCRIPTION_VECTOR, bossRunId: "boss-run-b" },
    { ...base, updatedAt: "2026-07-28T11:59:59.000Z" },
    { ...base, expiresAt: "2026-07-28T11:59:59.000Z" },
    { ...base, dueAt: "2026-07-28T11:59:59.000Z" },
    { ...base, cooldownMs: -1 },
    { ...base, maxFires: 0 },
  ];
  for (const value of invalid) assert.throws(() => parseLifecycleSubscription(value), ContractValidationError);

  const noInactivity = {
    ...base,
    predicates: [{ kind: "failed" }],
    inactivityMode: undefined,
    inactiveAfterMs: undefined,
    activityBasis: undefined,
    dueAt: undefined,
  };
  assert.doesNotThrow(() => parseLifecycleSubscription(noInactivity));
  assert.throws(() => parseLifecycleSubscription({ ...noInactivity, dueAt: base.dueAt }), /inactive_for/);
  assert.throws(() => parseLifecycleSubscription({ ...noInactivity, inactivityMode: "smart" }), /forbidden otherwise/);
});

for (const vector of LIFECYCLE_SUBSCRIPTION_SCHEDULER_NEGATIVE_VECTORS) {
  test(`lifecycle subscription scheduler rejects: ${vector.name}`, () => {
    const before = structuredClone(vector.value);
    assert.throws(() => parseLifecycleSubscription(vector.value), ContractValidationError);
    const stored = validateLifecycleSubscriptionStore(vector.value);
    assert.equal(stored.ok, false);
    if (!stored.ok) {
      assert.equal(stored.status, "corrupt");
      assert.equal(stored.preserveExisting, true);
      assert.equal(stored.mutationAllowed, false);
    }
    assert.deepEqual(vector.value, before);
  });
}

test("lifecycle subscription scheduler accepts exact deadline and fire-cap boundaries", () => {
  const exactDeadline = {
    ...MANAGER_WORKER_SUBSCRIPTION_VECTOR,
    createdAt: "1970-01-01T00:00:00.000Z",
    updatedAt: "1970-01-01T00:00:00.000Z",
    lastActivityAt: "1970-01-01T00:00:00.000Z",
    inactiveAfterMs: 253_402_300_799_999,
    dueAt: "9999-12-31T23:59:59.999Z",
  };
  assert.deepEqual(parseLifecycleSubscription(exactDeadline), exactDeadline);

  const exactCap = {
    ...BOSS_MANAGER_SUBSCRIPTION_VECTOR,
    triggerGeneration: triggerGeneration(BOSS_MANAGER_SUBSCRIPTION_VECTOR.maxFires!),
  };
  assert.deepEqual(parseLifecycleSubscription(exactCap), exactCap);

  const uncapped = {
    ...MANAGER_WORKER_SUBSCRIPTION_VECTOR,
    triggerGeneration: triggerGeneration(Number.MAX_SAFE_INTEGER),
  };
  assert.deepEqual(parseLifecycleSubscription(uncapped), uncapped);
});

test("lifecycle subscription scheduler fields are descriptor-safe and never coerced", () => {
  for (const field of ["lastActivityAt", "inactiveAfterMs", "dueAt", "triggerGeneration", "maxFires"] as const) {
    let getterCalls = 0;
    const accessor = Object.defineProperty({ ...BOSS_MANAGER_SUBSCRIPTION_VECTOR }, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return BOSS_MANAGER_SUBSCRIPTION_VECTOR[field];
      },
    });
    assert.throws(() => parseLifecycleSubscription(accessor), ContractValidationError, field);
    assert.equal(validateLifecycleSubscriptionStore(accessor).ok, false, field);
    assert.equal(getterCalls, 0, `${field} getter must not run`);
  }

  for (const field of ["lastActivityAt", "inactiveAfterMs", "dueAt", "triggerGeneration", "maxFires"] as const) {
    let coercionCalls = 0;
    const coercible = {
      valueOf() {
        coercionCalls += 1;
        return BOSS_MANAGER_SUBSCRIPTION_VECTOR[field];
      },
      toString() {
        coercionCalls += 1;
        return String(BOSS_MANAGER_SUBSCRIPTION_VECTOR[field]);
      },
    };
    const value = { ...BOSS_MANAGER_SUBSCRIPTION_VECTOR, [field]: coercible };
    assert.throws(() => parseLifecycleSubscription(value), ContractValidationError, field);
    assert.equal(validateLifecycleSubscriptionStore(value).ok, false, field);
    assert.equal(coercionCalls, 0, `${field} coercion hooks must not run`);
  }

  for (const field of ["lastActivityAt", "inactiveAfterMs", "dueAt", "triggerGeneration", "maxFires"] as const) {
    let trapCalls = 0;
    const trappedValue = new Proxy({}, {
      get(target, property, receiver) {
        trapCalls += 1;
        return Reflect.get(target, property, receiver);
      },
      getOwnPropertyDescriptor(target, property) {
        trapCalls += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
      getPrototypeOf(target) {
        trapCalls += 1;
        return Reflect.getPrototypeOf(target);
      },
      ownKeys(target) {
        trapCalls += 1;
        return Reflect.ownKeys(target);
      },
    });
    const value = { ...BOSS_MANAGER_SUBSCRIPTION_VECTOR, [field]: trappedValue };
    assert.throws(() => parseLifecycleSubscription(value), ContractValidationError, field);
    assert.equal(validateLifecycleSubscriptionStore(value).ok, false, field);
    assert.equal(trapCalls, 0, `${field} proxy traps must not run`);
  }
});

test("lifecycle subscription parser and store gate reject proxies without executing traps", () => {
  let trapCalls = 0;
  const proxied = new Proxy(MANAGER_WORKER_SUBSCRIPTION_VECTOR, {
    get(target, property, receiver) {
      trapCalls += 1;
      return Reflect.get(target, property, receiver);
    },
    getOwnPropertyDescriptor(target, property) {
      trapCalls += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    getPrototypeOf(target) {
      trapCalls += 1;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      trapCalls += 1;
      return Reflect.ownKeys(target);
    },
  });
  assert.throws(() => parseLifecycleSubscription(proxied), ContractValidationError);
  const stored = validateLifecycleSubscriptionStore(proxied);
  assert.equal(stored.ok, false);
  if (!stored.ok) assert.equal(stored.status, "corrupt");
  assert.equal(trapCalls, 0);
});

test("subscription predicate arrays require dense own enumerable data indices without metadata", () => {
  const base = {
    ...MANAGER_WORKER_SUBSCRIPTION_VECTOR,
    predicates: [{ kind: "failed" as const }],
    inactivityMode: undefined,
    inactiveAfterMs: undefined,
    activityBasis: undefined,
    dueAt: undefined,
  };
  assert.deepEqual(parseLifecycleSubscription(base).predicates, [{ kind: "failed" }]);

  for (const variant of invalidArrayShapes({ kind: "failed" as const })) {
    assert.throws(
      () => parseLifecycleSubscription({ ...base, predicates: variant.value }),
      ContractValidationError,
      variant.name,
    );
    assert.equal(variant.accessorCalls?.() ?? 0, 0, variant.name);
  }
});

test("state_in state arrays require dense own enumerable data indices without metadata", () => {
  const subscription = (states: unknown) => ({
    ...MANAGER_WORKER_SUBSCRIPTION_VECTOR,
    predicates: [{ kind: "state_in", states }],
    inactivityMode: undefined,
    inactiveAfterMs: undefined,
    activityBasis: undefined,
    dueAt: undefined,
  });
  assert.deepEqual(parseLifecycleSubscription(subscription(["ready"])).predicates, [{ kind: "state_in", states: ["ready"] }]);

  for (const variant of invalidArrayShapes("ready")) {
    assert.throws(
      () => parseLifecycleSubscription(subscription(variant.value)),
      ContractValidationError,
      variant.name,
    );
    assert.equal(variant.accessorCalls?.() ?? 0, 0, variant.name);
  }
});

test("target schemas reject ambiguity, stale generations, and unknown role vocabulary", () => {
  assert.deepEqual(parseLifecycleTarget({ kind: "worker", workerId: "w", workerGeneration: 1 }), {
    kind: "worker",
    workerId: "w",
    workerGeneration: 1,
  });
  assert.deepEqual(parseLifecycleTarget({ kind: "role", bossRunId: "r", role: "boss" }), {
    kind: "role",
    bossRunId: "r",
    role: "boss",
  });
  assert.throws(() => parseLifecycleTarget({ kind: "worker", workerId: "w", workerGeneration: 0 }), /workerGeneration/);
  assert.throws(() => parseLifecycleTarget({ kind: "role", bossRunId: "r", role: "root" }), /role/);
  assert.throws(() => parseLifecycleTarget({ kind: "role", bossRunId: "r", role: "manager", workerId: "w" }), /workerId/);
});

test("authenticated activity classifies meaningful and liveness events without overlap", () => {
  for (const activityType of ["turn", "tool", "progress", "checkpoint", "assignment", "state_transition"] as const) {
    assert.equal(parseAuthenticatedActivity({ ...AUTHENTICATED_ACTIVITY_VECTOR, activityType }).kind, "meaningful");
    assert.throws(() => parseAuthenticatedActivity({ ...AUTHENTICATED_ACTIVITY_VECTOR, activityType, kind: "liveness" }), /not liveness/);
  }
  for (const activityType of ["heartbeat", "health_confirmation"] as const) {
    assert.equal(parseAuthenticatedActivity({ ...AUTHENTICATED_ACTIVITY_VECTOR, activityType, kind: "liveness" }).kind, "liveness");
    assert.throws(() => parseAuthenticatedActivity({ ...AUTHENTICATED_ACTIVITY_VECTOR, activityType }), /not meaningful/);
  }
});

test("active-operation leases are generation fenced and never exceed hard deadlines", () => {
  const lease = ACTIVE_OPERATION_LEASE_VECTOR;
  const invalid: unknown[] = [
    { ...lease, workerGeneration: 0 },
    { ...lease, processId: 0 },
    { ...lease, renewBy: "2026-07-28T11:59:59.000Z" },
    { ...lease, renewBy: "2026-07-28T12:21:00.000Z" },
    { ...lease, maxUntil: "2026-07-28T12:31:00.000Z" },
    { ...lease, maxUntil: "2026-07-28T13:01:00.000Z", hardWorkerLeaseExpiresAt: "2026-07-28T14:00:00.000Z" },
    { ...lease, state: "running" },
  ];
  for (const value of invalid) assert.throws(() => parseActiveOperationLease(value), ContractValidationError);
});

test("external-wait leases obey the configured ceiling, hard bounds, and process identity rule", () => {
  const lease = EXTERNAL_WAIT_LEASE_VECTOR;
  const invalid: unknown[] = [
    { ...lease, processIdentity: undefined },
    { ...lease, renewBy: "2026-07-28T11:59:59.000Z" },
    { ...lease, renewBy: "2026-07-28T13:31:00.000Z" },
    { ...lease, maxUntil: "2026-07-28T14:00:11.000Z" },
    { ...lease, maxUntil: "2026-07-28T14:00:01.000Z", hardWorkerLeaseExpiresAt: "2026-07-28T14:00:00.000Z" },
    { ...lease, maxUntil: "2026-07-28T15:00:01.000Z", hardWorkerLeaseExpiresAt: "2026-07-28T16:00:00.000Z" },
    { ...lease, expectedWakeAt: "2026-07-28T13:30:01.000Z" },
    { ...lease, expectedWakeAt: "2026-07-28T12:00:09.999Z" },
    { ...lease, sourceRefHash: "not-a-digest" },
    { ...lease, sourceKind: "return_on" },
  ];
  for (const value of invalid) assert.throws(() => parseExternalWaitLease(value), ContractValidationError);
  assert.doesNotThrow(() => parseExternalWaitLease({ ...lease, sourceKind: "timer", processIdentity: undefined }));
  assert.throws(() => parseExternalWaitLease(lease, 0), /positive safe integer/);
  assert.throws(() => parseExternalWaitLease(lease, Number.MAX_SAFE_INTEGER + 1), /positive safe integer/);
});

test("lease renewals preserve identity and immutable maximums while permitting terminal settlement", () => {
  const operationRenewed = { ...ACTIVE_OPERATION_LEASE_VECTOR, renewBy: "2026-07-28T12:02:00.000Z" };
  assert.deepEqual(validateActiveOperationLeaseRenewal(ACTIVE_OPERATION_LEASE_VECTOR, operationRenewed), operationRenewed);
  assert.doesNotThrow(() => validateActiveOperationLeaseRenewal(operationRenewed, { ...operationRenewed, state: "settled" }));
  assert.throws(() => validateActiveOperationLeaseRenewal(operationRenewed, { ...operationRenewed, renewBy: ACTIVE_OPERATION_LEASE_VECTOR.renewBy }), /backwards/);
  assert.throws(() => validateActiveOperationLeaseRenewal(operationRenewed, { ...operationRenewed, maxUntil: "2026-07-28T12:21:00.000Z" }), /cannot change/);
  assert.throws(() => validateActiveOperationLeaseRenewal(operationRenewed, { ...operationRenewed, invocationId: "different" }), /cannot change/);
  assert.throws(() => validateActiveOperationLeaseRenewal({ ...operationRenewed, state: "settled" }, operationRenewed), /terminal lease state/);

  const waitRenewed = { ...EXTERNAL_WAIT_LEASE_VECTOR, renewBy: "2026-07-28T12:20:00.000Z" };
  assert.deepEqual(validateExternalWaitLeaseRenewal(EXTERNAL_WAIT_LEASE_VECTOR, waitRenewed), waitRenewed);
  assert.doesNotThrow(() => validateExternalWaitLeaseRenewal(waitRenewed, { ...waitRenewed, state: "fired" }));
  assert.throws(() => validateExternalWaitLeaseRenewal(waitRenewed, { ...waitRenewed, renewBy: EXTERNAL_WAIT_LEASE_VECTOR.renewBy }), /backwards/);
  assert.throws(() => validateExternalWaitLeaseRenewal(waitRenewed, { ...waitRenewed, maxUntil: "2026-07-28T13:31:00.000Z" }), /cannot change/);
  assert.throws(() => validateExternalWaitLeaseRenewal(waitRenewed, {
    ...waitRenewed,
    sourceRefHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  }), /cannot change/);
  assert.throws(() => validateExternalWaitLeaseRenewal({ ...waitRenewed, state: "fired" }, waitRenewed), /terminal lease state/);
});

test("smart inactivity suppression requires the exact current worker and live operation identity", () => {
  const evidence = {
    workerId: "worker-a",
    workerGeneration: workerGeneration(7),
    now: "2026-07-28T12:01:00.000Z",
    currentOperation: {
      invocationId: ACTIVE_OPERATION_LEASE_VECTOR.invocationId,
      processId: ACTIVE_OPERATION_LEASE_VECTOR.processId,
      cgroupIdentity: ACTIVE_OPERATION_LEASE_VECTOR.cgroupIdentity,
      live: true,
    },
    activeOperation: ACTIVE_OPERATION_LEASE_VECTOR,
  };
  assert.equal(isSmartInactivitySuppressed(evidence), true);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, now: "2026-07-28T12:00:09.999Z" }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, now: ACTIVE_OPERATION_LEASE_VECTOR.startedAt }), true);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, workerGeneration: workerGeneration(8) }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, now: "2026-07-28T12:01:10.001Z" }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, currentOperation: { ...evidence.currentOperation, processId: 4243 } }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, currentOperation: { ...evidence.currentOperation, live: false } }), false);
});

test("smart inactivity honors only current bounded external waits and fails closed on terminal evidence", () => {
  const evidence = {
    workerId: "worker-a",
    workerGeneration: workerGeneration(7),
    now: "2026-07-28T12:09:59.000Z",
    externalWait: EXTERNAL_WAIT_LEASE_VECTOR,
  };
  assert.equal(isSmartInactivitySuppressed(evidence), true);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, now: "2026-07-28T12:00:09.999Z" }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, now: EXTERNAL_WAIT_LEASE_VECTOR.startedAt }), true);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, externalWaitSourceTerminal: true }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, workerGeneration: workerGeneration(8) }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, now: "2026-07-28T12:10:00.001Z" }), false);
  assert.equal(isSmartInactivitySuppressed({ ...evidence, externalWait: { ...EXTERNAL_WAIT_LEASE_VECTOR, state: "cancelled" as const } }), false);
});

test("trigger parsing fences generations, successor transfers, and acknowledgment ordering", () => {
  const trigger = LIFECYCLE_TRIGGER_VECTOR;
  const invalid: unknown[] = [
    { ...trigger, triggerGeneration: 0 },
    { ...trigger, targetWorkerGeneration: 0 },
    { ...trigger, deliveryGroupMembershipRevision: 0 },
    { ...trigger, successorDeliveryGroupId: trigger.deliveryGroupId, recipientTransferGeneration: 1 },
    { ...trigger, successorDeliveryGroupId: "successor", recipientTransferGeneration: 0 },
    { ...trigger, acknowledgedAt: "2026-07-28T12:00:59.000Z" },
  ];
  for (const value of invalid) assert.throws(() => parseLifecycleTrigger(value), ContractValidationError);
  assert.doesNotThrow(() => parseLifecycleTrigger({ ...trigger, successorDeliveryGroupId: "successor", recipientTransferGeneration: 1 }));
});

test("inactivity transition encoding includes every normalized edge dimension", () => {
  const baseline = INACTIVITY_EDGE_VECTORS[0];
  const dimensions = [
    { workerId: "worker-b" },
    { workerGeneration: workerGeneration(8) },
    { inactivityEpochId: "inactive-epoch-2" },
    { inactivityMode: "raw" as const },
    { activityBasis: "liveness" as const },
    { inactiveAfterMs: 60_001 },
    { dueAt: "2026-07-28T12:01:00.001Z" },
  ];
  for (const change of dimensions) {
    assert.notEqual(inactivityTransitionId({ ...baseline, ...change }), inactivityTransitionId(baseline));
  }
  assert.throws(() => inactivityTransitionId({ ...baseline, inactiveAfterMs: 0 }), /inactiveAfterMs/);
  assert.throws(() => inactivityTransitionId({ ...baseline, extra: true } as never), /extra/);
});

test("subscriber rebind migration increments epochs once and validates exact old-to-new links", () => {
  const migration = COMMITTED_REBIND_MIGRATION_VECTOR;
  const duplicateOld = [...migration.deliveryGroups, { ...migration.deliveryGroups[0], successorDeliveryGroupId: "another-successor" }];
  const duplicateSuccessor = [...migration.deliveryGroups, {
    oldDeliveryGroupId: "another-old",
    successorDeliveryGroupId: migration.deliveryGroups[0].successorDeliveryGroupId,
    disposition: "migrated" as const,
    recipientTransferGeneration: 1,
  }];
  const invalid: unknown[] = [
    { ...migration, newSubscriberBindingEpoch: migration.oldSubscriberBindingEpoch },
    { ...migration, newSubscriberBindingGeneration: migration.oldSubscriberBindingGeneration + 2 },
    { ...migration, committedAt: undefined },
    { ...migration, committedAt: "2026-07-28T12:04:59.000Z" },
    { ...migration, deliveryGroups: duplicateOld },
    { ...migration, deliveryGroups: duplicateSuccessor },
    { ...migration, deliveryGroups: [{ ...migration.deliveryGroups[0], successorDeliveryGroupId: migration.deliveryGroups[0].oldDeliveryGroupId }] },
    { ...migration, deliveryGroups: [{ ...migration.deliveryGroups[0], successorDeliveryGroupId: undefined }] },
    { ...migration, deliveryGroups: [{ ...migration.deliveryGroups[1], successorDeliveryGroupId: "illegal" }] },
    { ...migration, reauthorized: false, resultingSubscriptionState: "armed" },
    { ...migration, reauthorized: false, resultingSubscriptionState: "suspended" },
    { ...migration, state: "blocked", committedAt: undefined },
    { ...migration, deliveryGroups: [{ ...BLOCKED_REBIND_MIGRATION_VECTOR.deliveryGroups[0] }] },
  ];
  for (const value of invalid) assert.throws(() => parseSubscriberRebindMigration(value), ContractValidationError);
  assert.doesNotThrow(() => parseSubscriberRebindMigration({
    ...migration,
    reauthorized: false,
    resultingSubscriptionState: "suspended",
    deliveryGroups: migration.deliveryGroups.filter((entry) => entry.disposition !== "migrated"),
  }));
});

function releasedClaimMigration(
  observedAt: string,
  releaseProofEstablishedAt: string,
  releasedAt: string,
  authenticatedAt = "2026-07-28T12:05:59.000Z",
): typeof BLOCKED_REBIND_MIGRATION_VECTOR {
  const migration = structuredClone(BLOCKED_REBIND_MIGRATION_VECTOR);
  const evidence = migration.deliveryGroups[0].evidence;
  const claim = evidence.currentClaim.claim;
  assert.ok(claim);
  evidence.currentClaim = {
    status: "claimed",
    observedAt,
    claim: {
      ...claim,
      state: "released",
      releaseProof: {
        deliveryClaimId: claim.deliveryClaimId,
        claimGeneration: claim.claimGeneration,
        recipientSessionId: claim.recipientSessionId,
        ...(claim.recipientTargetSessionId === undefined ? {} : { recipientTargetSessionId: claim.recipientTargetSessionId }),
        recipientBindingEpoch: claim.recipientBindingEpoch,
        barrierId: "release-barrier-claim-blocked",
        noSessionEntry: true,
        noAdapterQueue: true,
        noInflightInvocation: true,
        noPiFollowUp: true,
        noOpenCodePendingPrompt: true,
        establishedAt: releaseProofEstablishedAt,
      },
      releasedAt,
    },
  };
  evidence.authenticatedAt = authenticatedAt;
  const { evidenceDigest: _discarded, ...digestInput } = evidence;
  evidence.evidenceDigest = rebindMigrationEvidenceDigest(digestInput);
  return migration;
}

test("subscriber rebind observations postdate every released-claim timestamp", () => {
  assert.throws(
    () => parseSubscriberRebindMigration(releasedClaimMigration(
      "2026-07-28T12:05:54.000Z",
      "2026-07-28T12:05:54.000Z",
      "2026-07-28T12:05:55.000Z",
    )),
    /currentClaim\.observedAt/,
  );
  assert.doesNotThrow(() => parseSubscriberRebindMigration(releasedClaimMigration(
    "2026-07-28T12:05:55.000Z",
    "2026-07-28T12:05:54.000Z",
    "2026-07-28T12:05:55.000Z",
    "2026-07-28T12:05:55.000Z",
  )));

  assert.throws(
    () => parseSubscriberRebindMigration(releasedClaimMigration(
      "2026-07-28T12:05:53.999Z",
      "2026-07-28T12:05:54.000Z",
      "2026-07-28T12:05:54.000Z",
    )),
    /currentClaim\.observedAt/,
  );
  assert.doesNotThrow(() => parseSubscriberRebindMigration(releasedClaimMigration(
    "2026-07-28T12:05:54.000Z",
    "2026-07-28T12:05:54.000Z",
    "2026-07-28T12:05:54.000Z",
  )));
  assert.throws(
    () => parseSubscriberRebindMigration(releasedClaimMigration(
      "2026-07-28T12:05:55.000Z",
      "2026-07-28T12:05:54.000Z",
      "2026-07-28T12:05:55.000Z",
      "2026-07-28T12:05:54.999Z",
    )),
    /authenticatedAt/,
  );
});

test("subscriber rebind delivery-group arrays require dense own enumerable data indices without metadata", () => {
  const migration = COMMITTED_REBIND_MIGRATION_VECTOR;
  const link = migration.deliveryGroups[0];
  assert.deepEqual(
    parseSubscriberRebindMigration({ ...migration, deliveryGroups: [link] }).deliveryGroups,
    [link],
  );

  for (const variant of invalidArrayShapes(link)) {
    assert.throws(
      () => parseSubscriberRebindMigration({ ...migration, deliveryGroups: variant.value }),
      ContractValidationError,
      variant.name,
    );
    assert.equal(variant.accessorCalls?.() ?? 0, 0, variant.name);
  }
});

for (const vector of REBIND_MIGRATION_NEGATIVE_VECTORS) {
  test(`subscriber rebind rejects: ${vector.name}`, () => {
    const before = structuredClone(vector.value);
    assert.throws(() => parseSubscriberRebindMigration(vector.value), ContractValidationError);
    assert.deepEqual(vector.value, before);
  });
}

for (const vector of SUPERVISOR_ACL_VECTORS) {
  test(`supervisor ACL vector: ${vector.name}`, () => {
    assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), vector.request), vector.expected);
  });
}

test("supervisor ACL vectors cover every permitted edge and fail-closed denial code", () => {
  const allowed = new Set(SUPERVISOR_ACL_VECTORS.flatMap((vector) => vector.expected.allowed ? [vector.expected.reason] : []));
  assert.deepEqual([...allowed].sort(), ["boss_to_manager", "controller_to_participant", "manager_to_assignment", "owner_to_worker"]);
  const denied = new Set(SUPERVISOR_ACL_VECTORS.flatMap((vector) => vector.expected.allowed ? [] : [vector.expected.code]));
  assert.deepEqual([...denied].sort(), [
    "CROSS_RUN_DENIED",
    "FOLLOW_REPLACEMENT_DENIED",
    "REVOKED_SUBSCRIBER",
    "ROLE_SELECTOR_DENIED",
    "STALE_SUBSCRIBER_BINDING",
    "STALE_TARGET_GENERATION",
    "SUPERVISION_EDGE_DENIED",
    "UNKNOWN_SUBSCRIBER",
    "UNKNOWN_TARGET",
  ]);
});

test("supervisor ACL owner-to-worker authorization rejects malformed authoritative map containers", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(vector);
  assertMalformedSupervisorMapsFailClosed(vector.request);
});

test("supervisor ACL Boss current-manager authorization rejects malformed authoritative map containers", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  assertMalformedSupervisorMapsFailClosed(vector.request);
});

test("supervisor ACL requires binding context to be owned by the request record", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(vector);

  const inheritedBindings = Object.assign(Object.create({
    actorBindingEpoch: vector.request.actorBindingEpoch,
    actorBindingGeneration: vector.request.actorBindingGeneration,
  }), {
    actorPrincipalId: vector.request.actorPrincipalId,
    target: vector.request.target,
    followReplacement: vector.request.followReplacement,
  }) as typeof vector.request;
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), inheritedBindings),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );

  assert.equal(vector.request.target.kind, "worker");
  const workerTarget = vector.request.target as Extract<LifecycleTarget, { kind: "worker" }>;
  const validTarget = Object.defineProperties({}, {
    kind: { enumerable: true, value: workerTarget.kind },
    workerId: { enumerable: true, value: workerTarget.workerId },
    workerGeneration: { enumerable: true, value: workerTarget.workerGeneration },
  }) as typeof workerTarget;
  const validRequest = Object.defineProperties({}, {
    actorPrincipalId: { enumerable: true, value: vector.request.actorPrincipalId },
    actorBindingEpoch: { enumerable: true, value: vector.request.actorBindingEpoch },
    actorBindingGeneration: { enumerable: true, value: vector.request.actorBindingGeneration },
    target: { enumerable: true, value: validTarget },
    followReplacement: { enumerable: true, value: vector.request.followReplacement },
  }) as typeof vector.request;
  assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), validRequest), vector.expected);
});

test("supervisor ACL rejects request-field accessors without invoking them", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(vector);

  for (const field of [
    "actorPrincipalId",
    "actorBindingEpoch",
    "actorBindingGeneration",
    "target",
    "followReplacement",
  ] as const) {
    let getterCalls = 0;
    const request: SupervisorAuthorizationRequest = withOwnGetter(
      vector.request,
      field,
      () => { getterCalls += 1; },
    );
    assert.deepEqual(
      authorizeSupervisorSubscription(stateForSupervisorAclVector(), request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `accessor request ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor request ${field} must not be invoked`);
  }

  for (const field of ["actorBindingEpoch", "actorBindingGeneration"] as const) {
    let getterCalls = 0;
    const request: SupervisorAuthorizationRequest = withInheritedGetter(
      vector.request,
      field,
      () => { getterCalls += 1; },
    );
    assert.deepEqual(
      authorizeSupervisorSubscription(stateForSupervisorAclVector(), request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `inherited accessor request ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `inherited accessor request ${field} must not be invoked`);
  }
});

test("supervisor ACL requires exact own enumerable request and target data fields", () => {
  const workerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(workerVector);
  assert.equal(workerVector.request.target.kind, "worker");
  const workerTarget = workerVector.request.target as Extract<LifecycleTarget, { kind: "worker" }>;

  for (const field of ["kind", "workerId", "workerGeneration"] as const) {
    const inheritedRequest: SupervisorAuthorizationRequest = {
      ...workerVector.request,
      target: withInheritedField(workerTarget, field),
    };
    assert.deepEqual(
      authorizeSupervisorSubscription(stateForSupervisorAclVector(), inheritedRequest),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `inherited worker target ${field} must not authorize`,
    );

    let getterCalls = 0;
    const accessorRequest: SupervisorAuthorizationRequest = {
      ...workerVector.request,
      target: withOwnGetter(workerTarget, field, () => { getterCalls += 1; }),
    };
    assert.deepEqual(
      authorizeSupervisorSubscription(stateForSupervisorAclVector(), accessorRequest),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `accessor worker target ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor worker target ${field} must not be invoked`);
  }

  const roleVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(roleVector);
  assert.equal(roleVector.request.target.kind, "role");
  const roleTarget = roleVector.request.target as Extract<LifecycleTarget, { kind: "role" }>;
  for (const field of ["kind", "bossRunId", "role"] as const) {
    let getterCalls = 0;
    const request: SupervisorAuthorizationRequest = {
      ...roleVector.request,
      target: withOwnGetter(roleTarget, field, () => { getterCalls += 1; }),
    };
    assert.deepEqual(
      authorizeSupervisorSubscription(stateForSupervisorAclVector(), request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `accessor role target ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor role target ${field} must not be invoked`);
  }

  const hiddenRequest = { ...workerVector.request };
  Object.defineProperty(hiddenRequest, "actorBindingEpoch", {
    enumerable: false,
    value: workerVector.request.actorBindingEpoch,
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), hiddenRequest),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  const extraRequest = { ...workerVector.request, metadata: true };
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), extraRequest),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  const symbolRequest = { ...workerVector.request };
  Reflect.set(symbolRequest, Symbol("metadata"), true);
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), symbolRequest),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );

  const symbolTarget = { ...workerTarget };
  Reflect.set(symbolTarget, Symbol("metadata"), true);
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), { ...workerVector.request, target: symbolTarget }),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  const extraTarget = { ...workerTarget, metadata: true };
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), {
      ...workerVector.request,
      target: extraTarget,
    }),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  const hiddenTarget = { ...workerTarget };
  Object.defineProperty(hiddenTarget, "workerGeneration", {
    enumerable: false,
    value: workerTarget.workerGeneration,
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), { ...workerVector.request, target: hiddenTarget }),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
});

test("supervisor ACL validates request and target scalars without coercion or proxy execution", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(vector);
  if (vector.request.target.kind !== "worker") assert.fail("expected an exact worker target");
  const workerTarget = vector.request.target;

  let coercionCalls = 0;
  const coercibleId = {
    [Symbol.toPrimitive]() {
      coercionCalls += 1;
      return vector.request.actorPrincipalId;
    },
  };
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), {
      ...vector.request,
      actorPrincipalId: coercibleId as unknown as string,
    }),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  assert.equal(coercionCalls, 0);

  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), {
      ...vector.request,
      actorBindingEpoch: 0 as typeof vector.request.actorBindingEpoch,
    }),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), {
      ...vector.request,
      followReplacement: "false" as unknown as boolean,
    }),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );

  let targetCoercionCalls = 0;
  const coercibleWorkerId = {
    toString() {
      targetCoercionCalls += 1;
      return workerTarget.workerId;
    },
  };
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), {
      ...vector.request,
      target: { ...workerTarget, workerId: coercibleWorkerId as unknown as string },
    }),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  assert.equal(targetCoercionCalls, 0);

  let targetTraps = 0;
  const targetProxy = new Proxy(workerTarget, {
    get(target, property, receiver) {
      targetTraps += 1;
      return Reflect.get(target, property, receiver);
    },
    getOwnPropertyDescriptor(target, property) {
      targetTraps += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    getPrototypeOf(target) {
      targetTraps += 1;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      targetTraps += 1;
      return Reflect.ownKeys(target);
    },
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(stateForSupervisorAclVector(), { ...vector.request, target: targetProxy }),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  assert.equal(targetTraps, 0);
});

test("supervisor ACL rejects an inherited subscriber as unknown", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  const inheritedActor = state.principals[vector.request.actorPrincipalId];
  delete state.principals[vector.request.actorPrincipalId];
  Object.setPrototypeOf(state.principals, { [vector.request.actorPrincipalId]: inheritedActor });
  assert.deepEqual(authorizeSupervisorSubscription(state, vector.request), { allowed: false, code: "UNKNOWN_SUBSCRIBER" });
});

test("supervisor ACL rejects a subscriber record substituted under another principal key", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  state.principals[vector.request.actorPrincipalId] = {
    ...state.principals[vector.request.actorPrincipalId],
    principalId: "boss-a",
  };
  assert.deepEqual(authorizeSupervisorSubscription(state, vector.request), { allowed: false, code: "UNKNOWN_SUBSCRIBER" });
});

test("supervisor ACL requires manager identity and authorization fields to be own properties", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), vector.request), vector.expected);

  for (const field of [
    "principalId",
    "kind",
    "state",
    "bindingEpoch",
    "bindingGeneration",
    "participantId",
    "bossRunId",
    "assignedParticipantIds",
  ] as const) {
    const state = stateForSupervisorAclVector();
    const manager = state.principals[vector.request.actorPrincipalId];
    state.principals[vector.request.actorPrincipalId] = withInheritedField(manager, field);
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `inherited manager ${field} must not authorize`,
    );
  }
});

test("supervisor ACL rejects manager authorization-field accessors without invoking them", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);

  for (const field of [
    "principalId",
    "kind",
    "state",
    "bindingEpoch",
    "bindingGeneration",
    "participantId",
    "bossRunId",
    "assignedParticipantIds",
  ] as const) {
    const state = stateForSupervisorAclVector();
    let getterCalls = 0;
    state.principals[vector.request.actorPrincipalId] = withOwnGetter(
      state.principals[vector.request.actorPrincipalId],
      field,
      () => { getterCalls += 1; },
    );
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `accessor manager ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor manager ${field} must not be invoked`);
  }
});

test("supervisor ACL fences a superseded Manager by authoritative principal and participant identity", () => {
  const currentVector = SUPERVISOR_ACL_VECTORS.find((entry) =>
    entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  const supersededVector = SUPERVISOR_ACL_VECTORS.find((entry) =>
    entry.name === "superseded Manager cannot use stale assignments in the same Boss run");
  assert.ok(currentVector);
  assert.ok(supersededVector);

  const state = stateForSupervisorAclVector();
  const superseded = state.principals[supersededVector.request.actorPrincipalId];
  assert.equal(superseded.state, "active");
  assert.deepEqual(superseded.assignedParticipantIds, ["worker-participant-a", "scout-participant-a"]);
  assert.deepEqual(authorizeSupervisorSubscription(state, currentVector.request), currentVector.expected);
  assert.deepEqual(authorizeSupervisorSubscription(state, supersededVector.request), supersededVector.expected);
});

test("supervisor ACL Manager authority resolution is descriptor-safe and fails closed", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) =>
    entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);

  const substitutedState = stateForSupervisorAclVector();
  substitutedState.currentManagerByRun["boss-run-a"] = "manager-a-superseded";
  assert.deepEqual(
    authorizeSupervisorSubscription(substitutedState, vector.request),
    { allowed: false, code: "SUPERVISION_EDGE_DENIED" },
  );

  const malformedState = stateForSupervisorAclVector();
  let coercionCalls = 0;
  malformedState.currentManagerByRun["boss-run-a"] = {
    toString() {
      coercionCalls += 1;
      return "manager-a";
    },
  } as unknown as string;
  assert.deepEqual(
    authorizeSupervisorSubscription(malformedState, vector.request),
    { allowed: false, code: "SUPERVISION_EDGE_DENIED" },
  );
  assert.equal(coercionCalls, 0);

  const accessorState = stateForSupervisorAclVector();
  let getterCalls = 0;
  Object.defineProperty(accessorState.currentManagerByRun, "boss-run-a", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return "manager-a";
    },
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(accessorState, vector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  assert.equal(getterCalls, 0);

  let proxyTraps = 0;
  const proxyState = stateForSupervisorAclVector();
  proxyState.currentManagerByRun = new Proxy(proxyState.currentManagerByRun, {
    get() {
      proxyTraps += 1;
      return "manager-a";
    },
    getOwnPropertyDescriptor(target, property) {
      proxyTraps += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    getPrototypeOf(target) {
      proxyTraps += 1;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      proxyTraps += 1;
      return Reflect.ownKeys(target);
    },
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(proxyState, vector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  assert.equal(proxyTraps, 0);
});

test("supervisor ACL rejects ordinary-owner ownership accessors without invoking them", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(vector);

  const validState = stateForSupervisorAclVector();
  const validOwner = validState.principals[vector.request.actorPrincipalId];
  Object.defineProperty(validOwner, "ownedWorkerIds", {
    enumerable: true,
    value: ["local-worker-a"],
  });
  assert.deepEqual(authorizeSupervisorSubscription(validState, vector.request), vector.expected);

  const accessorState = stateForSupervisorAclVector();
  let getterCalls = 0;
  accessorState.principals[vector.request.actorPrincipalId] = withOwnGetter(
    accessorState.principals[vector.request.actorPrincipalId],
    "ownedWorkerIds",
    () => { getterCalls += 1; },
  );
  assert.deepEqual(
    authorizeSupervisorSubscription(accessorState, vector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  assert.equal(getterCalls, 0);
});

test("supervisor ACL never invokes ordinary-owner or Manager collection methods", () => {
  const ownerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  const managerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(ownerVector);
  assert.ok(managerVector);

  for (const [vector, field] of [
    [ownerVector, "ownedWorkerIds"],
    [managerVector, "assignedParticipantIds"],
  ] as const) {
    const state = stateForSupervisorAclVector();
    let includesCalls = 0;
    state.principals[vector.request.actorPrincipalId][field] = {
      includes() {
        includesCalls += 1;
        return true;
      },
    } as unknown as string[];
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `${field} must be parsed as an array before authorization`,
    );
    assert.equal(includesCalls, 0, `${field}.includes must never be invoked`);

    const getterState = stateForSupervisorAclVector();
    let includesGetterCalls = 0;
    const includesAccessor = Object.defineProperty({}, "includes", {
      enumerable: true,
      get() {
        includesGetterCalls += 1;
        return () => true;
      },
    });
    getterState.principals[vector.request.actorPrincipalId][field] = includesAccessor as unknown as string[];
    assert.deepEqual(
      authorizeSupervisorSubscription(getterState, vector.request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `${field} must not be treated as an array-like object`,
    );
    assert.equal(includesGetterCalls, 0, `${field}.includes getter must never be invoked`);
  }
});

test("supervisor ACL authorization arrays require dense unique own string data entries", () => {
  const ownerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  const managerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(ownerVector);
  assert.ok(managerVector);

  for (const [vector, field, member] of [
    [ownerVector, "ownedWorkerIds", "local-worker-a"],
    [managerVector, "assignedParticipantIds", "worker-participant-a"],
  ] as const) {
    for (const variant of invalidArrayShapes(member)) {
      const state = stateForSupervisorAclVector();
      state.principals[vector.request.actorPrincipalId][field] = variant.value;
      assert.deepEqual(
        authorizeSupervisorSubscription(state, vector.request),
        { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
        `${field} ${variant.name} array must fail closed`,
      );
      assert.equal(variant.accessorCalls?.() ?? 0, 0, `${field} ${variant.name} accessor must not run`);
    }

    for (const invalid of [[member, member], [member, 1], [member, ""]] as unknown[][]) {
      const state = stateForSupervisorAclVector();
      state.principals[vector.request.actorPrincipalId][field] = invalid as string[];
      assert.deepEqual(
        authorizeSupervisorSubscription(state, vector.request),
        { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
        `${field} must contain unique non-empty strings`,
      );
    }
  }
});

test("supervisor ACL rejects proxied state records and arrays without executing traps", () => {
  const ownerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  const managerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(ownerVector);
  assert.ok(managerVector);

  const trapped = <T extends object>(value: T, onTrap: () => void): T => new Proxy(value, {
    get(target, property, receiver) {
      onTrap();
      return Reflect.get(target, property, receiver);
    },
    getOwnPropertyDescriptor(target, property) {
      onTrap();
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    getPrototypeOf(target) {
      onTrap();
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      onTrap();
      return Reflect.ownKeys(target);
    },
  });

  let principalTraps = 0;
  const principalState = stateForSupervisorAclVector();
  principalState.principals[managerVector.request.actorPrincipalId] = trapped(
    principalState.principals[managerVector.request.actorPrincipalId],
    () => { principalTraps += 1; },
  );
  assert.deepEqual(
    authorizeSupervisorSubscription(principalState, managerVector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  assert.equal(principalTraps, 0);

  let arrayTraps = 0;
  const arrayState = stateForSupervisorAclVector();
  arrayState.principals[ownerVector.request.actorPrincipalId].ownedWorkerIds = trapped(
    ["local-worker-a"],
    () => { arrayTraps += 1; },
  );
  assert.deepEqual(
    authorizeSupervisorSubscription(arrayState, ownerVector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  assert.equal(arrayTraps, 0);

  let workerTraps = 0;
  const workerState = stateForSupervisorAclVector();
  assert.equal(managerVector.request.target.kind, "worker");
  workerState.workers[managerVector.request.target.workerId] = trapped(
    workerState.workers[managerVector.request.target.workerId],
    () => { workerTraps += 1; },
  );
  assert.deepEqual(
    authorizeSupervisorSubscription(workerState, managerVector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  assert.equal(workerTraps, 0);

  let stateTraps = 0;
  const proxyState = trapped(stateForSupervisorAclVector(), () => { stateTraps += 1; });
  assert.deepEqual(
    authorizeSupervisorSubscription(proxyState, ownerVector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  assert.equal(stateTraps, 0);

  const bossVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(bossVector);
  for (const [field, request, denial] of [
    ["principals", ownerVector.request, "UNKNOWN_SUBSCRIBER"],
    ["workers", managerVector.request, "UNKNOWN_TARGET"],
    ["currentManagerByRun", bossVector.request, "UNKNOWN_TARGET"],
  ] as const) {
    const mapState = stateForSupervisorAclVector();
    let mapTraps = 0;
    Object.defineProperty(mapState, field, {
      configurable: true,
      enumerable: true,
      value: trapped(mapState[field], () => { mapTraps += 1; }),
      writable: true,
    });
    assert.deepEqual(
      authorizeSupervisorSubscription(mapState, request),
      { allowed: false, code: denial },
      `proxied ${field} must fail closed`,
    );
    assert.equal(mapTraps, 0, `proxied ${field} traps must not run`);
  }
});

test("supervisor ACL principal variants have exact keys and validated scalar fields", () => {
  const ownerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  const managerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  const bossVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(ownerVector);
  assert.ok(managerVector);
  assert.ok(bossVector);

  const malformedManagerFields: Array<[string, unknown]> = [
    ["principalId", 7],
    ["kind", "root"],
    ["state", "replaced"],
    ["bindingEpoch", 0],
    ["bindingGeneration", Number.NaN],
    ["participantId", false],
    ["bossRunId", false],
  ];
  for (const [field, value] of malformedManagerFields) {
    const state = stateForSupervisorAclVector();
    Object.defineProperty(state.principals[managerVector.request.actorPrincipalId], field, {
      configurable: true,
      enumerable: true,
      value,
      writable: true,
    });
    assert.deepEqual(
      authorizeSupervisorSubscription(state, managerVector.request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `malformed Manager ${field} must fail closed`,
    );
  }

  const wrongVariantStates = [
    (() => {
      const state = stateForSupervisorAclVector();
      Object.assign(state.principals[ownerVector.request.actorPrincipalId], { bossRunId: "boss-run-a" });
      return [state, ownerVector.request] as const;
    })(),
    (() => {
      const state = stateForSupervisorAclVector();
      Object.assign(state.principals[managerVector.request.actorPrincipalId], { ownedWorkerIds: ["worker-a"] });
      return [state, managerVector.request] as const;
    })(),
    (() => {
      const state = stateForSupervisorAclVector();
      Object.assign(state.principals[bossVector.request.actorPrincipalId], { assignedParticipantIds: ["manager-a"] });
      return [state, bossVector.request] as const;
    })(),
  ];
  for (const [state, request] of wrongVariantStates) {
    assert.deepEqual(
      authorizeSupervisorSubscription(state, request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
    );
  }

  const workerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Worker to Worker supervision is denied");
  assert.ok(workerVector);
  for (const kind of ["worker", "scout", "adversary", "council"] as const) {
    const state = stateForSupervisorAclVector();
    state.principals[workerVector.request.actorPrincipalId] = {
      ...state.principals[workerVector.request.actorPrincipalId],
      kind,
    };
    assert.deepEqual(
      authorizeSupervisorSubscription(state, workerVector.request),
      { allowed: false, code: "SUPERVISION_EDGE_DENIED" },
      `${kind} principal variant must parse before its edge is denied`,
    );
  }
});

test("supervisor ACL worker variants have exact keys and validated scalar fields", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  assert.equal(vector.request.target.kind, "worker");

  for (const [field, value] of [
    ["workerId", 7],
    ["workerGeneration", 0],
    ["active", "true"],
    ["participantId", {}],
    ["role", "controller"],
    ["bossRunId", () => "boss-run-a"],
  ] as Array<[string, unknown]>) {
    const state = stateForSupervisorAclVector();
    Object.defineProperty(state.workers[vector.request.target.workerId], field, {
      configurable: true,
      enumerable: true,
      value,
      writable: true,
    });
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `malformed worker ${field} must fail closed`,
    );
  }

  const extraState = stateForSupervisorAclVector();
  Object.assign(extraState.workers[vector.request.target.workerId], { metadata: true });
  assert.deepEqual(
    authorizeSupervisorSubscription(extraState, vector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );

  const partialRunWorkerState = stateForSupervisorAclVector();
  delete partialRunWorkerState.workers[vector.request.target.workerId].bossRunId;
  assert.deepEqual(
    authorizeSupervisorSubscription(partialRunWorkerState, vector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );

  const ordinaryVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(ordinaryVector);
  assert.equal(ordinaryVector.request.target.kind, "worker");
  const mixedOrdinaryState = stateForSupervisorAclVector();
  Object.assign(mixedOrdinaryState.workers[ordinaryVector.request.target.workerId], { participantId: "worker-participant-a" });
  assert.deepEqual(
    authorizeSupervisorSubscription(mixedOrdinaryState, ordinaryVector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
});

test("supervisor ACL snapshots ignore unrelated malformed entries without executing them", () => {
  const ownerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "ordinary owner may supervise its ordinary owned worker");
  assert.ok(ownerVector);
  const state = stateForSupervisorAclVector();
  let getterCalls = 0;
  state.principals["unrelated-malformed"] = Object.defineProperty({}, "kind", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "manager";
    },
  }) as typeof state.principals[string];
  state.workers["unrelated-malformed"] = Object.defineProperty({}, "workerId", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "unrelated-malformed";
    },
  }) as typeof state.workers[string];
  state.currentManagerByRun["unrelated-run"] = {
    toString() {
      getterCalls += 1;
      return "manager-a";
    },
  } as unknown as string;
  assert.deepEqual(authorizeSupervisorSubscription(state, ownerVector.request), ownerVector.expected);
  assert.equal(getterCalls, 0);
});

test("supervisor ACL rejects Boss authorization-field accessors without invoking them", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), vector.request), vector.expected);

  for (const field of ["principalId", "kind", "state", "bindingEpoch", "bindingGeneration", "bossRunId"] as const) {
    const state = stateForSupervisorAclVector();
    let getterCalls = 0;
    state.principals[vector.request.actorPrincipalId] = withOwnGetter(
      state.principals[vector.request.actorPrincipalId],
      field,
      () => { getterCalls += 1; },
    );
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
      `accessor Boss ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor Boss ${field} must not be invoked`);
  }
});

test("supervisor ACL rejects an inherited exact worker target as unknown", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  assert.equal(vector.request.target.kind, "worker");
  const inheritedWorker = state.workers[vector.request.target.workerId];
  delete state.workers[vector.request.target.workerId];
  Object.setPrototypeOf(state.workers, { [vector.request.target.workerId]: inheritedWorker });
  assert.deepEqual(authorizeSupervisorSubscription(state, vector.request), { allowed: false, code: "UNKNOWN_TARGET" });
});

test("supervisor ACL rejects an exact worker record substituted under another worker key", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  assert.equal(vector.request.target.kind, "worker");
  state.workers[vector.request.target.workerId] = {
    ...state.workers[vector.request.target.workerId],
    workerId: "scout-a",
  };
  assert.deepEqual(authorizeSupervisorSubscription(state, vector.request), { allowed: false, code: "UNKNOWN_TARGET" });
});

test("supervisor ACL requires exact worker identity and authorization fields to be own properties", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  assert.equal(vector.request.target.kind, "worker");
  assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), vector.request), vector.expected);

  for (const field of ["workerId", "workerGeneration", "participantId", "role", "bossRunId", "active"] as const) {
    const state = stateForSupervisorAclVector();
    const worker = state.workers[vector.request.target.workerId];
    state.workers[vector.request.target.workerId] = withInheritedField(worker, field);
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `inherited exact worker ${field} must not authorize`,
    );
  }
});

test("supervisor ACL rejects exact-worker authorization-field accessors without invoking them", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(vector);
  assert.equal(vector.request.target.kind, "worker");

  for (const field of ["workerId", "workerGeneration", "participantId", "role", "bossRunId", "active"] as const) {
    const state = stateForSupervisorAclVector();
    let getterCalls = 0;
    state.workers[vector.request.target.workerId] = withOwnGetter(
      state.workers[vector.request.target.workerId],
      field,
      () => { getterCalls += 1; },
    );
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `accessor exact worker ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor exact worker ${field} must not be invoked`);
  }
});

test("supervisor ACL role selectors ignore inherited manager selectors and workers", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  assert.equal(vector.request.target.kind, "role");

  const inheritedSelectorState = stateForSupervisorAclVector();
  const inheritedPrincipalId = inheritedSelectorState.currentManagerByRun[vector.request.target.bossRunId];
  delete inheritedSelectorState.currentManagerByRun[vector.request.target.bossRunId];
  Object.setPrototypeOf(inheritedSelectorState.currentManagerByRun, { [vector.request.target.bossRunId]: inheritedPrincipalId });
  assert.deepEqual(authorizeSupervisorSubscription(inheritedSelectorState, vector.request), { allowed: false, code: "UNKNOWN_TARGET" });

  const inheritedWorkerState = stateForSupervisorAclVector();
  const managerWorkerId = "manager-worker-a";
  const inheritedWorker = inheritedWorkerState.workers[managerWorkerId];
  delete inheritedWorkerState.workers[managerWorkerId];
  Object.setPrototypeOf(inheritedWorkerState.workers, { [managerWorkerId]: inheritedWorker });
  assert.deepEqual(authorizeSupervisorSubscription(inheritedWorkerState, vector.request), { allowed: false, code: "UNKNOWN_TARGET" });
});

test("supervisor ACL rejects accessor-backed map entries and selectors without invoking them", () => {
  const managerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(managerVector);
  assert.equal(managerVector.request.target.kind, "worker");

  const principalState = stateForSupervisorAclVector();
  const principal = principalState.principals[managerVector.request.actorPrincipalId];
  let principalGetterCalls = 0;
  Object.defineProperty(principalState.principals, managerVector.request.actorPrincipalId, {
    configurable: true,
    enumerable: true,
    get() {
      principalGetterCalls += 1;
      return principal;
    },
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(principalState, managerVector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );
  assert.equal(principalGetterCalls, 0);

  const workerState = stateForSupervisorAclVector();
  const worker = workerState.workers[managerVector.request.target.workerId];
  let workerGetterCalls = 0;
  Object.defineProperty(workerState.workers, managerVector.request.target.workerId, {
    configurable: true,
    enumerable: true,
    get() {
      workerGetterCalls += 1;
      return worker;
    },
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(workerState, managerVector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  assert.equal(workerGetterCalls, 0);

  const bossVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(bossVector);
  assert.equal(bossVector.request.target.kind, "role");
  const selectorState = stateForSupervisorAclVector();
  const managerPrincipalId = selectorState.currentManagerByRun[bossVector.request.target.bossRunId];
  let selectorGetterCalls = 0;
  Object.defineProperty(selectorState.currentManagerByRun, bossVector.request.target.bossRunId, {
    configurable: true,
    enumerable: true,
    get() {
      selectorGetterCalls += 1;
      return managerPrincipalId;
    },
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(selectorState, bossVector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
  assert.equal(selectorGetterCalls, 0);
});

test("supervisor ACL role enumeration ignores a worker substituted under another map key", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  const managerWorker = state.workers["manager-worker-a"];
  delete state.workers["manager-worker-a"];
  state.workers["substituted-manager-worker"] = managerWorker;
  assert.deepEqual(authorizeSupervisorSubscription(state, vector.request), { allowed: false, code: "UNKNOWN_TARGET" });
});

test("supervisor ACL non-manager role enumeration rejects a substituted worker identity", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Controller may supervise an authenticated participant in its run");
  assert.ok(vector);
  const request = {
    ...vector.request,
    target: { kind: "role" as const, bossRunId: "boss-run-a", role: "scout" as const },
  };
  assert.deepEqual(authorizeSupervisorSubscription(state, request), { allowed: true, reason: "controller_to_participant" });
  state.workers["scout-a"] = { ...state.workers["scout-a"], workerId: "worker-a" };
  assert.deepEqual(authorizeSupervisorSubscription(state, request), { allowed: false, code: "UNKNOWN_TARGET" });
});

test("supervisor ACL role enumeration requires worker fields to be own properties", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Controller may supervise an authenticated participant in its run");
  assert.ok(vector);
  const request = {
    ...vector.request,
    target: { kind: "role" as const, bossRunId: "boss-run-a", role: "scout" as const },
  };
  assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), request), vector.expected);

  for (const field of ["workerId", "workerGeneration", "participantId", "role", "bossRunId", "active"] as const) {
    const state = stateForSupervisorAclVector();
    state.workers["scout-a"] = withInheritedField(state.workers["scout-a"], field);
    assert.deepEqual(
      authorizeSupervisorSubscription(state, request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `inherited enumerated worker ${field} must not authorize`,
    );
  }
});

test("supervisor ACL Controller role authorization validates every active selected participant", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) =>
    entry.name === "Controller may supervise every active Worker in its run");
  assert.ok(vector);
  assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), vector.request), vector.expected);

  const participantlessState = stateForSupervisorAclVector();
  delete participantlessState.workers["worker-a-2"].participantId;
  assert.deepEqual(
    authorizeSupervisorSubscription(participantlessState, vector.request),
    { allowed: false, code: "SUPERVISION_EDGE_DENIED" },
  );

  participantlessState.workers["worker-a-2"].active = false;
  assert.deepEqual(authorizeSupervisorSubscription(participantlessState, vector.request), vector.expected);
});

test("supervisor ACL current-manager selectors reject a substituted principal record", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  const substitutedPrincipalId = "substituted-manager";
  state.currentManagerByRun["boss-run-a"] = substitutedPrincipalId;
  state.principals[substitutedPrincipalId] = { ...state.principals["manager-a"], principalId: "manager-a" };
  state.workers["manager-worker-a"] = { ...state.workers["manager-worker-a"], participantId: substitutedPrincipalId };
  assert.deepEqual(authorizeSupervisorSubscription(state, vector.request), { allowed: false, code: "UNKNOWN_TARGET" });
});

test("supervisor ACL current-manager selectors compare participant identities, not principal identities", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  const state = stateForSupervisorAclVector();
  const managerPrincipalId = state.currentManagerByRun["boss-run-a"];
  const managerParticipantId = state.principals[managerPrincipalId].participantId;
  assert.equal(managerPrincipalId, MANAGER_PRINCIPAL_ID);
  assert.equal(managerParticipantId, MANAGER_PARTICIPANT_ID);
  assert.notEqual(managerPrincipalId, managerParticipantId);
  assert.equal(state.workers["manager-worker-a"].participantId, managerParticipantId);
  assert.deepEqual(authorizeSupervisorSubscription(state, vector.request), vector.expected);

  state.workers["manager-worker-a"] = {
    ...state.workers["manager-worker-a"],
    participantId: managerPrincipalId,
  };
  assert.deepEqual(
    authorizeSupervisorSubscription(state, vector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
});

test("supervisor ACL current-manager resolution rejects missing, invalid, participantless, and ambiguous authority", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);

  const invalidStates = [
    (() => {
      const state = stateForSupervisorAclVector();
      delete state.currentManagerByRun["boss-run-a"];
      return state;
    })(),
    (() => {
      const state = stateForSupervisorAclVector();
      state.currentManagerByRun["boss-run-a"] = "worker-principal-a";
      return state;
    })(),
    (() => {
      const state = stateForSupervisorAclVector();
      delete state.principals["manager-a"].participantId;
      return state;
    })(),
    (() => {
      const state = stateForSupervisorAclVector();
      delete state.workers["manager-worker-a"].participantId;
      return state;
    })(),
    (() => {
      const state = stateForSupervisorAclVector();
      state.workers["ambiguous-manager-worker-a"] = {
        ...state.workers["manager-worker-a"],
        workerId: "ambiguous-manager-worker-a",
      };
      return state;
    })(),
  ];
  for (const state of invalidStates) {
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
    );
  }
});

test("supervisor ACL current-manager resolution requires own principal and worker fields", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  assert.deepEqual(authorizeSupervisorSubscription(stateForSupervisorAclVector(), vector.request), vector.expected);

  for (const field of ["principalId", "kind", "state", "bindingEpoch", "bindingGeneration", "participantId", "bossRunId"] as const) {
    const state = stateForSupervisorAclVector();
    state.principals["manager-a"] = withInheritedField(state.principals["manager-a"], field);
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `inherited current-manager principal ${field} must not authorize`,
    );
  }

  for (const field of ["workerId", "workerGeneration", "participantId", "role", "bossRunId", "active"] as const) {
    const state = stateForSupervisorAclVector();
    state.workers["manager-worker-a"] = withInheritedField(state.workers["manager-worker-a"], field);
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `inherited current-manager worker ${field} must not authorize`,
    );
  }
});

test("supervisor ACL current-manager resolution rejects accessors without invoking them", () => {
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);

  for (const field of ["principalId", "kind", "state", "bindingEpoch", "bindingGeneration", "participantId", "bossRunId"] as const) {
    const state = stateForSupervisorAclVector();
    let getterCalls = 0;
    state.principals["manager-a"] = withOwnGetter(
      state.principals["manager-a"],
      field,
      () => { getterCalls += 1; },
    );
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `accessor current-manager principal ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor current-manager principal ${field} must not be invoked`);
  }

  for (const field of ["workerId", "workerGeneration", "participantId", "role", "bossRunId", "active"] as const) {
    const state = stateForSupervisorAclVector();
    let getterCalls = 0;
    state.workers["manager-worker-a"] = withOwnGetter(
      state.workers["manager-worker-a"],
      field,
      () => { getterCalls += 1; },
    );
    assert.deepEqual(
      authorizeSupervisorSubscription(state, vector.request),
      { allowed: false, code: "UNKNOWN_TARGET" },
      `accessor current-manager worker ${field} must not authorize`,
    );
    assert.equal(getterCalls, 0, `accessor current-manager worker ${field} must not be invoked`);
  }
});

test("supervisor ACL rejects hidden or symbol principal and worker metadata", () => {
  const managerVector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Manager may supervise an assigned Worker in the same Boss run");
  assert.ok(managerVector);
  assert.equal(managerVector.request.target.kind, "worker");

  const hiddenPrincipalState = stateForSupervisorAclVector();
  Object.defineProperty(hiddenPrincipalState.principals[managerVector.request.actorPrincipalId], "metadata", {
    enumerable: false,
    value: true,
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(hiddenPrincipalState, managerVector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );

  const hiddenAuthorizationFieldState = stateForSupervisorAclVector();
  Object.defineProperty(
    hiddenAuthorizationFieldState.principals[managerVector.request.actorPrincipalId],
    "assignedParticipantIds",
    { enumerable: false, value: ["worker-participant-a"] },
  );
  assert.deepEqual(
    authorizeSupervisorSubscription(hiddenAuthorizationFieldState, managerVector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );

  const symbolPrincipalState = stateForSupervisorAclVector();
  Reflect.set(symbolPrincipalState.principals[managerVector.request.actorPrincipalId], Symbol("metadata"), true);
  assert.deepEqual(
    authorizeSupervisorSubscription(symbolPrincipalState, managerVector.request),
    { allowed: false, code: "UNKNOWN_SUBSCRIBER" },
  );

  const hiddenWorkerState = stateForSupervisorAclVector();
  Object.defineProperty(hiddenWorkerState.workers[managerVector.request.target.workerId], "metadata", {
    enumerable: false,
    value: true,
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(hiddenWorkerState, managerVector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );

  const hiddenWorkerFieldState = stateForSupervisorAclVector();
  Object.defineProperty(hiddenWorkerFieldState.workers[managerVector.request.target.workerId], "active", {
    enumerable: false,
    value: true,
  });
  assert.deepEqual(
    authorizeSupervisorSubscription(hiddenWorkerFieldState, managerVector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );

  const symbolWorkerState = stateForSupervisorAclVector();
  Reflect.set(symbolWorkerState.workers[managerVector.request.target.workerId], Symbol("metadata"), true);
  assert.deepEqual(
    authorizeSupervisorSubscription(symbolWorkerState, managerVector.request),
    { allowed: false, code: "UNKNOWN_TARGET" },
  );
});

test("supervisor ACL boss edges reject inherited current-manager authority", () => {
  const state = stateForSupervisorAclVector();
  const vector = SUPERVISOR_ACL_VECTORS.find((entry) => entry.name === "Boss may follow the current Manager role");
  assert.ok(vector);
  assert.equal(vector.request.target.kind, "role");
  const bossRunId = vector.request.target.bossRunId;
  const currentManager = state.currentManagerByRun[bossRunId];
  delete state.currentManagerByRun[bossRunId];
  Object.setPrototypeOf(state.currentManagerByRun, { [bossRunId]: currentManager });
  const exactManagerRequest = {
    ...vector.request,
    target: { kind: "worker" as const, workerId: "manager-worker-a", workerGeneration: workerGeneration(5) },
    followReplacement: false,
  };
  assert.deepEqual(authorizeSupervisorSubscription(state, exactManagerRequest), { allowed: false, code: "SUPERVISION_EDGE_DENIED" });
});

test("delivery intent aggregation is permutation-independent and cannot downgrade", () => {
  const permutations: DeliveryIntent[][] = [
    ["status_only", "follow_up", "wake"],
    ["status_only", "wake", "follow_up"],
    ["follow_up", "status_only", "wake"],
    ["follow_up", "wake", "status_only"],
    ["wake", "status_only", "follow_up"],
    ["wake", "follow_up", "status_only"],
  ];
  for (const intents of permutations) assert.equal(aggregateDeliveryIntent(intents), "wake");
  assert.equal(aggregateDeliveryIntent(["status_only", "follow_up"]), "follow_up");
  assert.equal(aggregateDeliveryIntent(["status_only"]), "status_only");
  assert.equal(aggregateDeliveryIntent([]), "status_only");
  assert.throws(() => aggregateDeliveryIntent(["interrupt" as DeliveryIntent]), /must be one of/);
});

import assert from "node:assert/strict";
import test from "node:test";
import {
  ContractValidationError,
  controllerGeneration,
  transitionVersion,
  validateVersionedStoreRecord,
  workerGeneration,
  type StoreValidationFailureReason,
  type StoreValidationResult,
} from "../src/canonical.ts";
import {
  DELIVERY_CLAIM_STATES,
  DELIVERY_GROUP_ASSEMBLY_VERSION,
  DELIVERY_GROUP_STATES,
  LIFECYCLE_NOTICE_VERSION,
  NOTICE_DELIVERY_CLAIM_STATES,
  assembleDeliveryGroup,
  effectiveDeliveryIntent,
  lifecycleNoticeId,
  mintDeliveryGroupAssemblyMember,
  parseDeliveryGroupAssemblyInput,
  parseLifecycleNotice,
  validateLifecycleNoticeStore,
  type DeliveryEquivalenceKey,
  type DeliveryGroupAssemblyMember,
  type LifecycleNotice,
} from "../src/boss-wire.ts";
import { validateLifecycleSubscriptionStore, validateSubscriberRebindMigrationStore } from "../src/supervision.ts";
import {
  COMMITTED_REBIND_MIGRATION_VECTOR,
  MANAGER_WORKER_SUBSCRIPTION_VECTOR,
  REBIND_MIGRATION_NEGATIVE_VECTORS,
} from "../src/supervision-vectors.ts";
import { validateWorkerStoreRecordV2 } from "../src/worker-store-migration.ts";
import { FULL_WORKER_STORE_MIGRATION_VECTORS } from "../src/worker-store-migration-vectors.ts";

const equivalenceKey: DeliveryEquivalenceKey = {
  recipientPrincipalId: "manager-opus",
  recipientBindingEpoch: 3,
  sourceAuthorityId: { kind: "controller", bossRunId: "run-opus", controllerGeneration: controllerGeneration(2) },
  sourceEventId: "event-opus-1",
  bossRunId: "run-opus",
  workerId: "worker-opus",
  workerGeneration: workerGeneration(4),
  transitionId: "transition-opus-1",
  transitionVersion: transitionVersion(1),
  assignmentId: "assignment-opus",
  turnId: "turn-opus",
};

const noticeKey = {
  workerId: equivalenceKey.workerId,
  workerGeneration: equivalenceKey.workerGeneration,
  transitionId: equivalenceKey.transitionId,
  transitionVersion: equivalenceKey.transitionVersion,
  kind: "turn_settled",
  assignmentId: equivalenceKey.assignmentId,
};

const lifecycleNotice: LifecycleNotice = {
  version: LIFECYCLE_NOTICE_VERSION,
  noticeId: lifecycleNoticeId(noticeKey),
  deliveryGroupId: "delivery-group-opus",
  deliveryGroupMembershipRevision: 1,
  requestedDeliveryIntent: "wake",
  sourceEventId: equivalenceKey.sourceEventId,
  transitionId: equivalenceKey.transitionId,
  transitionVersion: equivalenceKey.transitionVersion,
  bossRunId: equivalenceKey.bossRunId,
  workerId: equivalenceKey.workerId,
  workerIncarnationId: "worker-incarnation-opus",
  workerGeneration: equivalenceKey.workerGeneration,
  assignmentId: equivalenceKey.assignmentId,
  turnId: equivalenceKey.turnId,
  kind: noticeKey.kind,
  severity: "info",
  observedState: "waiting",
  reason: "turn settled",
  createdAt: "2026-07-28T12:00:00.000Z",
  recipientContext: "pi",
};

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length === 0) return [[]];
  return values.flatMap((value, index) => permutations([
    ...values.slice(0, index),
    ...values.slice(index + 1),
  ]).map((tail) => [value, ...tail]));
}

function assertFailClosed<T>(
  result: StoreValidationResult<T>,
  status: StoreValidationFailureReason,
): asserts result is Extract<StoreValidationResult<T>, { ok: false }> {
  assert.equal(result.ok, false);
  if (result.ok) assert.fail("expected a fail-closed store result");
  assert.equal(result.status, status);
  assert.equal(result.preserveExisting, true);
  assert.equal(result.mutationAllowed, false);
  assert.equal("value" in result, false);
  assert.equal("default" in result, false);
}

test("notice claim projection is distinct and cannot project released authority claims", () => {
  assert.deepEqual(NOTICE_DELIVERY_CLAIM_STATES, ["reserved", "inserting", "inserted", "delivered", "blocked"]);
  assert.equal(new Set<string>(NOTICE_DELIVERY_CLAIM_STATES).has("released"), false);
  assert.equal(new Set<string>(DELIVERY_CLAIM_STATES).has("released"), true);
  assert.equal(new Set<string>(DELIVERY_GROUP_STATES).has("migrated"), true);

  assert.throws(() => parseLifecycleNotice({
    ...lifecycleNotice,
    deliveryClaimId: "claim-opus",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: "2026-07-28T12:05:00.000Z",
    deliveryClaimState: "released",
  }), ContractValidationError);
});

test("minted intents are required at assembly and replay identically for every member order", () => {
  const members: DeliveryGroupAssemblyMember[] = [
    mintDeliveryGroupAssemblyMember({ kind: "built_in", noticeId: lifecycleNotice.noticeId }),
    mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "notice-opus-wake", requestedDeliveryIntent: "wake" }),
    mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "notice-opus-follow", requestedDeliveryIntent: "follow_up" }),
    mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "notice-opus-status", requestedDeliveryIntent: "status_only" }),
  ];
  assert.equal(members[0].requestedDeliveryIntent, "wake");
  assert.throws(
    () => mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "notice-opus-missing" }),
    /must declare an intent/,
  );
  assert.throws(() => effectiveDeliveryIntent(["unknown" as never]), /must be one of/);

  const base = {
    version: DELIVERY_GROUP_ASSEMBLY_VERSION,
    equivalenceKey,
    subscriptionRegistryRevision: 9,
    membershipRevision: 2,
    primaryNoticeId: lifecycleNotice.noticeId,
    recipientTransferGeneration: 0,
  } as const;
  assert.throws(() => parseDeliveryGroupAssemblyInput({
    ...base,
    members: [{ noticeId: lifecycleNotice.noticeId }],
  }), /requestedDeliveryIntent/);

  const replays = permutations(members).map((orderedMembers) => assembleDeliveryGroup({
    ...base,
    members: orderedMembers,
  }));
  assert.equal(replays.length, 24);
  assert.equal(replays[0].effectiveDeliveryIntent, "wake");
  for (const replay of replays.slice(1)) assert.deepEqual(replay, replays[0]);
});

test("generic store validation classifies every failure without a synthetic record", () => {
  type FixtureStore = { version: "fixture.store.v2"; payload: string };
  const parseFixture = (value: unknown): FixtureStore => {
    if (
      typeof value !== "object"
      || value === null
      || Array.isArray(value)
      || (value as Record<string, unknown>).version !== "fixture.store.v2"
      || typeof (value as Record<string, unknown>).payload !== "string"
    ) throw new ContractValidationError("$.payload", "must be a string");
    return value as FixtureStore;
  };

  const valid = { version: "fixture.store.v2", payload: "preserved" } as const;
  assert.deepEqual(validateVersionedStoreRecord(valid, valid.version, parseFixture), {
    ok: true,
    status: "valid",
    value: valid,
  });

  const fixtures: Array<[unknown, StoreValidationFailureReason]> = [
    [{ version: "fixture.store.v2", payload: 7 }, "corrupt"],
    [{ version: undefined, payload: "missing" }, "corrupt"],
    [{ version: "fixture.store.v3", payload: "newer" }, "unsupported_newer_version"],
    [{ version: "fixture.store.v1", payload: "older" }, "unsupported_older_version"],
    [{ version: "other.store.v2", payload: "foreign" }, "foreign_version"],
  ];
  for (const [fixture, status] of fixtures) {
    const before = structuredClone(fixture);
    assertFailClosed(validateVersionedStoreRecord(fixture, valid.version, parseFixture), status);
    assert.deepEqual(fixture, before);
  }
  assertFailClosed(validateVersionedStoreRecord([], valid.version, parseFixture), "corrupt");
});

test("generic store validation rejects non-plain and hidden version records before parsing", () => {
  type FixtureStore = { version: "fixture.store.v2"; payload: string };
  let parserCalls = 0;
  const parseFixture = (value: unknown): FixtureStore => {
    parserCalls += 1;
    return value as FixtureStore;
  };
  const validateFixture = (value: unknown) => validateVersionedStoreRecord(
    value,
    "fixture.store.v2",
    parseFixture,
  );

  const valid = { version: "fixture.store.v2", payload: "preserved" } as const;
  assert.deepEqual(validateFixture(valid), { ok: true, status: "valid", value: valid });
  assert.equal(parserCalls, 1);

  const nullPrototype = Object.assign(Object.create(null) as Record<string, unknown>, valid);
  const customPrototype = Object.assign(Object.create({ marker: true }) as Record<string, unknown>, valid);
  for (const fixture of [nullPrototype, customPrototype]) {
    assertFailClosed(validateFixture(fixture), "corrupt");
  }

  const priorVersionDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "version");
  let inheritedVersionResult: StoreValidationResult<FixtureStore>;
  Object.defineProperty(Object.prototype, "version", {
    configurable: true,
    enumerable: true,
    value: "fixture.store.v2",
    writable: true,
  });
  try {
    inheritedVersionResult = validateFixture({ payload: "inherited" });
  } finally {
    if (priorVersionDescriptor === undefined) Reflect.deleteProperty(Object.prototype, "version");
    else Object.defineProperty(Object.prototype, "version", priorVersionDescriptor);
  }
  assertFailClosed(inheritedVersionResult, "corrupt");

  let getterCalls = 0;
  const accessorVersion = Object.defineProperty({ payload: "accessor" }, "version", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "fixture.store.v2";
    },
  });
  assertFailClosed(validateFixture(accessorVersion), "corrupt");
  assert.equal(getterCalls, 0);

  const symbolMetadata = { ...valid } as Record<PropertyKey, unknown>;
  symbolMetadata[Symbol("metadata")] = true;
  assertFailClosed(validateFixture(symbolMetadata), "corrupt");

  const hiddenMetadata = Object.defineProperty({ ...valid }, "metadata", { value: true });
  assertFailClosed(validateFixture(hiddenMetadata), "corrupt");

  const hiddenVersion = Object.defineProperty({ payload: "hidden" }, "version", {
    value: "fixture.store.v2",
  });
  assertFailClosed(validateFixture(hiddenVersion), "corrupt");
  assert.equal(parserCalls, 1);
});

test("explicit store wrappers preserve valid records and fail closed across schema boundaries", () => {
  const worker = FULL_WORKER_STORE_MIGRATION_VECTORS[0].expected;
  const workerValid = validateWorkerStoreRecordV2(worker);
  assert.equal(workerValid.ok, true);
  if (workerValid.ok) assert.deepEqual(workerValid.value, worker);

  const noticeValid = validateLifecycleNoticeStore(lifecycleNotice);
  assert.equal(noticeValid.ok, true);
  if (noticeValid.ok) assert.deepEqual(noticeValid.value, lifecycleNotice);

  const subscriptionValid = validateLifecycleSubscriptionStore(MANAGER_WORKER_SUBSCRIPTION_VECTOR);
  assert.equal(subscriptionValid.ok, true);
  if (subscriptionValid.ok) assert.deepEqual(subscriptionValid.value, MANAGER_WORKER_SUBSCRIPTION_VECTOR);

  const rebindValid = validateSubscriberRebindMigrationStore(COMMITTED_REBIND_MIGRATION_VECTOR);
  assert.equal(rebindValid.ok, true);
  if (rebindValid.ok) assert.deepEqual(rebindValid.value, COMMITTED_REBIND_MIGRATION_VECTOR);

  const newerWorker = { ...worker, version: "orc.worker-store-record.v3" };
  const olderNotice = { ...lifecycleNotice, version: "orc.lifecycle-notice.v0" };
  const foreignSubscription = { ...MANAGER_WORKER_SUBSCRIPTION_VECTOR, version: "foreign.lifecycle-subscription.v1" };
  const corruptNotice = { ...lifecycleNotice, noticeId: "not-the-logical-id" };
  const cases = [
    [newerWorker, validateWorkerStoreRecordV2, "unsupported_newer_version"],
    [olderNotice, validateLifecycleNoticeStore, "unsupported_older_version"],
    [foreignSubscription, validateLifecycleSubscriptionStore, "foreign_version"],
    [corruptNotice, validateLifecycleNoticeStore, "corrupt"],
  ] as const;
  for (const [fixture, validate, status] of cases) {
    const before = structuredClone(fixture);
    assertFailClosed(validate(fixture) as StoreValidationResult<unknown>, status);
    assert.deepEqual(fixture, before);
  }

  for (const vector of REBIND_MIGRATION_NEGATIVE_VECTORS) {
    const before = structuredClone(vector.value);
    assertFailClosed(validateSubscriberRebindMigrationStore(vector.value), "corrupt");
    assert.deepEqual(vector.value, before);
  }
});

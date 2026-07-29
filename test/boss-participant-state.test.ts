import assert from "node:assert/strict";
import test from "node:test";
import {
  CANONICAL_WORKER_STORE_SCHEMA_VERSION,
  LEGACY_WORKER_STATES,
  PARTICIPANT_DISPATCHABLE_STATES,
  PARTICIPANT_NEW_GENERATION_TRANSITIONS,
  PARTICIPANT_READ_ONLY_STATES,
  PARTICIPANT_STATES,
  PARTICIPANT_STATE_TRANSITION_TABLE,
  TERMINAL_PARTICIPANT_STATES,
  canDispatchParticipantState,
  canDispatchMigratedWorker,
  isParticipantStateReadOnly,
  isTerminalParticipantState,
  migrateLegacyWorkerRecordV1,
  parseLegacyStoppingReconciliationV1,
  parseLegacyWorkerMigrationInputV1,
  parseMigratedWorkerRecordV2,
  parseParticipantHealthEventV1,
  parseParticipantStateTransitionContextV1,
  reconcileLegacyStoppingWorker,
  requiresDirectProcessEvidenceForCleanup,
  validateParticipantStateTransition,
  type LegacyWorkerMigrationInputV1,
  type MigratedWorkerRecordV2,
  type ParticipantState,
} from "../src/boss-participant-state.ts";
import {
  PARTICIPANT_HEALTH_EVENT_VECTOR,
  PARTICIPANT_STATE_MIGRATION_VECTORS,
  PARTICIPANT_STATE_TRANSITION_VECTOR_CORPUS,
  PARTICIPANT_STATE_TRANSITION_VECTOR_HASH_DOMAIN,
  PARTICIPANT_STATE_TRANSITION_VECTORS,
  PARTICIPANT_STATE_TRANSITION_VECTORS_HASH,
  PARTICIPANT_STATE_VECTOR_CORPUS,
  PARTICIPANT_STATE_VECTOR_HASH_DOMAIN,
  PARTICIPANT_STATE_VECTORS_HASH,
  STOPPING_RECONCILIATION_VECTORS,
} from "../src/boss-participant-state-vectors.ts";
import { ContractValidationError, canonicalHash, canonicalJson } from "../src/canonical.ts";

test("participant state vocabulary and current-generation terminal set are exact", () => {
  assert.deepEqual(PARTICIPANT_STATES, [
    "provisioning",
    "registering",
    "ready",
    "working",
    "waiting",
    "paused",
    "stalled",
    "blocked",
    "failed",
    "lost",
    "unreachable",
    "stopped",
  ]);
  assert.deepEqual(TERMINAL_PARTICIPANT_STATES, ["failed", "lost", "stopped"]);
  for (const state of PARTICIPANT_STATES) {
    assert.equal(isTerminalParticipantState(state), TERMINAL_PARTICIPANT_STATES.includes(state as never), state);
    assert.equal(requiresDirectProcessEvidenceForCleanup(state), true, state);
  }
  assert.equal(isTerminalParticipantState("unreachable"), false);
  assert.equal(CANONICAL_WORKER_STORE_SCHEMA_VERSION, 2);
});

test("golden migration corpus is exhaustive and canonical hash is frozen", () => {
  const represented = PARTICIPANT_STATE_MIGRATION_VECTORS.map((vector) => vector.input.legacyState);
  assert.deepEqual(represented, LEGACY_WORKER_STATES);
  assert.equal(new Set(represented).size, LEGACY_WORKER_STATES.length);
  assert.equal(
    canonicalHash(PARTICIPANT_STATE_VECTOR_HASH_DOMAIN, PARTICIPANT_STATE_VECTOR_CORPUS),
    PARTICIPANT_STATE_VECTORS_HASH,
  );
  assert.match(canonicalJson(PARTICIPANT_STATE_VECTOR_CORPUS), /^\{"healthEvent":/);
});

for (const vector of PARTICIPANT_STATE_MIGRATION_VECTORS) {
  test(`legacy migration vector: ${vector.name}`, () => {
    const result = migrateLegacyWorkerRecordV1(vector.input);
    assert.deepEqual(result, vector.expected);
    assert.deepEqual(parseMigratedWorkerRecordV2(result), vector.expected);
    assert.equal(result.workerIncarnationId, vector.input.legacyRunId);
    assert.equal(Object.hasOwn(result, "bossRunId"), false);
    assert.equal(result.migrationAudit.originalState, vector.input.legacyState);
    assert.equal(result.migrationAudit.originalOutcome, vector.input.legacyOutcome);
    assert.equal(result.resumeState, result.state === "blocked" ? "registering" : null);
    assert.equal(canDispatchMigratedWorker(result), false);
  });
}

test("deprecated AGENT_INTERCOM_RUN_ID stays audit-only and cannot become Boss authority", () => {
  const vector = PARTICIPANT_STATE_MIGRATION_VECTORS[0];
  const result = migrateLegacyWorkerRecordV1(vector.input);
  assert.notEqual(vector.input.deprecatedAgentIntercomRunId, vector.input.legacyRunId);
  assert.equal(result.workerIncarnationId, vector.input.legacyRunId);
  assert.equal(result.migrationAudit.originalDeprecatedAgentIntercomRunId, vector.input.deprecatedAgentIntercomRunId);
  assert.equal("bossRunId" in result, false);
  assert.throws(
    () => parseMigratedWorkerRecordV2({ ...result, bossRunId: vector.input.deprecatedAgentIntercomRunId }),
    /bossRunId: is not supported/,
  );
});

test("running and idle never infer ready or working", () => {
  for (const legacyState of ["running", "idle"] as const) {
    const vector = PARTICIPANT_STATE_MIGRATION_VECTORS.find((entry) => entry.input.legacyState === legacyState)!;
    const result = migrateLegacyWorkerRecordV1(vector.input);
    assert.equal(result.state, "registering");
    assert.equal(result.requiresReadinessReconciliation, true);
    assert.notEqual(result.state as ParticipantState, "ready");
    assert.notEqual(result.state as ParticipantState, "working");
  }
});

test("migration input versions and shape fail closed", () => {
  const baseline = PARTICIPANT_STATE_MIGRATION_VECTORS[0].input;
  const invalid: unknown[] = [
    { ...baseline, version: 2 },
    { ...baseline, sourceStoreVersion: 2 },
    { ...baseline, targetStoreVersion: 3 },
    { ...baseline, assignedWorkerGeneration: 0 },
    { ...baseline, workerGenerationFloor: baseline.assignedWorkerGeneration },
    { ...baseline, legacyState: "ready" },
    { ...baseline, migratedAt: "yesterday" },
    { ...baseline, unknownField: true },
    { ...baseline, bossRunId: "must-never-be-inferred" },
  ];
  for (const value of invalid) {
    assert.throws(() => parseLegacyWorkerMigrationInputV1(value), ContractValidationError);
    assert.throws(() => migrateLegacyWorkerRecordV1(value), ContractValidationError);
  }
});

test("migrated record validation rejects corrupt identity, mapping, and pending-state combinations", () => {
  const provisioning = structuredClone(PARTICIPANT_STATE_MIGRATION_VECTORS[0].expected);
  const running = structuredClone(PARTICIPANT_STATE_MIGRATION_VECTORS[1].expected);
  const idle = structuredClone(PARTICIPANT_STATE_MIGRATION_VECTORS[2].expected);
  const blocked = structuredClone(PARTICIPANT_STATE_MIGRATION_VECTORS[3].expected);
  const pending = structuredClone(PARTICIPANT_STATE_MIGRATION_VECTORS[8].expected);
  const { resumeState: _omittedResumeState, ...missingResumeState } = blocked;
  const invalid: unknown[] = [
    { ...provisioning, schemaVersion: 3 },
    { ...provisioning, workerIncarnationId: "rewritten" },
    { ...provisioning, dispatchAllowed: true },
    { ...provisioning, bossRunId: "inferred-cross-namespace-authority" },
    { ...provisioning, resumeState: "registering" },
    { ...running, state: "ready" },
    { ...idle, legacyIdleHint: false },
    missingResumeState,
    { ...blocked, resumeState: null },
    { ...blocked, resumeState: "provisioning" },
    { ...blocked, resumeState: "paused" },
    { ...pending, state: "stopped" },
    { ...pending, readOnly: false },
  ];
  for (const value of invalid) {
    assert.throws(() => parseMigratedWorkerRecordV2(value), ContractValidationError);
  }
});

for (const vector of STOPPING_RECONCILIATION_VECTORS) {
  test(`legacy stopping vector: ${vector.name}`, () => {
    const result = reconcileLegacyStoppingWorker(vector.pending, vector.evidence);
    assert.equal(result.state, vector.expectedState);
    assert.equal(result.reason, vector.expectedReason);
    assert.equal(result.migrationStatus, "complete");
    assert.equal(result.readOnly, false);
    assert.equal(result.dispatchAllowed, false);
    assert.deepEqual(result.stoppingReconciliation, vector.evidence);
    assert.deepEqual(parseMigratedWorkerRecordV2(result), result);
  });
}

test("legacy stopping stays fenced until matching direct evidence or bounded-settle expiry", () => {
  const vector = STOPPING_RECONCILIATION_VECTORS[0];
  assert.throws(
    () => reconcileLegacyStoppingWorker(vector.pending, { ...vector.evidence, workerGeneration: 10 }),
    /does not match/,
  );
  assert.throws(
    () => reconcileLegacyStoppingWorker(PARTICIPANT_STATE_MIGRATION_VECTORS[0].expected, vector.evidence),
    /not pending/,
  );
  assert.throws(
    () => parseLegacyStoppingReconciliationV1({
      ...STOPPING_RECONCILIATION_VECTORS[3].evidence,
      boundedSettleWindowExpired: false,
    }),
    /must be true/,
  );
  assert.throws(
    () => parseLegacyStoppingReconciliationV1({ ...vector.evidence, boundedSettleWindowExpired: true }),
    /must be false/,
  );
  const migratedAt = vector.pending.migrationAudit.migratedAt;
  assert.throws(
    () => reconcileLegacyStoppingWorker(vector.pending, { ...vector.evidence, observedAt: "2025-12-31T23:59:59.999Z" }),
    /must not precede the pending migration/,
  );
  const boundary = reconcileLegacyStoppingWorker(vector.pending, { ...vector.evidence, observedAt: migratedAt });
  assert.equal(boundary.stoppingReconciliation?.observedAt, migratedAt);
  assert.deepEqual(parseMigratedWorkerRecordV2(boundary), boundary);
});

test("health event schema is strict, versioned, and preserves acknowledgment ordering", () => {
  assert.deepEqual(parseParticipantHealthEventV1(PARTICIPANT_HEALTH_EVENT_VECTOR), PARTICIPANT_HEALTH_EVENT_VECTOR);
  assert.throws(
    () => parseParticipantHealthEventV1({ ...PARTICIPANT_HEALTH_EVENT_VECTOR, version: 2 }),
    /unsupported version/,
  );
  assert.throws(
    () => parseParticipantHealthEventV1({ ...PARTICIPANT_HEALTH_EVENT_VECTOR, reason: null }),
    /requires an explicit reason/,
  );
  assert.throws(
    () => parseParticipantHealthEventV1({
      ...PARTICIPANT_HEALTH_EVENT_VECTOR,
      state: "failed",
      reason: "adapter crashed",
      failureCode: null,
    }),
    /failure code/,
  );
  assert.throws(
    () => parseParticipantHealthEventV1({
      ...PARTICIPANT_HEALTH_EVENT_VECTOR,
      acknowledgedAt: "2026-07-28T11:59:59.000Z",
    }),
    /must not precede/,
  );
  assert.throws(
    () => parseParticipantHealthEventV1({ ...PARTICIPANT_HEALTH_EVENT_VECTOR, invented: true }),
    /is not supported/,
  );
});

function completeReadinessEvidence() {
  return {
    adapterStartupReady: true,
    brokerRegistrationReady: true,
    bindingAttested: true,
    capabilityProfileAttested: true,
    assignmentControlSupported: true,
  } as const;
}

function evidenceForRule(rule: string, previousState: ParticipantState, state: ParticipantState): unknown {
  const base = { kind: rule, evidenceId: `evidence-${previousState}-${state}` };
  switch (rule) {
    case "state_confirmation":
    case "registration_started":
    case "stop_observed":
    case "new_generation_provisioned":
      return base;
    case "readiness_reconciled":
      return { ...base, ...completeReadinessEvidence() };
    case "legacy_idle_reconciled":
      return { ...base, ...completeReadinessEvidence(), legacyIdleHint: true, noActiveTurn: true };
    case "turn_started":
      return { ...base, turnId: "turn-matrix" };
    case "turn_settled":
      return { ...base, turnId: "turn-matrix", noActiveTurn: true };
    case "intentional_pause":
      return { ...base, checkpointId: "checkpoint-matrix" };
    case "parked_resume":
      return {
        ...base,
        ...completeReadinessEvidence(),
        resumableState: state,
        parkedProcessConfirmed: true,
        noActiveTurn: true,
      };
    case "blocker_detected":
      return { ...base, resumeState: previousState, reason: "matrix_blocker" };
    case "blocked_reaffirmed":
      return { ...base, storedResumeState: "working", reason: "matrix_blocker" };
    case "blocker_cleared":
      return { ...base, storedResumeState: state, blockerClearConfirmed: true };
    case "controller_liveness_stalled":
      return {
        ...base,
        controllerParticipantId: "participant-controller",
        livenessDeadlineExceeded: true,
      };
    case "controller_liveness_recovered":
      return {
        ...base,
        controllerParticipantId: "participant-controller",
        resumableState: state,
        positiveStateEvidenceId: "positive-state-matrix",
      };
    case "connectivity_recovered":
      return { ...base, freshReadinessReconciliationRequired: true };
    case "failure_observed":
      return { ...base, outcome: state };
    default:
      throw new Error(`missing test evidence factory for ${rule}`);
  }
}

test("same-generation transition table is a complete 12 by 12 guarded matrix", () => {
  assert.deepEqual(Object.keys(PARTICIPANT_STATE_TRANSITION_TABLE), PARTICIPANT_STATES);
  for (const previousState of PARTICIPANT_STATES) {
    const row = PARTICIPANT_STATE_TRANSITION_TABLE[previousState];
    assert.deepEqual(Object.keys(row), PARTICIPANT_STATES, previousState);
    for (const state of PARTICIPANT_STATES) {
      const rule = row[state];
      const input = {
        version: 1,
        previousState,
        ...(previousState === "blocked"
          ? { previousResumeState: rule === "blocker_cleared" ? state : "working" }
          : {}),
        state,
        previousWorkerGeneration: 3,
        workerGeneration: 3,
        evidence: rule === null
          ? { kind: "state_confirmation", evidenceId: "denied-edge-probe" }
          : evidenceForRule(rule, previousState, state),
      };
      if (rule === null) {
        assert.throws(() => validateParticipantStateTransition(input), ContractValidationError, `${previousState}->${state}`);
      } else {
        assert.doesNotThrow(() => validateParticipantStateTransition(input), `${previousState}->${state}`);
      }
    }
  }
});

test("transition evidence and version parsing are strict and fail closed", () => {
  const baseline = PARTICIPANT_STATE_TRANSITION_VECTORS[0].input;
  assert.deepEqual(parseParticipantStateTransitionContextV1(baseline), baseline);
  const invalid: unknown[] = [
    { ...baseline, version: 2 },
    { ...baseline, evidence: { ...baseline.evidence, invented: true } },
    { ...baseline, evidence: { ...baseline.evidence, evidenceId: "" } },
    { ...baseline, evidence: { ...baseline.evidence, adapterStartupReady: false } },
    { ...baseline, unknownField: true },
  ];
  for (const value of invalid) {
    assert.throws(() => parseParticipantStateTransitionContextV1(value), ContractValidationError);
    assert.throws(() => validateParticipantStateTransition(value), ContractValidationError);
  }
});

test("guarded transitions enforce legacy idle, blocker, stall, pause, and unreachable rulings", () => {
  for (const vector of PARTICIPANT_STATE_TRANSITION_VECTORS) {
    assert.doesNotThrow(() => validateParticipantStateTransition(vector.input), vector.name);
  }

  const legacyIdle = PARTICIPANT_STATE_TRANSITION_VECTORS[1].input;
  const blockClear = PARTICIPANT_STATE_TRANSITION_VECTORS[3].input;
  const stallRecovery = PARTICIPANT_STATE_TRANSITION_VECTORS[5].input;
  const pausedResume = PARTICIPANT_STATE_TRANSITION_VECTORS[6].input;
  const unreachableRecovery = PARTICIPANT_STATE_TRANSITION_VECTORS[7].input;
  const invalid: unknown[] = [
    { ...legacyIdle, evidence: { kind: "readiness_reconciled", evidenceId: "not-legacy-idle", ...completeReadinessEvidence() } },
    { ...legacyIdle, evidence: { ...legacyIdle.evidence, noActiveTurn: false } },
    { ...blockClear, previousResumeState: "ready" },
    { ...blockClear, evidence: { ...blockClear.evidence, storedResumeState: "waiting" } },
    { ...stallRecovery, evidence: { ...stallRecovery.evidence, resumableState: "ready" } },
    { ...pausedResume, state: "stalled", evidence: {
      kind: "controller_liveness_stalled",
      evidenceId: "invalid-paused-stall",
      controllerParticipantId: "participant-controller",
      livenessDeadlineExceeded: true,
    } },
    { ...unreachableRecovery, state: "ready", evidence: {
      kind: "readiness_reconciled",
      evidenceId: "invalid-direct-unreachable-ready",
      ...completeReadinessEvidence(),
    } },
  ];
  for (const value of invalid) {
    assert.throws(() => validateParticipantStateTransition(value), ContractValidationError);
  }
});

test("blocked transitions are bound to the authoritative persisted resume state", () => {
  const blockClear = PARTICIPANT_STATE_TRANSITION_VECTORS[3].input;
  const blockedReaffirmed = PARTICIPANT_STATE_TRANSITION_VECTORS.at(-1)!.input;
  assert.doesNotThrow(() => validateParticipantStateTransition(blockClear));
  assert.doesNotThrow(() => validateParticipantStateTransition(blockedReaffirmed));

  const { previousResumeState: _omitted, ...withoutPersistedResumeState } = blockClear;
  assert.throws(
    () => validateParticipantStateTransition(withoutPersistedResumeState),
    /previousResumeState.*required.*persisted blocked state/,
  );
  assert.throws(
    () => validateParticipantStateTransition({ ...blockClear, previousResumeState: "ready" }),
    /storedResumeState.*persisted blocked resume state/,
  );
  assert.throws(
    () => validateParticipantStateTransition({
      ...blockedReaffirmed,
      evidence: { ...blockedReaffirmed.evidence, storedResumeState: "working" },
    }),
    /storedResumeState.*preserve.*persisted blocked resume state/,
  );
  assert.throws(
    () => validateParticipantStateTransition({ ...PARTICIPANT_STATE_TRANSITION_VECTORS[0].input, previousResumeState: "ready" }),
    /previousResumeState.*only.*persisted blocked state/,
  );

  let getterCalls = 0;
  const accessor = Object.defineProperty({ ...blockClear }, "previousResumeState", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return "working";
    },
  });
  assert.throws(() => validateParticipantStateTransition(accessor), ContractValidationError);
  assert.equal(getterCalls, 0);
});

test("terminal generations have no exits and generation changes use the exhaustive restart table", () => {
  assert.deepEqual(PARTICIPANT_NEW_GENERATION_TRANSITIONS, {
    provisioning: [],
    registering: [],
    ready: [],
    working: [],
    waiting: [],
    paused: ["ready", "waiting"],
    stalled: [],
    blocked: [],
    failed: ["provisioning"],
    lost: ["provisioning"],
    unreachable: [],
    stopped: ["provisioning"],
  });
  for (const terminal of TERMINAL_PARTICIPANT_STATES) {
    for (const target of PARTICIPANT_STATES) {
      const input = {
        version: 1,
        previousState: terminal,
        state: target,
        previousWorkerGeneration: 4,
        workerGeneration: 4,
        evidence: evidenceForRule(target === terminal ? "state_confirmation" : "new_generation_provisioned", terminal, target),
      };
      if (target === terminal) assert.doesNotThrow(() => validateParticipantStateTransition(input));
      else assert.throws(() => validateParticipantStateTransition(input), ContractValidationError);
    }
  }

  const stoppedRestart = PARTICIPANT_STATE_TRANSITION_VECTORS[9].input;
  assert.doesNotThrow(() => validateParticipantStateTransition(stoppedRestart));
  assert.throws(
    () => validateParticipantStateTransition({ ...stoppedRestart, workerGeneration: 9 }),
    /exactly one generation/,
  );
  assert.throws(
    () => validateParticipantStateTransition({ ...stoppedRestart, previousState: "working" }),
    /not canonical for a new generation/,
  );
  assert.throws(
    () => validateParticipantStateTransition({ ...stoppedRestart, workerGeneration: 6 }),
    /must not regress/,
  );
});

test("dispatch is positively gated and all ruled non-dispatch states fail closed", () => {
  assert.deepEqual(PARTICIPANT_DISPATCHABLE_STATES, ["ready", "waiting"]);
  assert.deepEqual(PARTICIPANT_READ_ONLY_STATES, ["unreachable"]);
  for (const state of PARTICIPANT_STATES) {
    assert.equal(canDispatchParticipantState(state), state === "ready" || state === "waiting", state);
    assert.equal(isParticipantStateReadOnly(state), state === "unreachable", state);
  }
  assert.throws(() => canDispatchParticipantState("newer-state"), ContractValidationError);
  assert.throws(() => isParticipantStateReadOnly("newer-state"), ContractValidationError);
});

test("transition table, generation table, and positive evidence vectors have a frozen canonical hash", () => {
  assert.equal(
    canonicalHash(PARTICIPANT_STATE_TRANSITION_VECTOR_HASH_DOMAIN, PARTICIPANT_STATE_TRANSITION_VECTOR_CORPUS),
    PARTICIPANT_STATE_TRANSITION_VECTORS_HASH,
  );
});

test("parser returns a fresh strict contract rather than trusting mutable input", () => {
  const input: LegacyWorkerMigrationInputV1 = structuredClone(PARTICIPANT_STATE_MIGRATION_VECTORS[0].input);
  const parsed = parseLegacyWorkerMigrationInputV1(input);
  input.workerId = "mutated-after-parse";
  assert.notEqual(parsed.workerId, input.workerId);

  const output: MigratedWorkerRecordV2 = structuredClone(PARTICIPANT_STATE_MIGRATION_VECTORS[0].expected);
  const parsedOutput = parseMigratedWorkerRecordV2(output);
  output.migrationAudit.originalRunId = "mutated-after-parse";
  assert.notEqual(parsedOutput.migrationAudit.originalRunId, output.migrationAudit.originalRunId);
});

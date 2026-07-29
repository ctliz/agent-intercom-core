import assert from "node:assert/strict";
import test from "node:test";
import { ContractValidationError } from "../src/canonical.ts";
import { WORKER_IDENTITY_VERSION, parseWorkerEventIdentityV2, parseWorkerIdentityV2, workerIdentityFromEnvironment } from "../src/worker-identity.ts";

test("ordinary v2 worker identities keep Boss authority absent", () => {
  const identity = { version: WORKER_IDENTITY_VERSION, workerId: "worker-a", workerIncarnationId: "inc-a", workerGeneration: 3 };
  assert.deepEqual(parseWorkerIdentityV2(identity), identity);
  assert.equal("bossRunId" in parseWorkerIdentityV2(identity), false);
});

test("Boss worker identity requires the complete authenticated binding tuple", () => {
  const identity = { version: WORKER_IDENTITY_VERSION, workerId: "worker-a", workerIncarnationId: "inc-a", workerGeneration: 3, bossRunId: "boss-a", participantId: "participant-a", bindingEpoch: 2 };
  assert.deepEqual(parseWorkerIdentityV2(identity), identity);
  assert.throws(() => parseWorkerIdentityV2({ ...identity, participantId: undefined }), ContractValidationError);
  assert.throws(() => parseWorkerIdentityV2({ ...identity, version: "orc.worker-identity.v3" }), ContractValidationError);
});

test("legacy AGENT_INTERCOM_RUN_ID remains an ordinary incarnation and never Boss authority", () => {
  const legacy = workerIdentityFromEnvironment({
    AGENT_INTERCOM_WORKER_ID: "worker-a",
    AGENT_INTERCOM_WORKER_GENERATION: "4",
    AGENT_INTERCOM_RUN_ID: "legacy-incarnation-byte-for-byte",
  });
  assert.deepEqual(legacy, {
    version: WORKER_IDENTITY_VERSION,
    workerId: "worker-a",
    workerIncarnationId: "legacy-incarnation-byte-for-byte",
    workerGeneration: 4,
  });
  assert.throws(() => workerIdentityFromEnvironment({
    AGENT_INTERCOM_WORKER_ID: "worker-a",
    AGENT_INTERCOM_WORKER_GENERATION: "4",
    AGENT_INTERCOM_RUN_ID: "pretend-boss-run",
    AGENT_INTERCOM_BOSS_RUN_ID: "pretend-boss-run",
    AGENT_INTERCOM_PARTICIPANT_ID: "worker-a",
    AGENT_INTERCOM_BINDING_EPOCH: "1",
  }), /cannot establish Boss authority/);
});

test("a real process.env ignores unrelated standard and Intercom runtime fields", () => {
  const keys = [
    "AGENT_INTERCOM_WORKER_ID",
    "AGENT_INTERCOM_WORKER_INCARNATION_ID",
    "AGENT_INTERCOM_WORKER_GENERATION",
    "AGENT_INTERCOM_BOSS_RUN_ID",
    "AGENT_INTERCOM_PARTICIPANT_ID",
    "AGENT_INTERCOM_BINDING_EPOCH",
    "AGENT_INTERCOM_RUN_ID",
    "AGENT_INTERCOM_SUPERVISOR_ID",
  ] as const;
  const original = new Map(keys.map((key) => [key, { present: Object.hasOwn(process.env, key), value: process.env[key] }]));
  try {
    for (const key of keys) delete process.env[key];
    Object.assign(process.env, {
      AGENT_INTERCOM_WORKER_ID: "worker-real-env",
      AGENT_INTERCOM_WORKER_INCARNATION_ID: "inc-real-env",
      AGENT_INTERCOM_WORKER_GENERATION: "6",
      AGENT_INTERCOM_BOSS_RUN_ID: "boss-real-env",
      AGENT_INTERCOM_PARTICIPANT_ID: "participant-real-env",
      AGENT_INTERCOM_BINDING_EPOCH: "3",
      AGENT_INTERCOM_SUPERVISOR_ID: "unrelated-runtime-field",
    });
    assert.deepEqual(workerIdentityFromEnvironment(process.env), {
      version: WORKER_IDENTITY_VERSION,
      workerId: "worker-real-env",
      workerIncarnationId: "inc-real-env",
      workerGeneration: 6,
      bossRunId: "boss-real-env",
      participantId: "participant-real-env",
      bindingEpoch: 3,
    });
  } finally {
    for (const key of keys) {
      const previous = original.get(key)!;
      if (previous.present) process.env[key] = previous.value;
      else delete process.env[key];
    }
  }
});

test("environment Boss authority namespaces reject unknown and partial fields", () => {
  const ordinary = {
    PATH: "/usr/bin",
    AGENT_INTERCOM_WORKER_ID: "worker-a",
    AGENT_INTERCOM_WORKER_INCARNATION_ID: "inc-a",
    AGENT_INTERCOM_WORKER_GENERATION: "4",
    AGENT_INTERCOM_SUPERVISOR_ID: "ignored-supervisor",
  };
  assert.deepEqual(workerIdentityFromEnvironment(ordinary), {
    version: WORKER_IDENTITY_VERSION,
    workerId: "worker-a",
    workerIncarnationId: "inc-a",
    workerGeneration: 4,
  });

  for (const key of [
    "AGENT_INTERCOM_BOSS_RUN",
    "AGENT_INTERCOM_PARTICIPANT_BINDING_ID",
    "AGENT_INTERCOM_BINDING_GENERATION",
  ]) {
    assert.throws(
      () => workerIdentityFromEnvironment({ ...ordinary, [key]: "typo-must-not-downgrade" }),
      (error: unknown) => error instanceof ContractValidationError && error.path === `$.${key}`,
    );
  }

  const authority = {
    AGENT_INTERCOM_BOSS_RUN_ID: "boss-a",
    AGENT_INTERCOM_PARTICIPANT_ID: "participant-a",
    AGENT_INTERCOM_BINDING_EPOCH: "2",
  };
  for (const omitted of Object.keys(authority) as Array<keyof typeof authority>) {
    const partial: Partial<typeof authority> = { ...authority };
    delete partial[omitted];
    assert.throws(() => workerIdentityFromEnvironment({ ...ordinary, ...partial }), /must be present together/);
  }
  assert.throws(
    () => workerIdentityFromEnvironment({ ...ordinary, ...authority, AGENT_INTERCOM_BINDING_EPOCH: "02" }),
    /must be a positive base-10 integer/,
  );
});

test("event identity rejects partial Boss metadata and unknown fields", () => {
  const event = { workerId: "worker-a", workerIncarnationId: "inc-a", workerGeneration: 5 };
  assert.deepEqual(parseWorkerEventIdentityV2(event), event);
  assert.throws(() => parseWorkerEventIdentityV2({ ...event, bossRunId: "run-a" }), ContractValidationError);
  assert.throws(() => parseWorkerEventIdentityV2({ ...event, runId: "ambiguous" }), ContractValidationError);
});

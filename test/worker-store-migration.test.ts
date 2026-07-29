import assert from "node:assert/strict";
import test from "node:test";
import { canonicalHash } from "../src/canonical.ts";
import { parseFullWorkerStoreMigrationInputV1, migrateFullWorkerStoreV1, parseWorkerStoreRecordV2 } from "../src/worker-store-migration.ts";
import {
  FULL_WORKER_STORE_MIGRATION_VECTOR_CORPUS,
  FULL_WORKER_STORE_MIGRATION_VECTOR_HASH_DOMAIN,
  FULL_WORKER_STORE_MIGRATION_VECTOR_VERSION,
  FULL_WORKER_STORE_MIGRATION_VECTORS,
  FULL_WORKER_STORE_MIGRATION_VECTORS_HASH,
  FULL_WORKER_STORE_V2_STRICT_REJECTION_VECTORS,
} from "../src/worker-store-migration-vectors.ts";

const IDENTITY_BOUND_SURFACES = ["health", "runtime", "adapter", "systemd", "notice", "controller"] as const;

test("full WorkerStore compatibility corpus covers every legacy state with a frozen hash", () => {
  assert.equal(FULL_WORKER_STORE_MIGRATION_VECTORS.length, 9);
  assert.equal(FULL_WORKER_STORE_MIGRATION_VECTOR_VERSION, 2);
  assert.equal(
    canonicalHash(FULL_WORKER_STORE_MIGRATION_VECTOR_HASH_DOMAIN, FULL_WORKER_STORE_MIGRATION_VECTOR_CORPUS),
    FULL_WORKER_STORE_MIGRATION_VECTORS_HASH,
  );
  assert.equal(FULL_WORKER_STORE_MIGRATION_VECTORS_HASH, "dfc3680c3b085a0a7a53266abe309d5710a181b7831d2582998dd38e76dca2bf");
  for (const vector of FULL_WORKER_STORE_MIGRATION_VECTORS) {
    assert.deepEqual(parseFullWorkerStoreMigrationInputV1(vector.input), vector.input);
    assert.deepEqual(migrateFullWorkerStoreV1(vector.input), vector.expected);
    assert.deepEqual(parseWorkerStoreRecordV2(vector.expected), vector.expected);
    assert.equal("bossRunId" in vector.expected.worker, false);
    assert.equal(vector.expected.environment.AGENT_INTERCOM_RUN_ID, vector.expected.worker.workerIncarnationId);
    assert.equal(vector.expected.environment.AGENT_INTERCOM_WORKER_INCARNATION_ID, vector.expected.worker.workerIncarnationId);
    assert.equal(vector.expected.environment.AGENT_INTERCOM_WORKER_GENERATION, String(vector.expected.worker.workerGeneration));
    assert.equal("AGENT_INTERCOM_BOSS_RUN_ID" in vector.expected.environment, false);
    assert.equal(vector.expected.environment.workspacePath, vector.input.environment.workspacePath);
    for (const surface of IDENTITY_BOUND_SURFACES) {
      assert.equal(vector.expected[surface].workerIncarnationId, vector.expected.worker.workerIncarnationId);
      assert.equal(vector.expected[surface].workerGeneration, vector.expected.worker.workerGeneration);
      assert.equal("bossRunId" in vector.expected[surface], false);
    }
    assert.equal(
      vector.expected.notice.owningManagerRecipient.recipientPrincipalId,
      vector.input.notice.owningManagerRecipient.recipientPrincipalId,
    );
    const recipient = vector.expected.notice.owningManagerRecipient;
    if (recipient.recipientContext === "headless_cli") {
      assert.equal("recipientSessionId" in recipient, false);
      assert.equal("recipientTargetSessionId" in recipient, false);
    } else {
      assert.ok(recipient.recipientSessionId.length > 0);
    }
    assert.equal(vector.expected.compatibilityAudit.deprecatedEnvironmentAliasLastSupportedVersion, vector.expected.version);
  }
});

test("strict WorkerStore v2 vectors reject stale surface identity, invalid Manager recipients, and Boss authority", () => {
  assert.equal(FULL_WORKER_STORE_V2_STRICT_REJECTION_VECTORS.length, 17);
  for (const vector of FULL_WORKER_STORE_V2_STRICT_REJECTION_VECTORS) {
    assert.throws(() => parseWorkerStoreRecordV2(vector.value), /./, vector.name);
  }
});

test("full migration rejects unknown schemas, field loss, and legacy incarnation substitution", () => {
  const input = FULL_WORKER_STORE_MIGRATION_VECTORS[0].input;
  assert.throws(() => parseFullWorkerStoreMigrationInputV1({ ...input, version: 2 }), /unsupported version/);
  assert.throws(() => parseFullWorkerStoreMigrationInputV1({ ...input, hidden: true }), /not supported/);
  assert.throws(() => parseFullWorkerStoreMigrationInputV1({ ...input, environment: { ...input.environment, AGENT_INTERCOM_RUN_ID: "pretend-boss" } }), /must match the legacy incarnation/);
  assert.throws(() => parseWorkerStoreRecordV2({ ...FULL_WORKER_STORE_MIGRATION_VECTORS[0].expected, version: "orc.worker-store-record.v3" }), /unsupported version/);
  const expected = FULL_WORKER_STORE_MIGRATION_VECTORS[0].expected;
  const { AGENT_INTERCOM_RUN_ID: _deprecatedAlias, ...environmentWithoutAlias } = expected.environment;
  assert.throws(() => parseWorkerStoreRecordV2({ ...expected, environment: environmentWithoutAlias }), /AGENT_INTERCOM_RUN_ID.*required/);
  const { owningManagerRecipient: _recipient, ...noticeWithoutRecipient } = expected.notice;
  assert.throws(() => parseWorkerStoreRecordV2({ ...expected, notice: noticeWithoutRecipient }), /owningManagerRecipient.*required/);
});

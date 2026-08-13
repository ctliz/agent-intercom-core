import assert from "node:assert/strict";
import test from "node:test";
import {
  ContractValidationError,
  brokerGeneration,
  brokerRevision,
  canonicalHash,
  canonicalJson,
  controllerGeneration,
  deliveryClaimGeneration,
  journalGeneration,
  participantBindingEpoch,
  recipientTransferGeneration,
  schedulerGeneration,
  transitionVersion,
  workerGeneration,
} from "../src/canonical.ts";
import {
  AUTHORITY_EVENT_VERSION,
  AUTHORITY_REQUEST_VERSION,
  AUTHORITY_TRANSITION_VERSION,
  BOSS_CONTROL_ENVELOPE_VERSION,
  BOSS_CREDENTIAL_DIGEST_RECORD_VERSION,
  BOSS_CREDENTIAL_AUDIT_EVENT_VERSION,
  BOSS_PARTICIPANT_BINDING_VERSION,
  BOSS_PARTICIPANT_CREDENTIAL_VERSION,
  BOSS_RUN_AUTHORITY_IDENTITY_VERSION,
  BOSS_RUN_FEATURE,
  BOSS_RUN_FEATURE_CONTRACT,
  BOSS_RUN_FEATURE_SEMANTICS_CORPUS,
  BOSS_RUN_FEATURE_SEMANTICS_HASH,
  BOSS_RUN_FEATURE_VERSION,
  BOSS_RUN_PROTOCOL_FEATURE_CONTRACT_HASH,
  BOSS_CAPABILITY_FEATURE_DIGEST,
  DELIVERY_CLAIM_VERSION,
  DELIVERY_GROUP_VERSION,
  DELIVERY_GROUP_ASSEMBLY_VERSION,
  LIFECYCLE_NOTICE_VERSION,
  NOTICE_RECIPIENT_INGRESS_VERSION,
  TARGET_LEDGER_RESULT_VERSION,
  authorizeBossCredentialUse,
  assembleDeliveryGroup,
  credentialDigest,
  deliveryGroupId,
  effectiveDeliveryIntent,
  lifecycleNoticeId,
  mintDeliveryGroupAssemblyMember,
  parseAuthorityTransitionEvent,
  parseAuthorityTransitionRecord,
  parseAuthorityTransitionRequest,
  parseBossControlEnvelope,
  parseBossCredentialDigestRecord,
  parseBossCredentialAuditEvent,
  parseBossParticipantBinding,
  parseBossParticipantCredentialEnvelope,
  parseBossRunAuthorityIdentity,
  parseBossRunFeatureContract,
  parseDeliveryClaimRecord,
  parseDeliveryEquivalenceKey,
  parseDeliveryGroupRecord,
  parseDeliveryGroupAssemblyInput,
  parseLifecycleNotice,
  parseNoticeRecipientIngressEnvelope,
  parseTargetLedgerLookupResult,
  validateDeliveryGroupStore,
  type AuthorityTransitionRecord,
  type BossControlEnvelope,
  type BossCredentialDigestRecord,
  type BossParticipantBinding,
  type BossParticipantCredentialEnvelope,
  type DeliveryClaimRecord,
  type DeliveryClaimReleaseProof,
  type DeliveryEquivalenceKey,
  type DeliveryGroupRecord,
  type LifecycleNotice,
  type NoticeRecipientIngressEnvelope,
} from "../src/boss-wire.ts";
import {
  FULL_WORKER_STORE_MIGRATION_VECTOR_VERSION,
  FULL_WORKER_STORE_MIGRATION_VECTORS_HASH,
  INTERCOM_BASE_PROTOCOL_VERSION,
  PARTICIPANT_STATE_TRANSITION_VECTOR_SCHEMA_VERSION,
  PARTICIPANT_STATE_TRANSITION_VECTORS_HASH,
  PARTICIPANT_STATE_VECTOR_SCHEMA_VERSION,
  PARTICIPANT_STATE_VECTORS_HASH,
  SUPERVISION_VECTOR_SCHEMA_VERSION,
  SUPERVISION_VECTORS_HASH,
} from "../src/boss-semantic-binding-constants.ts";

const t0 = "2026-07-28T12:00:00.000Z";
const t1 = "2026-07-28T12:01:00.000Z";
const t2 = "2026-07-28T12:02:00.000Z";

function rejectsContract(run: () => unknown, pattern?: RegExp): void {
  assert.throws(run, (error: unknown) => {
    assert.ok(error instanceof ContractValidationError);
    if (pattern) assert.match(error.message, pattern);
    return true;
  });
}

type ArrayShapeCase<T> = {
  name: string;
  value: T[];
  pattern: RegExp;
  getterCalls?: () => number;
};

function untrustedArrayShapeCases<T>(entries: readonly T[]): ArrayShapeCase<T>[] {
  assert.ok(entries.length > 0);

  const sparse = new Array<T>(entries.length);

  const inherited = new Array<T>(entries.length);
  const inheritedPrototype = Object.create(Array.prototype) as object;
  for (let index = 0; index < entries.length; index += 1) {
    Object.defineProperty(inheritedPrototype, String(index), {
      configurable: true,
      enumerable: true,
      value: entries[index],
      writable: true,
    });
  }
  Object.setPrototypeOf(inherited, inheritedPrototype);

  let getterCallCount = 0;
  const accessor = [...entries];
  Object.defineProperty(accessor, "0", {
    configurable: true,
    enumerable: true,
    get() {
      getterCallCount += 1;
      return entries[0];
    },
  });

  const symbolExtra = [...entries] as T[] & Record<PropertyKey, unknown>;
  Object.defineProperty(symbolExtra, Symbol("metadata"), { enumerable: true, value: true });

  const nonIndexExtra = [...entries];
  Object.defineProperty(nonIndexExtra, "metadata", { enumerable: true, value: true });

  return [
    { name: "sparse holes", value: sparse, pattern: /sparse array holes are not supported/ },
    { name: "inherited indices", value: inherited, pattern: /sparse array holes are not supported/ },
    {
      name: "accessor indices",
      value: accessor,
      pattern: /must be an enumerable data property/,
      getterCalls: () => getterCallCount,
    },
    { name: "symbol extras", value: symbolExtra, pattern: /array must not have symbol or non-index properties/ },
    { name: "non-index extras", value: nonIndexExtra, pattern: /array must not have symbol or non-index properties/ },
  ];
}

test("boss-run-v1 feature contract has an independent stable golden hash and rejects downgrade/unknown versions", () => {
  assert.equal(BOSS_RUN_FEATURE, "boss-run-v1");
  assert.equal(BOSS_RUN_FEATURE_VERSION, 1);
  assert.equal(INTERCOM_BASE_PROTOCOL_VERSION, 4);
  assert.equal(BOSS_RUN_FEATURE_CONTRACT.baseProtocolVersion, INTERCOM_BASE_PROTOCOL_VERSION);
  assert.equal(BOSS_CONTROL_ENVELOPE_VERSION, 1);
  assert.equal(BOSS_RUN_FEATURE_SEMANTICS_HASH, "8943eb60d29afa5264322b5cc7df3de245b01b1cf48a8cbf9cfb6188b02fcfa9");
  assert.equal(BOSS_RUN_PROTOCOL_FEATURE_CONTRACT_HASH, "dae30efe2c48d2de0fe72a7ebdfd107d3feaefc180d42056ba05df6088a94364");
  assert.equal(BOSS_CAPABILITY_FEATURE_DIGEST, "239bee8bb64cc8c149d49ac00c7396f33f375a89a1d6dea6bd86ff840d551a59");
  assert.equal(
    BOSS_RUN_FEATURE_SEMANTICS_CORPUS.controllerDeliveryRunIdentity,
    "embedded_and_top_level_boss_run_id_present_and_equal",
  );
  assert.deepEqual(parseBossRunFeatureContract(structuredClone(BOSS_RUN_FEATURE_CONTRACT)), BOSS_RUN_FEATURE_CONTRACT);
  rejectsContract(() => parseBossRunFeatureContract({ ...BOSS_RUN_FEATURE_CONTRACT, version: 2 }), /unsupported Boss feature version/);
  for (const baseProtocolVersion of [1, 2, 3]) {
    rejectsContract(
      () => parseBossRunFeatureContract({ ...BOSS_RUN_FEATURE_CONTRACT, baseProtocolVersion }),
      /unsupported Boss base protocol version/,
    );
  }
  rejectsContract(() => parseBossRunFeatureContract({ ...BOSS_RUN_FEATURE_CONTRACT, semanticsHash: "0".repeat(64) }), /semantics corpus/);
  rejectsContract(() => parseBossRunFeatureContract({ ...BOSS_RUN_FEATURE_CONTRACT, feature: "remote-access-v1" }), /boss-run-v1/);
  rejectsContract(() => parseBossRunFeatureContract({ ...BOSS_RUN_FEATURE_CONTRACT, ignored: true }), /not supported/);
});

test("Boss semantics bind the reviewed lifecycle and migration corpora and reject a canonically rehashed base downgrade", () => {
  assert.deepEqual(
    {
      participantStateVectorSchemaVersion: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.participantStateVectorSchemaVersion,
      participantStateVectorsHash: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.participantStateVectorsHash,
      participantStateTransitionVectorSchemaVersion: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.participantStateTransitionVectorSchemaVersion,
      participantStateTransitionVectorsHash: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.participantStateTransitionVectorsHash,
      supervisionVectorSchemaVersion: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.supervisionVectorSchemaVersion,
      supervisionVectorsHash: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.supervisionVectorsHash,
      fullWorkerStoreMigrationVectorVersion: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.fullWorkerStoreMigrationVectorVersion,
      fullWorkerStoreMigrationVectorsHash: BOSS_RUN_FEATURE_SEMANTICS_CORPUS.fullWorkerStoreMigrationVectorsHash,
    },
    {
      participantStateVectorSchemaVersion: PARTICIPANT_STATE_VECTOR_SCHEMA_VERSION,
      participantStateVectorsHash: PARTICIPANT_STATE_VECTORS_HASH,
      participantStateTransitionVectorSchemaVersion: PARTICIPANT_STATE_TRANSITION_VECTOR_SCHEMA_VERSION,
      participantStateTransitionVectorsHash: PARTICIPANT_STATE_TRANSITION_VECTORS_HASH,
      supervisionVectorSchemaVersion: SUPERVISION_VECTOR_SCHEMA_VERSION,
      supervisionVectorsHash: SUPERVISION_VECTORS_HASH,
      fullWorkerStoreMigrationVectorVersion: FULL_WORKER_STORE_MIGRATION_VECTOR_VERSION,
      fullWorkerStoreMigrationVectorsHash: FULL_WORKER_STORE_MIGRATION_VECTORS_HASH,
    },
  );
  assert.equal(BOSS_RUN_FEATURE_SEMANTICS_CORPUS.baseProtocolVersion, INTERCOM_BASE_PROTOCOL_VERSION);

  const downgradedSemanticsHash = canonicalHash(
    "agent-intercom-core/boss-run-v1/feature-semantics",
    { ...BOSS_RUN_FEATURE_SEMANTICS_CORPUS, baseProtocolVersion: 2 },
  );
  assert.notEqual(downgradedSemanticsHash, BOSS_RUN_FEATURE_SEMANTICS_HASH);
  rejectsContract(
    () => parseBossRunFeatureContract({
      ...BOSS_RUN_FEATURE_CONTRACT,
      baseProtocolVersion: 2,
      semanticsHash: downgradedSemanticsHash,
    }),
    /unsupported Boss base protocol version/,
  );
  rejectsContract(
    () => parseBossRunFeatureContract({ ...BOSS_RUN_FEATURE_CONTRACT, semanticsHash: downgradedSemanticsHash }),
    /semantics corpus/,
  );
});

test("broker-authenticated run and participant bindings distinguish the two epochs and bind role to profile", () => {
  const runIdentity = {
    version: BOSS_RUN_AUTHORITY_IDENTITY_VERSION,
    controllerPrincipalId: "controller:run-a",
    bossRunId: "run-a",
    controllerGeneration: 4,
    authorityTransitionRevision: 9,
    activeBossSessionId: "session-boss",
    bossBindingEpoch: 7,
  };
  assert.equal(parseBossRunAuthorityIdentity(runIdentity).bossBindingEpoch, 7);
  rejectsContract(() => parseBossRunAuthorityIdentity({ ...runIdentity, version: "boss.run-authority.v2" }), /unsupported version/);

  const binding: BossParticipantBinding = {
    version: BOSS_PARTICIPANT_BINDING_VERSION,
    bossRunId: "run-a",
    participantId: "manager-a",
    role: "manager",
    communicationProfile: "manager",
    bindingEpoch: participantBindingEpoch(3),
    sessionId: "session-manager",
    brokerGeneration: brokerGeneration(11),
    brokerBootInstance: "boot-22",
    state: "active",
    authorityTransitionId: "transition-bind-manager",
  };
  assert.deepEqual(parseBossParticipantBinding(binding), binding);
  rejectsContract(() => parseBossParticipantBinding({ ...binding, communicationProfile: "worker" }), /match the authenticated role/);
  rejectsContract(() => parseBossParticipantBinding({ ...binding, bindingEpoch: 0 }), /safe integer >= 1/);
  rejectsContract(() => parseBossParticipantBinding({ ...binding, role: "controller" }), /must be one of/);
});

const enrollment: BossParticipantCredentialEnvelope = {
  version: BOSS_PARTICIPANT_CREDENTIAL_VERSION,
  namespace: BOSS_RUN_FEATURE,
  credentialKind: "enrollment",
  credentialId: "cred-1",
  credential: "secret-once-1",
  bossRunId: "run-a",
  participantId: "worker-a",
  role: "worker",
  communicationProfile: "worker",
  bindingEpoch: participantBindingEpoch(2),
  issuedAt: t0,
  expiresAt: t2,
  nonce: "nonce-1",
};

test("one-time participant credentials have a canonical digest and fail closed on expiry/profile substitution", () => {
  assert.deepEqual(parseBossParticipantCredentialEnvelope(enrollment), enrollment);
  assert.equal(credentialDigest(enrollment), "d44af1c36ff21c06177dd7a698ff014eab9aceee4eb6af66b8ca91e643f2d77d");
  assert.notEqual(credentialDigest({ ...enrollment, bossRunId: "run-b" }), credentialDigest(enrollment));
  assert.notEqual(credentialDigest({ ...enrollment, bindingEpoch: participantBindingEpoch(3) }), credentialDigest(enrollment));
  rejectsContract(() => parseBossParticipantCredentialEnvelope({ ...enrollment, expiresAt: t0 }), /later than issuedAt/);
  rejectsContract(() => parseBossParticipantCredentialEnvelope({ ...enrollment, communicationProfile: "scout" }), /match role/);
  rejectsContract(() => parseBossParticipantCredentialEnvelope({ ...enrollment, version: "boss.participant-credential.v2" }), /unsupported version/);
});

test("credential digest registry encodes one-way consumption/revocation audit state", () => {
  const issued = digestRecord();
  assert.deepEqual(parseBossCredentialDigestRecord(issued), issued);
  assert.equal(parseBossCredentialDigestRecord({ ...issued, state: "consumed", consumedAt: t1 }).state, "consumed");
  assert.equal(parseBossCredentialDigestRecord({ ...issued, state: "revoked", revokedAt: t1 }).state, "revoked");
  rejectsContract(() => parseBossCredentialDigestRecord({ ...issued, state: "consumed" }), /consumedAt/);
  rejectsContract(() => parseBossCredentialDigestRecord({ ...issued, consumedAt: t1 }), /consumedAt/);
  rejectsContract(() => parseBossCredentialDigestRecord({ ...issued, state: "revoked" }), /revokedAt/);
  rejectsContract(() => parseBossCredentialDigestRecord({ ...issued, revokedAt: t1 }), /revokedAt/);
  rejectsContract(() => parseBossCredentialDigestRecord({
    ...issued,
    state: "consumed",
    consumedAt: t1,
    revokedAt: t1,
  }), /revokedAt/);
});

test("credential terminal timestamps preserve the issued-inclusive, expiry-exclusive consumption window", () => {
  const issued = digestRecord();
  assert.equal(parseBossCredentialDigestRecord({ ...issued, state: "consumed", consumedAt: t0 }).consumedAt, t0);
  assert.equal(parseBossCredentialDigestRecord({
    ...issued,
    state: "consumed",
    consumedAt: "2026-07-28T12:01:59.999Z",
  }).state, "consumed");
  rejectsContract(() => parseBossCredentialDigestRecord({
    ...issued,
    state: "consumed",
    consumedAt: "2026-07-28T11:59:59.999Z",
  }), /consumedAt.*must not precede issuedAt/);
  rejectsContract(() => parseBossCredentialDigestRecord({ ...issued, state: "consumed", consumedAt: t2 }), /consumedAt.*earlier than expiresAt/);
  rejectsContract(() => parseBossCredentialDigestRecord({
    ...issued,
    state: "consumed",
    consumedAt: "2026-07-28T12:02:00.001Z",
  }), /consumedAt.*earlier than expiresAt/);
});

test("credential revocation cannot predate issuance and remains valid through or after expiry", () => {
  const issued = digestRecord();
  assert.equal(parseBossCredentialDigestRecord({ ...issued, state: "revoked", revokedAt: t0 }).revokedAt, t0);
  assert.equal(parseBossCredentialDigestRecord({ ...issued, state: "revoked", revokedAt: t2 }).revokedAt, t2);
  assert.equal(parseBossCredentialDigestRecord({
    ...issued,
    state: "revoked",
    revokedAt: "2026-07-28T12:02:00.001Z",
  }).state, "revoked");
  rejectsContract(() => parseBossCredentialDigestRecord({
    ...issued,
    state: "revoked",
    revokedAt: "2026-07-28T11:59:59.999Z",
  }), /revokedAt.*must not precede issuedAt/);
});

test("credential attempts have a strict replay/substitution audit event", () => {
  const event = {
    version: BOSS_CREDENTIAL_AUDIT_EVENT_VERSION,
    eventId: "audit-attempt-1",
    credentialId: enrollment.credentialId,
    credentialKind: "enrollment",
    bossRunId: enrollment.bossRunId,
    participantId: enrollment.participantId,
    presentedBindingEpoch: enrollment.bindingEpoch,
    operation: "deny",
    outcome: "RUN_SUBSTITUTION",
    nonceDigest: "a".repeat(64),
    occurredAt: t1,
  };
  assert.deepEqual(parseBossCredentialAuditEvent(event), event);
  rejectsContract(() => parseBossCredentialAuditEvent({ ...event, version: "boss.credential-audit-event.v2" }), /unsupported version/);
  rejectsContract(() => parseBossCredentialAuditEvent({ ...event, operation: "consume", outcome: "RUN_SUBSTITUTION" }), /deny requires/);
});

function digestRecord(overrides: Partial<BossCredentialDigestRecord> = {}): BossCredentialDigestRecord {
  return {
    version: BOSS_CREDENTIAL_DIGEST_RECORD_VERSION,
    namespace: BOSS_RUN_FEATURE,
    credentialKind: "enrollment",
    credentialId: enrollment.credentialId,
    digest: credentialDigest(enrollment),
    bossRunId: enrollment.bossRunId,
    participantId: enrollment.participantId,
    role: enrollment.role,
    bindingEpoch: enrollment.bindingEpoch,
    nonce: enrollment.nonce,
    issuedAt: enrollment.issuedAt,
    expiresAt: enrollment.expiresAt,
    state: "issued",
    auditEventId: "audit-issued-1",
    ...overrides,
  };
}

test("credential use rejects expiry, replay, theft, substitution, stale epochs, and revoked records with audit correlation", () => {
  const context = {
    now: t1,
    credentialKind: "enrollment" as const,
    bossRunId: "run-a",
    participantId: "worker-a",
    role: "worker" as const,
    bindingEpoch: 2,
    nonce: "nonce-1",
  };
  assert.deepEqual(authorizeBossCredentialUse(enrollment, digestRecord(), context), {
    accepted: true,
    credentialId: "cred-1",
    auditEventId: "audit-issued-1",
  });
  assert.equal(authorizeBossCredentialUse(enrollment, digestRecord(), { ...context, now: t0 }).accepted, true);
  assert.deepEqual(authorizeBossCredentialUse(enrollment, digestRecord(), {
    ...context,
    now: "2026-07-28T11:59:59.999Z",
  }), {
    accepted: false,
    code: "NOT_YET_VALID",
    auditEventId: "audit-issued-1",
  });
  assert.equal(authorizeBossCredentialUse(enrollment, digestRecord(), {
    ...context,
    now: "2026-07-28T12:01:59.999Z",
  }).accepted, true);
  assert.equal(authorizeBossCredentialUse(enrollment, digestRecord({ state: "consumed", consumedAt: t1 }), context).accepted, false);
  assert.deepEqual(authorizeBossCredentialUse(enrollment, digestRecord({ state: "revoked", revokedAt: t1 }), context), {
    accepted: false,
    code: "REVOKED",
    auditEventId: "audit-issued-1",
  });
  assert.deepEqual(authorizeBossCredentialUse(enrollment, digestRecord(), { ...context, now: t2 }), {
    accepted: false,
    code: "EXPIRED",
    auditEventId: "audit-issued-1",
  });
  assert.deepEqual(authorizeBossCredentialUse(enrollment, digestRecord(), {
    ...context,
    now: "2026-07-28T12:02:00.001Z",
  }), {
    accepted: false,
    code: "EXPIRED",
    auditEventId: "audit-issued-1",
  });
  assert.equal(authorizeBossCredentialUse({ ...enrollment, credential: "stolen-substitute" }, digestRecord(), context).accepted, false);
  assert.equal(authorizeBossCredentialUse(enrollment, digestRecord(), { ...context, bossRunId: "run-b" }).accepted, false);
  assert.equal(authorizeBossCredentialUse(enrollment, digestRecord(), { ...context, role: "scout" }).accepted, false);
  assert.equal(authorizeBossCredentialUse(enrollment, digestRecord(), { ...context, bindingEpoch: 1 }).accepted, false);
  assert.equal(authorizeBossCredentialUse(enrollment, digestRecord(), { ...context, nonce: "nonce-stolen" }).accepted, false);
  assert.deepEqual(authorizeBossCredentialUse(enrollment, digestRecord({ expiresAt: "2026-07-28T12:03:00.000Z" }), context), {
    accepted: false,
    code: "REGISTRY_MISMATCH",
    auditEventId: "audit-issued-1",
  });
});

function transition(state: AuthorityTransitionRecord["state"] = "prepared"): AuthorityTransitionRecord {
  const base: AuthorityTransitionRecord = {
    version: AUTHORITY_TRANSITION_VERSION,
    authorityTransitionId: "transition-manager-2",
    expectedBrokerRevision: brokerRevision(12),
    brokerRevision: brokerRevision(13),
    operation: "replace_manager",
    target: { bossRunId: "run-a", participantId: "manager-a", replacementParticipantId: "manager-b" },
    prior: { participantBindingEpoch: participantBindingEpoch(4) },
    proposed: { participantBindingEpoch: participantBindingEpoch(5) },
    idempotencyKey: "idem-transition-manager-2",
    state: "prepared",
    prepareToken: "prepare-token-2",
    preparedAt: t0,
  };
  if (state === "committed") return { ...base, state, brokerRevision: brokerRevision(14), committedAt: t1 };
  if (state === "aborted") return { ...base, state, brokerRevision: brokerRevision(14), abortedAt: t1, abortReason: "projection rejected" };
  return base;
}

test("authority transition records enforce monotonic epochs, stable preparation, and exclusive terminal states", () => {
  assert.deepEqual(parseAuthorityTransitionRecord(transition()), transition());
  assert.equal(parseAuthorityTransitionRecord(transition("committed")).brokerRevision, 14);
  assert.equal(parseAuthorityTransitionRecord(transition("aborted")).state, "aborted");
  rejectsContract(() => parseAuthorityTransitionRecord({ ...transition(), proposed: { participantBindingEpoch: 4 } }), /monotonically increase/);
  rejectsContract(() => parseAuthorityTransitionRecord({ ...transition(), target: { bossRunId: "run-a", participantId: "manager-a" } }), /replacementParticipantId/);
  rejectsContract(() => parseAuthorityTransitionRecord({ ...transition(), committedAt: t1 }), /prepared transition/);
  rejectsContract(() => parseAuthorityTransitionRecord({ ...transition("committed"), abortedAt: t2, abortReason: "late" }), /cannot be aborted/);
  rejectsContract(() => parseAuthorityTransitionRecord({ ...transition(), brokerRevision: 12 }), /later than expectedBrokerRevision/);
  rejectsContract(() => parseAuthorityTransitionRecord({ ...transition(), version: "boss.authority-transition.v2" }), /unsupported version/);
  assert.equal(parseAuthorityTransitionRecord({
    ...transition(),
    operation: "bind_participant",
    target: { bossRunId: "run-a", participantId: "worker-new" },
    prior: { participantBindingEpoch: 0 },
    proposed: { participantBindingEpoch: 1 },
  }).proposed.participantBindingEpoch, 1);
  rejectsContract(() => parseAuthorityTransitionRecord({
    ...transition(),
    operation: "bind_participant",
    target: { bossRunId: "run-a", participantId: "worker-new" },
    prior: { participantBindingEpoch: 1 },
    proposed: { participantBindingEpoch: 2 },
  }), /must be exactly 0 for initial bind_participant/);
  rejectsContract(() => parseAuthorityTransitionRecord({
    ...transition(),
    operation: "bind_boss",
    target: { bossRunId: "run-a" },
    prior: { bossBindingEpoch: 1 },
    proposed: { bossBindingEpoch: 2 },
  }), /must be exactly 0 for initial bind_boss/);
  for (const candidate of [
    { operation: "rebind_boss", target: { bossRunId: "run-a" }, prior: { bossBindingEpoch: 0 }, proposed: { bossBindingEpoch: 1 } },
    { operation: "revoke_boss", target: { bossRunId: "run-a" }, prior: { bossBindingEpoch: 0 }, proposed: { bossBindingEpoch: 1 } },
    { operation: "rebind_participant", target: { bossRunId: "run-a", participantId: "worker-a" }, prior: { participantBindingEpoch: 0 }, proposed: { participantBindingEpoch: 1 } },
    { operation: "revoke_participant", target: { bossRunId: "run-a", participantId: "worker-a" }, prior: { participantBindingEpoch: 0 }, proposed: { participantBindingEpoch: 1 } },
    { operation: "replace_participant", target: { bossRunId: "run-a", participantId: "worker-a", replacementParticipantId: "worker-b" }, prior: { participantBindingEpoch: 0 }, proposed: { participantBindingEpoch: 1 } },
    { operation: "replace_manager", target: { bossRunId: "run-a", participantId: "manager-a", replacementParticipantId: "manager-b" }, prior: { participantBindingEpoch: 0 }, proposed: { participantBindingEpoch: 1 } },
  ] as const) {
    rejectsContract(() => parseAuthorityTransitionRecord({ ...transition(), ...candidate }), /safe integer >= 1/);
  }
  assert.equal(parseAuthorityTransitionRecord({
    ...transition(),
    operation: "rebind_subscriber",
    target: { subscriberPrincipalId: "ordinary-owner-a" },
    prior: { subscriberBindingEpoch: 2 },
    proposed: { subscriberBindingEpoch: 3 },
  }).target.subscriberPrincipalId, "ordinary-owner-a");
});

test("authority events are broker-revisioned and cross-check their run and monotonic result", () => {
  const event = {
    version: AUTHORITY_EVENT_VERSION,
    eventId: "authority-event-1",
    bossRunId: "run-a",
    authorityTransitionId: "transition-manager-2",
    brokerRevision: 13,
    operation: "replace_manager",
    state: "committed",
    target: { bossRunId: "run-a", participantId: "manager-a", replacementParticipantId: "manager-b" },
    prior: { participantBindingEpoch: 4 },
    resulting: { participantBindingEpoch: 5 },
    occurredAt: t1,
  };
  assert.deepEqual(parseAuthorityTransitionEvent(event), event);
  rejectsContract(() => parseAuthorityTransitionEvent({ ...event, bossRunId: "run-b" }), /must match bossRunId/);
  rejectsContract(() => parseAuthorityTransitionEvent({ ...event, resulting: { participantBindingEpoch: 3 } }), /monotonically increase|must not decrease/);
  rejectsContract(() => parseAuthorityTransitionEvent({ ...event, state: "prepared" }), /only for committed/);
  assert.equal(parseAuthorityTransitionEvent({
    ...event,
    bossRunId: undefined,
    operation: "rebind_subscriber",
    target: { subscriberPrincipalId: "ordinary-owner-a" },
    prior: { subscriberBindingEpoch: 2 },
    resulting: { subscriberBindingEpoch: 3 },
  }).target.subscriberPrincipalId, "ordinary-owner-a");
});

test("authority socket requests explicitly cover prepare, commit, abort, and revision-fenced query", () => {
  const common = {
    version: AUTHORITY_REQUEST_VERSION,
    requestId: "authority-request-1",
    idempotencyKey: "authority-idem-1",
    authorityTransitionId: "transition-manager-2",
    expectedBrokerRevision: 12,
  };
  const requests = [
    {
      ...common,
      operation: "prepare",
      payload: {
        requestedOperation: "replace_manager",
        target: { bossRunId: "run-a", participantId: "manager-a", replacementParticipantId: "manager-b" },
        prior: { participantBindingEpoch: 4 },
      },
    },
    { ...common, operation: "commit", payload: { prepareToken: "prepare-token-2" } },
    { ...common, operation: "abort", payload: { prepareToken: "prepare-token-2", reason: "projection rejected" } },
    { ...common, operation: "query", payload: {} },
  ];
  for (const request of requests) assert.deepEqual(parseAuthorityTransitionRequest(request), request);
  rejectsContract(() => parseAuthorityTransitionRequest({ ...requests[0], version: "boss.authority-request.v2" }), /unsupported version/);
  rejectsContract(() => parseAuthorityTransitionRequest({ ...requests[0], operation: "force_commit" }), /must be one of/);
  rejectsContract(() => parseAuthorityTransitionRequest({ ...requests[3], payload: { ignored: true } }), /not supported/);
  rejectsContract(() => parseAuthorityTransitionRequest({
    ...requests[0],
    payload: { ...(requests[0].payload as Record<string, unknown>), prior: { bossBindingEpoch: 4 } },
  }), /participantBindingEpoch/);
  rejectsContract(() => parseAuthorityTransitionRequest({
    ...requests[0],
    payload: {
      requestedOperation: "bind_participant",
      target: { bossRunId: "run-a", participantId: "worker-new" },
      prior: { participantBindingEpoch: 1 },
    },
  }), /must be exactly 0 for initial bind_participant/);
  rejectsContract(() => parseAuthorityTransitionRequest({
    ...requests[0],
    payload: {
      requestedOperation: "rebind_participant",
      target: { bossRunId: "run-a", participantId: "worker-a" },
      prior: { participantBindingEpoch: 0 },
    },
  }), /safe integer >= 1/);
});

const control: BossControlEnvelope = {
  type: "boss.assignment.checkpoint",
  version: BOSS_CONTROL_ENVELOPE_VERSION,
  messageId: "message-1",
  bossRunId: "run-a",
  participantId: "worker-a",
  bindingEpoch: participantBindingEpoch(2),
  causationId: "assignment-created-1",
  replyTo: "manager-request-1",
  idempotencyKey: "checkpoint-assignment-1-3",
  payload: { assignmentId: "assignment-1", checkpoint: 3, complete: false },
};

test("generic Boss control envelopes have deterministic canonical bytes and reject unknown/downgraded controls", () => {
  assert.deepEqual(parseBossControlEnvelope(control), control);
  assert.equal(
    canonicalJson(control),
    "{\"bindingEpoch\":2,\"bossRunId\":\"run-a\",\"causationId\":\"assignment-created-1\",\"idempotencyKey\":\"checkpoint-assignment-1-3\",\"messageId\":\"message-1\",\"participantId\":\"worker-a\",\"payload\":{\"assignmentId\":\"assignment-1\",\"checkpoint\":3,\"complete\":false},\"replyTo\":\"manager-request-1\",\"type\":\"boss.assignment.checkpoint\",\"version\":1}",
  );
  rejectsContract(() => parseBossControlEnvelope({ ...control, version: 2 }), /unsupported Boss control envelope version/);
  rejectsContract(() => parseBossControlEnvelope({ ...control, type: "boss.assignment.future" }), /must be one of/);
  rejectsContract(() => parseBossControlEnvelope({ ...control, bindingEpoch: 0 }), /safe integer >= 1/);
  rejectsContract(() => parseBossControlEnvelope({ ...control, payload: { ok: true, skipped: undefined } }), /undefined is not a canonical value/);
});

const noticeLogicalKey = {
  workerId: "worker-a",
  workerGeneration: workerGeneration(6),
  transitionId: "turn-settled-9",
  transitionVersion: transitionVersion(1),
  kind: "turn_settled",
  assignmentId: "assignment-1",
};

const equivalenceKey: DeliveryEquivalenceKey = {
  recipientPrincipalId: "manager-a",
  recipientBindingEpoch: 4,
  sourceAuthorityId: { kind: "controller", bossRunId: "run-a", controllerGeneration: controllerGeneration(2) },
  sourceEventId: "controller-event-33",
  bossRunId: "run-a",
  workerId: "worker-a",
  workerGeneration: workerGeneration(6),
  transitionId: "turn-settled-9",
  transitionVersion: transitionVersion(1),
  assignmentId: "assignment-1",
  turnId: "turn-9",
};

test("controller delivery equivalence keys require one matching embedded and top-level Boss run identity", () => {
  assert.deepEqual(parseDeliveryEquivalenceKey(equivalenceKey), equivalenceKey);

  const { bossRunId: _omittedBossRunId, ...withoutBossRunId } = equivalenceKey;
  rejectsContract(() => parseDeliveryEquivalenceKey(withoutBossRunId), /bossRunId.*required.*controller source authority/);
  rejectsContract(
    () => parseDeliveryEquivalenceKey({ ...equivalenceKey, bossRunId: "run-b" }),
    /sourceAuthorityId\.bossRunId.*exactly match bossRunId/,
  );

  const nonControllerAuthorities: DeliveryEquivalenceKey["sourceAuthorityId"][] = [
    { kind: "worker_store", workerStoreId: "worker-store-a", journalGeneration: journalGeneration(2) },
    { kind: "orc_scheduler", ownerUid: 1000, schedulerGeneration: schedulerGeneration(3) },
  ];
  for (const sourceAuthorityId of nonControllerAuthorities) {
    const { bossRunId: _omittedOptionalBossRunId, ...withoutOptionalBossRunId } = {
      ...equivalenceKey,
      sourceAuthorityId,
    };
    assert.deepEqual(parseDeliveryEquivalenceKey(withoutOptionalBossRunId), withoutOptionalBossRunId);
    assert.deepEqual(
      parseDeliveryEquivalenceKey({ ...withoutOptionalBossRunId, bossRunId: "run-optional" }),
      { ...withoutOptionalBossRunId, bossRunId: "run-optional" },
    );
  }
});

test("delivery equivalence parsing reads source authority once and rejects accessors or coercions without executing them", () => {
  let sourceAuthorityReads = 0;
  const readTrackedKey = new Proxy({ ...equivalenceKey }, {
    get(target, property, receiver) {
      if (property === "sourceAuthorityId") sourceAuthorityReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.equal(parseDeliveryEquivalenceKey(readTrackedKey), readTrackedKey);
  assert.equal(sourceAuthorityReads, 1);

  let sourceAuthorityGetterCalls = 0;
  const sourceAuthorityAccessor = Object.defineProperty({ ...equivalenceKey }, "sourceAuthorityId", {
    configurable: true,
    enumerable: true,
    get() {
      sourceAuthorityGetterCalls += 1;
      return equivalenceKey.sourceAuthorityId;
    },
  });
  rejectsContract(() => parseDeliveryEquivalenceKey(sourceAuthorityAccessor), /sourceAuthorityId.*enumerable data property/);
  assert.equal(sourceAuthorityGetterCalls, 0);

  let embeddedBossRunGetterCalls = 0;
  const embeddedBossRunAccessor = Object.defineProperty({
    kind: "controller",
    controllerGeneration: controllerGeneration(2),
  }, "bossRunId", {
    configurable: true,
    enumerable: true,
    get() {
      embeddedBossRunGetterCalls += 1;
      return "run-a";
    },
  });
  rejectsContract(
    () => parseDeliveryEquivalenceKey({ ...equivalenceKey, sourceAuthorityId: embeddedBossRunAccessor }),
    /sourceAuthorityId\.bossRunId.*enumerable data property/,
  );
  assert.equal(embeddedBossRunGetterCalls, 0);

  let coercionCalls = 0;
  const coercionTrap = {
    [Symbol.toPrimitive]() {
      coercionCalls += 1;
      return "run-a";
    },
    toString() {
      coercionCalls += 1;
      return "run-a";
    },
    valueOf() {
      coercionCalls += 1;
      return "run-a";
    },
  };
  rejectsContract(() => parseDeliveryEquivalenceKey({ ...equivalenceKey, bossRunId: coercionTrap }), /bossRunId.*non-empty string/);
  rejectsContract(() => parseDeliveryEquivalenceKey({
    ...equivalenceKey,
    sourceAuthorityId: {
      kind: "controller",
      bossRunId: coercionTrap,
      controllerGeneration: controllerGeneration(2),
    },
  }), /sourceAuthorityId\.bossRunId.*non-empty string/);
  assert.equal(coercionCalls, 0);
});

test("notice and group IDs are domain-separated golden vectors over the full logical/equivalence keys", () => {
  assert.equal(lifecycleNoticeId(noticeLogicalKey), "62a55d55fc11518e0ac6eedc485a9224493664f1e47022cb5ed2708ad68401cb");
  assert.equal(deliveryGroupId(equivalenceKey), "537f7bc0c3a53a97f9ecbe8b96c3b832350a7099244131e05788c964b3bbdf4e");
  assert.notEqual(deliveryGroupId({ ...equivalenceKey, recipientBindingEpoch: 5 }), deliveryGroupId(equivalenceKey));
  assert.notEqual(deliveryGroupId({ ...equivalenceKey, workerGeneration: workerGeneration(7) }), deliveryGroupId(equivalenceKey));
  rejectsContract(() => lifecycleNoticeId({ ...noticeLogicalKey, subscriptionId: "sub-1" }), /must be present together/);
});

const notice: LifecycleNotice = {
  version: LIFECYCLE_NOTICE_VERSION,
  noticeId: lifecycleNoticeId(noticeLogicalKey),
  deliveryGroupId: deliveryGroupId(equivalenceKey),
  deliveryGroupMembershipRevision: 1,
  requestedDeliveryIntent: "wake",
  sourceEventId: equivalenceKey.sourceEventId,
  transitionId: noticeLogicalKey.transitionId,
  transitionVersion: transitionVersion(1),
  bossRunId: "run-a",
  workerId: "worker-a",
  workerIncarnationId: "incarnation-worker-a-2",
  assignmentId: "assignment-1",
  turnId: "turn-9",
  recipientSessionId: "session-manager-a",
  recipientPrincipalId: "manager-a",
  recipientBindingEpoch: 4,
  workerGeneration: workerGeneration(6),
  kind: "turn_settled",
  severity: "info",
  observedState: "waiting",
  reason: "checkpoint submitted",
  createdAt: t0,
  recipientContext: "pi",
};

test("lifecycle notice v1 validates exact fields and requires atomic claim/receipt tuples", () => {
  const immediatelyBeforeExpiry = "2026-07-28T12:01:59.999Z";
  const deliveredCorrelatedNotice: LifecycleNotice = {
    ...notice,
    deliveryAttemptedAt: t0,
    deliveryClaimId: "claim-correlated-1",
    deliveryClaimGeneration: deliveryClaimGeneration(1),
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "delivered",
    deliveredAt: t1,
    deliveryMode: "correlated_result",
    deliveryReceiptId: "receipt-correlated-1",
    resultMessageId: "result-message-1",
    coalescedByResult: true,
  };
  assert.deepEqual(parseLifecycleNotice(notice), notice);
  assert.equal(parseLifecycleNotice({
    ...notice,
    deliveryClaimId: "claim-1",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "reserved",
  }).deliveryClaimState, "reserved");
  assert.equal(parseLifecycleNotice({
    ...notice,
    deliveryAttemptedAt: immediatelyBeforeExpiry,
    deliveryClaimId: "claim-1",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "inserting",
  }).deliveryAttemptedAt, immediatelyBeforeExpiry);
  assert.equal(parseLifecycleNotice({
    ...notice,
    deliveryAttemptedAt: t1,
    deliveryClaimId: "claim-1",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "inserted",
  }).deliveryClaimState, "inserted");
  assert.equal(parseLifecycleNotice({
    ...notice,
    deliveryAttemptedAt: t0,
    deliveryClaimId: "claim-1",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "delivered",
    deliveredAt: t2,
    deliveryMode: "lifecycle_message",
    deliveryReceiptId: "receipt-1",
  }).deliveryMode, "lifecycle_message");
  assert.deepEqual(parseLifecycleNotice(deliveredCorrelatedNotice), deliveredCorrelatedNotice);
  rejectsContract(() => parseLifecycleNotice({ ...notice, version: "orc.lifecycle-notice.v2" }), /unsupported version/);
  rejectsContract(() => parseLifecycleNotice({ ...notice, deliveryClaimId: "claim-1" }), /must be present together/);
  rejectsContract(() => parseLifecycleNotice({ ...notice, deliveredAt: t2 }), /must be present together/);
  rejectsContract(() => parseLifecycleNotice({ ...notice, deliveryAttemptedAt: t1 }), /requires delivery claim fields/);
  rejectsContract(() => parseLifecycleNotice({
    ...notice,
    deliveryAttemptedAt: t1,
    deliveryClaimId: "claim-1",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "reserved",
  }), /not valid.*reserved/);
  for (const deliveryClaimState of ["inserting", "inserted"] as const) {
    rejectsContract(() => parseLifecycleNotice({
      ...notice,
      deliveryClaimId: "claim-1",
      deliveryClaimGeneration: 1,
      deliveryClaimExpiresAt: t2,
      deliveryClaimState,
    }), /deliveryAttemptedAt/);
  }
  rejectsContract(() => parseLifecycleNotice({
    ...notice,
    deliveryAttemptedAt: t2,
    deliveryClaimId: "claim-1",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "inserting",
  }), /must occur before claim expiry/);
  rejectsContract(() => parseLifecycleNotice({
    ...notice,
    deliveryClaimId: "claim-1",
    deliveryClaimGeneration: 1,
    deliveryClaimExpiresAt: t2,
    deliveryClaimState: "delivered",
    deliveredAt: t2,
    deliveryMode: "lifecycle_message",
    deliveryReceiptId: "receipt-no-attempt",
  }), /deliveryAttemptedAt/);
  rejectsContract(() => parseLifecycleNotice({
    ...notice,
    resultMessageId: "result-before-delivery",
  }), /resultMessageId.*only.*delivered/);
  const { resultMessageId: _omittedCoalescedResultMessageId, ...coalescedWithoutResultMessageId } = deliveredCorrelatedNotice;
  rejectsContract(() => parseLifecycleNotice(coalescedWithoutResultMessageId), /coalescedByResult.*requires resultMessageId/);
  const {
    resultMessageId: _omittedCorrelatedResultMessageId,
    coalescedByResult: _omittedCorrelatedCoalescing,
    ...correlatedWithoutResultMessageId
  } = deliveredCorrelatedNotice;
  rejectsContract(() => parseLifecycleNotice(correlatedWithoutResultMessageId), /deliveryMode.*correlated_result.*requires resultMessageId/);
  rejectsContract(() => parseLifecycleNotice({
    ...deliveredCorrelatedNotice,
    deliveryMode: "lifecycle_message",
  }), /coalescedByResult.*only.*correlated_result/);
  rejectsContract(() => parseLifecycleNotice({
    ...deliveredCorrelatedNotice,
    deliveryMode: "lifecycle_message",
    coalescedByResult: false,
  }), /resultMessageId.*forbidden.*lifecycle_message/);
  rejectsContract(() => parseLifecycleNotice({
    ...deliveredCorrelatedNotice,
    deliveryAttemptedAt: t1,
    deliveredAt: t0,
  }), /deliveredAt.*must not precede deliveryAttemptedAt/);
  rejectsContract(() => parseLifecycleNotice({
    ...deliveredCorrelatedNotice,
    deliveryAttemptedAt: "2026-07-28T11:59:59.999Z",
  }), /deliveryAttemptedAt.*must not precede createdAt/);
  rejectsContract(() => parseLifecycleNotice({
    ...deliveredCorrelatedNotice,
    acknowledgedAt: t0,
  }), /acknowledgedAt.*must not precede delivery/);
  rejectsContract(() => parseLifecycleNotice({ ...notice, noticeId: "forged-notice-id" }), /does not match the lifecycle logical key/);
  rejectsContract(() => parseLifecycleNotice({ ...notice, ignored: "metadata" }), /not supported/);
});

function group(overrides: Partial<DeliveryGroupRecord> = {}): DeliveryGroupRecord {
  return {
    version: DELIVERY_GROUP_VERSION,
    deliveryGroupId: deliveryGroupId(equivalenceKey),
    equivalenceKey,
    subscriptionRegistryRevision: 8,
    membershipRevision: 3,
    membershipState: "sealed",
    primaryNoticeId: notice.noticeId,
    memberNoticeIds: [notice.noticeId, "notice-subscription-1", "notice-subscription-2"],
    requestedIntents: ["status_only", "wake", "follow_up"],
    effectiveDeliveryIntent: "wake",
    recipientTransferGeneration: recipientTransferGeneration(0),
    state: "pending",
    ...overrides,
  };
}

test("sealed delivery groups validate equivalence, immutable membership, and order-independent intent precedence", () => {
  assert.deepEqual(parseDeliveryGroupRecord(group()), group());
  for (const intents of [
    ["wake", "follow_up", "status_only"],
    ["status_only", "wake", "follow_up"],
    ["follow_up", "status_only", "wake"],
  ] as const) assert.equal(effectiveDeliveryIntent(intents), "wake");
  assert.equal(effectiveDeliveryIntent(["status_only", "follow_up"]), "follow_up");
  rejectsContract(() => parseDeliveryGroupRecord(group({ effectiveDeliveryIntent: "follow_up" })), /monotonic/);
  rejectsContract(() => parseDeliveryGroupRecord(group({ deliveryGroupId: "wrong" })), /does not match equivalenceKey/);
  rejectsContract(() => parseDeliveryGroupRecord(group({ memberNoticeIds: [notice.noticeId, notice.noticeId, "notice-subscription-2"] })), /duplicates/);
  rejectsContract(() => parseDeliveryGroupRecord(group({ membershipState: "assembling", state: "reserved" })), /must remain pending/);
  rejectsContract(() => parseDeliveryGroupRecord(group({ state: "migrated" })), /migrated old group requires/);
  rejectsContract(() => parseDeliveryGroupRecord(group({ state: "reserved", operativeActivationConsumedAt: t1 })), /receipted non-status/);
});

test("minting defaults built-in intent once and code-unit assembly is identical across all 24 non-ASCII member permutations", () => {
  const members = [
    mintDeliveryGroupAssemblyMember({ kind: "built_in", noticeId: "é-notice" }),
    mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "z-notice", requestedDeliveryIntent: "wake" }),
    mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "中-notice", requestedDeliveryIntent: "follow_up" }),
    mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "ä-notice", requestedDeliveryIntent: "status_only" }),
  ];
  assert.equal(members[0].requestedDeliveryIntent, "wake");
  rejectsContract(() => mintDeliveryGroupAssemblyMember({ kind: "subscription", noticeId: "missing-intent" }), /must declare an intent/);
  const permutations = <T>(entries: readonly T[]): T[][] => entries.length === 0
    ? [[]]
    : entries.flatMap((entry, index) => permutations([...entries.slice(0, index), ...entries.slice(index + 1)]).map((rest) => [entry, ...rest]));
  const assembled = permutations(members).map((permutation) => assembleDeliveryGroup({
    version: DELIVERY_GROUP_ASSEMBLY_VERSION,
    equivalenceKey,
    subscriptionRegistryRevision: 8,
    membershipRevision: 4,
    primaryNoticeId: "é-notice",
    members: permutation,
    recipientTransferGeneration: recipientTransferGeneration(0),
  }));
  assert.equal(assembled.length, 24);
  for (const result of assembled.slice(1)) assert.deepEqual(result, assembled[0]);
  assert.deepEqual(assembled[0].memberNoticeIds, ["z-notice", "ä-notice", "é-notice", "中-notice"]);
  assert.deepEqual(assembled[0].requestedIntents, ["wake", "status_only", "wake", "follow_up"]);
  assert.equal(assembled[0].effectiveDeliveryIntent, "wake");
  assert.equal(effectiveDeliveryIntent([]), "status_only");
  rejectsContract(() => effectiveDeliveryIntent(["not_an_intent" as never]), /must be one of/);
  rejectsContract(() => parseDeliveryGroupAssemblyInput({
    version: DELIVERY_GROUP_ASSEMBLY_VERSION,
    equivalenceKey,
    subscriptionRegistryRevision: 8,
    membershipRevision: 4,
    primaryNoticeId: notice.noticeId,
    members: [{ noticeId: "missing-intent" }],
    recipientTransferGeneration: recipientTransferGeneration(0),
  }), /requestedDeliveryIntent/);
});

test("manual delivery array parsers require dense own data indices and reject hidden array metadata", () => {
  const validIntents: DeliveryGroupRecord["requestedIntents"] = ["status_only", "follow_up", "wake"];
  for (const malformed of untrustedArrayShapeCases(validIntents)) {
    rejectsContract(() => effectiveDeliveryIntent(malformed.value), malformed.pattern);
    assert.equal(malformed.getterCalls?.() ?? 0, 0, malformed.name);
  }

  const validMembers = [
    { noticeId: notice.noticeId, requestedDeliveryIntent: "wake" },
    { noticeId: "notice-follow", requestedDeliveryIntent: "follow_up" },
  ] as const;
  const assemblyInput = (members: unknown) => ({
    version: DELIVERY_GROUP_ASSEMBLY_VERSION,
    equivalenceKey,
    subscriptionRegistryRevision: 8,
    membershipRevision: 4,
    primaryNoticeId: notice.noticeId,
    members,
    recipientTransferGeneration: recipientTransferGeneration(0),
  });
  for (const malformed of untrustedArrayShapeCases(validMembers)) {
    rejectsContract(() => parseDeliveryGroupAssemblyInput(assemblyInput(malformed.value)), malformed.pattern);
    assert.equal(malformed.getterCalls?.() ?? 0, 0, malformed.name);
  }

  for (const malformed of untrustedArrayShapeCases(validIntents)) {
    rejectsContract(
      () => parseDeliveryGroupRecord(group({ requestedIntents: malformed.value })),
      malformed.pattern,
    );
    assert.equal(malformed.getterCalls?.() ?? 0, 0, malformed.name);
  }

  assert.equal(effectiveDeliveryIntent(Object.freeze([...validIntents])), "wake");
  assert.deepEqual(
    parseDeliveryGroupAssemblyInput(assemblyInput(Object.freeze([...validMembers]))).members,
    validMembers,
  );
  assert.deepEqual(parseDeliveryGroupRecord(group({ requestedIntents: [...validIntents] })).requestedIntents, validIntents);
});

function claim(overrides: Partial<DeliveryClaimRecord> = {}): DeliveryClaimRecord {
  return {
    version: DELIVERY_CLAIM_VERSION,
    deliveryClaimId: "claim-group-a-1",
    deliveryGroupId: group().deliveryGroupId,
    membershipRevision: group().membershipRevision,
    effectiveDeliveryIntent: "wake",
    primaryNoticeId: notice.noticeId,
    memberNoticeIds: group().memberNoticeIds,
    claimGeneration: deliveryClaimGeneration(1),
    expiresAt: t2,
    recipientContext: "pi",
    recipientSessionId: "session-manager-a",
    recipientPrincipalId: "manager-a",
    recipientBindingEpoch: 4,
    recipientTransferGeneration: recipientTransferGeneration(0),
    workerId: "worker-a",
    workerGeneration: workerGeneration(6),
    transitionId: "turn-settled-9",
    transitionVersion: transitionVersion(1),
    assignmentId: "assignment-1",
    turnId: "turn-9",
    ingressMode: "lifecycle_message",
    state: "reserved",
    ...overrides,
  };
}

function releaseProof(overrides: Partial<DeliveryClaimReleaseProof> = {}): DeliveryClaimReleaseProof {
  return {
    deliveryClaimId: "claim-group-a-1",
    claimGeneration: deliveryClaimGeneration(1),
    recipientSessionId: "session-manager-a",
    recipientBindingEpoch: 4,
    barrierId: "drain-barrier-1",
    noSessionEntry: true,
    noAdapterQueue: true,
    noInflightInvocation: true,
    noPiFollowUp: true,
    noOpenCodePendingPrompt: true,
    establishedAt: t1,
    ...overrides,
  };
}

test("delivery claims encode the CAS progression and fail closed on missing insertion/receipt/barrier evidence", () => {
  const immediatelyBeforeExpiry = "2026-07-28T12:01:59.999Z";
  const deliveredEvidence = {
    state: "delivered" as const,
    deliveryAttemptedAt: t0,
    targetLedgerEntryId: "ledger-1",
    insertedAt: t1,
    deliveredAt: t2,
    deliveryReceiptId: "receipt-1",
  };
  assert.deepEqual(parseDeliveryClaimRecord(claim()), claim());
  assert.equal(parseDeliveryClaimRecord(claim({ ingressMode: "correlated_result" })).ingressMode, "correlated_result");
  assert.equal(parseDeliveryClaimRecord(claim({ state: "inserting", deliveryAttemptedAt: t0 })).state, "inserting");
  assert.equal(parseDeliveryClaimRecord(claim({
    state: "inserting",
    deliveryAttemptedAt: immediatelyBeforeExpiry,
  })).deliveryAttemptedAt, immediatelyBeforeExpiry);
  assert.equal(parseDeliveryClaimRecord(claim({
    state: "inserted",
    deliveryAttemptedAt: t0,
    targetLedgerEntryId: "ledger-1",
    insertedAt: t1,
  })).state, "inserted");
  assert.equal(parseDeliveryClaimRecord(claim(deliveredEvidence)).state, "delivered");
  assert.equal(parseDeliveryClaimRecord(claim({
    ...deliveredEvidence,
    ingressMode: "correlated_result",
    resultMessageId: "result-message-1",
    coalescedByResult: true,
  })).ingressMode, "correlated_result");
  assert.equal(parseDeliveryClaimRecord(claim({ state: "blocked", blockedReason: "ambiguous target ledger" })).state, "blocked");
  assert.equal(parseDeliveryClaimRecord(claim({ state: "released", releaseProof: releaseProof(), releasedAt: t2 })).state, "released");
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "inserting",
    deliveryAttemptedAt: t2,
  })), /must occur before claim expiry/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    expiresAt: "2026-07-28T12:07:00.000Z",
    state: "released",
    deliveryAttemptedAt: "2026-07-28T12:05:00.000Z",
    releaseProof: releaseProof({ establishedAt: "2026-07-28T12:04:00.000Z" }),
    releasedAt: "2026-07-28T12:06:00.000Z",
  })), /releaseProof.establishedAt.*must not precede deliveryAttemptedAt/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({ state: "inserted" })), /insertion evidence/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({ state: "delivered", deliveryAttemptedAt: t0, targetLedgerEntryId: "ledger-1", insertedAt: t1 })), /deliveryReceiptId/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({ deliveredAt: t2, deliveryReceiptId: "receipt-early" })), /only when state is delivered/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    ...deliveredEvidence,
    ingressMode: "correlated_result",
  })), /ingressMode.*correlated_result.*requires resultMessageId/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    ...deliveredEvidence,
    resultMessageId: "result-with-lifecycle-message",
  })), /resultMessageId.*forbidden.*lifecycle_message/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    ...deliveredEvidence,
    resultMessageId: "result-with-lifecycle-coalescing",
    coalescedByResult: true,
  })), /coalescedByResult.*only.*correlated_result/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    ...deliveredEvidence,
    ingressMode: "correlated_result",
    coalescedByResult: true,
  })), /coalescedByResult.*requires resultMessageId/);
  const preDeliveryResultClaims: DeliveryClaimRecord[] = [
    claim({ ingressMode: "correlated_result", resultMessageId: "result-before-reservation-delivery" }),
    claim({
      state: "inserting",
      deliveryAttemptedAt: t0,
      ingressMode: "correlated_result",
      resultMessageId: "result-before-inserting-delivery",
    }),
    claim({
      state: "inserted",
      deliveryAttemptedAt: t0,
      targetLedgerEntryId: "ledger-1",
      insertedAt: t1,
      ingressMode: "correlated_result",
      resultMessageId: "result-before-inserted-delivery",
    }),
    claim({
      state: "blocked",
      ingressMode: "correlated_result",
      resultMessageId: "result-before-blocked-delivery",
      blockedReason: "ambiguous target ledger",
    }),
    claim({
      state: "released",
      ingressMode: "correlated_result",
      resultMessageId: "result-before-released-delivery",
      releaseProof: releaseProof(),
      releasedAt: t2,
    }),
  ];
  for (const preDeliveryClaim of preDeliveryResultClaims) {
    rejectsContract(() => parseDeliveryClaimRecord(preDeliveryClaim), /resultMessageId.*only after delivery/);
  }
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "inserted",
    deliveryAttemptedAt: t0,
    targetLedgerEntryId: "ledger-1",
    insertedAt: t1,
    ingressMode: "correlated_result",
    coalescedByResult: true,
  })), /coalescedByResult.*only after delivery/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({ blockedReason: "not blocked" })), /only valid while blocked/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({ state: "released", releasedAt: t2 })), /releaseProof/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({ releaseProof: releaseProof() })), /only valid when released/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "released",
    releaseProof: releaseProof({ deliveryClaimId: "claim-substitute" }),
    releasedAt: t2,
  })), /releaseProof.deliveryClaimId.*match/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "released",
    releaseProof: releaseProof({ claimGeneration: deliveryClaimGeneration(2) }),
    releasedAt: t2,
  })), /releaseProof.claimGeneration.*match/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "released",
    releaseProof: releaseProof({ recipientSessionId: "session-substitute" }),
    releasedAt: t2,
  })), /releaseProof.recipientSessionId.*match/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "released",
    releaseProof: releaseProof({ recipientBindingEpoch: 5 }),
    releasedAt: t2,
  })), /releaseProof.recipientBindingEpoch.*match/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    recipientTargetSessionId: "target-session-manager-a",
    state: "released",
    releaseProof: releaseProof(),
    releasedAt: t2,
  })), /releaseProof.recipientTargetSessionId.*match/);
  const { barrierId: _missingBarrierId, ...withoutBarrierId } = releaseProof();
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "released",
    releaseProof: withoutBarrierId as DeliveryClaimReleaseProof,
    releasedAt: t2,
  })), /releaseProof.barrierId.*required/);
  for (const key of ["noSessionEntry", "noAdapterQueue", "noInflightInvocation", "noPiFollowUp", "noOpenCodePendingPrompt"] as const) {
    rejectsContract(() => parseDeliveryClaimRecord(claim({
      state: "released",
      releaseProof: { ...releaseProof(), [key]: false } as DeliveryClaimReleaseProof,
      releasedAt: t2,
    })), new RegExp(`${key}.*must be true`));
  }
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "released",
    releaseProof: { ...releaseProof(), operativePathsDrained: true } as DeliveryClaimReleaseProof,
    releasedAt: t2,
  })), /operativePathsDrained.*not supported/);
  rejectsContract(() => parseDeliveryClaimRecord(claim({
    state: "released",
    releaseProof: releaseProof({ establishedAt: t2 }),
    releasedAt: t1,
  })), /must not precede the drained barrier/);
  rejectsContract(() => parseDeliveryClaimRecord({ ...claim(), version: "orc.delivery-claim.v2" }), /unsupported version/);
});

function ingress(operation: NoticeRecipientIngressEnvelope["operation"], payload: Record<string, unknown>): NoticeRecipientIngressEnvelope {
  return {
    version: NOTICE_RECIPIENT_INGRESS_VERSION,
    operation,
    requestId: `request-${operation}`,
    idempotencyKey: `idem-${operation}`,
    payload: payload as never,
  };
}

test("NoticeRecipientIngress validates reservation, lookup, insertion, receipt, drained-barrier, and acknowledgment operations", () => {
  const messages: NoticeRecipientIngressEnvelope[] = [
    ingress("reserve_delivery", {
      deliveryGroupId: group().deliveryGroupId,
      membershipRevision: 3,
      effectiveDeliveryIntent: "wake",
      primaryNoticeId: notice.noticeId,
      memberNoticeIds: group().memberNoticeIds,
      recipientContext: "pi",
      recipientSessionId: "session-manager-a",
      recipientPrincipalId: "manager-a",
      recipientBindingEpoch: 4,
      recipientTransferGeneration: 0,
      workerGeneration: 6,
      requestedAt: t0,
    }),
    ingress("lookup_target_ledger", {
      deliveryClaimId: "claim-group-a-1",
      claimGeneration: 1,
      recipientContext: "pi",
      recipientSessionId: "session-manager-a",
      checkedAt: t1,
    }),
    ingress("insert_or_attach", {
      deliveryClaimId: "claim-group-a-1",
      claimGeneration: 1,
      deliveryGroupId: group().deliveryGroupId,
      membershipRevision: 3,
      effectiveDeliveryIntent: "wake",
      primaryNoticeId: notice.noticeId,
      memberNoticeIds: group().memberNoticeIds,
      transitionIds: ["turn-settled-9"],
      recipientPrincipalId: "manager-a",
      recipientBindingEpoch: 4,
      workerGeneration: 6,
      ingressMode: "lifecycle_message",
      requestedAt: t1,
    }),
    ingress("record_receipt", {
      deliveryClaimId: "claim-group-a-1",
      claimGeneration: 1,
      deliveryGroupId: group().deliveryGroupId,
      membershipRevision: 3,
      recipientPrincipalId: "manager-a",
      recipientBindingEpoch: 4,
      workerGeneration: 6,
      deliveryReceiptId: "receipt-1",
      targetLedgerEntryId: "ledger-1",
      deliveryMode: "lifecycle_message",
      insertedAt: t1,
      deliveredAt: t2,
    }),
    ingress("prove_target_drained", {
      deliveryClaimId: "claim-group-a-1",
      claimGeneration: 1,
      recipientSessionId: "session-manager-a",
      recipientBindingEpoch: 4,
      barrierId: "drain-barrier-1",
      noSessionEntry: true,
      noAdapterQueue: true,
      noInflightInvocation: true,
      noPiFollowUp: true,
      noOpenCodePendingPrompt: true,
      establishedAt: t2,
    }),
    ingress("acknowledge", {
      deliveryGroupId: group().deliveryGroupId,
      noticeIds: group().memberNoticeIds,
      recipientPrincipalId: "manager-a",
      recipientBindingEpoch: 4,
      acknowledgedAt: t2,
    }),
  ];
  for (const message of messages) assert.deepEqual(parseNoticeRecipientIngressEnvelope(message), message);
  const insertionPayload = messages[2].payload as Record<string, unknown>;
  const correlatedInsertion = ingress("insert_or_attach", {
    ...insertionPayload,
    ingressMode: "correlated_result",
    resultMessageId: "result-message-1",
  });
  assert.deepEqual(parseNoticeRecipientIngressEnvelope(correlatedInsertion), correlatedInsertion);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("insert_or_attach", {
    ...insertionPayload,
    ingressMode: "correlated_result",
  })), /ingressMode.*correlated_result.*requires resultMessageId/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("insert_or_attach", {
    ...insertionPayload,
    resultMessageId: "result-with-lifecycle-message",
  })), /resultMessageId.*forbidden.*lifecycle_message/);
  const receiptPayload = messages[3].payload as Record<string, unknown>;
  const boundaryReceipt = ingress("record_receipt", {
    ...receiptPayload,
    deliveryMode: "correlated_result",
    insertedAt: t1,
    deliveredAt: t1,
    resultMessageId: "result-message-1",
    coalescedByResult: true,
  });
  assert.deepEqual(parseNoticeRecipientIngressEnvelope(boundaryReceipt), boundaryReceipt);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("record_receipt", {
    ...receiptPayload,
    insertedAt: t2,
    deliveredAt: t1,
  })), /deliveredAt.*must not precede insertedAt/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("record_receipt", {
    ...receiptPayload,
    coalescedByResult: true,
  })), /coalescedByResult.*requires resultMessageId/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("record_receipt", {
    ...receiptPayload,
    deliveryMode: "correlated_result",
  })), /deliveryMode.*correlated_result.*requires resultMessageId/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("record_receipt", {
    ...receiptPayload,
    resultMessageId: "result-with-lifecycle-message",
  })), /resultMessageId.*forbidden.*lifecycle_message/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("record_receipt", {
    ...receiptPayload,
    resultMessageId: "result-with-lifecycle-coalescing",
    coalescedByResult: true,
  })), /coalescedByResult.*only.*correlated_result/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope({ ...messages[0], operation: "inject_without_claim" }), /must be one of/);
  const drainedProof = messages[4].payload as Record<string, unknown>;
  for (const key of ["noSessionEntry", "noAdapterQueue", "noInflightInvocation", "noPiFollowUp", "noOpenCodePendingPrompt"] as const) {
    rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("prove_target_drained", {
      ...drainedProof,
      [key]: false,
    })), new RegExp(`${key}.*must be true`));
  }
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("prove_target_drained", {
    ...drainedProof,
    operativePathsDrained: true,
  })), /operativePathsDrained.*not supported/);
  const { recipientSessionId: _missingSession, ...withoutSession } = drainedProof;
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("prove_target_drained", withoutSession)), /recipientSessionId.*required/);
  const { recipientBindingEpoch: _missingEpoch, ...withoutEpoch } = drainedProof;
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("prove_target_drained", withoutEpoch)), /recipientBindingEpoch.*required/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope(ingress("prove_target_drained", {
    ...drainedProof,
    recipientBindingEpoch: 0,
  })), /recipientBindingEpoch.*safe integer >= 1/);
  rejectsContract(() => parseNoticeRecipientIngressEnvelope({ ...messages[0], version: "orc.notice-recipient-ingress.v2" }), /unsupported version/);
});

test("invalid controller run identities cannot mint or propagate a delivery group into lifecycle, claim, ingress, or store surfaces", () => {
  const { bossRunId: _omittedBossRunId, ...withoutBossRunId } = equivalenceKey;
  const invalidKeys = [
    { key: withoutBossRunId, pattern: /bossRunId.*required.*controller source authority/ },
    { key: { ...equivalenceKey, bossRunId: "run-b" }, pattern: /sourceAuthorityId\.bossRunId.*exactly match bossRunId/ },
  ] as const;

  for (const { key, pattern } of invalidKeys) {
    rejectsContract(() => deliveryGroupId(key as DeliveryEquivalenceKey), pattern);

    const assemblyInput = {
      version: DELIVERY_GROUP_ASSEMBLY_VERSION,
      equivalenceKey: key,
      subscriptionRegistryRevision: 8,
      membershipRevision: 4,
      primaryNoticeId: notice.noticeId,
      members: [{ noticeId: notice.noticeId, requestedDeliveryIntent: "wake" }],
      recipientTransferGeneration: recipientTransferGeneration(0),
    };
    rejectsContract(() => parseDeliveryGroupAssemblyInput(assemblyInput), pattern);
    rejectsContract(() => assembleDeliveryGroup(assemblyInput), pattern);

    const forgedGroup = group({
      deliveryGroupId: canonicalHash("orc-delivery-group-v1", key),
      equivalenceKey: key as DeliveryEquivalenceKey,
    });
    rejectsContract(() => parseDeliveryGroupRecord(forgedGroup), pattern);
    const storedGroup = validateDeliveryGroupStore(forgedGroup);
    assert.equal(storedGroup.ok, false);
    if (storedGroup.ok) assert.fail("expected invalid controller run identity to fail closed in the group store");
    assert.equal(storedGroup.status, "corrupt");
    assert.equal(storedGroup.preserveExisting, true);
    assert.equal(storedGroup.mutationAllowed, false);

    const downstreamProjections: Array<() => unknown> = [
      () => parseLifecycleNotice({ ...notice, deliveryGroupId: deliveryGroupId(key as DeliveryEquivalenceKey) }),
      () => parseDeliveryClaimRecord(claim({ deliveryGroupId: deliveryGroupId(key as DeliveryEquivalenceKey) })),
      () => parseNoticeRecipientIngressEnvelope(ingress("acknowledge", {
        deliveryGroupId: deliveryGroupId(key as DeliveryEquivalenceKey),
        noticeIds: [notice.noticeId],
        recipientPrincipalId: "manager-a",
        recipientBindingEpoch: 4,
        acknowledgedAt: t2,
      })),
    ];
    for (const project of downstreamProjections) rejectsContract(project, pattern);
  }
});

test("target-ledger recovery distinguishes proved insertion from absent or ambiguous state", () => {
  const inserted = {
    version: TARGET_LEDGER_RESULT_VERSION,
    deliveryClaimId: "claim-group-a-1",
    claimGeneration: 1,
    state: "inserted",
    checkedAt: t2,
    targetLedgerEntryId: "ledger-1",
    insertedAt: t1,
  };
  assert.deepEqual(parseTargetLedgerLookupResult(inserted), inserted);
  const insertedAtLookupBoundary = {
    ...inserted,
    checkedAt: t1,
  };
  assert.deepEqual(parseTargetLedgerLookupResult(insertedAtLookupBoundary), insertedAtLookupBoundary);
  assert.equal(parseTargetLedgerLookupResult({
    version: TARGET_LEDGER_RESULT_VERSION,
    deliveryClaimId: "claim-group-a-1",
    claimGeneration: 1,
    state: "ambiguous",
    checkedAt: t2,
  }).state, "ambiguous");
  rejectsContract(() => parseTargetLedgerLookupResult({
    ...inserted,
    checkedAt: t1,
    insertedAt: t2,
  }), /checkedAt.*must not precede insertedAt/);
  rejectsContract(() => parseTargetLedgerLookupResult({ ...inserted, state: "absent" }), /only when state is inserted/);
  rejectsContract(() => parseTargetLedgerLookupResult({ ...inserted, version: "orc.target-ledger-result.v2" }), /unsupported version/);
});

import assert from "node:assert/strict";
import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import test from "node:test";
import {
  brokerGeneration,
  brokerRevision,
  ContractValidationError,
  participantBindingEpoch,
  subscriberBindingEpoch,
  subscriberBindingGeneration,
  triggerGeneration,
} from "../src/canonical.ts";
import { BOSS_POLICY_PRINCIPAL_VERSION, type BossPolicyState } from "../src/boss-policy.ts";
import {
  BOSS_CAPABILITY_FEATURE_DIGEST,
  BOSS_CONTROL_ENVELOPE_VERSION,
  BOSS_PARTICIPANT_BINDING_VERSION,
  BOSS_RUN_FEATURE_CONTRACT,
  BOSS_RUN_PROTOCOL_FEATURE_CONTRACT_HASH,
  type BossParticipantBinding,
} from "../src/boss-wire.ts";
import {
  BOSS_MANAGER_OPERATIONS,
  BOSS_PARTICIPANT_OPERATIONS,
  BOSS_RESTRICTED_CLIENT_REQUEST_VERSION,
  BOSS_RESTRICTED_CLIENT_RESULT_VERSION,
  BOSS_REVIEWER_OPERATIONS,
  BROKER_PROTECTED_PROVIDER_ROOT,
  BROKER_FEATURE_ATTESTATION_VERSION,
  BROKER_IDENTITY_RECORD_VERSION,
  BROKER_JOURNAL_RECOVERY_VERSION,
  BROKER_PEER_EXPECTATION_VERSION,
  BROKER_PROVIDER_ATTESTATION_VERSION,
  LEGACY_ADMIN_MIGRATION_VERSION,
  INTERCOM_BASE_PROTOCOL_VERSION,
  assertBossRestrictedClientResultBinding,
  authorizeBossRestrictedClientRequest,
  authorizeBrokerPeer,
  brokerFeatureSetHash,
  brokerIdentitySigningBytes,
  brokerProviderAttestationSigningBytes,
  createBossRestrictedClientIdempotencyRecord,
  evaluateBrokerCompatibility,
  parseBossRestrictedClientRequest,
  parseBossRestrictedClientResult,
  parseBrokerCapabilityAdvertisement,
  parseBrokerCompatibilityRequest,
  parseBrokerIdentityRecord,
  parseBrokerJournalRecoveryRecord,
  parseBrokerPeerExpectation,
  parseBrokerProviderAttestation,
  parseLegacyAdminMigrationRecord,
  validateBrokerIdentityStore,
  verifyBrokerProviderAttestation,
  verifyProtectedBrokerIdentity,
  type BrokerCapabilityAdvertisement,
  type BrokerFeatureAttestation,
  type BrokerIdentityRecord,
  type BrokerIdentityVerificationContext,
  type BrokerProviderAttestation,
  type BossRestrictedClientAuthorizationContext,
} from "../src/boss-service.ts";
import { LIFECYCLE_SUBSCRIPTION_VERSION, parseLifecycleSubscription } from "../src/supervision.ts";

const identityKeys = generateKeyPairSync("ed25519");
const otherIdentityKeys = generateKeyPairSync("ed25519");
const providerKeys = generateKeyPairSync("ed25519");
const otherProviderKeys = generateKeyPairSync("ed25519");

const feature = {
  version: BROKER_FEATURE_ATTESTATION_VERSION,
  feature: BOSS_RUN_FEATURE_CONTRACT.feature,
  featureVersion: BOSS_RUN_FEATURE_CONTRACT.version,
  semanticsHash: BOSS_RUN_FEATURE_CONTRACT.semanticsHash,
  controlEnvelopeVersion: BOSS_RUN_FEATURE_CONTRACT.controlEnvelopeVersion,
  capabilityDigest: BOSS_CAPABILITY_FEATURE_DIGEST,
};

function boundAdvertisement(features: BrokerFeatureAttestation[]): BrokerCapabilityAdvertisement {
  return {
    baseProtocolVersion: INTERCOM_BASE_PROTOCOL_VERSION,
    features,
    protocolFeatureContractHash: BOSS_RUN_PROTOCOL_FEATURE_CONTRACT_HASH,
    featureSetHash: brokerFeatureSetHash(features),
    controlEnvelopeVersion: BOSS_CONTROL_ENVELOPE_VERSION,
    capabilityDigest: BOSS_CAPABILITY_FEATURE_DIGEST,
  };
}

const advertisement = boundAdvertisement([feature]);

function signedProvider(overrides: Record<string, unknown> = {}): BrokerProviderAttestation {
  const unsigned = {
    version: BROKER_PROVIDER_ATTESTATION_VERSION,
    providerPackage: "@dataforxyz/agent-intercom-pi",
    providerVersion: "1.0.0",
    providerDigest: "a".repeat(64),
    artifactPath: "/usr/lib/agent-intercom/providers/pi-broker",
    artifactOwnerUid: 0,
    artifactOwnerGid: 0,
    artifactMode: "0755",
    userWritable: false,
    attestedAt: "2026-07-28T12:00:00.000Z",
    attestationKeyId: "provider-root-1",
    ...overrides,
    signature: "",
  };
  return parseBrokerProviderAttestation({
    ...unsigned,
    signature: signBytes(null, brokerProviderAttestationSigningBytes(unsigned), providerKeys.privateKey).toString("base64"),
  });
}

const provider = signedProvider();

function correctlySignedIdentityValue(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const unsigned = {
    version: BROKER_IDENTITY_RECORD_VERSION,
    owningProviderPackage: provider.providerPackage,
    providerDigest: provider.providerDigest,
    providerVersion: provider.providerVersion,
    baseProtocolVersion: advertisement.baseProtocolVersion,
    features: advertisement.features,
    protocolFeatureContractHash: advertisement.protocolFeatureContractHash,
    featureSetHash: advertisement.featureSetHash,
    controlEnvelopeVersion: advertisement.controlEnvelopeVersion,
    capabilityDigest: advertisement.capabilityDigest,
    protectedServiceUid: 991,
    ownerUid: 1000,
    bootInstance: "boot-1",
    processId: 123,
    brokerGeneration: 4,
    publicEndpoint: "/run/agent-intercom/1000/public.sock",
    authorityEndpoint: "/run/agent-intercom/1000/authority.sock",
    identityKeyId: "identity-key-1",
    ...overrides,
    signature: "",
  };
  return {
    ...unsigned,
    signature: signBytes(null, brokerIdentitySigningBytes(unsigned), identityKeys.privateKey).toString("base64"),
  };
}

function signedIdentity(overrides: Record<string, unknown> = {}): BrokerIdentityRecord {
  return parseBrokerIdentityRecord(correctlySignedIdentityValue(overrides));
}

const identity = signedIdentity();
const identityVerification: BrokerIdentityVerificationContext = {
  expectedProviderPackage: identity.owningProviderPackage,
  expectedProviderVersion: identity.providerVersion,
  expectedProviderDigest: identity.providerDigest,
  expectedProviderArtifactRoot: BROKER_PROTECTED_PROVIDER_ROOT,
  expectedProviderArtifactOwnerUid: 0,
  expectedProviderArtifactOwnerGid: 0,
  expectedProviderArtifactMode: provider.artifactMode,
  expectedOwnerUid: identity.ownerUid,
  expectedBrokerServiceUid: identity.protectedServiceUid,
  expectedBootInstance: identity.bootInstance,
  minimumBrokerGeneration: identity.brokerGeneration,
  expectedPublicEndpoint: identity.publicEndpoint,
  expectedAuthorityEndpoint: identity.authorityEndpoint,
  trustedIdentityKeys: { [identity.identityKeyId]: identityKeys.publicKey },
  trustedProviderKeys: { [provider.attestationKeyId]: providerKeys.publicKey },
  providerAttestation: provider,
};
const providerVerification = {
  expectedProviderPackage: provider.providerPackage,
  expectedProviderVersion: provider.providerVersion,
  expectedProviderDigest: provider.providerDigest,
  expectedArtifactRoot: BROKER_PROTECTED_PROVIDER_ROOT,
  expectedArtifactOwnerUid: 0,
  expectedArtifactOwnerGid: 0,
  expectedArtifactMode: provider.artifactMode,
  trustedProviderKeys: { [provider.attestationKeyId]: providerKeys.publicKey },
};
const publicPeerExpectation = {
  version: BROKER_PEER_EXPECTATION_VERSION,
  endpointClass: "public" as const,
  ownerUid: identity.ownerUid,
  expectedBrokerServiceUid: identity.protectedServiceUid,
  expectedBrokerProcessId: identity.processId,
  expectedClientUid: identity.ownerUid,
  requiresKernelPeerCredentials: true as const,
  requiresServiceCapability: false,
};
const observedPublicPeer = {
  kernelPeerCredentialsPresent: true,
  endpointClass: "public" as const,
  brokerServiceUid: identity.protectedServiceUid,
  brokerProcessId: identity.processId,
  clientUid: identity.ownerUid,
  serviceCapabilityPresented: false,
};
function bossCompatibilityRequest(overrides: Record<string, unknown> = {}) {
  return {
    clientKind: "boss" as const,
    supportedBaseProtocolVersions: [INTERCOM_BASE_PROTOCOL_VERSION],
    requiredFeature: "boss-run-v1" as const,
    expectedProtectedOwnerUid: identity.ownerUid,
    identityVerification,
    peerExpectation: publicPeerExpectation,
    observedPeer: observedPublicPeer,
    ...overrides,
  };
}

function assertRejectsUntrustedArrayShapes(entry: unknown, parse: (value: unknown) => unknown): void {
  const sparse = Array(1);
  const inheritedIndex = Array(1);
  const pollutedPrototype = Object.create(Array.prototype) as unknown[];
  Object.defineProperty(pollutedPrototype, "0", {
    configurable: true,
    enumerable: true,
    value: entry,
    writable: true,
  });
  Object.setPrototypeOf(inheritedIndex, pollutedPrototype);

  let getterCalls = 0;
  const accessorIndex = Object.defineProperty([entry], "0", {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1;
      return entry;
    },
  });
  const nonEnumerableIndex = Object.defineProperty([entry], "0", { enumerable: false });
  const nonIndexProperty = Object.assign([entry], { metadata: true });
  const symbolProperty = [entry] as unknown[] & Record<PropertyKey, unknown>;
  symbolProperty[Symbol("metadata")] = true;

  for (const invalid of [sparse, inheritedIndex, accessorIndex, nonEnumerableIndex, nonIndexProperty, symbolProperty]) {
    assert.throws(() => parse(invalid), ContractValidationError);
  }
  assert.equal(getterCalls, 0);
}

test("strict capability parsing validates every feature and the complete feature-set binding", () => {
  const optionalFeature = {
    version: BROKER_FEATURE_ATTESTATION_VERSION,
    feature: "future-extra",
    featureVersion: 1,
    semanticsHash: "b".repeat(64),
    optional: true as const,
  };
  assert.deepEqual(parseBrokerCapabilityAdvertisement(advertisement), advertisement);
  assert.deepEqual(
    parseBrokerCapabilityAdvertisement({ baseProtocolVersion: INTERCOM_BASE_PROTOCOL_VERSION, features: [] }),
    { baseProtocolVersion: INTERCOM_BASE_PROTOCOL_VERSION, features: [] },
  );
  assert.deepEqual(
    evaluateBrokerCompatibility(
      { clientKind: "ordinary", supportedBaseProtocolVersions: [3] },
      { baseProtocolVersion: 3, features: [optionalFeature], featureSetHash: brokerFeatureSetHash([optionalFeature]) },
    ),
    { compatible: true, mode: "ordinary" },
  );
  assert.throws(
    () => parseBrokerCapabilityAdvertisement({ baseProtocolVersion: 3, features: [optionalFeature] }),
    /featureSetHash/,
  );
  const supersetAdvertisement = boundAdvertisement([feature, optionalFeature]);
  const supersetIdentity = signedIdentity({ features: supersetAdvertisement.features, featureSetHash: supersetAdvertisement.featureSetHash });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), supersetAdvertisement, supersetIdentity), { compatible: true, mode: "boss" });
  assert.throws(
    () => parseBrokerCapabilityAdvertisement({ ...advertisement, features: [...advertisement.features, { ...feature }] }),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "DUPLICATE_FEATURE",
  );
  assert.throws(
    () => parseBrokerCapabilityAdvertisement({ ...advertisement, features: [{ ...feature, feature: "future-extra" }] }),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "UNKNOWN_FEATURE",
  );
  assert.deepEqual(
    evaluateBrokerCompatibility(
      { clientKind: "ordinary", supportedBaseProtocolVersions: [3] },
      { ...supersetAdvertisement, features: [feature, { ...optionalFeature, semanticsHash: "c".repeat(64) }] },
    ),
    { compatible: false, code: "FEATURE_DIVERGENCE" },
  );
  assert.throws(() => parseBrokerCapabilityAdvertisement({ ...advertisement, featureSetHash: "f".repeat(64) }), /hash/);
  assert.throws(() => parseBrokerCapabilityAdvertisement({ ...advertisement, features: [{ ...feature, ignored: true }] }), /not supported/);
});

test("Boss advertisements require exact base protocol 3 while ordinary negotiation remains version-compatible", () => {
  assert.equal(INTERCOM_BASE_PROTOCOL_VERSION, 3);
  for (const baseProtocolVersion of [1, 2]) {
    const downgradedBossAdvertisement = { ...advertisement, baseProtocolVersion };
    assert.throws(
      () => parseBrokerCapabilityAdvertisement(downgradedBossAdvertisement),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "FEATURE_DIVERGENCE",
    );
    assert.deepEqual(
      evaluateBrokerCompatibility(
        bossCompatibilityRequest({ supportedBaseProtocolVersions: [baseProtocolVersion, INTERCOM_BASE_PROTOCOL_VERSION] }),
        downgradedBossAdvertisement,
        identity,
      ),
      { compatible: false, code: "FEATURE_DIVERGENCE" },
    );

    const ordinaryAdvertisement = { baseProtocolVersion, features: [] };
    assert.deepEqual(parseBrokerCapabilityAdvertisement(ordinaryAdvertisement), ordinaryAdvertisement);
    assert.deepEqual(
      evaluateBrokerCompatibility(
        { clientKind: "ordinary", supportedBaseProtocolVersions: [baseProtocolVersion] },
        ordinaryAdvertisement,
      ),
      { compatible: true, mode: "ordinary" },
    );
  }
});

test("feature-set hashing uses locale-independent UTF-16 code-unit order", () => {
  const codeUnitSortedFeatures: BrokerFeatureAttestation[] = [
    { version: BROKER_FEATURE_ATTESTATION_VERSION, feature: "z-feature", featureVersion: 1, semanticsHash: "a".repeat(64), optional: true },
    { version: BROKER_FEATURE_ATTESTATION_VERSION, feature: "ä-feature", featureVersion: 1, semanticsHash: "b".repeat(64), optional: true },
    { version: BROKER_FEATURE_ATTESTATION_VERSION, feature: "é-feature", featureVersion: 1, semanticsHash: "c".repeat(64), optional: true },
    { version: BROKER_FEATURE_ATTESTATION_VERSION, feature: "Ω-feature", featureVersion: 1, semanticsHash: "d".repeat(64), optional: true },
  ];
  const unsortedFeatures = [
    codeUnitSortedFeatures[2],
    codeUnitSortedFeatures[3],
    codeUnitSortedFeatures[0],
    codeUnitSortedFeatures[1],
  ];
  const localeCompareDescriptor = Object.getOwnPropertyDescriptor(String.prototype, "localeCompare");
  if (localeCompareDescriptor === undefined) throw new Error("String.prototype.localeCompare descriptor missing");
  let localeCompareCalls = 0;
  Object.defineProperty(String.prototype, "localeCompare", {
    ...localeCompareDescriptor,
    value() {
      localeCompareCalls += 1;
      throw new Error("localeCompare must not influence canonical feature ordering");
    },
  });
  try {
    const expectedHash = "25a74c0d5b8261f551713ed706ce45b343d24aa78f0ee6ca924759bb32dc8fe3";
    assert.equal(brokerFeatureSetHash(unsortedFeatures), expectedHash);
    assert.equal(brokerFeatureSetHash([...unsortedFeatures].reverse()), expectedHash);
  } finally {
    Object.defineProperty(String.prototype, "localeCompare", localeCompareDescriptor);
  }
  assert.equal(localeCompareCalls, 0);
});

test("identity and provider attestations use domain-separated canonical Ed25519 verification", () => {
  assert.deepEqual(verifyBrokerProviderAttestation(provider, providerVerification), { accepted: true });
  assert.deepEqual(verifyProtectedBrokerIdentity(identity, identityVerification), { accepted: true });
  assert.deepEqual(
    verifyProtectedBrokerIdentity({ identityKeyId: "malformed", signature: "malformed" }, identityVerification),
    { accepted: false, code: "IDENTITY_RECORD_INVALID" },
  );
  assert.deepEqual(
    verifyProtectedBrokerIdentity(identity, { ...identityVerification, trustedIdentityKeys: {} }),
    { accepted: false, code: "IDENTITY_KEY_UNKNOWN" },
  );
  const inheritedIdentityTrust = Object.create(identityVerification.trustedIdentityKeys);
  assert.deepEqual(
    verifyProtectedBrokerIdentity(identity, { ...identityVerification, trustedIdentityKeys: inheritedIdentityTrust }),
    { accepted: false, code: "IDENTITY_KEY_UNKNOWN" },
  );
  assert.deepEqual(
    verifyProtectedBrokerIdentity(identity, { ...identityVerification, trustedIdentityKeys: { [identity.identityKeyId]: otherIdentityKeys.publicKey } }),
    { accepted: false, code: "IDENTITY_SIGNATURE_INVALID" },
  );
  assert.deepEqual(
    verifyBrokerProviderAttestation(provider, { ...providerVerification, trustedProviderKeys: {} }),
    { accepted: false, code: "PROVIDER_KEY_UNKNOWN" },
  );
  const inheritedProviderTrust = Object.create(providerVerification.trustedProviderKeys);
  assert.deepEqual(
    verifyBrokerProviderAttestation(provider, { ...providerVerification, trustedProviderKeys: inheritedProviderTrust }),
    { accepted: false, code: "PROVIDER_KEY_UNKNOWN" },
  );
  assert.deepEqual(
    verifyBrokerProviderAttestation(provider, { ...providerVerification, trustedProviderKeys: { [provider.attestationKeyId]: otherProviderKeys.publicKey } }),
    { accepted: false, code: "PROVIDER_SIGNATURE_INVALID" },
  );
  assert.deepEqual(
    verifyBrokerProviderAttestation(provider, { ...providerVerification, expectedArtifactMode: "0555" }),
    { accepted: false, code: "PROVIDER_ARTIFACT_MISMATCH" },
  );
});

test("protected broker identities bind the exact canonical Boss feature contract before signature or store acceptance", () => {
  const optionalFeature: BrokerFeatureAttestation = {
    version: BROKER_FEATURE_ATTESTATION_VERSION,
    feature: "future-extra",
    featureVersion: 1,
    semanticsHash: "b".repeat(64),
    optional: true,
  };
  const divergentDigest = (digest: string): string => `${digest[0] === "0" ? "1" : "0"}${digest.slice(1)}`;
  const correctlySignedDivergentIdentities: Array<[string, Record<string, unknown>]> = [
    ["base protocol 1", correctlySignedIdentityValue({ baseProtocolVersion: 1 })],
    ["base protocol 2", correctlySignedIdentityValue({ baseProtocolVersion: 2 })],
    ["feature-set hash", correctlySignedIdentityValue({ featureSetHash: divergentDigest(identity.featureSetHash) })],
    ["protocol feature contract", correctlySignedIdentityValue({
      protocolFeatureContractHash: divergentDigest(identity.protocolFeatureContractHash),
    })],
    ["control envelope", correctlySignedIdentityValue({ controlEnvelopeVersion: identity.controlEnvelopeVersion + 1 })],
    ["capability digest", correctlySignedIdentityValue({ capabilityDigest: divergentDigest(identity.capabilityDigest) })],
    ["missing Boss feature", correctlySignedIdentityValue({
      features: [optionalFeature],
      featureSetHash: brokerFeatureSetHash([optionalFeature]),
    })],
  ];

  for (const [label, divergentIdentity] of correctlySignedDivergentIdentities) {
    assert.throws(() => parseBrokerIdentityRecord(divergentIdentity), ContractValidationError, label);
    assert.deepEqual(
      verifyProtectedBrokerIdentity(divergentIdentity, identityVerification),
      { accepted: false, code: "IDENTITY_RECORD_INVALID" },
      label,
    );
    const storeDecision = validateBrokerIdentityStore(divergentIdentity);
    assert.equal(storeDecision.ok, false, label);
    if (storeDecision.ok) throw new Error(`${label} unexpectedly passed the identity store gate`);
    assert.equal(storeDecision.status, "corrupt", label);
    assert.equal(storeDecision.preserveExisting, true, label);
    assert.equal(storeDecision.mutationAllowed, false, label);
  }

  const supersetFeatures = [feature, optionalFeature];
  const correctlySignedSuperset = correctlySignedIdentityValue({
    features: supersetFeatures,
    featureSetHash: brokerFeatureSetHash(supersetFeatures),
  });
  const parsedSuperset = parseBrokerIdentityRecord(correctlySignedSuperset);
  assert.deepEqual(parsedSuperset.features, supersetFeatures);
  assert.deepEqual(verifyProtectedBrokerIdentity(correctlySignedSuperset, identityVerification), { accepted: true });
  assert.deepEqual(validateBrokerIdentityStore(correctlySignedSuperset), {
    ok: true,
    status: "valid",
    value: parsedSuperset,
  });
});

test("broker verifiers descriptor-project exact contexts, trust maps, attestations, and identities", () => {
  for (const field of Object.keys(provider)) {
    let getterCalls = 0;
    const accessorAttestation = { ...provider } as Record<string, unknown>;
    Object.defineProperty(accessorAttestation, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return provider[field as keyof BrokerProviderAttestation];
      },
    });
    assert.equal(verifyBrokerProviderAttestation(accessorAttestation, providerVerification).accepted, false, field);
    assert.equal(getterCalls, 0, field);
  }

  for (const field of Object.keys(identity)) {
    let getterCalls = 0;
    const accessorIdentity = { ...identity } as Record<string, unknown>;
    Object.defineProperty(accessorIdentity, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return identity[field as keyof BrokerIdentityRecord];
      },
    });
    assert.equal(verifyProtectedBrokerIdentity(accessorIdentity, identityVerification).accepted, false, field);
    assert.equal(getterCalls, 0, field);
  }

  for (const field of Object.keys(providerVerification)) {
    let getterCalls = 0;
    const accessorContext = { ...providerVerification } as Record<string, unknown>;
    Object.defineProperty(accessorContext, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return providerVerification[field as keyof typeof providerVerification];
      },
    });
    assert.equal(verifyBrokerProviderAttestation(provider, accessorContext as never).accepted, false, field);
    assert.equal(getterCalls, 0, field);
  }

  for (const field of Object.keys(identityVerification)) {
    let getterCalls = 0;
    const accessorContext = { ...identityVerification } as Record<string, unknown>;
    Object.defineProperty(accessorContext, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return identityVerification[field as keyof BrokerIdentityVerificationContext];
      },
    });
    assert.equal(verifyProtectedBrokerIdentity(identity, accessorContext as never).accepted, false, field);
    assert.equal(getterCalls, 0, field);
  }

  let providerTrustGetterCalls = 0;
  const accessorProviderTrust = Object.defineProperty({}, provider.attestationKeyId, {
    enumerable: true,
    get() {
      providerTrustGetterCalls += 1;
      return providerKeys.publicKey;
    },
  });
  assert.deepEqual(
    verifyBrokerProviderAttestation(provider, { ...providerVerification, trustedProviderKeys: accessorProviderTrust }),
    { accepted: false, code: "PROVIDER_KEY_UNKNOWN" },
  );
  assert.equal(providerTrustGetterCalls, 0);

  let identityTrustGetterCalls = 0;
  const accessorIdentityTrust = Object.defineProperty({}, identity.identityKeyId, {
    enumerable: true,
    get() {
      identityTrustGetterCalls += 1;
      return identityKeys.publicKey;
    },
  });
  assert.deepEqual(
    verifyProtectedBrokerIdentity(identity, { ...identityVerification, trustedIdentityKeys: accessorIdentityTrust }),
    { accepted: false, code: "IDENTITY_KEY_UNKNOWN" },
  );
  assert.equal(identityTrustGetterCalls, 0);

  const invalidProviderTrustMaps = [
    Object.create(providerVerification.trustedProviderKeys),
    Object.defineProperty({}, provider.attestationKeyId, { enumerable: false, value: providerKeys.publicKey }),
    { [Symbol("provider-key")]: providerKeys.publicKey },
    [providerKeys.publicKey],
  ];
  for (const trustedProviderKeys of invalidProviderTrustMaps) {
    assert.deepEqual(
      verifyBrokerProviderAttestation(provider, { ...providerVerification, trustedProviderKeys } as never),
      { accepted: false, code: "PROVIDER_KEY_UNKNOWN" },
    );
  }

  const invalidIdentityTrustMaps = [
    Object.create(identityVerification.trustedIdentityKeys),
    Object.defineProperty({}, identity.identityKeyId, { enumerable: false, value: identityKeys.publicKey }),
    { [Symbol("identity-key")]: identityKeys.publicKey },
    [identityKeys.publicKey],
  ];
  for (const trustedIdentityKeys of invalidIdentityTrustMaps) {
    assert.deepEqual(
      verifyProtectedBrokerIdentity(identity, { ...identityVerification, trustedIdentityKeys } as never),
      { accepted: false, code: "IDENTITY_KEY_UNKNOWN" },
    );
  }

  const malformedProviderContexts = [
    { ...providerVerification, unknown: true },
    { ...providerVerification, [Symbol("metadata")]: true },
    Object.defineProperty({ ...providerVerification }, "expectedProviderVersion", {
      configurable: true,
      enumerable: false,
      value: provider.providerVersion,
    }),
    Object.create(providerVerification),
    Object.assign([], providerVerification),
  ];
  for (const malformed of malformedProviderContexts) {
    assert.equal(verifyBrokerProviderAttestation(provider, malformed as never).accepted, false);
  }

  const malformedIdentityContexts = [
    { ...identityVerification, unknown: true },
    { ...identityVerification, [Symbol("metadata")]: true },
    Object.defineProperty({ ...identityVerification }, "expectedBootInstance", {
      configurable: true,
      enumerable: false,
      value: identity.bootInstance,
    }),
    Object.create(identityVerification),
    Object.assign([], identityVerification),
  ];
  for (const malformed of malformedIdentityContexts) {
    assert.equal(verifyProtectedBrokerIdentity(identity, malformed as never).accepted, false);
  }

  for (const malformed of [
    Object.create(provider),
    Object.defineProperty({ ...provider }, "signature", { enumerable: false, value: provider.signature }),
    { ...provider, [Symbol("metadata")]: true },
    Object.assign([], provider),
  ]) assert.equal(verifyBrokerProviderAttestation(malformed, providerVerification).accepted, false);

  for (const malformed of [
    Object.create(identity),
    Object.defineProperty({ ...identity }, "signature", { enumerable: false, value: identity.signature }),
    { ...identity, [Symbol("metadata")]: true },
    Object.assign([], identity),
  ]) assert.equal(verifyProtectedBrokerIdentity(malformed, identityVerification).accepted, false);
});

test("peer authorization parses observed credentials before branching and stably denies malformed shapes", () => {
  for (const field of Object.keys(observedPublicPeer)) {
    let getterCalls = 0;
    const accessorObserved = { ...observedPublicPeer } as Record<string, unknown>;
    Object.defineProperty(accessorObserved, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return observedPublicPeer[field as keyof typeof observedPublicPeer];
      },
    });
    assert.deepEqual(
      authorizeBrokerPeer(publicPeerExpectation, accessorObserved),
      { allowed: false, code: "KERNEL_PEER_CREDENTIALS_REQUIRED" },
      field,
    );
    assert.equal(getterCalls, 0, field);
  }

  let unknownGetterCalls = 0;
  const unknownAccessorObserved = Object.defineProperty({ ...observedPublicPeer }, "unknown", {
    enumerable: true,
    get() {
      unknownGetterCalls += 1;
      return true;
    },
  });
  const malformedObservedPeers = [
    unknownAccessorObserved,
    Object.create(observedPublicPeer),
    Object.defineProperty({ ...observedPublicPeer }, "kernelPeerCredentialsPresent", {
      configurable: true,
      enumerable: false,
      value: true,
    }),
    { ...observedPublicPeer, [Symbol("metadata")]: true },
    Object.assign([], observedPublicPeer),
  ];
  for (const malformed of malformedObservedPeers) {
    assert.deepEqual(
      authorizeBrokerPeer(publicPeerExpectation, malformed),
      { allowed: false, code: "KERNEL_PEER_CREDENTIALS_REQUIRED" },
    );
  }
  assert.equal(unknownGetterCalls, 0);
});

test("compatibility evaluation classifies identity only after descriptor-safe parsing", () => {
  for (const field of Object.keys(identity)) {
    let getterCalls = 0;
    const accessorIdentity = { ...identity } as Record<string, unknown>;
    Object.defineProperty(accessorIdentity, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return identity[field as keyof BrokerIdentityRecord];
      },
    });
    assert.deepEqual(
      evaluateBrokerCompatibility(bossCompatibilityRequest(), advertisement, accessorIdentity as never),
      { compatible: false, code: "IDENTITY_RECORD_INVALID" },
      field,
    );
    assert.equal(getterCalls, 0, field);
  }

  let symbolGetterCalls = 0;
  const symbolAccessorIdentity = Object.defineProperty({ ...identity }, Symbol("metadata"), {
    enumerable: true,
    get() {
      symbolGetterCalls += 1;
      return true;
    },
  });
  assert.deepEqual(
    evaluateBrokerCompatibility(bossCompatibilityRequest(), advertisement, symbolAccessorIdentity as never),
    { compatible: false, code: "IDENTITY_RECORD_INVALID" },
  );
  assert.equal(symbolGetterCalls, 0);
});

test("compatibility requests are exact discriminated contracts before evaluation branches", () => {
  const ordinary = { clientKind: "ordinary" as const, supportedBaseProtocolVersions: [3] };
  const boss = bossCompatibilityRequest();
  assert.deepEqual(parseBrokerCompatibilityRequest(ordinary), ordinary);
  assert.deepEqual(parseBrokerCompatibilityRequest(boss), boss);
  const bossWithAdditionalVersions = bossCompatibilityRequest({ supportedBaseProtocolVersions: [1, 2, INTERCOM_BASE_PROTOCOL_VERSION] });
  assert.deepEqual(parseBrokerCompatibilityRequest(bossWithAdditionalVersions), bossWithAdditionalVersions);
  const { observedPeer: _observedPeer, ...missingObservedPeer } = boss;
  const invalidRequests: unknown[] = [
    { clientKind: "unknown", supportedBaseProtocolVersions: [3] },
    { ...ordinary, requiredFeature: BOSS_RUN_FEATURE_CONTRACT.feature },
    { ...boss, requiredFeature: "remote-access-v1" },
    missingObservedPeer,
    { ...boss, ignored: true },
    { ...boss, identityVerification: { ...identityVerification, ignored: true } },
    { ...boss, identityVerification: { ...identityVerification, trustedIdentityKeys: { bad: false } } },
    { ...boss, peerExpectation: { ...publicPeerExpectation, ignored: true } },
    { ...boss, observedPeer: { ...observedPublicPeer, ignored: true } },
    { ...boss, supportedBaseProtocolVersions: [3, 3] },
    { ...boss, supportedBaseProtocolVersions: [1, 2] },
  ];
  for (const request of invalidRequests) {
    assert.throws(() => parseBrokerCompatibilityRequest(request), ContractValidationError);
    assert.deepEqual(
      evaluateBrokerCompatibility(request, advertisement, identity),
      { compatible: false, code: "INVALID_COMPATIBILITY_REQUEST" },
    );
  }
});

test("service array contracts require dense own data indices before reading entries", () => {
  assert.deepEqual(parseBrokerCapabilityAdvertisement(advertisement), advertisement);
  assert.deepEqual(
    parseBrokerCompatibilityRequest({ clientKind: "ordinary", supportedBaseProtocolVersions: [3] }),
    { clientKind: "ordinary", supportedBaseProtocolVersions: [3] },
  );
  const recovery = {
    version: BROKER_JOURNAL_RECOVERY_VERSION,
    providerDigest: identity.providerDigest,
    bootInstance: identity.bootInstance,
    brokerGeneration: identity.brokerGeneration,
    committedBrokerRevision: brokerRevision(9),
    recoveredAuthorityTransitionIds: ["transition-a"],
    state: "reconciled",
    recoveredAt: "2026-07-28T12:00:00.000Z",
  };
  assert.deepEqual(parseBrokerJournalRecoveryRecord(recovery), recovery);

  assertRejectsUntrustedArrayShapes(feature, (features) => parseBrokerCapabilityAdvertisement({ ...advertisement, features }));
  assertRejectsUntrustedArrayShapes(3, (supportedBaseProtocolVersions) => (
    parseBrokerCompatibilityRequest({ clientKind: "ordinary", supportedBaseProtocolVersions })
  ));
  assertRejectsUntrustedArrayShapes("transition-a", (recoveredAuthorityTransitionIds) => (
    parseBrokerJournalRecoveryRecord({ ...recovery, recoveredAuthorityTransitionIds })
  ));
});

test("Boss compatibility is a single fail-closed binding predicate with distinct denial vectors", () => {
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), advertisement, identity), { compatible: true, mode: "boss" });
  assert.deepEqual(
    evaluateBrokerCompatibility(
      bossCompatibilityRequest({ supportedBaseProtocolVersions: [1, 2, INTERCOM_BASE_PROTOCOL_VERSION] }),
      advertisement,
      identity,
    ),
    { compatible: true, mode: "boss" },
  );
  assert.deepEqual(evaluateBrokerCompatibility({ clientKind: "ordinary", supportedBaseProtocolVersions: [3] }, { baseProtocolVersion: 3, features: [] }), { compatible: true, mode: "ordinary" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), { baseProtocolVersion: 3, features: [] }), { compatible: false, code: "BOSS_FEATURE_REQUIRED" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), advertisement), { compatible: false, code: "PROTECTED_IDENTITY_REQUIRED" });

  const unsignedIdentity = { ...identity } as Record<string, unknown>;
  delete unsignedIdentity.signature;
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), advertisement, unsignedIdentity as never), { compatible: false, code: "IDENTITY_UNSIGNED" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, trustedIdentityKeys: {} } }), advertisement, identity), { compatible: false, code: "IDENTITY_KEY_UNKNOWN" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, trustedIdentityKeys: { [identity.identityKeyId]: otherIdentityKeys.publicKey } } }), advertisement, identity), { compatible: false, code: "IDENTITY_SIGNATURE_INVALID" });

  const unsignedProvider = { ...provider } as Record<string, unknown>;
  delete unsignedProvider.signature;
  assert.deepEqual(verifyProtectedBrokerIdentity(identity, { ...identityVerification, providerAttestation: undefined }), { accepted: false, code: "PROVIDER_ATTESTATION_REQUIRED" });
  assert.deepEqual(verifyBrokerProviderAttestation(unsignedProvider, providerVerification), { accepted: false, code: "PROVIDER_ATTESTATION_UNSIGNED" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, providerAttestation: undefined } }), advertisement, identity), { compatible: false, code: "INVALID_COMPATIBILITY_REQUEST" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, providerAttestation: unsignedProvider } }), advertisement, identity), { compatible: false, code: "INVALID_COMPATIBILITY_REQUEST" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, trustedProviderKeys: {} } }), advertisement, identity), { compatible: false, code: "PROVIDER_KEY_UNKNOWN" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, trustedProviderKeys: { [provider.attestationKeyId]: otherProviderKeys.publicKey } } }), advertisement, identity), { compatible: false, code: "PROVIDER_SIGNATURE_INVALID" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, expectedProviderVersion: "2.0.0" } }), advertisement, identity), { compatible: false, code: "PROVIDER_MISMATCH" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, expectedProviderArtifactMode: "0555" } }), advertisement, identity), { compatible: false, code: "PROVIDER_ARTIFACT_MISMATCH" });

  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, expectedBootInstance: "old-boot" } }), advertisement, identity), { compatible: false, code: "STALE_BOOT_INSTANCE" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ identityVerification: { ...identityVerification, minimumBrokerGeneration: brokerGeneration(5) } }), advertisement, identity), { compatible: false, code: "REGRESSED_BROKER_GENERATION" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), advertisement, signedIdentity({ publicEndpoint: "/run/agent-intercom/1000/other.sock" })), { compatible: false, code: "ENDPOINT_MISMATCH" });
  assert.deepEqual(verifyProtectedBrokerIdentity(identity, { ...identityVerification, expectedBrokerServiceUid: 1000 }), { accepted: false, code: "PROTECTED_SERVICE_MISMATCH" });
  assert.deepEqual(
    verifyProtectedBrokerIdentity(signedIdentity({ protectedServiceUid: identity.ownerUid }), { ...identityVerification, expectedBrokerServiceUid: identity.ownerUid }),
    { accepted: false, code: "PROTECTED_SERVICE_MISMATCH" },
  );
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), { ...advertisement, featureSetHash: "f".repeat(64) }, identity), { compatible: false, code: "FEATURE_DIVERGENCE" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), { ...advertisement, features: [...advertisement.features, feature] }, identity), { compatible: false, code: "DUPLICATE_FEATURE" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest(), { ...advertisement, features: [{ ...feature, feature: "unknown" }] }, identity), { compatible: false, code: "UNKNOWN_FEATURE" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ observedPeer: { ...observedPublicPeer, kernelPeerCredentialsPresent: false } }), advertisement, identity), { compatible: false, code: "PEER_CREDENTIALS_MISSING" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ observedPeer: { ...observedPublicPeer, brokerServiceUid: identity.ownerUid } }), advertisement, identity), { compatible: false, code: "PEER_MISMATCH" });
  assert.deepEqual(evaluateBrokerCompatibility(bossCompatibilityRequest({ observedPeer: { ...observedPublicPeer, brokerProcessId: identity.processId + 1 } }), advertisement, identity), { compatible: false, code: "PEER_MISMATCH" });
});

test("provider, identity, peer, migration, and recovery parsers retain strict service boundaries", async () => {
  assert.deepEqual(parseBrokerProviderAttestation(provider), provider);
  assert.deepEqual(parseBrokerIdentityRecord(identity), identity);
  assert.throws(() => parseBrokerProviderAttestation({ ...provider, userWritable: true }), /must be false/);
  assert.throws(() => parseBrokerProviderAttestation({ ...provider, artifactPath: "/tmp/pi-broker" }), /must be beneath/);
  assert.throws(() => parseBrokerProviderAttestation({ ...provider, artifactOwnerUid: 1000 }), /root:root/);
  assert.throws(() => parseBrokerProviderAttestation({ ...provider, artifactMode: "0775" }), /no group\/other write/);
  assert.throws(() => parseBrokerIdentityRecord({ ...identity, authorityEndpoint: identity.publicEndpoint }), /distinct/);
  assert.throws(() => parseBrokerPeerExpectation({ ...publicPeerExpectation, expectedClientUid: 992 }), /owner uid/);
  assert.deepEqual(authorizeBrokerPeer(publicPeerExpectation, { ...observedPublicPeer, serviceCapabilityPresented: true }), { allowed: false, code: "UNEXPECTED_SERVICE_CAPABILITY" });
  const authority = {
    ...publicPeerExpectation,
    endpointClass: "authority",
    expectedClientUid: 992,
    expectedControllerUid: 992,
    requiresServiceCapability: true,
  };
  assert.deepEqual(parseBrokerPeerExpectation(authority), authority);
  assert.throws(() => parseBrokerPeerExpectation({ ...authority, expectedControllerUid: 1000, expectedClientUid: 1000 }), /distinct Controller uid/);
  assert.deepEqual(authorizeBrokerPeer(authority, { kernelPeerCredentialsPresent: false, endpointClass: "authority", brokerServiceUid: 991, brokerProcessId: 123, clientUid: 992, serviceCapabilityPresented: true }), { allowed: false, code: "KERNEL_PEER_CREDENTIALS_REQUIRED" });
  assert.deepEqual(authorizeBrokerPeer(authority, { kernelPeerCredentialsPresent: true, endpointClass: "authority", brokerServiceUid: 991, brokerProcessId: 123, clientUid: 992, serviceCapabilityPresented: false }), { allowed: false, code: "SERVICE_CAPABILITY_REQUIRED" });
  assert.deepEqual(authorizeBrokerPeer(authority, { kernelPeerCredentialsPresent: true, endpointClass: "authority", brokerServiceUid: 991, brokerProcessId: 123, clientUid: 992, serviceCapabilityPresented: true }), { allowed: true });

  const migration = {
    version: LEGACY_ADMIN_MIGRATION_VERSION,
    ownerUid: 1000,
    legacyAdminDigest: "b".repeat(64),
    remoteAccessRegistrationsImported: 3,
    remoteAccessSemanticsVersion: 2,
    legacyAdminState: "revoked_and_removed",
    compatibilityProxyMode: "ordinary_data_only",
    bossFeatureAdvertisedByProxy: false,
    protectedRegistryPath: "/var/lib/agent-intercom/brokers/1000/remote-access-registry.json",
    migratedAt: "2026-07-28T12:01:00.000Z",
    auditEventId: "audit-migration-1",
  };
  assert.deepEqual(parseLegacyAdminMigrationRecord(migration), migration);
  for (const protectedRegistryPath of [
    "/var/lib/agent-intercom/brokers/1000/../1001/registry.json",
    "/var/lib/agent-intercom/brokers/1000/./registry.json",
    "/var/lib/agent-intercom/brokers/1000//registry.json",
    "/var/lib/agent-intercom/brokers/1000-extra/registry.json",
    "/var/lib/agent-intercom/brokers/1000",
    "/var/lib/agent-intercom/brokers/1000/",
    "//var/lib/agent-intercom/brokers/1000/registry.json",
    "/var/lib/agent-intercom/brokers/1000\\registry.json",
    "/var/lib/agent-intercom/brokers/1000/registry\0.json",
  ]) {
    assert.throws(
      () => parseLegacyAdminMigrationRecord({ ...migration, protectedRegistryPath }),
      /canonical path strictly contained/,
    );
  }
  const recovery = {
    version: BROKER_JOURNAL_RECOVERY_VERSION,
    providerDigest: identity.providerDigest,
    bootInstance: identity.bootInstance,
    brokerGeneration: identity.brokerGeneration,
    committedBrokerRevision: brokerRevision(9),
    recoveredAuthorityTransitionIds: ["transition-a"],
    state: "reconciled",
    recoveredAt: "2026-07-28T12:00:00.000Z",
  };
  assert.deepEqual(parseBrokerJournalRecoveryRecord(recovery), recovery);
});

const bindingEpoch = participantBindingEpoch(2);
const participantRequest = {
  version: BOSS_RESTRICTED_CLIENT_REQUEST_VERSION,
  client: "boss_participant" as const,
  bossRunId: "run-a",
  participantId: "worker-a",
  bindingEpoch,
  requestId: "request-a",
  idempotencyKey: "idem-a",
  operation: "participant_submit_checkpoint" as const,
  payload: {
    assignmentId: "assignment-a",
    checkpointId: "checkpoint-a",
    summary: "checkpoint summary",
    occurredAt: "2026-07-28T12:05:00.000Z",
  },
};
const lifecycleSubscription = {
  version: LIFECYCLE_SUBSCRIPTION_VERSION,
  subscriptionId: "subscription-a",
  subscriberPrincipalId: "principal-manager-a",
  subscriberBindingEpoch: subscriberBindingEpoch(2),
  subscriberBindingGeneration: subscriberBindingGeneration(1),
  lastSubscriberAuthorityTransitionId: "transition-a",
  bossRunId: "run-a",
  target: { kind: "role" as const, bossRunId: "run-a", role: "worker" as const },
  followReplacement: true,
  predicates: [{ kind: "state_in" as const, states: ["blocked" as const] }],
  cooldownMs: 0,
  delivery: "status_only" as const,
  state: "armed" as const,
  triggerGeneration: triggerGeneration(0),
  createdAt: "2026-07-28T12:00:00.000Z",
  updatedAt: "2026-07-28T12:00:00.000Z",
};
const storedLifecycleSubscription = {
  ...lifecycleSubscription,
  subscriptionId: "subscription-stored",
};
const subscriptionRequest = {
  version: BOSS_RESTRICTED_CLIENT_REQUEST_VERSION,
  client: "boss_manager" as const,
  bossRunId: "run-a",
  managerParticipantId: "manager-a",
  bindingEpoch,
  requestId: "request-subscription-a",
  idempotencyKey: "idem-subscription-a",
  operation: "manager_create_subscription" as const,
  payload: lifecycleSubscription,
};
const workerBinding: BossParticipantBinding = {
  version: BOSS_PARTICIPANT_BINDING_VERSION,
  bossRunId: "run-a",
  participantId: "worker-a",
  role: "worker",
  communicationProfile: "worker",
  bindingEpoch,
  sessionId: "session-worker-a",
  brokerGeneration: brokerGeneration(4),
  brokerBootInstance: "boot-1",
  state: "active",
  assignedManagerParticipantId: "manager-a",
  authorityTransitionId: "transition-a",
};
const workerPolicy: BossPolicyState = {
  principals: {
    "principal-worker-a": {
      version: BOSS_POLICY_PRINCIPAL_VERSION,
      principalId: "principal-worker-a",
      principalClass: "boss-private",
      state: "active",
      bossRunId: "run-a",
      participantId: "worker-a",
      role: "worker",
      bindingEpoch,
      assignedManagerParticipantId: "manager-a",
    },
  },
};
const workerContext = {
  policy: workerPolicy,
  principalId: "principal-worker-a",
  currentBinding: workerBinding,
  assignments: [{
    bossRunId: "run-a",
    assignmentId: "assignment-a",
    managerParticipantId: "manager-a",
    participantId: "worker-a",
  }],
};

test("restricted requests are exact per client and operation", () => {
  assert.deepEqual(parseBossRestrictedClientRequest(participantRequest), participantRequest);
  assert.deepEqual(parseBossRestrictedClientRequest(subscriptionRequest), subscriptionRequest);
  const healthRequest = {
    ...participantRequest,
    requestId: "request-health-a",
    idempotencyKey: "idem-health-a",
    operation: "participant_report_health" as const,
    payload: { state: "ready" as const, severity: "info" as const, observedAt: "2026-07-28T12:06:00.000Z" },
  };
  assert.deepEqual(parseBossRestrictedClientRequest(healthRequest), healthRequest);
  assert.throws(() => parseBossRestrictedClientRequest({ ...participantRequest, client: "boss_manager" }), ContractValidationError);
  assert.throws(() => parseBossRestrictedClientRequest({ ...participantRequest, operation: "unknown_operation" }), ContractValidationError);
  assert.throws(() => parseBossRestrictedClientRequest({ ...participantRequest, operation: "manager_create_assignment" }), ContractValidationError);
  assert.throws(() => parseBossRestrictedClientRequest({ ...participantRequest, ignored: true }), ContractValidationError);
  assert.throws(() => parseBossRestrictedClientRequest({ ...participantRequest, payload: { ...participantRequest.payload, ignored: true } }), /not supported/);
  assert.throws(() => parseBossRestrictedClientRequest({ ...participantRequest, payload: {} }), /required/);
  assert.throws(() => parseBossRestrictedClientRequest({ ...participantRequest, payload: { ...participantRequest.payload, occurredAt: "not-a-timestamp" } }), /timestamp/);
  assert.throws(() => parseBossRestrictedClientRequest({ ...subscriptionRequest, payload: { ...lifecycleSubscription, state: "unknown" } }), /must be one of/);
  assert.throws(() => parseBossRestrictedClientRequest({
    ...participantRequest,
    operation: "participant_report_health",
    payload: { state: "unknown", severity: "warning", observedAt: "2026-07-28T12:05:00.000Z" },
  }), /must be one of/);
});

test("restricted request and result digests are strict lowercase SHA-256 values", () => {
  const invalidDigests = ["a".repeat(63), "A".repeat(64), "g".repeat(64)];
  for (const digest of invalidDigests) {
    assert.throws(() => parseBossRestrictedClientRequest(managerOperationRequest("manager_submit_proof", {
      proofId: "proof-a",
      digest,
    }, `invalid-manager-digest-${digest.length}`)), /lowercase SHA-256 digest/);
    assert.throws(() => parseBossRestrictedClientRequest(reviewerOperationRequest("reviewer_submit_proof", {
      proofId: "proof-reviewer-a",
      digest,
    }, `invalid-reviewer-digest-${digest.length}`)), /lowercase SHA-256 digest/);
    assert.throws(() => parseBossRestrictedClientRequest(participantOperationRequest("participant_submit_assignment", {
      assignmentId: "assignment-a",
      resultDigest: digest,
    }, `invalid-result-digest-${digest.length}`)), /lowercase SHA-256 digest/);

    const proofRequest = reviewerOperationRequest("reviewer_get_proof", {
      proofId: "proof-a",
    }, `invalid-proof-result-digest-${digest.length}`);
    assert.throws(() => parseBossRestrictedClientResult({
      version: BOSS_RESTRICTED_CLIENT_RESULT_VERSION,
      bossRunId: proofRequest.bossRunId,
      client: proofRequest.client,
      participantId: proofRequest.participantId,
      bindingEpoch: proofRequest.bindingEpoch,
      requestId: proofRequest.requestId,
      idempotencyKey: proofRequest.idempotencyKey,
      operation: proofRequest.operation,
      status: "ok",
      payload: { proofId: "proof-a", digest },
    }, proofRequest), /lowercase SHA-256 digest/);
  }
});

test("restricted authorization couples client role, run, participant, and current branded epoch", () => {
  const allowed = authorizeBossRestrictedClientRequest(participantRequest, workerContext);
  assert.equal(allowed.allowed, true);
  if (!allowed.allowed) throw new Error("expected authorization");
  assert.equal(allowed.idempotency, "new");
  const inheritedPrincipalMap = Object.create(workerPolicy.principals) as BossPolicyState["principals"];
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      policy: { principals: inheritedPrincipalMap },
    }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  const inheritedPolicy = Object.create({ principals: workerPolicy.principals }) as BossPolicyState;
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, { ...workerContext, policy: inheritedPolicy }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, { ...workerContext, principalId: "toString" }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  const workerPrincipal = workerPolicy.principals["principal-worker-a"];
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      policy: {
        principals: {
          "principal-worker-a": { ...workerPrincipal, principalId: "principal-substitute" },
        },
      },
    }),
    { allowed: false, code: "POLICY_BINDING_MISMATCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({ ...participantRequest, bindingEpoch: 1 }, workerContext),
    { allowed: false, code: "STALE_BINDING_EPOCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({ ...participantRequest, bossRunId: "run-old" }, workerContext),
    { allowed: false, code: "CROSS_RUN_REPLAY" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({ ...participantRequest, participantId: "worker-b" }, workerContext),
    { allowed: false, code: "PARTICIPANT_MISMATCH" },
  );
  const reviewerEpoch = participantBindingEpoch(3);
  const reviewerContext: BossRestrictedClientAuthorizationContext = {
    policy: {
      principals: {
        "principal-reviewer": {
          version: BOSS_POLICY_PRINCIPAL_VERSION,
          principalId: "principal-reviewer",
          principalClass: "boss-private",
          state: "active",
          bossRunId: "run-a",
          participantId: "reviewer-a",
          role: "adversary",
          bindingEpoch: reviewerEpoch,
        },
      },
    },
    principalId: "principal-reviewer",
    currentBinding: {
      version: BOSS_PARTICIPANT_BINDING_VERSION,
      bossRunId: "run-a",
      participantId: "reviewer-a",
      role: "adversary",
      communicationProfile: "adversary",
      bindingEpoch: reviewerEpoch,
      sessionId: "reviewer-session",
      brokerGeneration: brokerGeneration(4),
      brokerBootInstance: "boot-1",
      state: "active",
      authorityTransitionId: "transition-a",
    },
  };
  assert.deepEqual(authorizeBossRestrictedClientRequest({ ...participantRequest, participantId: "reviewer-a", bindingEpoch: reviewerEpoch }, reviewerContext), { allowed: false, code: "UNAUTHORIZED_ROLE" });
  const councilEpoch = participantBindingEpoch(4);
  const councilRequest = {
    version: BOSS_RESTRICTED_CLIENT_REQUEST_VERSION,
    client: "boss_reviewer" as const,
    bossRunId: "run-a",
    participantId: "council-a",
    bindingEpoch: councilEpoch,
    requestId: "request-council-proof",
    idempotencyKey: "idem-council-proof",
    operation: "reviewer_get_proof" as const,
    payload: { proofId: "proof-a" },
  };
  const councilDecision = authorizeBossRestrictedClientRequest(councilRequest, {
    policy: {
      principals: {
        "principal-council": {
          version: BOSS_POLICY_PRINCIPAL_VERSION,
          principalId: "principal-council",
          principalClass: "boss-private",
          state: "active",
          bossRunId: "run-a",
          participantId: "council-a",
          role: "council",
          bindingEpoch: councilEpoch,
          requestingPrincipalId: "boss-a",
        },
      },
    },
    principalId: "principal-council",
    currentBinding: {
      version: BOSS_PARTICIPANT_BINDING_VERSION,
      bossRunId: "run-a",
      participantId: "council-a",
      role: "council",
      communicationProfile: "council",
      bindingEpoch: councilEpoch,
      sessionId: "council-session",
      brokerGeneration: brokerGeneration(4),
      brokerBootInstance: "boot-1",
      state: "active",
      authorityTransitionId: "transition-a",
    },
    proofs: [{
      bossRunId: "run-a",
      proofId: "proof-a",
      ownerParticipantId: "manager-a",
      reviewerParticipantIds: ["council-a"],
    }],
  });
  assert.equal(councilDecision.allowed, true);
});

test("restricted authorization reads only own enumerable principal-map data descriptors", () => {
  const workerPrincipal = workerPolicy.principals["principal-worker-a"];
  const dataPrincipalMap = Object.defineProperty({}, "principal-worker-a", {
    enumerable: true,
    value: workerPrincipal,
  }) as BossPolicyState["principals"];
  const dataPolicy = Object.defineProperty({}, "principals", {
    enumerable: true,
    value: dataPrincipalMap,
  }) as BossPolicyState;
  assert.equal(authorizeBossRestrictedClientRequest(participantRequest, {
    ...workerContext,
    policy: dataPolicy,
  }).allowed, true);

  let policyGetterCalls = 0;
  const accessorPolicy = Object.defineProperty({}, "principals", {
    enumerable: true,
    get() {
      policyGetterCalls += 1;
      return workerPolicy.principals;
    },
  }) as BossPolicyState;
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, { ...workerContext, policy: accessorPolicy }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  assert.equal(policyGetterCalls, 0);

  const hiddenPolicy = Object.defineProperty({}, "principals", {
    enumerable: false,
    value: workerPolicy.principals,
  }) as BossPolicyState;
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, { ...workerContext, policy: hiddenPolicy }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );

  let principalGetterCalls = 0;
  const accessorPrincipalMap = Object.defineProperty({}, "principal-worker-a", {
    enumerable: true,
    get() {
      principalGetterCalls += 1;
      return workerPrincipal;
    },
  }) as BossPolicyState["principals"];
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      policy: { principals: accessorPrincipalMap },
    }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  assert.equal(principalGetterCalls, 0);

  const hiddenPrincipalMap = Object.defineProperty({}, "principal-worker-a", {
    enumerable: false,
    value: workerPrincipal,
  }) as BossPolicyState["principals"];
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      policy: { principals: hiddenPrincipalMap },
    }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );

  let symbolGetterCalls = 0;
  const symbolPrincipalMap = Object.defineProperty({}, Symbol("principal-worker-a"), {
    enumerable: true,
    get() {
      symbolGetterCalls += 1;
      return workerPrincipal;
    },
  }) as BossPolicyState["principals"];
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      policy: { principals: symbolPrincipalMap },
    }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  assert.equal(symbolGetterCalls, 0);
});

const restrictedPolicy: BossPolicyState = {
  principals: {
    "principal-manager-a": {
      version: BOSS_POLICY_PRINCIPAL_VERSION,
      principalId: "principal-manager-a",
      principalClass: "boss-private",
      state: "active",
      bossRunId: "run-a",
      participantId: "manager-a",
      role: "manager",
      bindingEpoch,
      assignedParticipantIds: ["worker-a", "scout-a"],
    },
    "principal-worker-a": workerPolicy.principals["principal-worker-a"],
    "principal-scout-a": {
      version: BOSS_POLICY_PRINCIPAL_VERSION,
      principalId: "principal-scout-a",
      principalClass: "boss-private",
      state: "active",
      bossRunId: "run-a",
      participantId: "scout-a",
      role: "scout",
      bindingEpoch,
      assignedManagerParticipantId: "manager-a",
    },
    "principal-reviewer-a": {
      version: BOSS_POLICY_PRINCIPAL_VERSION,
      principalId: "principal-reviewer-a",
      principalClass: "boss-private",
      state: "active",
      bossRunId: "run-a",
      participantId: "reviewer-a",
      role: "adversary",
      bindingEpoch,
    },
  },
};

const managerBinding: BossParticipantBinding = {
  version: BOSS_PARTICIPANT_BINDING_VERSION,
  bossRunId: "run-a",
  participantId: "manager-a",
  role: "manager",
  communicationProfile: "manager",
  bindingEpoch,
  sessionId: "session-manager-a",
  brokerGeneration: brokerGeneration(4),
  brokerBootInstance: "boot-1",
  state: "active",
  authorityTransitionId: "transition-a",
};

const reviewerBinding: BossParticipantBinding = {
  version: BOSS_PARTICIPANT_BINDING_VERSION,
  bossRunId: "run-a",
  participantId: "reviewer-a",
  role: "adversary",
  communicationProfile: "adversary",
  bindingEpoch,
  sessionId: "session-reviewer-a",
  brokerGeneration: brokerGeneration(4),
  brokerBootInstance: "boot-1",
  state: "active",
  authorityTransitionId: "transition-a",
};

const assignmentEvidence = [{
  bossRunId: "run-a",
  assignmentId: "assignment-a",
  managerParticipantId: "manager-a",
  participantId: "worker-a",
}, {
  bossRunId: "run-a",
  assignmentId: "assignment-scout-a",
  managerParticipantId: "manager-a",
  participantId: "scout-a",
}];

const proofEvidence = [{
  bossRunId: "run-a",
  proofId: "proof-a",
  ownerParticipantId: "manager-a",
  reviewerParticipantIds: ["reviewer-a"],
}, {
  bossRunId: "run-a",
  proofId: "proof-reviewer-a",
  ownerParticipantId: "reviewer-a",
  reviewerParticipantIds: [],
}];

const reviewEvidence = [{
  bossRunId: "run-a",
  reviewId: "review-a",
  proofId: "proof-a",
  requesterParticipantId: "manager-a",
  reviewerParticipantId: "reviewer-a",
  state: "pending" as const,
}];

const supervisionEvidence = [{
  bossRunId: "run-a",
  subscriberPrincipalId: "principal-manager-a",
  subscriberParticipantId: "manager-a",
  subscriberBindingEpoch: subscriberBindingEpoch(2),
  subscriberBindingGeneration: subscriberBindingGeneration(1),
  target: lifecycleSubscription.target,
  targetParticipantIds: ["worker-a"],
}];

const managerContext: BossRestrictedClientAuthorizationContext = {
  policy: restrictedPolicy,
  principalId: "principal-manager-a",
  currentBinding: managerBinding,
  assignments: assignmentEvidence,
  proofs: proofEvidence,
  reviews: reviewEvidence,
  supervision: supervisionEvidence,
  subscriptions: [storedLifecycleSubscription],
};

const reviewerContext: BossRestrictedClientAuthorizationContext = {
  policy: restrictedPolicy,
  principalId: "principal-reviewer-a",
  currentBinding: reviewerBinding,
  proofs: proofEvidence,
  reviews: reviewEvidence,
};

function managerOperationRequest(operation: string, payload: unknown, suffix = operation) {
  return {
    version: BOSS_RESTRICTED_CLIENT_REQUEST_VERSION,
    client: "boss_manager",
    bossRunId: "run-a",
    managerParticipantId: "manager-a",
    bindingEpoch,
    requestId: `request-${suffix}`,
    idempotencyKey: `idem-${suffix}`,
    operation,
    payload,
  };
}

function participantOperationRequest(operation: string, payload: unknown, suffix = operation) {
  return {
    version: BOSS_RESTRICTED_CLIENT_REQUEST_VERSION,
    client: "boss_participant",
    bossRunId: "run-a",
    participantId: "worker-a",
    bindingEpoch,
    requestId: `request-${suffix}`,
    idempotencyKey: `idem-${suffix}`,
    operation,
    payload,
  };
}

function reviewerOperationRequest(operation: string, payload: unknown, suffix = operation) {
  return {
    version: BOSS_RESTRICTED_CLIENT_REQUEST_VERSION,
    client: "boss_reviewer",
    bossRunId: "run-a",
    participantId: "reviewer-a",
    bindingEpoch,
    requestId: `request-${suffix}`,
    idempotencyKey: `idem-${suffix}`,
    operation,
    payload,
  };
}

test("restricted authorization descriptor-projects the exact top-level context before any field read", () => {
  const request = managerOperationRequest("manager_get_status", {}, "authorization-context-projection");
  const completeContext = { ...managerContext, idempotencyRecords: [] } as Record<string, unknown>;
  const contextFields = [
    "policy",
    "principalId",
    "currentBinding",
    "assignments",
    "proofs",
    "reviews",
    "supervision",
    "subscriptions",
    "idempotencyRecords",
  ] as const;

  for (const field of contextFields) {
    let getterCalls = 0;
    const accessorContext = { ...completeContext };
    Object.defineProperty(accessorContext, field, {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return completeContext[field];
      },
    });
    assert.throws(
      () => authorizeBossRestrictedClientRequest(request, accessorContext as never),
      ContractValidationError,
      field,
    );
    assert.equal(getterCalls, 0, field);
  }

  let unknownGetterCalls = 0;
  const unknownAccessorContext = Object.defineProperty({ ...completeContext }, "unknown", {
    enumerable: true,
    get() {
      unknownGetterCalls += 1;
      return true;
    },
  });
  assert.throws(
    () => authorizeBossRestrictedClientRequest(request, unknownAccessorContext as never),
    ContractValidationError,
  );
  assert.equal(unknownGetterCalls, 0);

  const hiddenContext = Object.defineProperty({ ...completeContext }, "reviews", {
    configurable: true,
    enumerable: false,
    value: reviewEvidence,
  });
  const symbolContext = { ...completeContext, [Symbol("metadata")]: true };
  const inheritedContext = Object.create(completeContext);
  const arrayContext = Object.assign([], completeContext);
  const missingContext = { ...completeContext };
  delete missingContext.currentBinding;
  for (const malformed of [hiddenContext, symbolContext, inheritedContext, arrayContext, missingContext]) {
    assert.throws(
      () => authorizeBossRestrictedClientRequest(request, malformed as never),
      ContractValidationError,
    );
  }
});

test("restricted policy states and principal maps are exact plain enumerable data records", () => {
  const numericManagerPrincipal = {
    ...restrictedPolicy.principals["principal-manager-a"],
    principalId: "0",
  };
  const numericPrincipalMap = { "0": numericManagerPrincipal };
  const request = managerOperationRequest("manager_get_status", {}, "numeric-manager-policy-shapes");
  const numericManagerContext: BossRestrictedClientAuthorizationContext = {
    ...managerContext,
    principalId: "0",
    policy: { principals: numericPrincipalMap },
  };
  assert.equal(authorizeBossRestrictedClientRequest(request, numericManagerContext).allowed, true);

  const assertUnknownPrincipal = (policy: unknown, label: string): void => {
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(request, {
        ...numericManagerContext,
        policy: policy as BossPolicyState,
      }),
      { allowed: false, code: "UNKNOWN_PRINCIPAL" },
      label,
    );
  };

  assertUnknownPrincipal({ principals: [numericManagerPrincipal] }, "array principal map with Manager principal id 0");
  assertUnknownPrincipal(Object.assign([], { principals: numericPrincipalMap }), "array policy");
  assertUnknownPrincipal({ principals: numericPrincipalMap, metadata: true }, "policy enumerable metadata");

  let policyMetadataGetterCalls = 0;
  const accessorPolicy = Object.defineProperty({ principals: numericPrincipalMap }, "metadata", {
    enumerable: true,
    get() {
      policyMetadataGetterCalls += 1;
      return true;
    },
  });
  assertUnknownPrincipal(accessorPolicy, "policy accessor metadata");
  assert.equal(policyMetadataGetterCalls, 0);

  const symbolPolicy = { principals: numericPrincipalMap } as Record<PropertyKey, unknown>;
  symbolPolicy[Symbol("metadata")] = true;
  assertUnknownPrincipal(symbolPolicy, "policy symbol metadata");
  const hiddenPolicy = Object.defineProperty({ principals: numericPrincipalMap }, "metadata", { value: true });
  assertUnknownPrincipal(hiddenPolicy, "policy non-enumerable metadata");
  const inheritedPolicy = Object.assign(Object.create({ metadata: true }), { principals: numericPrincipalMap });
  assertUnknownPrincipal(inheritedPolicy, "policy inherited metadata");

  let policyPrincipalsGetterCalls = 0;
  const policyWithAccessorPrincipals = Object.defineProperty({}, "principals", {
    enumerable: true,
    get() {
      policyPrincipalsGetterCalls += 1;
      return numericPrincipalMap;
    },
  });
  assertUnknownPrincipal(policyWithAccessorPrincipals, "policy accessor principals");
  assert.equal(policyPrincipalsGetterCalls, 0);

  let policyProxyTrapCalls = 0;
  const proxyPolicy = new Proxy({ principals: numericPrincipalMap }, {
    get() {
      policyProxyTrapCalls += 1;
      return undefined;
    },
    getOwnPropertyDescriptor() {
      policyProxyTrapCalls += 1;
      return undefined;
    },
    getPrototypeOf() {
      policyProxyTrapCalls += 1;
      return Object.prototype;
    },
    ownKeys() {
      policyProxyTrapCalls += 1;
      return ["principals"];
    },
  });
  assertUnknownPrincipal(proxyPolicy, "proxy policy");
  assert.equal(policyProxyTrapCalls, 0);

  let principalMapMetadataGetterCalls = 0;
  const accessorPrincipalMap = Object.defineProperty({ ...numericPrincipalMap }, "metadata", {
    enumerable: true,
    get() {
      principalMapMetadataGetterCalls += 1;
      return true;
    },
  });
  assertUnknownPrincipal({ principals: accessorPrincipalMap }, "principal-map accessor metadata");
  assert.equal(principalMapMetadataGetterCalls, 0);

  const symbolPrincipalMap = { ...numericPrincipalMap } as Record<PropertyKey, unknown>;
  symbolPrincipalMap[Symbol("metadata")] = true;
  assertUnknownPrincipal({ principals: symbolPrincipalMap }, "principal-map symbol metadata");
  const hiddenPrincipalMap = Object.defineProperty({ ...numericPrincipalMap }, "metadata", { value: true });
  assertUnknownPrincipal({ principals: hiddenPrincipalMap }, "principal-map non-enumerable metadata");

  let principalMapProxyTrapCalls = 0;
  const proxyPrincipalMap = new Proxy(numericPrincipalMap, {
    getOwnPropertyDescriptor() {
      principalMapProxyTrapCalls += 1;
      return undefined;
    },
    getPrototypeOf() {
      principalMapProxyTrapCalls += 1;
      return Object.prototype;
    },
    ownKeys() {
      principalMapProxyTrapCalls += 1;
      return ["0"];
    },
  });
  assertUnknownPrincipal({ principals: proxyPrincipalMap }, "proxy principal map");
  assert.equal(principalMapProxyTrapCalls, 0);
});

test("manager subscription creation accepts only fresh lifecycle state", () => {
  const configuredFreshSubscription = {
    ...lifecycleSubscription,
    predicates: [{ kind: "inactive_for" as const }],
    inactivityMode: "smart" as const,
    inactiveAfterMs: 60_000,
    activityBasis: "meaningful" as const,
    cooldownMs: 5_000,
    maxFires: 3,
    expiresAt: "2026-07-29T12:00:00.000Z",
    delivery: "wake" as const,
  };
  for (const [label, subscription] of [
    ["minimal", lifecycleSubscription],
    ["configured", configuredFreshSubscription],
  ] as const) {
    const request = managerOperationRequest("manager_create_subscription", subscription, `fresh-subscription-${label}`);
    assert.deepEqual(parseBossRestrictedClientRequest(request).payload, subscription, label);
    assert.equal(authorizeBossRestrictedClientRequest(request, managerContext).allowed, true, label);
  }

  const persistedOnlyCases: readonly [string, unknown, RegExp][] = [
    ["cancelled state", { ...lifecycleSubscription, state: "cancelled" }, /must be armed on creation/],
    ["triggered state", { ...lifecycleSubscription, state: "triggered" }, /must be armed on creation/],
    ["non-initial trigger generation", { ...lifecycleSubscription, triggerGeneration: triggerGeneration(7) }, /must be zero on creation/],
    ["divergent update timestamp", { ...lifecycleSubscription, updatedAt: "2026-07-28T12:01:00.000Z" }, /must equal createdAt on creation/],
    ["activity history", { ...lifecycleSubscription, lastActivityAt: lifecycleSubscription.createdAt }, /lastActivityAt.*must be absent on creation/],
    ["scheduler due time", { ...configuredFreshSubscription, dueAt: "2026-07-28T12:01:00.000Z" }, /dueAt.*must be absent on creation/],
    ["source event history", { ...lifecycleSubscription, lastSourceEventId: "event-1" }, /lastSourceEventId.*must be absent on creation/],
  ];
  for (const [label, subscription, expectedError] of persistedOnlyCases) {
    assert.deepEqual(parseLifecycleSubscription(subscription), subscription, `persisted parser control: ${label}`);
    const request = managerOperationRequest("manager_create_subscription", subscription, `persisted-subscription-${label}`);
    assert.throws(() => parseBossRestrictedClientRequest(request), expectedError, label);
    assert.throws(() => authorizeBossRestrictedClientRequest(request, managerContext), expectedError, label);
  }

  let optionalFieldGetterCalls = 0;
  for (const [field, fieldValue] of [
    ["lastActivityAt", lifecycleSubscription.createdAt],
    ["dueAt", "2026-07-28T12:01:00.000Z"],
    ["lastSourceEventId", "event-accessor"],
  ] as const) {
    const accessorSubscription = { ...configuredFreshSubscription };
    Object.defineProperty(accessorSubscription, field, {
      enumerable: true,
      get() {
        optionalFieldGetterCalls += 1;
        return fieldValue;
      },
    });
    const request = managerOperationRequest("manager_create_subscription", accessorSubscription, `accessor-subscription-${field}`);
    assert.throws(() => parseLifecycleSubscription(accessorSubscription), /must be an enumerable data property/, field);
    assert.throws(() => parseBossRestrictedClientRequest(request), /must be an enumerable data property/, field);
    assert.throws(() => authorizeBossRestrictedClientRequest(request, managerContext), /must be an enumerable data property/, field);
  }
  assert.equal(optionalFieldGetterCalls, 0);
});

test("manager subscription creation rejects global authoritative id collisions and malformed evidence", () => {
  const request = managerOperationRequest("manager_create_subscription", lifecycleSubscription, "subscription-collision-check");
  assert.equal(authorizeBossRestrictedClientRequest(request, managerContext).allowed, true, "distinct stored id control");
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, { ...managerContext, subscriptions: undefined }),
    { allowed: false, code: "MISSING_AUTHORIZATION_EVIDENCE" },
    "subscription creation requires an authoritative collision set",
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, { ...managerContext, subscriptions: [lifecycleSubscription] }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
    "same-owner collision",
  );

  const otherRunCollision = {
    ...lifecycleSubscription,
    subscriberPrincipalId: "principal-other",
    lastSubscriberAuthorityTransitionId: "transition-other",
    bossRunId: "run-other",
    target: { kind: "role" as const, bossRunId: "run-other", role: "worker" as const },
    state: "cancelled" as const,
  };
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, { ...managerContext, subscriptions: [otherRunCollision] }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
    "subscription ids are globally collision-free across owner and run",
  );

  let arrayIndexGetterCalls = 0;
  const accessorArray = Object.defineProperty([storedLifecycleSubscription], "0", {
    configurable: true,
    enumerable: true,
    get() {
      arrayIndexGetterCalls += 1;
      return storedLifecycleSubscription;
    },
  });
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, { ...managerContext, subscriptions: accessorArray }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.equal(arrayIndexGetterCalls, 0);

  let recordGetterCalls = 0;
  const accessorRecord = Object.defineProperty({ ...storedLifecycleSubscription }, "lastSourceEventId", {
    enumerable: true,
    get() {
      recordGetterCalls += 1;
      return "event-accessor";
    },
  });
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, {
      ...managerContext,
      subscriptions: [accessorRecord] as never,
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.equal(recordGetterCalls, 0);

  for (const malformed of [
    Object.assign([storedLifecycleSubscription], { metadata: true }),
    [{ ...storedLifecycleSubscription, unexpected: true }],
  ]) {
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(request, {
        ...managerContext,
        subscriptions: malformed as never,
      }),
      { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
    );
  }
});

test("assignment evidence target lookups use only own enumerable principal-map data", () => {
  const request = managerOperationRequest("manager_cancel_assignment", {
    assignmentId: "assignment-a",
    reason: "descriptor control",
  }, "assignment-descriptor-control");
  assert.equal(authorizeBossRestrictedClientRequest(request, managerContext).allowed, true);

  const workerPrincipal = restrictedPolicy.principals["principal-worker-a"];
  let accessorCalls = 0;
  const accessorPrincipalMap = { ...restrictedPolicy.principals };
  Object.defineProperty(accessorPrincipalMap, "principal-worker-a", {
    configurable: true,
    enumerable: true,
    get() {
      accessorCalls += 1;
      return workerPrincipal;
    },
  });
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, {
      ...managerContext,
      policy: { principals: accessorPrincipalMap },
    }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  assert.equal(accessorCalls, 0);

  const hiddenPrincipalMap = { ...restrictedPolicy.principals };
  Object.defineProperty(hiddenPrincipalMap, "principal-worker-a", {
    configurable: true,
    enumerable: false,
    value: workerPrincipal,
  });
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, {
      ...managerContext,
      policy: { principals: hiddenPrincipalMap },
    }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );

  let symbolAccessorCalls = 0;
  const symbolPrincipalMap = { ...restrictedPolicy.principals };
  Reflect.deleteProperty(symbolPrincipalMap, "principal-worker-a");
  Object.defineProperty(symbolPrincipalMap, Symbol("principal-worker-a"), {
    enumerable: true,
    get() {
      symbolAccessorCalls += 1;
      return workerPrincipal;
    },
  });
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, {
      ...managerContext,
      policy: { principals: symbolPrincipalMap },
    }),
    { allowed: false, code: "UNKNOWN_PRINCIPAL" },
  );
  assert.equal(symbolAccessorCalls, 0);
});

test("manager assignment creation requires an authoritative globally fresh assignment id", () => {
  const noCollisionRequest = managerOperationRequest("manager_create_assignment", {
    assignmentId: "assignment-fresh",
    participantId: "worker-a",
    objective: "fresh work",
  }, "assignment-no-collision-control");
  assert.equal(authorizeBossRestrictedClientRequest(noCollisionRequest, managerContext).allowed, true);

  const sameOwnerCollisionRequest = managerOperationRequest("manager_create_assignment", {
    assignmentId: "assignment-a",
    participantId: "worker-a",
    objective: "replace existing work under a fresh request",
  }, "assignment-same-owner-collision-fresh-request-key");
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(sameOwnerCollisionRequest, managerContext),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(noCollisionRequest, { ...managerContext, assignments: undefined }),
    { allowed: false, code: "MISSING_AUTHORIZATION_EVIDENCE" },
  );

  const globallyCollidingRequest = managerOperationRequest("manager_create_assignment", {
    assignmentId: "assignment-global",
    participantId: "worker-a",
    objective: "reuse an id from another run and owner",
  }, "assignment-global-collision");
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(globallyCollidingRequest, {
      ...managerContext,
      assignments: [...assignmentEvidence, {
        bossRunId: "run-other",
        assignmentId: "assignment-global",
        managerParticipantId: "manager-other",
        participantId: "worker-other",
      }],
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
});

test("restricted payload authorization has a valid authoritative control for every operation", () => {
  const managerRows: [string, unknown][] = [
    ["manager_get_status", {}],
    ["manager_request_staff", { role: "worker", count: 1 }],
    ["manager_create_assignment", { assignmentId: "assignment-new", participantId: "worker-a", objective: "do work" }],
    ["manager_cancel_assignment", { assignmentId: "assignment-a", reason: "superseded" }],
    ["manager_create_subscription", lifecycleSubscription],
    ["manager_list_subscriptions", {}],
    ["manager_cancel_subscription", { subscriptionId: "subscription-stored" }],
    ["manager_submit_checkpoint", {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-manager-a",
      summary: "integrated",
      occurredAt: "2026-07-28T12:05:00.000Z",
    }],
    ["manager_report_blocker", { blockerId: "blocker-a", reason: "needs decision" }],
    ["manager_submit_proof", { proofId: "proof-a", digest: "a".repeat(64) }],
    ["manager_request_adversary_review", { proofId: "proof-a" }],
    ["manager_request_council", { question: "Is this design sound?" }],
  ];
  const participantRows: [string, unknown][] = [
    ["participant_accept_assignment", { assignmentId: "assignment-a" }],
    ["participant_reject_assignment", { assignmentId: "assignment-a", reason: "cannot reproduce" }],
    ["participant_submit_checkpoint", {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-worker-a",
      summary: "implemented",
      occurredAt: "2026-07-28T12:05:00.000Z",
    }],
    ["participant_submit_assignment", { assignmentId: "assignment-a", resultDigest: "b".repeat(64) }],
    ["participant_report_blocker", { assignmentId: "assignment-a", reason: "dependency unavailable" }],
    ["participant_report_health", { state: "working", severity: "info", observedAt: "2026-07-28T12:05:00.000Z" }],
  ];
  const reviewerRows: [string, unknown][] = [
    ["reviewer_get_proof", { proofId: "proof-a" }],
    ["reviewer_submit_review", { reviewId: "review-a", proofId: "proof-a", decision: "approved", reason: "verified" }],
    ["reviewer_submit_proof", { proofId: "proof-reviewer-a", digest: "c".repeat(64) }],
    ["reviewer_get_objection_status", { reviewId: "review-a" }],
    ["reviewer_report_health", { state: "ready", severity: "info", observedAt: "2026-07-28T12:05:00.000Z" }],
  ];

  assert.deepEqual(managerRows.map(([operation]) => operation), [...BOSS_MANAGER_OPERATIONS]);
  assert.deepEqual(participantRows.map(([operation]) => operation), [...BOSS_PARTICIPANT_OPERATIONS]);
  assert.deepEqual(reviewerRows.map(([operation]) => operation), [...BOSS_REVIEWER_OPERATIONS]);
  for (const [operation, payload] of managerRows) {
    assert.equal(authorizeBossRestrictedClientRequest(managerOperationRequest(operation, payload), managerContext).allowed, true, operation);
  }
  for (const [operation, payload] of participantRows) {
    assert.equal(authorizeBossRestrictedClientRequest(participantOperationRequest(operation, payload), workerContext).allowed, true, operation);
  }
  for (const [operation, payload] of reviewerRows) {
    assert.equal(authorizeBossRestrictedClientRequest(reviewerOperationRequest(operation, payload), reviewerContext).allowed, true, operation);
  }
});

test("review submission binds one exact pending server-created review", () => {
  const submissionPayload = {
    reviewId: "review-a",
    proofId: "proof-a",
    decision: "approved" as const,
    reason: "verified",
  };
  const submissionRequest = reviewerOperationRequest("reviewer_submit_review", submissionPayload, "exact-pending-review");
  assert.deepEqual(parseBossRestrictedClientRequest(submissionRequest).payload, submissionPayload);
  assert.equal(authorizeBossRestrictedClientRequest(submissionRequest, reviewerContext).allowed, true);
  assert.throws(
    () => parseBossRestrictedClientRequest(reviewerOperationRequest("reviewer_submit_review", {
      proofId: "proof-a",
      decision: "approved",
      reason: "legacy unbound submission",
    })),
    /reviewId.*required/,
  );

  for (const state of ["submitted", "cancelled"] as const) {
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(submissionRequest, {
        ...reviewerContext,
        reviews: [{ ...reviewEvidence[0], state }],
      }),
      { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
      state,
    );
    assert.equal(
      authorizeBossRestrictedClientRequest(
        reviewerOperationRequest("reviewer_get_objection_status", { reviewId: "review-a" }, `objection-${state}`),
        { ...reviewerContext, reviews: [{ ...reviewEvidence[0], state }] },
      ).allowed,
      true,
      `objection status remains visible for ${state} reviews`,
    );
  }

  assert.deepEqual(
    authorizeBossRestrictedClientRequest(submissionRequest, { ...reviewerContext, reviews: [] }),
    { allowed: false, code: "MISSING_AUTHORIZATION_EVIDENCE" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(submissionRequest, { ...reviewerContext, proofs: undefined }),
    { allowed: false, code: "MISSING_AUTHORIZATION_EVIDENCE" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(submissionRequest, {
      ...reviewerContext,
      reviews: [reviewEvidence[0], { ...reviewEvidence[0] }],
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );

  const mismatchedRecords = [
    { ...reviewEvidence[0], bossRunId: "run-other" },
    { ...reviewEvidence[0], proofId: "proof-reviewer-a" },
    { ...reviewEvidence[0], requesterParticipantId: "worker-a" },
    { ...reviewEvidence[0], reviewerParticipantId: "reviewer-b" },
    { ...reviewEvidence[0], state: "unknown" },
  ];
  for (const [index, review] of mismatchedRecords.entries()) {
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(submissionRequest, {
        ...reviewerContext,
        reviews: [review] as never,
      }),
      { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
      `mismatched review record ${index}`,
    );
  }
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(
      reviewerOperationRequest("reviewer_submit_review", {
        ...submissionPayload,
        reviewId: "review-missing",
      }, "missing-review-id"),
      reviewerContext,
    ),
    { allowed: false, code: "MISSING_AUTHORIZATION_EVIDENCE" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(
      reviewerOperationRequest("reviewer_submit_review", {
        ...submissionPayload,
        proofId: "proof-reviewer-a",
      }, "mismatched-review-proof"),
      reviewerContext,
    ),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
});

test("manager role subscriptions bind the exact reciprocal assignment subset", () => {
  const twoManagerPolicy: BossPolicyState = {
    principals: {
      "principal-manager-b": {
        version: BOSS_POLICY_PRINCIPAL_VERSION,
        principalId: "principal-manager-b",
        principalClass: "boss-private",
        state: "active",
        bossRunId: "run-a",
        participantId: "manager-b",
        role: "manager",
        bindingEpoch,
        assignedParticipantIds: ["worker-b"],
      },
      "principal-worker-b": {
        version: BOSS_POLICY_PRINCIPAL_VERSION,
        principalId: "principal-worker-b",
        principalClass: "boss-private",
        state: "active",
        bossRunId: "run-a",
        participantId: "worker-b",
        role: "worker",
        bindingEpoch,
        assignedManagerParticipantId: "manager-b",
      },
      ...restrictedPolicy.principals,
    },
  };
  const twoManagerContext: BossRestrictedClientAuthorizationContext = {
    ...managerContext,
    policy: twoManagerPolicy,
  };
  const createRequest = managerOperationRequest(
    "manager_create_subscription",
    lifecycleSubscription,
    "role-subset-create",
  );
  const cancelRequest = managerOperationRequest(
    "manager_cancel_subscription",
    { subscriptionId: "subscription-stored" },
    "role-subset-cancel",
  );

  assert.equal(authorizeBossRestrictedClientRequest(createRequest, twoManagerContext).allowed, true);
  assert.equal(authorizeBossRestrictedClientRequest(cancelRequest, twoManagerContext).allowed, true);

  const invalidTargetSets: [string, string[]][] = [
    ["missing Manager-a's worker and selecting Manager-b's worker", ["worker-b"]],
    ["including Manager-b's worker", ["worker-a", "worker-b"]],
    ["including an assigned participant with the wrong role", ["worker-a", "scout-a"]],
    ["omitting Manager-a's worker", []],
    ["duplicating Manager-a's worker", ["worker-a", "worker-a"]],
  ];
  for (const [label, targetParticipantIds] of invalidTargetSets) {
    const context = {
      ...twoManagerContext,
      supervision: [{ ...supervisionEvidence[0], targetParticipantIds }],
    };
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(createRequest, context),
      { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
      `create: ${label}`,
    );
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(cancelRequest, context),
      { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
      `cancel: ${label}`,
    );
  }

  const reorderedSetPolicy: BossPolicyState = {
    principals: {
      ...twoManagerPolicy.principals,
      "principal-manager-a": {
        version: BOSS_POLICY_PRINCIPAL_VERSION,
        principalId: "principal-manager-a",
        principalClass: "boss-private",
        state: "active",
        bossRunId: "run-a",
        participantId: "manager-a",
        role: "manager",
        bindingEpoch,
        assignedParticipantIds: ["worker-b", "worker-a", "scout-a"],
      },
      "principal-manager-b": {
        version: BOSS_POLICY_PRINCIPAL_VERSION,
        principalId: "principal-manager-b",
        principalClass: "boss-private",
        state: "active",
        bossRunId: "run-a",
        participantId: "manager-b",
        role: "manager",
        bindingEpoch,
        assignedParticipantIds: [],
      },
      "principal-worker-b": {
        version: BOSS_POLICY_PRINCIPAL_VERSION,
        principalId: "principal-worker-b",
        principalClass: "boss-private",
        state: "active",
        bossRunId: "run-a",
        participantId: "worker-b",
        role: "worker",
        bindingEpoch,
        assignedManagerParticipantId: "manager-a",
      },
    },
  };
  const reorderedSetContext = {
    ...twoManagerContext,
    policy: reorderedSetPolicy,
    supervision: [{
      ...supervisionEvidence[0],
      targetParticipantIds: ["worker-a", "worker-b"],
    }],
  };
  assert.equal(authorizeBossRestrictedClientRequest(createRequest, reorderedSetContext).allowed, true);
  assert.equal(authorizeBossRestrictedClientRequest(cancelRequest, reorderedSetContext).allowed, true);
});

test("manager payload authorization denies assignment and subscription confused-deputy attacks", () => {
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(managerOperationRequest("manager_create_assignment", {
      assignmentId: "assignment-rogue",
      participantId: "worker-b",
      objective: "write outside scope",
    }), {
      ...managerContext,
      policy: {
        principals: {
          ...restrictedPolicy.principals,
          "principal-worker-b": {
            version: BOSS_POLICY_PRINCIPAL_VERSION,
            principalId: "principal-worker-b",
            principalClass: "boss-private",
            state: "active",
            bossRunId: "run-a",
            participantId: "worker-b",
            role: "worker",
            bindingEpoch,
            assignedManagerParticipantId: "manager-b",
          },
        },
      },
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(managerOperationRequest("manager_cancel_assignment", {
      assignmentId: "assignment-other",
      reason: "cancel another Manager's work",
    }), {
      ...managerContext,
      assignments: [...assignmentEvidence, {
        bossRunId: "run-a",
        assignmentId: "assignment-other",
        managerParticipantId: "manager-b",
        participantId: "worker-a",
      }],
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(managerOperationRequest("manager_submit_checkpoint", {
      assignmentId: "assignment-other",
      checkpointId: "checkpoint-forged",
      summary: "forged",
      occurredAt: "2026-07-28T12:05:00.000Z",
    }), {
      ...managerContext,
      assignments: [...assignmentEvidence, {
        bossRunId: "run-a",
        assignmentId: "assignment-other",
        managerParticipantId: "manager-b",
        participantId: "worker-a",
      }],
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );

  assert.deepEqual(
    authorizeBossRestrictedClientRequest(managerOperationRequest("manager_create_subscription", {
      ...lifecycleSubscription,
      subscriberPrincipalId: "principal-manager-b",
    }), managerContext),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(managerOperationRequest("manager_create_subscription", {
      ...lifecycleSubscription,
      lastSubscriberAuthorityTransitionId: "transition-other",
    }), managerContext),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  const adversarySubscription = {
    ...lifecycleSubscription,
    target: { kind: "role" as const, bossRunId: "run-a", role: "adversary" as const },
  };
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(managerOperationRequest("manager_create_subscription", adversarySubscription), {
      ...managerContext,
      supervision: [{
        ...supervisionEvidence[0],
        target: adversarySubscription.target,
        targetParticipantIds: ["reviewer-a"],
      }],
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(managerOperationRequest("manager_cancel_subscription", {
      subscriptionId: "subscription-stored",
    }), {
      ...managerContext,
      subscriptions: [{ ...storedLifecycleSubscription, subscriberPrincipalId: "principal-manager-b" }],
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
});

test("participant and reviewer payload authorization requires exact ownership and correlation", () => {
  const participantAssignmentOperations: [string, unknown][] = [
    ["participant_accept_assignment", { assignmentId: "assignment-scout-a" }],
    ["participant_reject_assignment", { assignmentId: "assignment-scout-a", reason: "forged" }],
    ["participant_submit_checkpoint", {
      assignmentId: "assignment-scout-a",
      checkpointId: "checkpoint-forged",
      summary: "forged",
      occurredAt: "2026-07-28T12:05:00.000Z",
    }],
    ["participant_submit_assignment", { assignmentId: "assignment-scout-a", resultDigest: "d".repeat(64) }],
    ["participant_report_blocker", { assignmentId: "assignment-scout-a", reason: "forged" }],
  ];
  for (const [operation, payload] of participantAssignmentOperations) {
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(participantOperationRequest(operation, payload, `attack-${operation}`), {
        ...workerContext,
        assignments: assignmentEvidence,
      }),
      { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
      operation,
    );
  }

  const otherReviewerProofs = proofEvidence.map((proof) => proof.proofId === "proof-a"
    ? { ...proof, reviewerParticipantIds: ["reviewer-b"] }
    : proof);
  for (const [operation, payload] of [
    ["reviewer_get_proof", { proofId: "proof-a" }],
    ["reviewer_submit_review", { reviewId: "review-a", proofId: "proof-a", decision: "approved", reason: "forged" }],
  ] as [string, unknown][]) {
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(reviewerOperationRequest(operation, payload, `attack-${operation}`), {
        ...reviewerContext,
        proofs: otherReviewerProofs,
      }),
      { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
      operation,
    );
  }
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(reviewerOperationRequest("reviewer_submit_proof", {
      proofId: "proof-reviewer-a",
      digest: "e".repeat(64),
    }), {
      ...reviewerContext,
      proofs: proofEvidence.map((proof) => proof.proofId === "proof-reviewer-a"
        ? { ...proof, ownerParticipantId: "reviewer-b" }
        : proof),
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(reviewerOperationRequest("reviewer_get_objection_status", {
      reviewId: "review-a",
    }), {
      ...reviewerContext,
      reviews: [{ ...reviewEvidence[0], reviewerParticipantId: "reviewer-b" }],
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
});

test("security-sensitive operation families fail closed without authoritative evidence", () => {
  const cases: [unknown, BossRestrictedClientAuthorizationContext][] = [
    [managerOperationRequest("manager_create_assignment", { assignmentId: "assignment-new", participantId: "worker-a", objective: "work" }), { ...managerContext, assignments: undefined }],
    [managerOperationRequest("manager_cancel_assignment", { assignmentId: "assignment-a", reason: "cancel" }), { ...managerContext, assignments: undefined }],
    [managerOperationRequest("manager_create_subscription", lifecycleSubscription), { ...managerContext, supervision: undefined }],
    [managerOperationRequest("manager_cancel_subscription", { subscriptionId: "subscription-stored" }), { ...managerContext, subscriptions: undefined }],
    [managerOperationRequest("manager_submit_proof", { proofId: "proof-a", digest: "a".repeat(64) }), { ...managerContext, proofs: undefined }],
    [participantOperationRequest("participant_accept_assignment", { assignmentId: "assignment-a" }), { ...workerContext, assignments: undefined }],
    [reviewerOperationRequest("reviewer_get_proof", { proofId: "proof-a" }), { ...reviewerContext, proofs: undefined }],
    [reviewerOperationRequest("reviewer_submit_review", { reviewId: "review-a", proofId: "proof-a", decision: "approved", reason: "reviewed" }), { ...reviewerContext, reviews: undefined }],
    [reviewerOperationRequest("reviewer_get_objection_status", { reviewId: "review-a" }), { ...reviewerContext, reviews: undefined }],
  ];
  for (const [request, context] of cases) {
    assert.deepEqual(
      authorizeBossRestrictedClientRequest(request, context),
      { allowed: false, code: "MISSING_AUTHORIZATION_EVIDENCE" },
    );
  }
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantOperationRequest("participant_accept_assignment", {
      assignmentId: "assignment-a",
    }), {
      ...workerContext,
      assignments: [{ ...assignmentEvidence[0], unexpected: true }] as never,
    }),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
  );
});

test("restricted idempotency is operation/run/participant/epoch scoped and replay-safe", () => {
  const prior = createBossRestrictedClientIdempotencyRecord(participantRequest);
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, { ...workerContext, idempotencyRecords: [prior] }),
    { allowed: true, idempotency: "replay", record: prior },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({ ...participantRequest, requestId: "request-b" }, { ...workerContext, idempotencyRecords: [prior] }),
    { allowed: false, code: "IDEMPOTENCY_CONFLICT" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({ ...participantRequest, idempotencyKey: "idem-b" }, { ...workerContext, idempotencyRecords: [prior] }),
    { allowed: false, code: "REQUEST_ID_CONFLICT" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({
      ...participantRequest,
      requestId: "request-c",
      operation: "participant_accept_assignment",
      payload: { assignmentId: "assignment-a" },
    }, { ...workerContext, idempotencyRecords: [prior] }),
    { allowed: false, code: "IDEMPOTENCY_CONFLICT" },
  );
});

test("restricted exact replays precede mutation-sensitive post-success payload checks", () => {
  const assignmentRequest = managerOperationRequest("manager_create_assignment", {
    assignmentId: "assignment-post-success",
    participantId: "worker-a",
    objective: "create once",
  }, "assignment-post-success");
  const assignmentRecord = createBossRestrictedClientIdempotencyRecord(assignmentRequest);
  const createdAssignment = {
    bossRunId: "run-a",
    assignmentId: "assignment-post-success",
    managerParticipantId: "manager-a",
    participantId: "worker-a",
  };
  const assignmentPostSuccessContext = {
    ...managerContext,
    assignments: [...assignmentEvidence, createdAssignment],
    idempotencyRecords: [assignmentRecord],
  };
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(assignmentRequest, assignmentPostSuccessContext),
    { allowed: true, idempotency: "replay", record: assignmentRecord },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(assignmentRequest, {
      ...assignmentPostSuccessContext,
      assignments: undefined,
    }),
    { allowed: true, idempotency: "replay", record: assignmentRecord },
    "exact assignment replay does not require mutable creation evidence",
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({
      ...assignmentRequest,
      requestId: "request-assignment-post-success-new",
      idempotencyKey: "idem-assignment-post-success-new",
    }, assignmentPostSuccessContext),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
    "a new assignment request still enforces global id freshness",
  );

  const subscriptionPostSuccessRequest = managerOperationRequest(
    "manager_create_subscription",
    lifecycleSubscription,
    "subscription-post-success",
  );
  const subscriptionRecord = createBossRestrictedClientIdempotencyRecord(subscriptionPostSuccessRequest);
  const subscriptionPostSuccessContext = {
    ...managerContext,
    subscriptions: [storedLifecycleSubscription, lifecycleSubscription],
    idempotencyRecords: [subscriptionRecord],
  };
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(subscriptionPostSuccessRequest, subscriptionPostSuccessContext),
    { allowed: true, idempotency: "replay", record: subscriptionRecord },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(subscriptionPostSuccessRequest, {
      ...subscriptionPostSuccessContext,
      supervision: undefined,
    }),
    { allowed: true, idempotency: "replay", record: subscriptionRecord },
    "exact subscription replay does not require mutable creation evidence",
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({
      ...subscriptionPostSuccessRequest,
      requestId: "request-subscription-post-success-new",
      idempotencyKey: "idem-subscription-post-success-new",
    }, subscriptionPostSuccessContext),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
    "a new subscription request still enforces global id freshness",
  );

  const reviewRequest = reviewerOperationRequest("reviewer_submit_review", {
    reviewId: "review-a",
    proofId: "proof-a",
    decision: "approved",
    reason: "verified",
  }, "review-post-success");
  const reviewRecord = createBossRestrictedClientIdempotencyRecord(reviewRequest);
  const reviewPostSuccessContext = {
    ...reviewerContext,
    reviews: [{ ...reviewEvidence[0], state: "submitted" as const }],
    idempotencyRecords: [reviewRecord],
  };
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(reviewRequest, reviewPostSuccessContext),
    { allowed: true, idempotency: "replay", record: reviewRecord },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(reviewRequest, {
      ...reviewPostSuccessContext,
      proofs: undefined,
    }),
    { allowed: true, idempotency: "replay", record: reviewRecord },
    "exact review replay does not require mutable proof evidence after submission",
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({
      ...reviewRequest,
      requestId: "request-review-post-success-new",
      idempotencyKey: "idem-review-post-success-new",
    }, reviewPostSuccessContext),
    { allowed: false, code: "PAYLOAD_AUTHORIZATION_MISMATCH" },
    "a new review submission still requires pending state",
  );
});

test("restricted replay classification preserves conflicts and authentication downgrades", () => {
  const request = managerOperationRequest("manager_create_assignment", {
    assignmentId: "assignment-conflict-after-success",
    participantId: "worker-a",
    objective: "create once",
  }, "assignment-conflict-after-success");
  const record = createBossRestrictedClientIdempotencyRecord(request);
  const postSuccessContext = {
    ...managerContext,
    assignments: [...assignmentEvidence, {
      bossRunId: "run-a",
      assignmentId: "assignment-conflict-after-success",
      managerParticipantId: "manager-a",
      participantId: "worker-a",
    }],
    idempotencyRecords: [record],
  };
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({ ...request, idempotencyKey: "idem-conflict-after-success-changed" }, postSuccessContext),
    { allowed: false, code: "REQUEST_ID_CONFLICT" },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest({ ...request, requestId: "request-conflict-after-success-changed" }, postSuccessContext),
    { allowed: false, code: "IDEMPOTENCY_CONFLICT" },
  );

  const otherRunRecord = createBossRestrictedClientIdempotencyRecord({ ...request, bossRunId: "run-other" });
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, { ...postSuccessContext, idempotencyRecords: [otherRunRecord] }),
    { allowed: false, code: "CROSS_RUN_REPLAY" },
  );

  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, {
      ...postSuccessContext,
      currentBinding: { ...managerBinding, state: "revoked" },
    }),
    { allowed: false, code: "BINDING_NOT_ACTIVE" },
    "a replay cannot revive a revoked binding",
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(request, {
      ...postSuccessContext,
      policy: {
        principals: {
          ...restrictedPolicy.principals,
          "principal-manager-a": {
            ...restrictedPolicy.principals["principal-manager-a"],
            state: "revoked",
          },
        },
      },
    }),
    { allowed: false, code: "PRINCIPAL_NOT_ACTIVE" },
    "a replay cannot revive a revoked principal",
  );
});

test("restricted idempotency strictly parses authoritative records before replay decisions", () => {
  const prior = createBossRestrictedClientIdempotencyRecord(participantRequest);
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, workerContext),
    { allowed: true, idempotency: "new", record: prior },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, { ...workerContext, idempotencyRecords: [prior] }),
    { allowed: true, idempotency: "replay", record: prior },
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(
      { ...participantRequest, requestId: "request-b" },
      { ...workerContext, idempotencyRecords: [prior] },
    ),
    { allowed: false, code: "IDEMPOTENCY_CONFLICT" },
  );

  const inheritedRecord = Object.create(prior) as typeof prior;
  assert.throws(
    () => authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      idempotencyRecords: [inheritedRecord],
    }),
    ContractValidationError,
  );

  let getterCalls = 0;
  const accessorRecord = { ...prior };
  Object.defineProperty(accessorRecord, "requestId", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return prior.requestId;
    },
  });
  assert.throws(
    () => authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      idempotencyRecords: [prior, accessorRecord],
    }),
    ContractValidationError,
  );
  assert.equal(getterCalls, 0);

  const symbolRecord = { ...prior, [Symbol("extra")]: true };
  const nonEnumerableRecord = { ...prior };
  Object.defineProperty(nonEnumerableRecord, "requestId", { enumerable: false, value: prior.requestId });
  const extraRecord = { ...prior, extra: true };
  for (const invalidRecord of [symbolRecord, nonEnumerableRecord, extraRecord]) {
    assert.throws(
      () => authorizeBossRestrictedClientRequest(participantRequest, {
        ...workerContext,
        idempotencyRecords: [invalidRecord],
      }),
      ContractValidationError,
    );
  }

  assert.throws(
    () => authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      idempotencyRecords: [{ ...prior, scope: "0".repeat(64) }],
    }),
    /not bound to the record identity/,
  );
  assert.throws(
    () => authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      idempotencyRecords: [{ ...prior, operation: "manager_get_status" } as typeof prior],
    }),
    /must be one of/,
  );
  assert.deepEqual(
    authorizeBossRestrictedClientRequest(participantRequest, {
      ...workerContext,
      idempotencyRecords: [{ ...prior, operation: "participant_accept_assignment" }],
    }),
    { allowed: false, code: "REQUEST_ID_CONFLICT" },
  );
});

test("restricted results are exact, explicitly unauthorized, and fully request-bound", () => {
  const result = {
    version: BOSS_RESTRICTED_CLIENT_RESULT_VERSION,
    bossRunId: participantRequest.bossRunId,
    client: participantRequest.client,
    participantId: participantRequest.participantId,
    bindingEpoch: participantRequest.bindingEpoch,
    requestId: participantRequest.requestId,
    idempotencyKey: participantRequest.idempotencyKey,
    operation: participantRequest.operation,
    status: "ok" as const,
    payload: { assignmentId: "assignment-a", checkpointId: "checkpoint-a", recordedAt: "2026-07-28T12:05:01.000Z" },
  };
  assert.deepEqual(parseBossRestrictedClientResult(result, participantRequest), result);
  assert.doesNotThrow(() => assertBossRestrictedClientResultBinding(result, participantRequest));
  assert.throws(() => parseBossRestrictedClientResult({ ...result, bossRunId: "run-old" }, participantRequest), /not bound/);
  assert.throws(() => parseBossRestrictedClientResult({ ...result, payload: { ...result.payload, ignored: true } }), /not supported/);
  assert.throws(() => parseBossRestrictedClientResult({ ...result, payload: {} }), /required/);
  const reviewRequest = reviewerOperationRequest("reviewer_submit_review", {
    reviewId: "review-a",
    proofId: "proof-a",
    decision: "approved",
    reason: "verified",
  }, "review-result-smoke");
  const reviewResult = {
    version: BOSS_RESTRICTED_CLIENT_RESULT_VERSION,
    bossRunId: reviewRequest.bossRunId,
    client: reviewRequest.client,
    participantId: reviewRequest.participantId,
    bindingEpoch: reviewRequest.bindingEpoch,
    requestId: reviewRequest.requestId,
    idempotencyKey: reviewRequest.idempotencyKey,
    operation: reviewRequest.operation,
    status: "ok" as const,
    payload: { reviewId: "review-a" },
  };
  assert.deepEqual(parseBossRestrictedClientResult(reviewResult, reviewRequest), reviewResult);
  assert.doesNotThrow(() => assertBossRestrictedClientResultBinding(reviewResult, reviewRequest));
  const unauthorized = {
    ...result,
    status: "unauthorized",
    denialCode: "UNAUTHORIZED_ROLE",
  };
  delete (unauthorized as { payload?: unknown }).payload;
  assert.deepEqual(parseBossRestrictedClientResult(unauthorized, participantRequest), unauthorized);
  assert.throws(() => parseBossRestrictedClientResult({ ...unauthorized, denialCode: "unknown" }), /must be one of/);
});

test("successful restricted results bind every echoed request resource identity", () => {
  const successfulResult = (request: Record<string, unknown>, payload: Record<string, unknown>) => ({
    version: BOSS_RESTRICTED_CLIENT_RESULT_VERSION,
    bossRunId: request.bossRunId,
    client: request.client,
    ...(request.client === "boss_manager"
      ? { managerParticipantId: request.managerParticipantId }
      : { participantId: request.participantId }),
    bindingEpoch: request.bindingEpoch,
    requestId: request.requestId,
    idempotencyKey: request.idempotencyKey,
    operation: request.operation,
    status: "ok" as const,
    payload,
  });
  const correlatedCases: readonly [
    string,
    Record<string, unknown>,
    Record<string, unknown>,
    readonly Record<string, unknown>[],
  ][] = [
    ["manager_create_assignment", managerOperationRequest("manager_create_assignment", {
      assignmentId: "assignment-created",
      participantId: "worker-a",
      objective: "work",
    }, "result-create-assignment"), { assignmentId: "assignment-created" }, [{ assignmentId: "assignment-other" }]],
    ["manager_cancel_assignment", managerOperationRequest("manager_cancel_assignment", {
      assignmentId: "assignment-a",
      reason: "cancel",
    }, "result-cancel-assignment"), { assignmentId: "assignment-a" }, [{ assignmentId: "assignment-other" }]],
    ["manager_create_subscription", managerOperationRequest(
      "manager_create_subscription",
      lifecycleSubscription,
      "result-create-subscription",
    ), { subscriptionId: "subscription-a" }, [{ subscriptionId: "subscription-other" }]],
    ["manager_cancel_subscription", managerOperationRequest("manager_cancel_subscription", {
      subscriptionId: "subscription-stored",
    }, "result-cancel-subscription"), { subscriptionId: "subscription-stored" }, [{ subscriptionId: "subscription-other" }]],
    ["manager_submit_checkpoint", managerOperationRequest("manager_submit_checkpoint", {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-manager",
      summary: "done",
      occurredAt: "2026-07-28T12:05:00.000Z",
    }, "result-manager-checkpoint"), {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-manager",
      recordedAt: "2026-07-28T12:05:01.000Z",
    }, [{
      assignmentId: "assignment-other",
      checkpointId: "checkpoint-manager",
      recordedAt: "2026-07-28T12:05:01.000Z",
    }, {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-other",
      recordedAt: "2026-07-28T12:05:01.000Z",
    }]],
    ["manager_report_blocker", managerOperationRequest("manager_report_blocker", {
      blockerId: "blocker-manager",
      reason: "blocked",
    }, "result-manager-blocker"), { blockerId: "blocker-manager" }, [{ blockerId: "blocker-other" }]],
    ["manager_submit_proof", managerOperationRequest("manager_submit_proof", {
      proofId: "proof-a",
      digest: "a".repeat(64),
    }, "result-manager-proof"), { proofId: "proof-a" }, [{ proofId: "proof-other" }]],
    ["participant_accept_assignment", participantOperationRequest("participant_accept_assignment", {
      assignmentId: "assignment-a",
    }, "result-accept-assignment"), { assignmentId: "assignment-a" }, [{ assignmentId: "assignment-other" }]],
    ["participant_reject_assignment", participantOperationRequest("participant_reject_assignment", {
      assignmentId: "assignment-a",
      reason: "reject",
    }, "result-reject-assignment"), { assignmentId: "assignment-a" }, [{ assignmentId: "assignment-other" }]],
    ["participant_submit_checkpoint", participantOperationRequest("participant_submit_checkpoint", {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-participant",
      summary: "done",
      occurredAt: "2026-07-28T12:05:00.000Z",
    }, "result-participant-checkpoint"), {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-participant",
      recordedAt: "2026-07-28T12:05:01.000Z",
    }, [{
      assignmentId: "assignment-other",
      checkpointId: "checkpoint-participant",
      recordedAt: "2026-07-28T12:05:01.000Z",
    }, {
      assignmentId: "assignment-a",
      checkpointId: "checkpoint-other",
      recordedAt: "2026-07-28T12:05:01.000Z",
    }]],
    ["participant_submit_assignment", participantOperationRequest("participant_submit_assignment", {
      assignmentId: "assignment-a",
      resultDigest: "b".repeat(64),
    }, "result-submit-assignment"), { assignmentId: "assignment-a" }, [{ assignmentId: "assignment-other" }]],
    ["reviewer_get_proof", reviewerOperationRequest("reviewer_get_proof", {
      proofId: "proof-a",
    }, "result-get-proof"), { proofId: "proof-a", digest: "a".repeat(64) }, [{
      proofId: "proof-other",
      digest: "a".repeat(64),
    }]],
    ["reviewer_submit_review", reviewerOperationRequest("reviewer_submit_review", {
      reviewId: "review-a",
      proofId: "proof-a",
      decision: "approved",
      reason: "verified",
    }, "result-submit-review"), { reviewId: "review-a" }, [{ reviewId: "review-other" }]],
    ["reviewer_submit_proof", reviewerOperationRequest("reviewer_submit_proof", {
      proofId: "proof-reviewer-a",
      digest: "c".repeat(64),
    }, "result-reviewer-proof"), { proofId: "proof-reviewer-a" }, [{ proofId: "proof-other" }]],
    ["reviewer_get_objection_status", reviewerOperationRequest("reviewer_get_objection_status", {
      reviewId: "review-a",
    }, "result-objection"), { reviewId: "review-a", status: "pending" }, [{ reviewId: "review-other", status: "pending" }]],
  ];

  for (const [operation, request, validPayload, mismatchedPayloads] of correlatedCases) {
    const validResult = successfulResult(request, validPayload);
    assert.deepEqual(parseBossRestrictedClientResult(validResult, request), validResult, `${operation} valid control`);
    for (const mismatchedPayload of mismatchedPayloads) {
      assert.throws(
        () => parseBossRestrictedClientResult(successfulResult(request, mismatchedPayload), request),
        /does not match the originating request payload/,
        operation,
      );
    }
  }

  const serverMintedCases: readonly [Record<string, unknown>, Record<string, unknown>][] = [
    [managerOperationRequest("manager_request_staff", { role: "worker", count: 1 }, "result-staff-minted"), {
      staffRequestId: "staff-request-server-minted",
    }],
    [managerOperationRequest("manager_request_adversary_review", { proofId: "proof-a" }, "result-review-minted"), {
      reviewId: "review-server-minted",
    }],
    [participantOperationRequest("participant_report_blocker", {
      assignmentId: "assignment-a",
      reason: "blocked",
    }, "result-participant-blocker-minted"), { blockerId: "blocker-server-minted" }],
    [participantOperationRequest("participant_report_health", {
      state: "working",
      severity: "info",
      observedAt: "2026-07-28T12:05:00.000Z",
    }, "result-participant-health-minted"), { healthEventId: "health-server-minted" }],
    [reviewerOperationRequest("reviewer_report_health", {
      state: "ready",
      severity: "info",
      observedAt: "2026-07-28T12:05:00.000Z",
    }, "result-reviewer-health-minted"), { healthEventId: "reviewer-health-server-minted" }],
  ];
  for (const [request, payload] of serverMintedCases) {
    const result = successfulResult(request, payload);
    assert.deepEqual(parseBossRestrictedClientResult(result, request), result);
  }
});

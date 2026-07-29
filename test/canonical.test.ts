import assert from "node:assert/strict";
import test from "node:test";
import {
  CANONICAL_UNICODE_NORMALIZATION,
  assertExactKeys,
  assertRecord,
  canonicalFrame,
  canonicalHash,
  canonicalJson,
  ContractValidationError,
  readString,
  readStringArray,
  readTimestamp,
} from "../src/canonical.ts";
import { parseBossPolicyPrincipal } from "../src/boss-policy.ts";

test("canonical JSON recursively sorts keys and rejects non-wire members", () => {
  assert.equal(canonicalJson({ z: [3, { b: true, a: "x" }], a: 0 }), '{"a":0,"z":[3,{"a":"x","b":true}]}');
});

test("canonical hash is domain separated and stable", () => {
  assert.equal(canonicalHash("boss-test-v1", { b: 2, a: 1 }), "4ff6c078039d0d494b220a4dafa919c183136d4cf7e303eed1bc642ab0b8e4c2");
  assert.notEqual(canonicalHash("boss-test-v2", { a: 1, b: 2 }), canonicalHash("boss-test-v1", { a: 1, b: 2 }));
});

test("canonical encoding rejects non-JSON and ambiguous values", () => {
  const sparse = Array(1);
  const arrayWithProperty = [1] as number[] & { extra?: number };
  arrayWithProperty.extra = 2;
  const symbolObject = { value: 1 } as Record<PropertyKey, unknown>;
  symbolObject[Symbol("hidden")] = 2;
  const accessorObject = Object.defineProperty({}, "value", {
    enumerable: true,
    get: () => 1,
  });
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, 1.5, -0, 1n, new Date(0), [undefined], { value: undefined }, "\ud800", sparse, arrayWithProperty, symbolObject, accessorObject]) {
    assert.throws(() => canonicalJson(value), ContractValidationError);
  }
  const protoKey = Object.fromEntries([["__proto__", null]]);
  assert.notEqual(canonicalJson(protoKey), canonicalJson({}));
});

test("record schemas require own enumerable data properties and reject hidden metadata", () => {
  const inheritedRequired = Object.create({ required: "polluted" }) as Record<string, unknown>;
  assert.throws(() => assertExactKeys(inheritedRequired, ["required"]), /\$\.required: is required/);

  const symbolMetadata = { required: true } as Record<PropertyKey, unknown>;
  symbolMetadata[Symbol("metadata")] = true;
  assert.throws(
    () => assertExactKeys(symbolMetadata as Record<string, unknown>, ["required"]),
    /symbol properties are not supported/,
  );

  const hiddenMetadata = { required: true };
  Object.defineProperty(hiddenMetadata, "metadata", { value: true });
  assert.throws(
    () => assertExactKeys(hiddenMetadata, ["required"]),
    /\$\.metadata: must be an enumerable data property/,
  );

  const hiddenRequired = Object.defineProperty({}, "required", { value: true }) as Record<string, unknown>;
  assert.throws(
    () => assertExactKeys(hiddenRequired, ["required"]),
    /\$\.required: must be an enumerable data property/,
  );

  let getterCalls = 0;
  const accessorRecord = Object.defineProperty({}, "required", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return true;
    },
  });
  assert.throws(() => assertRecord(accessorRecord), /\$\.required: must be an enumerable data property/);
  assert.throws(
    () => assertExactKeys(accessorRecord, ["required"]),
    /\$\.required: must be an enumerable data property/,
  );
  assert.equal(getterCalls, 0);
});

test("string arrays require dense own enumerable data indices without metadata", () => {
  assert.deepEqual(readStringArray(["worker-a", "worker-b"], "participants"), ["worker-a", "worker-b"]);

  const sparse = Array(1);
  const extraProperty = Object.assign(["worker-a"], { metadata: true });
  const symbolProperty = ["worker-a"] as unknown[] & Record<PropertyKey, unknown>;
  symbolProperty[Symbol("metadata")] = true;
  for (const value of [sparse, extraProperty, symbolProperty]) {
    assert.throws(() => readStringArray(value, "participants"), ContractValidationError);
  }

  let getterCalls = 0;
  const accessorIndex = Object.defineProperty(["worker-a"], "0", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "polluted";
    },
  });
  assert.throws(
    () => readStringArray(accessorIndex, "participants"),
    /participants\[0\]: must be an enumerable data property/,
  );
  assert.throws(() => canonicalJson(accessorIndex), /\$\[0\]: must be an enumerable data property/);
  assert.equal(getterCalls, 0);
});

test("manager assignedParticipantIds rejects an inherited Array.prototype slot", () => {
  const priorDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  Object.defineProperty(Array.prototype, "0", {
    configurable: true,
    enumerable: true,
    value: "prototype-polluted-participant",
    writable: true,
  });
  try {
    const assignedParticipantIds = Array(1);
    assert.throws(
      () => parseBossPolicyPrincipal({
        version: "boss.policy-principal.v1",
        principalId: "manager-principal",
        principalClass: "boss-private",
        state: "active",
        bossRunId: "boss-run",
        participantId: "manager-participant",
        role: "manager",
        bindingEpoch: 1,
        assignedParticipantIds,
      }),
      /\$\.assignedParticipantIds\[0\]: sparse array holes are not supported/,
    );
  } finally {
    if (priorDescriptor === undefined) Reflect.deleteProperty(Array.prototype, "0");
    else Object.defineProperty(Array.prototype, "0", priorDescriptor);
  }
});

test("canonical framing is injective across absence, null, string, tags, and domains", () => {
  const encodings = [
    canonicalJson({}),
    canonicalJson({ value: null }),
    canonicalJson({ value: "null" }),
    canonicalJson({ sourceAuthorityId: { kind: "controller", bossRunId: "r", controllerGeneration: 1 } }),
    canonicalJson({ sourceAuthorityId: { kind: "worker_store", workerStoreId: "r", journalGeneration: 1 } }),
  ];
  assert.equal(new Set(encodings).size, encodings.length);
  assert.notDeepEqual(canonicalFrame("a", { value: "b:c" }), canonicalFrame("a:b", { value: "c" }));
  assert.throws(() => canonicalFrame("a\0b", {}), ContractValidationError);
  assert.throws(() => readString("", "id"), /non-empty/);
});

test("canonical Unicode is byte-preserving and never normalized implicitly", () => {
  assert.equal(CANONICAL_UNICODE_NORMALIZATION, "none");
  assert.notEqual(canonicalJson("é"), canonicalJson("e\u0301"));
});

test("canonical timestamps reject normalized dates and omitted milliseconds", () => {
  assert.equal(readTimestamp("2026-07-28T12:00:00.000Z", "time"), "2026-07-28T12:00:00.000Z");
  assert.throws(() => readTimestamp("2026-02-31T12:00:00.000Z", "time"), ContractValidationError);
  assert.throws(() => readTimestamp("2026-07-28T12:00:00Z", "time"), ContractValidationError);
});

import test from "node:test";
import assert from "node:assert/strict";
import {
  INTERCOM_PROTOCOL_NAME,
  INTERCOM_PROTOCOL_V4_SEMANTICS_HASH,
  INTERCOM_PROTOCOL_V4_VECTOR_SCHEMA_VERSION,
  INTERCOM_PROTOCOL_V4_VECTORS,
  INTERCOM_PROTOCOL_VERSION,
  intercomScopeIdFromEnv,
  parseIntercomScopeId,
  sameIntercomScope,
} from "../src/protocol-v4.ts";

const EXPECTED_PROTOCOL_V4_SEMANTICS_HASH = "ef23cae55b3cca7683fee60e5f2421350cde731dc5424c82286a33a8b9cdf6cb";

test("protocol v4 constants and reviewed vector hash are frozen", () => {
  assert.equal(INTERCOM_PROTOCOL_NAME, "pi-intercom");
  assert.equal(INTERCOM_PROTOCOL_VERSION, 4);
  assert.equal(INTERCOM_PROTOCOL_V4_VECTOR_SCHEMA_VERSION, 2);
  assert.equal(INTERCOM_PROTOCOL_V4_VECTORS.length, 48);
  assert.equal(INTERCOM_PROTOCOL_V4_SEMANTICS_HASH, EXPECTED_PROTOCOL_V4_SEMANTICS_HASH);
});

test("vector corpus covers executable validation, discovery, routing, asks, and replacement classes", () => {
  const operations = new Set(INTERCOM_PROTOCOL_V4_VECTORS.map((vector) => vector.operation));
  assert.deepEqual(operations, new Set([
    "validate_scope", "list", "session_joined", "session_left", "presence_update",
    "resolve", "send", "ask", "reply", "cancel_ask", "defer_ask", "replace", "late_frame",
  ]));
  assert.ok(INTERCOM_PROTOCOL_V4_VECTORS.some((vector) => vector.expected === "AMBIGUOUS_TARGET"));
  assert.ok(INTERCOM_PROTOCOL_V4_VECTORS.some((vector) => vector.expected === "SESSION_NOT_FOUND"));
  assert.ok(INTERCOM_PROTOCOL_V4_VECTORS.some((vector) => vector.name.includes("full id wins")));
  assert.ok(INTERCOM_PROTOCOL_V4_VECTORS.some((vector) => vector.name.includes("unscoped to scoped")));
  for (const vector of INTERCOM_PROTOCOL_V4_VECTORS) {
    if (vector.operation === "list") assert.ok(vector.candidates && vector.expectedTargetIds);
    if (["session_joined", "session_left", "presence_update"].includes(vector.operation)) {
      assert.ok(vector.candidates && vector.expectedAudienceIds);
    }
    if (vector.operation === "resolve") assert.ok(vector.selector && vector.candidates);
    if (vector.operation === "replace" || vector.operation === "late_frame") assert.ok(vector.expectedEvents);
  }
});

test("scope IDs are case-sensitive ASCII tokens from 16 through 128 characters", () => {
  assert.equal(parseIntercomScopeId(undefined), undefined);
  assert.equal(parseIntercomScopeId(""), undefined);
  assert.equal(parseIntercomScopeId("Abcdefghijklmnop"), "Abcdefghijklmnop");
  assert.equal(parseIntercomScopeId("abcdefghijklmnop"), "abcdefghijklmnop");
  assert.throws(() => parseIntercomScopeId("short"), /must match/);
  assert.throws(() => parseIntercomScopeId(" abcdefghijklmnop"), /must match/);
  assert.throws(() => parseIntercomScopeId("abcdefghijklmnop "), /must match/);
  assert.throws(() => parseIntercomScopeId("abcdefghijklmno."), /must match/);
  assert.throws(() => parseIntercomScopeId("ébcdefghijklmnop"), /must match/);
  assert.throws(() => parseIntercomScopeId("a".repeat(129)), /must match/);
});

test("environment parsing preserves exact bytes and treats only empty as unscoped", () => {
  assert.equal(intercomScopeIdFromEnv({}), undefined);
  assert.equal(intercomScopeIdFromEnv({ AGENT_INTERCOM_SCOPE_ID: "" }), undefined);
  assert.equal(intercomScopeIdFromEnv({ AGENT_INTERCOM_SCOPE_ID: "Scope_1234567890" }), "Scope_1234567890");
  assert.throws(() => intercomScopeIdFromEnv({ AGENT_INTERCOM_SCOPE_ID: " Scope_1234567890" }), /AGENT_INTERCOM_SCOPE_ID/);
});

test("same scope is strict equality including the unscoped group", () => {
  assert.equal(sameIntercomScope(undefined, undefined), true);
  assert.equal(sameIntercomScope("Scope_1234567890", "Scope_1234567890"), true);
  assert.equal(sameIntercomScope("Scope_1234567890", "scope_1234567890"), false);
  assert.equal(sameIntercomScope(undefined, "Scope_1234567890"), false);
});

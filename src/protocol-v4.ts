import { canonicalHash } from "./canonical.ts";

export const INTERCOM_PROTOCOL_NAME = "pi-intercom" as const;
export const INTERCOM_PROTOCOL_VERSION = 4 as const;
export const INTERCOM_SCOPE_ENV = "AGENT_INTERCOM_SCOPE_ID" as const;
export const INTERCOM_SCOPE_ID_PATTERN_SOURCE = "^[A-Za-z0-9_-]{16,128}$" as const;
export const INTERCOM_SCOPE_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
export const INTERCOM_PROTOCOL_V4_VECTOR_SCHEMA_VERSION = 2 as const;

export type IntercomScopeId = string;
export type ProtocolV4Scope = string | null;
export type ProtocolV4Operation =
  | "validate_scope"
  | "list"
  | "session_joined"
  | "session_left"
  | "presence_update"
  | "resolve"
  | "send"
  | "ask"
  | "reply"
  | "cancel_ask"
  | "defer_ask"
  | "replace"
  | "late_frame";
export type ProtocolV4Expected =
  | "valid_scoped"
  | "valid_unscoped"
  | "invalid_scope"
  | "visible"
  | "hidden"
  | "global_exact_id"
  | "same_scope_name"
  | "same_scope_prefix"
  | "AMBIGUOUS_TARGET"
  | "SESSION_NOT_FOUND"
  | "delivered"
  | "exact_edge"
  | "old_left_before_new_joined"
  | "same_scope_left_before_joined"
  | "discard";

export interface ProtocolV4Candidate {
  readonly id: string;
  readonly name: string;
  readonly scope: ProtocolV4Scope;
}

export interface ProtocolV4Vector {
  readonly name: string;
  readonly operation: ProtocolV4Operation;
  readonly actorId?: string;
  readonly actorScope?: ProtocolV4Scope;
  readonly subjectId?: string;
  readonly subjectScope?: ProtocolV4Scope;
  readonly selector?: string;
  readonly scopeInput?: unknown;
  readonly candidates?: readonly ProtocolV4Candidate[];
  readonly expected: ProtocolV4Expected;
  readonly expectedTargetIds?: readonly string[];
  readonly expectedAudienceIds?: readonly string[];
  readonly expectedEvents?: readonly string[];
}

export const PROTOCOL_V4_SCOPE_A = "Scope_AAAAAAAAAA" as const;
export const PROTOCOL_V4_SCOPE_B = "Scope_BBBBBBBBBB" as const;

const A1 = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", name: "alpha", scope: PROTOCOL_V4_SCOPE_A } as const;
const A2 = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2", name: "worker", scope: PROTOCOL_V4_SCOPE_A } as const;
const A3 = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3", name: "worker", scope: PROTOCOL_V4_SCOPE_A } as const;
const AP1 = { id: "abcde111-1111-4111-8111-111111111111", name: "prefix-one", scope: PROTOCOL_V4_SCOPE_A } as const;
const AP2 = { id: "abcde222-2222-4222-8222-222222222222", name: "prefix-two", scope: PROTOCOL_V4_SCOPE_A } as const;
const B1 = { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1", name: "worker", scope: PROTOCOL_V4_SCOPE_B } as const;
const B2 = { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2", name: A1.id, scope: PROTOCOL_V4_SCOPE_B } as const;
const U1 = { id: "11111111-1111-4111-8111-111111111111", name: "unscoped-one", scope: null } as const;
const U2 = { id: "22222222-2222-4222-8222-222222222222", name: "unscoped-two", scope: null } as const;
const ALL = [A1, A2, A3, AP1, AP2, B1, B2, U1, U2] as const;

export const INTERCOM_PROTOCOL_V4_VECTORS: readonly ProtocolV4Vector[] = [
  { name: "scope unset is unscoped", operation: "validate_scope", expected: "valid_unscoped" },
  { name: "scope empty is unscoped", operation: "validate_scope", scopeInput: "", expected: "valid_unscoped" },
  { name: "scope lower bound", operation: "validate_scope", scopeInput: "A".repeat(16), expected: "valid_scoped" },
  { name: "scope upper bound", operation: "validate_scope", scopeInput: "A".repeat(128), expected: "valid_scoped" },
  { name: "scope mixed case is preserved", operation: "validate_scope", scopeInput: PROTOCOL_V4_SCOPE_A, expected: "valid_scoped" },
  { name: "scope short rejected", operation: "validate_scope", scopeInput: "A".repeat(15), expected: "invalid_scope" },
  { name: "scope long rejected", operation: "validate_scope", scopeInput: "A".repeat(129), expected: "invalid_scope" },
  { name: "scope leading whitespace rejected", operation: "validate_scope", scopeInput: ` ${PROTOCOL_V4_SCOPE_A}`, expected: "invalid_scope" },
  { name: "scope trailing whitespace rejected", operation: "validate_scope", scopeInput: `${PROTOCOL_V4_SCOPE_A} `, expected: "invalid_scope" },
  { name: "scope punctuation rejected", operation: "validate_scope", scopeInput: "Scope.AAAAAAAAAA", expected: "invalid_scope" },
  { name: "scope non ASCII rejected", operation: "validate_scope", scopeInput: "éAAAAAAAAAAAAAAA", expected: "invalid_scope" },
  { name: "scope non string rejected", operation: "validate_scope", scopeInput: 42, expected: "invalid_scope" },

  { name: "A list", operation: "list", actorId: A1.id, actorScope: A1.scope, candidates: ALL, expected: "visible", expectedTargetIds: [A1.id, A2.id, A3.id, AP1.id, AP2.id] },
  { name: "B list", operation: "list", actorId: B1.id, actorScope: B1.scope, candidates: ALL, expected: "visible", expectedTargetIds: [B1.id, B2.id] },
  { name: "unscoped list", operation: "list", actorId: U1.id, actorScope: null, candidates: ALL, expected: "visible", expectedTargetIds: [U1.id, U2.id] },
  { name: "A joined audience", operation: "session_joined", subjectId: A2.id, subjectScope: A2.scope, candidates: ALL, expected: "visible", expectedAudienceIds: [A1.id, A3.id, AP1.id, AP2.id] },
  { name: "B joined audience", operation: "session_joined", subjectId: B2.id, subjectScope: B2.scope, candidates: ALL, expected: "visible", expectedAudienceIds: [B1.id] },
  { name: "unscoped joined audience", operation: "session_joined", subjectId: U2.id, subjectScope: null, candidates: ALL, expected: "visible", expectedAudienceIds: [U1.id] },
  { name: "A left audience", operation: "session_left", subjectId: A2.id, subjectScope: A2.scope, candidates: ALL, expected: "visible", expectedAudienceIds: [A1.id, A3.id, AP1.id, AP2.id] },
  { name: "B left audience", operation: "session_left", subjectId: B2.id, subjectScope: B2.scope, candidates: ALL, expected: "visible", expectedAudienceIds: [B1.id] },
  { name: "unscoped left audience", operation: "session_left", subjectId: U2.id, subjectScope: null, candidates: ALL, expected: "visible", expectedAudienceIds: [U1.id] },
  { name: "A presence audience", operation: "presence_update", subjectId: A2.id, subjectScope: A2.scope, candidates: ALL, expected: "visible", expectedAudienceIds: [A1.id, A3.id, AP1.id, AP2.id] },
  { name: "B presence audience", operation: "presence_update", subjectId: B2.id, subjectScope: B2.scope, candidates: ALL, expected: "visible", expectedAudienceIds: [B1.id] },
  { name: "unscoped presence audience", operation: "presence_update", subjectId: U2.id, subjectScope: null, candidates: ALL, expected: "visible", expectedAudienceIds: [U1.id] },

  { name: "same scope exact name", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: AP1.name, candidates: ALL, expected: "same_scope_name", expectedTargetIds: [AP1.id] },
  { name: "same scope duplicate name ambiguous", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: A2.name, candidates: ALL, expected: "AMBIGUOUS_TARGET", expectedTargetIds: [A2.id, A3.id] },
  { name: "same scope unique prefix", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: "abcde1", candidates: ALL, expected: "same_scope_prefix", expectedTargetIds: [AP1.id] },
  { name: "same scope duplicate prefix ambiguous", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: "abcde", candidates: ALL, expected: "AMBIGUOUS_TARGET", expectedTargetIds: [AP1.id, AP2.id] },
  { name: "cross scope name hidden", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: B1.name, candidates: [A1, B1], expected: "SESSION_NOT_FOUND" },
  { name: "cross scope prefix hidden", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: "bbbbbb", candidates: ALL, expected: "SESSION_NOT_FOUND" },
  { name: "scoped to unscoped name hidden", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: U1.name, candidates: ALL, expected: "SESSION_NOT_FOUND" },
  { name: "unscoped to scoped name hidden", operation: "resolve", actorId: U1.id, actorScope: null, selector: A1.name, candidates: ALL, expected: "SESSION_NOT_FOUND" },
  { name: "exact full id crosses A to B", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: B1.id, candidates: ALL, expected: "global_exact_id", expectedTargetIds: [B1.id] },
  { name: "exact full id crosses scoped to unscoped", operation: "resolve", actorId: A1.id, actorScope: A1.scope, selector: U1.id, candidates: ALL, expected: "global_exact_id", expectedTargetIds: [U1.id] },
  { name: "exact full id crosses unscoped to scoped", operation: "resolve", actorId: U1.id, actorScope: null, selector: A1.id, candidates: ALL, expected: "global_exact_id", expectedTargetIds: [A1.id] },
  { name: "full id wins over same selector name", operation: "resolve", actorId: A2.id, actorScope: A2.scope, selector: A1.id, candidates: ALL, expected: "global_exact_id", expectedTargetIds: [A1.id] },

  { name: "cross scope exact send", operation: "send", actorId: A1.id, actorScope: A1.scope, subjectId: B1.id, subjectScope: B1.scope, selector: B1.id, candidates: ALL, expected: "delivered", expectedTargetIds: [B1.id] },
  { name: "cross scope exact ask", operation: "ask", actorId: A1.id, actorScope: A1.scope, subjectId: B1.id, subjectScope: B1.scope, selector: B1.id, candidates: ALL, expected: "exact_edge", expectedTargetIds: [B1.id] },
  { name: "cross scope exact reply", operation: "reply", actorId: B1.id, actorScope: B1.scope, subjectId: A1.id, subjectScope: A1.scope, selector: A1.id, candidates: ALL, expected: "exact_edge", expectedTargetIds: [A1.id] },
  { name: "cross scope exact cancel", operation: "cancel_ask", actorId: A1.id, actorScope: A1.scope, subjectId: B1.id, subjectScope: B1.scope, selector: B1.id, candidates: ALL, expected: "exact_edge", expectedTargetIds: [B1.id] },
  { name: "cross scope exact defer", operation: "defer_ask", actorId: B1.id, actorScope: B1.scope, subjectId: A1.id, subjectScope: A1.scope, selector: A1.id, candidates: ALL, expected: "exact_edge", expectedTargetIds: [A1.id] },

  { name: "A to B replacement ordering", operation: "replace", actorId: A2.id, actorScope: A2.scope, subjectId: A2.id, subjectScope: B1.scope, candidates: ALL, expected: "old_left_before_new_joined", expectedEvents: [`left:${A2.id}:A`, `joined:${A2.id}:B`] },
  { name: "B to unscoped replacement ordering", operation: "replace", actorId: B1.id, actorScope: B1.scope, subjectId: B1.id, subjectScope: null, candidates: ALL, expected: "old_left_before_new_joined", expectedEvents: [`left:${B1.id}:B`, `joined:${B1.id}:U`] },
  { name: "same scope replacement ordering", operation: "replace", actorId: A2.id, actorScope: A2.scope, subjectId: A2.id, subjectScope: A2.scope, candidates: ALL, expected: "same_scope_left_before_joined", expectedEvents: [`left:${A2.id}:A`, `joined:${A2.id}:A`] },
  { name: "late old list discarded", operation: "late_frame", actorId: A2.id, actorScope: A2.scope, subjectId: A2.id, subjectScope: B1.scope, expected: "discard", expectedEvents: [] },
  { name: "late old presence discarded", operation: "late_frame", actorId: A2.id, actorScope: A2.scope, subjectId: A2.id, subjectScope: B1.scope, expected: "discard", expectedEvents: [] },
  { name: "late old send discarded", operation: "late_frame", actorId: A2.id, actorScope: A2.scope, subjectId: B1.id, subjectScope: B1.scope, expected: "discard", expectedEvents: [] },
  { name: "late old control discarded", operation: "late_frame", actorId: A2.id, actorScope: A2.scope, subjectId: B1.id, subjectScope: B1.scope, expected: "discard", expectedEvents: [] },
] as const;

export const INTERCOM_PROTOCOL_V4_SEMANTICS_HASH = canonicalHash(
  "agent-intercom-core/protocol-v4/acceptance-vectors",
  { version: INTERCOM_PROTOCOL_V4_VECTOR_SCHEMA_VERSION, vectors: INTERCOM_PROTOCOL_V4_VECTORS },
);

export function parseIntercomScopeId(value: unknown, path = "scopeId"): IntercomScopeId | undefined {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string" || !INTERCOM_SCOPE_ID_PATTERN.test(value)) {
    throw new Error(`${path} must match ${INTERCOM_SCOPE_ID_PATTERN_SOURCE}`);
  }
  return value;
}

export function intercomScopeIdFromEnv(env: NodeJS.ProcessEnv = process.env): IntercomScopeId | undefined {
  return parseIntercomScopeId(env[INTERCOM_SCOPE_ENV], INTERCOM_SCOPE_ENV);
}

export function sameIntercomScope(left: IntercomScopeId | undefined, right: IntercomScopeId | undefined): boolean {
  return left === right;
}

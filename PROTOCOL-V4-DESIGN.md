# Agent Intercom protocol v4 — scoped broker design

Status: protocol v4 shipped in the `connect.1` release. The current work is the `connect.2` package-namespace migration candidate (`@dataforxyz/*` → `@ctliz/*`), which is not yet released or installed. The protocol wire contract, acceptance vectors, and semantics hash are unchanged by that migration.

## Wire contract

Protocol identity is exactly `pi-intercom` version `4`. Clients and brokers must reject every other version; there is no silent downgrade. If `AGENT_INTERCOM_SCOPE_ID` is set while a harness cannot speak v4, startup must fail closed.

The register request adds one optional top-level member:

```ts
{ type: "register", protocol: "pi-intercom", version: 4, scopeId?: string, ... }
```

`scopeId` validation is exactly `^[A-Za-z0-9_-]{16,128}$`. It is case-sensitive ASCII. The empty environment value is the unscoped group; every invalid non-empty value is an error. Implementations must not trim, lowercase, normalize, hash, derive, or rewrite it.

The broker stores the parsed scope only in its private `ConnectedSession` record. It is forbidden in `SessionInfo`, list output, lifecycle events, presence, `message.from`, tools, logs, errors, audit records, health, or registration responses. Presence cannot change scope.

## Discovery and routing

`sameScope(a,b)` is strict equality. Missing scope equals missing scope; scoped and unscoped sessions are separate groups.

- list returns self plus authorized sessions in the same scope
- joined, left, and presence are sent only to authorized recipients in the same scope
- send/ask resolution order is global exact full session ID, same-scope exact name, same-scope unique ID prefix, otherwise `SESSION_NOT_FOUND`
- a full ID wins over a conflicting name
- name or prefix never crosses scope
- reply, ask edge, cancel, and defer continue using exact IDs and may cross scope
- an adapter directory filter may narrow the broker-visible set but cannot widen it

For same-ID replacement across scopes, recipients in the old scope observe `left` before recipients in the new scope observe `joined`. The broker installs the new private scope binding before ending the old socket. Any later frame from the old socket is ignored because socket identity no longer matches the current session binding.

## Adapter environment contract

`AGENT_INTERCOM_SCOPE_ID` is a general launcher contract. Shells, direnv, IDEs, service managers, CI, and optional desktop launchers may set it; TmuxDeck is not required. Documentation must not require `TMUXDECK_WORKSPACE` or derive scope from TmuxDeck metadata.

Each broker-capable adapter (Pi, Claude, Codex, OpenCode) reads `AGENT_INTERCOM_SCOPE_ID` at registration and sends the exact validated value. Reconnect keeps the same value. Child processes and managed workers inherit this private environment by default, including manager/worker, restart, resume, adopt, and nested ownership paths. Contact-copy output always includes the full session ID.

`scopeId` and session IDs are routing identifiers, not credentials. Protocol-v4 scope is same-UID UX isolation and a broker visibility boundary; it is not tenant isolation against hostile processes sharing the Unix account.

## Canonical source and drift guard

`@ctliz/agent-intercom-core/protocol-v4` is the canonical source for constants, validation, acceptance vectors, and the semantics hash. Core remains a pure-contract package and does not host the broker.

Each broker-capable package must either consume this entry point or vendor an auditable one-file re-export with a coordinated source SHA-256 test, and must assert the same vector schema version and semantics hash. Cross-package acceptance starts each participating package's broker and runs the same machine-readable corpus. Core itself is an internal dependency rather than a separately installed runtime component, and Orchestrator neither implements nor starts a broker, so it is outside this broker compatibility set.

## Standalone release gate

The coordinated release must pass `docs/standalone-v4-acceptance.md` from a separate cross-package integration workspace using packed tarballs. The gate explicitly removes terminal/TmuxDeck metadata, never invokes TmuxDeck, launches each participating broker-capable adapter directly from a shell, repeats the corpus with each package owning the broker, validates A/B/unscoped cross-harness messaging, and proves exact cleanup without changing the real v3 broker or default tmux state. Orchestrator inheritance is validated only when Orchestrator is installed on a supported Linux/systemd host; its absence is a supported configuration, not a gate failure.

## Replacement and non-leak acceptance

Candidate tests must prove:

- A/B/unscoped list and lifecycle partitioning
- exact full-ID cross-scope send and ask lifecycle
- cross-scope name/prefix refusal
- same-ID cross-scope replacement ordering and late-old-socket frame discard
- no `scopeId` text or field in output, logs, errors, audit, or persisted ask/delivery state
- v3/v4 mismatch fails closed
- any adapter's broker produces identical results

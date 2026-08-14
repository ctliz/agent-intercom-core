# Standalone protocol-v4 acceptance gate

Status: required coordinated release gate for the broker-capable adapters. This test is independent of TmuxDeck and must pass before any Pi, Claude, Codex, or OpenCode protocol-v4 candidate is published, because those packages negotiate against one shared Broker.

Orchestrator is a separate optional product and is **not** a prerequisite for adapter releases. It may be released on its own schedule, but when it is released it must pass its own conditional section on a real Linux host with a systemd user manager. That requirement is not relaxed by its exclusion from the adapter gate.

The broker-capable adapters are Pi, Claude, Codex, and OpenCode; only these connect to or start the shared Broker. Core is an internal dependency, not a separately installed runtime component. Orchestrator is an optional Linux/systemd lifecycle component that neither implements nor starts a Broker, so it is not part of the Broker compatibility set; sections below that cover it are conditional on it being installed on a supported host.

## Launcher contract

`AGENT_INTERCOM_SCOPE_ID` is a general launcher contract. A shell, direnv, IDE, service manager, CI runner, or optional desktop launcher may set it. TmuxDeck is not required and is not part of this test. No example may require `TMUXDECK_WORKSPACE` or another TmuxDeck variable. Unset or empty means the unscoped group.

## Integration workspace

The executable cross-package test runner lives in its own integration repository/workspace, not in TmuxDeck and not inside one adapter package. It consumes packed candidate tarballs and the canonical `@ctliz/agent-intercom-core/protocol-v4` acceptance vectors/hash.

The runner records:

- exact source commit, package version, tarball SHA-256, protocol-vector hash, Node version, platform, and command line for each candidate
- whether each check is live host E2E, runtime/CLI process E2E, or a raw protocol harness
- every started PID, socket, temporary directory, and cleanup result without recording message bodies or `scopeId`

## 1. Host isolation and protected-state proof

Before starting candidates:

1. Create private temporary `HOME`, `USERPROFILE`, XDG directories, `PI_CODING_AGENT_DIR`, npm cache, and `TMPDIR`.
2. Explicitly unset `TMUX`, `TMUX_PANE`, every `TMUXDECK_*` variable, `GHOSTTY_*`, `TERM_PROGRAM`, `TERM_PROGRAM_VERSION`, and comparable terminal metadata.
3. The candidate environment must never invoke, inspect, signal, or depend on any real TmuxDeck process. A real TmuxDeck process may remain running outside the isolated environment; record enough read-only process/config state to prove the run did not affect it.
4. Record the user's default tmux session/pane topology hash without sending commands into panes. Do not access the default tmux server after the initial proof until final verification.
5. Do not invoke or read a TmuxDeck binary, RPC, command, resource, configuration file, managed directory, or test helper.
6. Record read-only hashes of the real Pi settings and existing broker runtime metadata. Never read inbox/message contents.

After cleanup, the default tmux topology, real Pi settings, real protocol-v3 broker PID/socket metadata, and TmuxDeck state must match the initial proof.

## 2. Packed installation and direct shell launch

Build each candidate, run `npm pack`, verify licenses/notices and package contents, then install the tarballs into the isolated environment. Runtime commands must resolve from the isolated installation and must not import source using repository absolute paths.

Exercise direct shell startup for:

- Pi extension/runtime
- Claude MCP and `cci` worker; cover ordinary `cci`, `ccim`, and `--tui` environment propagation separately
- Codex MCP, `coi`, bridge, and app-server control path
- OpenCode server/plugin, TUI control, fleet, and resume path
- Orchestrator manager and workers — only when Orchestrator is installed on a supported Linux/systemd host; skip on macOS and on hosts without a systemd user manager

Any Pi/Claude/Codex/OpenCode package may be the first process and therefore start the one shared v4 broker. Repeat the protocol corpus with each package as broker owner and require identical observable results. If a real host UI cannot be automated safely, run the runtime/CLI child processes and label the check accordingly; do not claim a native-UI result from a protocol harness.

## 3. Scope A cross-harness matrix

Set one manually generated valid value only through `AGENT_INTERCOM_SCOPE_ID`. Start at least one Pi, Claude, Codex, and OpenCode session.

For every harness prove:

- list and its Alt+M/control picker see only A
- exact same-scope name succeeds
- unique same-scope ID prefix succeeds
- exact full ID succeeds
- contact-copy/identity output contains the full ID
- send, ask, deferred ask if supported, reply, delivery acknowledgment, cancel, timeout, and late reply retain exact threading across harness pairs
- join, leave, and presence are visible only within A
- reconnect preserves A

Use a pairwise cross-harness routing matrix so each participating broker-capable adapter sends and receives through another participating adapter, not only through Pi. Cover the broker-capable adapters under test; an adapter that is not part of the run is simply absent from the matrix.

## 4. Scope B isolation and exact-ID escape hatch

Start at least Pi and one other harness in B while A remains connected.

Prove:

- A and B do not list each other
- A and B receive no cross-scope join, leave, or presence event
- cross-scope name returns `SESSION_NOT_FOUND`
- cross-scope ID prefix returns `SESSION_NOT_FOUND`
- exact full IDs deliver bidirectionally
- exact-ID ask/reply/cancel/defer lifecycle works bidirectionally
- `scopeId` is absent from `SessionInfo`, `message.from`, tool output, CLI output, logs, transcripts, health, lifecycle frames, errors, audit records, and persisted ask/delivery state

## 5. Unscoped standalone compatibility

Start at least two different harnesses with `AGENT_INTERCOM_SCOPE_ID` unset.

Prove:

- unscoped sessions discover and contact each other by name, prefix, and full ID
- scoped sessions and unscoped sessions cannot discover one another
- scoped/unscoped name and prefix fail with `SESSION_NOT_FOUND`
- exact full IDs contact scoped ↔ unscoped in both directions
- no TmuxDeck metadata is needed for the legacy standalone experience

## 6. Fail-closed and reconnect behavior

Prove:

- a scoped v4 client connecting to a v3 broker reports an explicit protocol mismatch
- it does not strip `AGENT_INTERCOM_SCOPE_ID`
- it does not silently downgrade
- it does not spawn a second broker island after the mismatch
- a v3 client connecting to a v4 broker fails explicitly
- every invalid non-empty scope value is rejected before registration, including whitespace-padded, non-ASCII, short, long, and punctuation values
- broker restart and client reconnect preserve the exact case-sensitive scope
- empty remains unscoped

## 7. Contact handoff

For Pi, Claude, Codex, and OpenCode, identity/contact commands and Alt+I where natively implemented always produce the full session ID. A human-readable name may accompany it but may not replace it.

Claude `--tui` is tested through its plugin slash identity command. Do not claim a native Alt+I shortcut in Claude Code's owned terminal unless the wrapper demonstrably implements it.

## 8. Orchestrator without TmuxDeck

Conditional section. Orchestrator is optional and Linux/systemd only, and does not implement or start a Broker. Run this section only when Orchestrator is installed on a supported Linux host or on WSL with a systemd user manager enabled. Skip it on macOS and on any host without a systemd user manager; skipping is a supported configuration and does not make the release mixed or unsupported.

Launch the manager from a direct shell environment with `AGENT_INTERCOM_SCOPE_ID` set. Prove:

- built-in workers for the broker-capable adapters that are installed inherit the exact scope privately
- custom profiles inherit it unless they explicitly replace their entire environment under an already documented contract
- manager/worker exact-ID routing works
- restart, resume, adoption, nested ownership, readiness helpers, and private launch environments preserve scope
- `intercom_team` remains ownership-based and does not reveal unrelated same-scope sessions
- ownership and scope checks both apply; neither substitutes for the other

## 9. Packaging gate

The test must run from packed candidate tarballs corresponding to immutable candidate commits/tags. Validate:

- version and source commit metadata
- archive SHA-256
- AGPL license, copyright, transition notice, and third-party notices
- canonical protocol-v4 vector hash/version guard
- no test fixture or private runtime leakage
- no absolute source-repository import or path
- built distributions contain protocol version 4 and environment propagation

No broker-capable package is published before all participating broker-capable candidates in the same coordinated set pass. Orchestrator is outside this set: its release neither blocks nor is blocked by the adapter gate, and it carries its own Linux/systemd production gate.

## 10. Exact cleanup

Track and terminate every started process by exact PID. Remove only the isolated sockets, homes, caches, logs, and temporary files created by the run. Do not use broad `pkill`, default tmux commands, or global npm removal.

Final proof must show:

- no candidate PID remains
- no candidate broker socket/runtime remains
- temporary homes and package installs are removed
- real protocol-v3 broker PID/socket/settings hashes are unchanged
- default tmux topology hash is unchanged
- TmuxDeck process/config/managed state is unchanged
- no input was sent to a real tmux pane or desktop harness session

A cleanup or protected-state mismatch fails the release gate even if protocol assertions passed.

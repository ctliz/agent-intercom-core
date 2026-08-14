# Agent Intercom Core

The shared security policy kernel and protocol primitives for the [Agent Intercom](https://github.com/ctliz/agent-intercom-pi) adapter family.

| Harness | Repository |
|---|---|
| Core / Protocol | [`agent-intercom-core`](https://github.com/ctliz/agent-intercom-core) |
| Pi | [`agent-intercom-pi`](https://github.com/ctliz/agent-intercom-pi) |
| Codex | [`agent-intercom-codex`](https://github.com/ctliz/agent-intercom-codex) |
| Claude Code | [`agent-intercom-claude`](https://github.com/ctliz/agent-intercom-claude) |
| OpenCode | [`agent-intercom-opencode`](https://github.com/ctliz/agent-intercom-opencode) |
| Fleet lifecycle | [`agent-intercom-orchestrator`](https://github.com/ctliz/agent-intercom-orchestrator) |

## Maintenance & Upstream Provenance

- **Maintained by `ctliz`**: This distribution is maintained independently by [ctliz](https://github.com/ctliz).
- **Upstream Heritage**: Agent Intercom grew from [Nico Bailon's original `pi-intercom`](https://github.com/nicobailon/pi-intercom) and the upstream `dataforxyz/*` repositories. This project is not officially endorsed by or affiliated with upstream organizations.
- **Branding & Compatibility**: The **Agent Intercom** branding and `@dataforxyz/*` package namespaces remain unchanged.

## Protocol v4 Scope & Security Contract

This package is intentionally narrow. It contains pure, versioned authorization rules, canonical protocol vectors, and policy state transitions used by every broker and remote gateway. Transport, worker lifecycle, queues, and harness integrations remain in their adapter repositories.

The explicit `@dataforxyz/agent-intercom-core/protocol-v4` entry point is the canonical source for protocol-v4 constants, `scopeId` validation, strict same-scope comparison, acceptance vectors, and their semantics hash:

- **Broker-Enforced Scope**: Client registers its `scopeId` on connect. The broker maintains `scopeId` in its private session state and enforces same-scope discovery (`intercom_list`), naming, and prefix resolution. Cross-scope messaging requires an explicit full session ID.
- **UX Isolation Boundary**: Scope provides same-OS-user workflow isolation (e.g. per-project or per-workspace agent teams), **not** an authentication, tenant, or security principal boundary.
- **No Raw Scope Value Leaks**: Scope terminology, the validation pattern, and the vector schema are public API and are exported from this package. What must never leak is the *raw scope value*: it never enters `SessionInfo`, discovery/list/lifecycle frames, frontend or mobile surfaces, logs, or public evidence. Scope validation failures report the offending field path and the public pattern without echoing the raw input.
- **Standalone Contract**: `AGENT_INTERCOM_SCOPE_ID` is a general shell/IDE/service launcher contract; TmuxDeck is optional visual tooling.
- The coordinated standalone release gate is documented in `docs/standalone-v4-acceptance.md`.

## License

GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`). See `LICENSE` and `PROTOCOL-V4-DESIGN.md`.

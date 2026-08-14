# Agent Intercom Core

The shared security policy kernel and protocol primitives for the [Agent Intercom](https://github.com/ctliz/agent-intercom-pi) adapter family.

| Component | Package | Role |
|---|---|---|
| Pi | [`@ctliz/agent-intercom-pi`](https://github.com/ctliz/agent-intercom-pi) | Broker-capable adapter |
| Claude Code | [`@ctliz/agent-intercom-claude`](https://github.com/ctliz/agent-intercom-claude) | Broker-capable adapter |
| Codex | [`@ctliz/agent-intercom-codex`](https://github.com/ctliz/agent-intercom-codex) | Broker-capable adapter |
| OpenCode | [`@ctliz/agent-intercom-opencode`](https://github.com/ctliz/agent-intercom-opencode) | Broker-capable adapter |
| Core / Protocol | [`@ctliz/agent-intercom-core`](https://github.com/ctliz/agent-intercom-core) | Internal dependency — not separately installed or upgraded by users |
| Fleet lifecycle | [`@ctliz/agent-intercom-orchestrator`](https://github.com/ctliz/agent-intercom-orchestrator) | Optional, Linux/systemd only — does not implement or start a Broker |

Only the broker-capable adapters connect to or start the shared Broker. Core is pulled in as a dependency of whichever adapters you install. Orchestrator is an optional lifecycle component and is not part of the Broker compatibility set.

## Maintenance & Upstream Provenance

- **Maintained by `ctliz`**: This distribution is maintained independently by [ctliz](https://github.com/ctliz).
- **Upstream Heritage**: Agent Intercom grew from [Nico Bailon's original `pi-intercom`](https://github.com/nicobailon/pi-intercom) and the upstream `dataforxyz/*` repositories. This project is not officially endorsed by or affiliated with upstream organizations.
- **Package Namespace**: The canonical npm namespace is `@ctliz/*`. The historical `@dataforxyz/*` namespace was used up to and including `connect.1` and is retained only as provenance and as a migration-detection input; it is never treated as a current or healthy installation. The **Agent Intercom** branding and the `intercom_*` API surface are unchanged.

## Protocol v4 Scope & Security Contract

This package is intentionally narrow. It contains pure, versioned authorization rules, canonical protocol vectors, and policy state transitions used by every broker and remote gateway. Transport, worker lifecycle, queues, and harness integrations remain in their adapter repositories.

The explicit `@ctliz/agent-intercom-core/protocol-v4` entry point is the canonical source for protocol-v4 constants, `scopeId` validation, strict same-scope comparison, acceptance vectors, and their semantics hash:

- **Broker-Enforced Scope**: Client registers its `scopeId` on connect. The broker maintains `scopeId` in its private session state and enforces same-scope discovery (`intercom_list`), naming, and prefix resolution. Cross-scope messaging requires an explicit full session ID.
- **UX Isolation Boundary**: Scope provides same-OS-user workflow isolation (e.g. per-project or per-workspace agent teams), **not** an authentication, tenant, or security principal boundary.
- **No Raw Scope Value Leaks**: Scope terminology, the validation pattern, and the vector schema are public API and are exported from this package. What must never leak is the *raw scope value*: it never enters `SessionInfo`, discovery/list/lifecycle frames, frontend or mobile surfaces, logs, or public evidence. Scope validation failures report the offending field path and the public pattern without echoing the raw input.
- **Standalone Contract**: `AGENT_INTERCOM_SCOPE_ID` is a general shell/IDE/service launcher contract; TmuxDeck is optional visual tooling.
- The coordinated standalone release gate is documented in `docs/standalone-v4-acceptance.md`.

## Upgrading from `connect.1` to `connect.2`

`connect.2` renames the canonical package namespace from `@dataforxyz/*` to `@ctliz/*`. The two namespaces are different packages to npm. Pi Git package installations deduplicate by repository URL without ref, but running agent sessions continue to execute legacy code in memory, and npm or global installs along with binary links can coexist and conflict. Operators must stop active sessions, clean active install surfaces, and follow remove-before-install — side-by-side installation is not supported.

**Scope of a coordinated upgrade.** Upgrade the broker-capable adapters that are *actually installed and enabled on this machine* — any of Pi, Claude, Codex, and OpenCode — within one maintenance window, because they negotiate against a shared Broker. Adapters you do not use do not need to be installed to satisfy the upgrade. Core is an internal dependency and is not upgraded on its own; it arrives with the adapters. Orchestrator is optional and Linux/systemd only: omitting it (for example on macOS, or with TmuxDeck) is a fully supported configuration and is **not** a mixed or unsupported state. If it is installed on a supported Linux or systemd-enabled WSL host, update it together with the adapters it manages so scope inheritance and package identity stay aligned.

**Side-by-side installation is not supported.** Remove `connect.1` before installing `connect.2`:

1. Back up the exact specs, lock files, and settings of every installed component.
2. Stop or close the installed broker-capable adapters.
3. Remove the old `@dataforxyz/*` specs, packages, and binary links that are actually installed.
4. Assert the old identity is gone from the **active install surfaces of the current OS user**: Pi settings and extension specs, resolved managed install roots, actual `node_modules` installations, and conflicting binary links that the current `PATH` would resolve. Do not scan or delete unrelated source checkouts, historical documentation, or other users' files — a `@dataforxyz/*` string in an unrelated development clone is not an installation.
5. Install the `@ctliz/*` `connect.2` exact tags for the components you actually use.
6. Reload or restart, then verify exactly one Broker is running.

**Rollback** reverses this and covers only the components that were installed on this machine before the upgrade: remove the `@ctliz/*` packages, then restore the backed-up exact `@dataforxyz/*` specs and locks. Roll Orchestrator back only if it was installed to begin with.

**Classification rule.** Migration-aware `connect.2` setup and update tooling must classify an old-namespace-only install surface as `MIGRATION_REQUIRED`, and the simultaneous presence of both namespaces as a duplicate/dual-load hard error that refuses setup, update, and further installation. This tooling does not exist for every platform and adapter combination; where it is not available, the operator applies the same two rules manually against the surfaces listed in step 4. Do not assume every adapter emits this code automatically.

The `connect.1` tags, source commits, and published release assets are immutable and are not modified by this migration. Release notes may carry an explicit erratum, which corrects the description only and never moves a tag or replaces an asset.

## License

GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`). See `LICENSE` and `PROTOCOL-V4-DESIGN.md`.

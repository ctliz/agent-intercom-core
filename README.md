# Agent Intercom Core

The shared security policy kernel and protocol primitives for the [Agent Intercom](https://github.com/dataforxyz/agent-intercom-pi) adapter family.

This package is intentionally narrow. It contains pure, versioned authorization rules and policy state transitions used by every broker and remote gateway. Transport, worker lifecycle, queues, and harness integrations remain in their adapter repositories.

## Current policy semantics

Version 2 provides ownership-tree routing:

- Existing local sessions retain public local behavior.
- Communication is symmetric along one ancestor chain: root ↔ manager ↔ lead ↔ worker.
- Remote siblings, cousins, unrelated local sessions, and unrelated trees remain denied.
- Administrative subtree actions are directional: ancestors may inspect, revoke, or adopt descendants, while descendants cannot control ancestors.
- A principal may request attenuated child delegation only under itself.
- Revoked principals and stale generations are denied.

Gateways negotiate the exact semantic version and golden-vector hash rather than checking a boolean feature flag.

## Verify

```bash
npm install
npm run verify
```

The golden policy-vector corpus is hashed and asserted in tests. Any semantic change requires a deliberate version/hash update.

## Security boundary

The policy kernel limits broker visibility and routing. It does not isolate hostile processes sharing one Unix account or host. Remote deployments should still use SSH/TLS transport, private credential files, dedicated users or containers where needed, and a physically separate authenticated remote gateway endpoint rather than forwarding the raw local broker socket.

## License

`AGPL-3.0-or-later`.

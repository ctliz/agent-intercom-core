import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  MAX_TEAM_MANIFEST_BYTES,
  MAX_TEAM_MANIFEST_MEMBERS,
  parseTeamManifest,
  readTeamManifest,
  readTeamManifestAsync,
  TeamManifestError,
  TMUXDECK_TEAM_MANIFEST_BACKEND,
  TMUXDECK_TEAM_MANIFEST_VERSION,
} from "../src/team-manifest.ts";

const validRunId = "team_1a2b3c4d-5e6f-47a8-b9c0-d1e2f3a4b5c6";
const validLeadId = "tmuxdeck-c8f1e03a-9b4d-4c7e-81f6-a8b0c3d5e7f9";
const validWorkerId1 = "tmuxdeck-9a1b3c5d-7e9f-4a2b-84cc-8f1e03a9b4d2";
const validWorkerId2 = "tmuxdeck-3e5f7a9b-1c2d-4e6f-8a0b-2c4d6e8f0a1b";

function createValidManifestObject() {
  return {
    version: TMUXDECK_TEAM_MANIFEST_VERSION,
    backend: TMUXDECK_TEAM_MANIFEST_BACKEND,
    runId: validRunId,
    leadId: validLeadId,
    members: [
      { sessionId: validLeadId, role: "lead" },
      { sessionId: validWorkerId1, role: "worker" },
      { sessionId: validWorkerId2, role: "worker" },
    ],
    createdAt: 1723680000000,
    capabilities: [],
  };
}

test("parseTeamManifest accepts valid object and stringified JSON", () => {
  const valid = createValidManifestObject();
  const parsedFromObj = parseTeamManifest(valid);
  assert.equal(parsedFromObj.version, TMUXDECK_TEAM_MANIFEST_VERSION);
  assert.equal(parsedFromObj.backend, TMUXDECK_TEAM_MANIFEST_BACKEND);
  assert.equal(parsedFromObj.runId, validRunId);
  assert.equal(parsedFromObj.leadId, validLeadId);
  assert.equal(parsedFromObj.members.length, 3);
  assert.deepEqual(parsedFromObj.capabilities, []);

  const parsedFromStr = parseTeamManifest(JSON.stringify(valid));
  assert.deepEqual(parsedFromStr, parsedFromObj);
});

test("parseTeamManifest accepts single-lead team", () => {
  const singleLead = {
    ...createValidManifestObject(),
    members: [{ sessionId: validLeadId, role: "lead" }],
  };
  const parsed = parseTeamManifest(singleLead);
  assert.equal(parsed.members.length, 1);
  assert.equal(parsed.members[0]?.role, "lead");
});

test("parseTeamManifest fails closed on unknown top-level keys without echoing values", () => {
  const secretScope = "7a4b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f";
  const withScope = { ...createValidManifestObject(), scope: secretScope };
  try {
    parseTeamManifest(withScope);
    assert.fail("Should have thrown");
  } catch (error) {
    assert.ok(error instanceof TeamManifestError);
    assert.equal(error.code, "ERR_TEAM_MANIFEST_INVALID");
    assert.equal(error.message, "ERR_TEAM_MANIFEST_INVALID");
  }

  const secretCwd = "/Users/secret/confidential-project";
  const withCwd = { ...createValidManifestObject(), cwd: secretCwd };
  try {
    parseTeamManifest(withCwd);
    assert.fail("Should have thrown");
  } catch (error) {
    assert.ok(error instanceof TeamManifestError);
    assert.equal(error.code, "ERR_TEAM_MANIFEST_INVALID");
    assert.equal(error.message, "ERR_TEAM_MANIFEST_INVALID");
  }
});

test("parseTeamManifest fails closed on unknown member keys", () => {
  const invalid = createValidManifestObject();
  (invalid.members[1] as Record<string, unknown>).extra = "forbidden";
  assert.throws(
    () => parseTeamManifest(invalid),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("parseTeamManifest validates exact version and backend", () => {
  const badVersion = { ...createValidManifestObject(), version: "tmuxdeck.team.v2" };
  assert.throws(
    () => parseTeamManifest(badVersion),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );

  const badBackend = { ...createValidManifestObject(), backend: "orchestrator" };
  assert.throws(
    () => parseTeamManifest(badBackend),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("parseTeamManifest validates runId and leadId UUID-v4 format", () => {
  const badRunId = { ...createValidManifestObject(), runId: "invalid-run-id" };
  assert.throws(
    () => parseTeamManifest(badRunId),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );

  const badLeadId = { ...createValidManifestObject(), leadId: "td_alpha_lead" };
  assert.throws(
    () => parseTeamManifest(badLeadId),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("parseTeamManifest rejects duplicate member session IDs", () => {
  const duplicate = {
    ...createValidManifestObject(),
    members: [
      { sessionId: validLeadId, role: "lead" },
      { sessionId: validWorkerId1, role: "worker" },
      { sessionId: validWorkerId1, role: "worker" },
    ],
  };
  assert.throws(
    () => parseTeamManifest(duplicate),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("parseTeamManifest requires lead member to match leadId with role 'lead'", () => {
  const missingLead = {
    ...createValidManifestObject(),
    members: [
      { sessionId: validWorkerId1, role: "worker" },
      { sessionId: validWorkerId2, role: "worker" },
    ],
  };
  assert.throws(
    () => parseTeamManifest(missingLead),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );

  const leadAsWorker = {
    ...createValidManifestObject(),
    members: [
      { sessionId: validLeadId, role: "worker" },
      { sessionId: validWorkerId1, role: "worker" },
    ],
  };
  assert.throws(
    () => parseTeamManifest(leadAsWorker),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );

  const workerAsLead = {
    ...createValidManifestObject(),
    members: [
      { sessionId: validLeadId, role: "lead" },
      { sessionId: validWorkerId1, role: "lead" },
    ],
  };
  assert.throws(
    () => parseTeamManifest(workerAsLead),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("parseTeamManifest enforces empty capabilities array in MVP", () => {
  const withCapabilities = {
    ...createValidManifestObject(),
    capabilities: ["inbox_inspection_authorized"],
  };
  assert.throws(
    () => parseTeamManifest(withCapabilities),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("parseTeamManifest enforces member count limits 1..64", () => {
  const emptyMembers = {
    ...createValidManifestObject(),
    members: [],
  };
  assert.throws(
    () => parseTeamManifest(emptyMembers),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );

  const tooManyMembers = {
    ...createValidManifestObject(),
    members: [
      { sessionId: validLeadId, role: "lead" },
      ...Array.from({ length: MAX_TEAM_MANIFEST_MEMBERS }, (_, i) => ({
        sessionId: `tmuxdeck-${(i + 1).toString().padStart(8, "0")}-0000-4000-8000-000000000000`,
        role: "worker" as const,
      })),
    ],
  };
  assert.throws(
    () => parseTeamManifest(tooManyMembers),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("parseTeamManifest rejects hostile proxies without executing traps", () => {
  let trapExecuted = false;
  const trapHandler: ProxyHandler<object> = {
    get(target, prop, receiver) {
      trapExecuted = true;
      return Reflect.get(target, prop, receiver);
    },
    has(target, prop) {
      trapExecuted = true;
      return Reflect.has(target, prop);
    },
  };

  // 1. Proxied root object
  const proxiedRoot = new Proxy(createValidManifestObject(), trapHandler);
  trapExecuted = false;
  assert.throws(
    () => parseTeamManifest(proxiedRoot),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
  assert.equal(trapExecuted, false, "Proxy trap should not have executed on root");

  // 2. Proxied members array
  const manifestWithProxiedMembers = createValidManifestObject();
  manifestWithProxiedMembers.members = new Proxy(manifestWithProxiedMembers.members, trapHandler) as any;
  trapExecuted = false;
  assert.throws(
    () => parseTeamManifest(manifestWithProxiedMembers),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
  assert.equal(trapExecuted, false, "Proxy trap should not have executed on members array");

  // 3. Proxied member object
  const manifestWithProxiedMember = createValidManifestObject();
  manifestWithProxiedMember.members[0] = new Proxy(manifestWithProxiedMember.members[0]!, trapHandler) as any;
  trapExecuted = false;
  assert.throws(
    () => parseTeamManifest(manifestWithProxiedMember),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
  assert.equal(trapExecuted, false, "Proxy trap should not have executed on member object");

  // 4. Proxied capabilities array
  const manifestWithProxiedCaps = createValidManifestObject();
  manifestWithProxiedCaps.capabilities = new Proxy(manifestWithProxiedCaps.capabilities, trapHandler) as any;
  trapExecuted = false;
  assert.throws(
    () => parseTeamManifest(manifestWithProxiedCaps),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
  assert.equal(trapExecuted, false, "Proxy trap should not have executed on capabilities array");
});

test("parseTeamManifest rejects accessors/getters and non-data descriptors without invoking them", () => {
  let getterInvoked = false;

  // 1. Getter on root property
  const rootWithGetter = createValidManifestObject();
  Object.defineProperty(rootWithGetter, "leadId", {
    get() {
      getterInvoked = true;
      return validLeadId;
    },
    enumerable: true,
    configurable: true,
  });
  getterInvoked = false;
  assert.throws(
    () => parseTeamManifest(rootWithGetter),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
  assert.equal(getterInvoked, false, "Getter on root property must not be invoked");

  // 2. Getter on member object property
  const memberWithGetter = createValidManifestObject();
  const rawMember = { role: "worker" as const };
  Object.defineProperty(rawMember, "sessionId", {
    get() {
      getterInvoked = true;
      return validWorkerId1;
    },
    enumerable: true,
    configurable: true,
  });
  memberWithGetter.members[1] = rawMember as any;
  getterInvoked = false;
  assert.throws(
    () => parseTeamManifest(memberWithGetter),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
  assert.equal(getterInvoked, false, "Getter on member property must not be invoked");

  // 3. Getter on array element
  const arrayWithGetter = createValidManifestObject();
  const membersWithGetter = [{ sessionId: validLeadId, role: "lead" as const }];
  Object.defineProperty(membersWithGetter, "1", {
    get() {
      getterInvoked = true;
      return { sessionId: validWorkerId1, role: "worker" };
    },
    enumerable: true,
    configurable: true,
  });
  arrayWithGetter.members = membersWithGetter as any;
  getterInvoked = false;
  assert.throws(
    () => parseTeamManifest(arrayWithGetter),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
  assert.equal(getterInvoked, false, "Getter on array index must not be invoked");
});

test("parseTeamManifest rejects sparse arrays and arrays with symbol or extra metadata", () => {
  // 1. Sparse members array
  const sparseMembers = createValidManifestObject();
  const arr = [{ sessionId: validLeadId, role: "lead" as const }, undefined as any, { sessionId: validWorkerId1, role: "worker" as const }];
  delete arr[1]; // creates hole
  sparseMembers.members = arr;
  assert.throws(
    () => parseTeamManifest(sparseMembers),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );

  // 2. Extra property on members array
  const extraOnArray = createValidManifestObject();
  (extraOnArray.members as any).customMeta = "forbidden";
  assert.throws(
    () => parseTeamManifest(extraOnArray),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );

  // 3. Symbol property on capabilities array
  const sym = Symbol("evil");
  const symOnArray = createValidManifestObject();
  (symOnArray.capabilities as any)[sym] = true;
  assert.throws(
    () => parseTeamManifest(symOnArray),
    (err: unknown) =>
      err instanceof TeamManifestError &&
      err.code === "ERR_TEAM_MANIFEST_INVALID" &&
      err.message === "ERR_TEAM_MANIFEST_INVALID",
  );
});

test("readTeamManifest returns undefined when path is absent or empty", () => {
  assert.equal(readTeamManifest(undefined), undefined);
  assert.equal(readTeamManifest(null), undefined);
  assert.equal(readTeamManifest(""), undefined);
  assert.equal(readTeamManifest("   "), undefined);
});

test("readTeamManifest rejects relative paths without leaking raw path in message", () => {
  const relativePath = "some/relative/path/team.json";
  try {
    readTeamManifest(relativePath);
    assert.fail("Should have thrown");
  } catch (error) {
    assert.ok(error instanceof TeamManifestError);
    assert.equal(error.code, "ERR_TEAM_MANIFEST_INVALID");
    assert.equal(error.message, "ERR_TEAM_MANIFEST_INVALID");
  }
});

test("readTeamManifest handles valid files and permissions on POSIX without leaking paths", async () => {
  const tempBaseDir = mkdtempSync(join(tmpdir(), "team-manifest-test-"));
  const teamDir = join(tempBaseDir, "teams");
  mkdirSync(teamDir, { mode: 0o700 });
  if (process.platform !== "win32") {
    chmodSync(teamDir, 0o700);
  }

  try {
    const manifestPath = join(teamDir, "team-valid.json");
    writeFileSync(manifestPath, JSON.stringify(createValidManifestObject(), null, 2), { mode: 0o600 });
    if (process.platform !== "win32") {
      chmodSync(manifestPath, 0o600);
    }

    const manifest = readTeamManifest(manifestPath);
    assert.ok(manifest);
    assert.equal(manifest.runId, validRunId);
    assert.equal(manifest.leadId, validLeadId);

    const asyncManifest = await readTeamManifestAsync(manifestPath);
    assert.deepEqual(asyncManifest, manifest);

    // Missing file check (must NOT leak path)
    const nonExistentPath = join(teamDir, "non-existent.json");
    try {
      readTeamManifest(nonExistentPath);
      assert.fail("Should have thrown");
    } catch (error) {
      assert.ok(error instanceof TeamManifestError);
      assert.equal(error.code, "ERR_TEAM_MANIFEST_UNAVAILABLE");
      assert.equal(error.message, "ERR_TEAM_MANIFEST_UNAVAILABLE");
    }

    // Symlink file rejection
    const symlinkPath = join(teamDir, "symlink-team.json");
    symlinkSync(manifestPath, symlinkPath);
    try {
      readTeamManifest(symlinkPath);
      assert.fail("Should have thrown");
    } catch (error) {
      assert.ok(error instanceof TeamManifestError);
      assert.equal(error.code, "ERR_TEAM_MANIFEST_UNAVAILABLE");
      assert.equal(error.message, "ERR_TEAM_MANIFEST_UNAVAILABLE");
    }

    // Oversized file rejection
    const oversizedPath = join(teamDir, "oversized-team.json");
    const oversizedPayload = {
      ...createValidManifestObject(),
      padding: "X".repeat(MAX_TEAM_MANIFEST_BYTES + 10),
    };
    writeFileSync(oversizedPath, JSON.stringify(oversizedPayload), { mode: 0o600 });
    if (process.platform !== "win32") {
      chmodSync(oversizedPath, 0o600);
    }
    try {
      readTeamManifest(oversizedPath);
      assert.fail("Should have thrown");
    } catch (error) {
      assert.ok(error instanceof TeamManifestError);
      assert.equal(error.code, "ERR_TEAM_MANIFEST_UNAVAILABLE");
      assert.equal(error.message, "ERR_TEAM_MANIFEST_UNAVAILABLE");
    }

    // File mode must be EXACT 0600 on POSIX: reject 0400, 0644, 0666, 0700
    if (process.platform !== "win32") {
      for (const invalidMode of [0o400, 0o644, 0o666, 0o700, 0o000]) {
        const modePath = join(teamDir, `mode-${invalidMode.toString(8)}-team.json`);
        writeFileSync(modePath, JSON.stringify(createValidManifestObject()));
        chmodSync(modePath, invalidMode);
        try {
          readTeamManifest(modePath);
          assert.fail(`Should have rejected file mode ${invalidMode.toString(8)}`);
        } catch (error) {
          assert.ok(error instanceof TeamManifestError);
          assert.equal(error.code, "ERR_TEAM_MANIFEST_UNAVAILABLE");
          assert.equal(error.message, "ERR_TEAM_MANIFEST_UNAVAILABLE");
        }
      }
    }

    // Parent directory validation: must be exact 0700, non-symlink
    if (process.platform !== "win32") {
      // 1. Parent mode 0755 rejection
      const permissiveParentDir = join(tempBaseDir, "teams-permissive");
      mkdirSync(permissiveParentDir, { mode: 0o755 });
      chmodSync(permissiveParentDir, 0o755);
      const fileInPermissiveParent = join(permissiveParentDir, "team.json");
      writeFileSync(fileInPermissiveParent, JSON.stringify(createValidManifestObject()), { mode: 0o600 });
      chmodSync(fileInPermissiveParent, 0o600);
      try {
        readTeamManifest(fileInPermissiveParent);
        assert.fail("Should have rejected parent with mode 0755");
      } catch (error) {
        assert.ok(error instanceof TeamManifestError);
        assert.equal(error.code, "ERR_TEAM_MANIFEST_UNAVAILABLE");
        assert.equal(error.message, "ERR_TEAM_MANIFEST_UNAVAILABLE");
      }

      // 2. Symlinked parent directory rejection
      const symlinkParentDir = join(tempBaseDir, "teams-symlink");
      symlinkSync(teamDir, symlinkParentDir);
      const fileInSymlinkParent = join(symlinkParentDir, "team-valid.json");
      try {
        readTeamManifest(fileInSymlinkParent);
        assert.fail("Should have rejected symlinked parent directory");
      } catch (error) {
        assert.ok(error instanceof TeamManifestError);
        assert.equal(error.code, "ERR_TEAM_MANIFEST_UNAVAILABLE");
        assert.equal(error.message, "ERR_TEAM_MANIFEST_UNAVAILABLE");
      }
    }
  } finally {
    rmSync(tempBaseDir, { recursive: true, force: true });
  }
});

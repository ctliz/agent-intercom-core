import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  access,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const expectedExports = {
  ".": {
    types: "./dist/index.d.ts",
    import: "./dist/index.js",
  },
  "./policy": {
    types: "./dist/policy.d.ts",
    import: "./dist/policy.js",
  },
  "./vectors": {
    types: "./dist/policy-vectors.d.ts",
    import: "./dist/policy-vectors.js",
  },
  "./canonical": {
    types: "./dist/canonical.d.ts",
    import: "./dist/canonical.js",
  },
  "./protocol-v4": {
    types: "./dist/protocol-v4.d.ts",
    import: "./dist/protocol-v4.js",
  },
  "./boss": {
    types: "./dist/boss.d.ts",
    import: "./dist/boss.js",
  },
  "./boss/policy": {
    types: "./dist/boss-policy.d.ts",
    import: "./dist/boss-policy.js",
  },
  "./boss/vectors": {
    types: "./dist/boss-vectors.d.ts",
    import: "./dist/boss-vectors.js",
  },
};

function run(command, args, cwd, environment = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...environment },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(new Error(`${command} ${args.join(" ")} exited ${code}\n${stdout}${stderr}`));
    });
  });
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const temporaryRoot = await mkdtemp(join(tmpdir(), "agent-intercom-core-consumer-"));

try {
  const packDirectory = join(temporaryRoot, "pack");
  const npmCacheDirectory = join(temporaryRoot, "empty-npm-cache");
  const consumerDirectory = join(temporaryRoot, "consumer");
  const installedPackageDirectory = join(
    consumerDirectory,
    "node_modules/@dataforxyz/agent-intercom-core",
  );
  await mkdir(packDirectory);
  await mkdir(npmCacheDirectory);
  await mkdir(installedPackageDirectory, { recursive: true });
  assert.deepEqual(await readdir(npmCacheDirectory), []);

  await run(
    "npm",
    [
      "pack",
      "--ignore-scripts",
      "--offline",
      "--cache",
      npmCacheDirectory,
      "--pack-destination",
      packDirectory,
    ],
    packageRoot,
    {
      npm_config_audit: "false",
      npm_config_fund: "false",
      npm_config_offline: "true",
      npm_config_update_notifier: "false",
    },
  );
  const tarballs = (await readdir(packDirectory)).filter((file) => file.endsWith(".tgz"));
  assert.equal(tarballs.length, 1);
  const tarball = join(packDirectory, tarballs[0]);

  await run(
    "tar",
    [
      "--extract",
      "--gzip",
      "--file",
      tarball,
      "--directory",
      installedPackageDirectory,
      "--strip-components=1",
    ],
    packageRoot,
  );

  const installedPackage = await readJson(join(installedPackageDirectory, "package.json"));
  assert.deepEqual(installedPackage.exports, expectedExports);
  for (const declaration of Object.values(expectedExports)) {
    await access(join(installedPackageDirectory, declaration.types));
    await access(join(installedPackageDirectory, declaration.import));
  }

  const nodeTypesRange = installedPackage.dependencies?.["@types/node"];
  assert.equal(
    typeof nodeTypesRange,
    "string",
    "the packed package must declare @types/node as a dependency",
  );

  const lockfile = await readJson(join(packageRoot, "package-lock.json"));
  assert.equal(lockfile.packages[""].dependencies?.["@types/node"], nodeTypesRange);
  const localNodeTypesDirectory = join(packageRoot, "node_modules/@types/node");
  const localNodeTypesPackage = await readJson(join(localNodeTypesDirectory, "package.json"));
  assert.equal(
    localNodeTypesPackage.version,
    lockfile.packages["node_modules/@types/node"].version,
  );
  const undiciTypesRange = localNodeTypesPackage.dependencies?.["undici-types"];
  assert.equal(typeof undiciTypesRange, "string");
  const localUndiciTypesDirectory = join(packageRoot, "node_modules/undici-types");
  const localUndiciTypesPackage = await readJson(
    join(localUndiciTypesDirectory, "package.json"),
  );
  assert.equal(
    localUndiciTypesPackage.version,
    lockfile.packages["node_modules/undici-types"].version,
  );

  await mkdir(join(consumerDirectory, "node_modules/@types"), { recursive: true });
  await cp(
    localNodeTypesDirectory,
    join(consumerDirectory, "node_modules/@types/node"),
    { recursive: true },
  );
  await cp(
    localUndiciTypesDirectory,
    join(consumerDirectory, "node_modules/undici-types"),
    { recursive: true },
  );

  await writeFile(
    join(consumerDirectory, "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
  );
  await writeFile(
    join(consumerDirectory, "consumer.mjs"),
    `import assert from "node:assert/strict";
import * as root from "@dataforxyz/agent-intercom-core";
import * as policy from "@dataforxyz/agent-intercom-core/policy";
import * as vectors from "@dataforxyz/agent-intercom-core/vectors";
import * as canonical from "@dataforxyz/agent-intercom-core/canonical";
import * as protocolV4 from "@dataforxyz/agent-intercom-core/protocol-v4";
import * as boss from "@dataforxyz/agent-intercom-core/boss";
import * as bossPolicy from "@dataforxyz/agent-intercom-core/boss/policy";
import * as bossVectors from "@dataforxyz/agent-intercom-core/boss/vectors";

assert.equal(root.POLICY_SEMANTICS_HASH, "f3b00e503631bc91123aedfbcf1df72cc9913e1893c09728b2c598f3dcdfdfe0");
assert.deepEqual(
  Object.keys(root).sort(),
  [...new Set([...Object.keys(policy), ...Object.keys(vectors)])].sort(),
);
assert.equal(Object.hasOwn(root, "canonicalHash"), false);
assert.equal(Object.hasOwn(root, "BOSS_RUN_FEATURE"), false);
assert.equal(policy.POLICY_SEMANTICS_VERSION, 2);
assert.equal(typeof policy.authorize, "function");
assert.equal(vectors.POLICY_SEMANTICS_HASH, root.POLICY_SEMANTICS_HASH);
assert.equal(boss.BOSS_RUN_FEATURE, "boss-run-v1");
assert.equal(boss.BOSS_POLICY_SEMANTICS_HASH, bossVectors.BOSS_POLICY_SEMANTICS_HASH);
assert.equal(bossPolicy.BOSS_POLICY_SEMANTICS_VERSION, 1);
assert.equal(typeof canonical.canonicalHash, "function");
assert.equal(protocolV4.INTERCOM_PROTOCOL_VERSION, 4);
assert.match(protocolV4.INTERCOM_PROTOCOL_V4_SEMANTICS_HASH, /^[a-f0-9]{64}$/);
`,
  );
  await run(process.execPath, ["consumer.mjs"], consumerDirectory);

  await writeFile(
    join(consumerDirectory, "consumer.ts"),
    `import * as root from "@dataforxyz/agent-intercom-core";
import * as policy from "@dataforxyz/agent-intercom-core/policy";
import * as vectors from "@dataforxyz/agent-intercom-core/vectors";
import * as canonical from "@dataforxyz/agent-intercom-core/canonical";
import * as protocolV4 from "@dataforxyz/agent-intercom-core/protocol-v4";
import * as boss from "@dataforxyz/agent-intercom-core/boss";
import * as bossPolicy from "@dataforxyz/agent-intercom-core/boss/policy";
import * as bossVectors from "@dataforxyz/agent-intercom-core/boss/vectors";

type BrokerPublicKey = import("@dataforxyz/agent-intercom-core/boss").BrokerPublicKey;
const surfaces = [root, policy, vectors, canonical, protocolV4, boss, bossPolicy, bossVectors];
const brokerPublicKey = null as unknown as BrokerPublicKey;
// @ts-expect-error Boss contracts are intentionally absent from the legacy root.
root.BOSS_RUN_FEATURE;
// @ts-expect-error Canonical contracts are intentionally absent from the legacy root.
root.canonicalHash;
void surfaces;
void brokerPublicKey;
`,
  );
  await writeFile(
    join(consumerDirectory, "tsconfig.json"),
    `${JSON.stringify(
      {
        compilerOptions: {
          target: "ES2023",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          strict: true,
          noEmit: true,
          skipLibCheck: false,
          typeRoots: ["./node_modules/@types"],
        },
        files: ["consumer.ts"],
      },
      null,
      2,
    )}\n`,
  );
  await run(
    process.execPath,
    [join(packageRoot, "node_modules/typescript/bin/tsc"), "--project", "tsconfig.json"],
    consumerDirectory,
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

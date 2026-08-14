import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

function readDoc(relPath: string): string {
  return readFileSync(join(repoRoot, relPath), "utf8");
}

function collectDocs(): string[] {
  const docs = ["README.md", "PROTOCOL-V4-DESIGN.md"];
  const docsDir = join(repoRoot, "docs");
  for (const entry of readdirSync(docsDir)) {
    if (entry.endsWith(".md") && statSync(join(docsDir, entry)).isFile()) {
      docs.push(join("docs", entry));
    }
  }
  return docs;
}

function linesOf(relPath: string): { line: string; number: number }[] {
  return readDoc(relPath)
    .split("\n")
    .map((line, index) => ({ line, number: index + 1 }));
}

// The coordinated upgrade set is only the broker-capable adapters that are
// actually installed. Core is an internal dependency and Orchestrator is an
// optional Linux/systemd component that never starts a Broker, so absolute
// "every adapter (... orchestrator)" phrasing is a documentation contract bug.
//
// These patterns are deliberately scoped to *obligation* wording. A bare
// "every adapter" in a capability description ("every adapter reads the same
// vectors") is legitimate; the bug is asserting that every adapter must be
// installed, upgraded, or released together.
const ADAPTER_SET_PHRASES = [
  /every adapter/i,
  /all adapters/i,
  /each adapter/i,
  /every package/i,
  /every broker package/i,
  /all (?:five|six) (?:packages|repos|repositories|components)/i,
  /entire adapter family/i,
];

const OBLIGATION_CONTEXT =
  /\bmust\b|\brequired\b|\bupgrade|\bupdated?\b|\btogether\b|same maintenance|maintenance window|coordinated set|before (?:any|all)|is published|prerequisite/i;

// A disclaimer that explicitly denies a universal obligation is the correct
// wording, not a violation: "Do not assume every adapter emits this code".
const NEGATION_BEFORE_PHRASE =
  /(?:do not assume|does not|do not|never|not\s+every|no\s+adapter|rather than|instead of)[^.]{0,60}$/i;

test("docs do not impose absolute adapter-set obligations", () => {
  const offenders: string[] = [];
  for (const doc of collectDocs()) {
    for (const { line, number } of linesOf(doc)) {
      if (!OBLIGATION_CONTEXT.test(line)) continue;
      for (const pattern of ADAPTER_SET_PHRASES) {
        const match = pattern.exec(line);
        if (!match) continue;
        const before = line.slice(0, match.index);
        if (NEGATION_BEFORE_PHRASE.test(before)) continue;
        offenders.push(`${doc}:${number}: ${line.trim()}`);
        break;
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `Absolute adapter-set obligation found. The coordinated set is only the installed broker-capable adapters (Pi/Claude/Codex/OpenCode); Core is an internal dependency and Orchestrator is optional and Linux/systemd only:\n${offenders.join("\n")}`,
  );
});

test("Orchestrator is not stated as a prerequisite for adapter releases", () => {
  const offenders: string[] = [];
  for (const doc of collectDocs()) {
    for (const { line, number } of linesOf(doc)) {
      // "before any Pi, Claude, Codex, OpenCode, or Orchestrator candidate is
      // published" wrongly binds the optional component to the adapter gate.
      if (/before any\b/i.test(line) && /orchestrator/i.test(line)) {
        offenders.push(`${doc}:${number}: ${line.trim()}`);
      }
      // "No single package is published before all coordinated candidates pass"
      // sweeps Core and Orchestrator into the broker release set.
      if (/no single package/i.test(line)) {
        offenders.push(`${doc}:${number}: ${line.trim()}`);
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `Orchestrator must not be a release prerequisite for the broker-capable adapters:\n${offenders.join("\n")}`,
  );
});

test("acceptance gate scopes itself to broker-capable adapters", () => {
  const gate = readDoc(join("docs", "standalone-v4-acceptance.md"));
  assert.match(gate, /required coordinated release gate for the broker-capable adapters/i);
  assert.match(gate, /not\*{0,2} a prerequisite for adapter releases/i);
  // Excluding it from the adapter gate must not weaken its own gate.
  assert.match(gate, /systemd user manager/i);
  assert.match(gate, /own Linux\/systemd production gate|not relaxed/i);
});

test("immutability claim covers tags/commits/assets and allows an erratum", () => {
  const readme = readDoc("README.md");
  assert.match(readme, /tags, source commits, and published release assets are immutable/i);
  assert.match(readme, /erratum/i);
  assert.match(readme, /never moves a tag or replaces an asset/i);
});

test("old-identity assertion is scoped to active install surfaces", () => {
  const readme = readDoc("README.md");
  assert.match(readme, /active install surfaces of the current OS user/i);
  assert.match(readme, /Do not scan or delete unrelated source checkouts/i);
  assert.doesNotMatch(
    readme,
    /gone machine-wide/i,
    "machine-wide assertion is too broad: unrelated checkouts are not installations",
  );
});

test("migration classification is normative, not an implemented-everywhere claim", () => {
  const readme = readDoc("README.md");
  assert.match(readme, /tooling must classify/i);
  assert.match(readme, /does not exist for every platform and adapter combination/i);
  assert.match(readme, /operator applies the same two rules manually/i);
  assert.doesNotMatch(
    readme,
    /is reported as `?MIGRATION_REQUIRED`?\./i,
    "stating it 'is reported' implies universal automatic detection",
  );
});

test("design status reflects connect.1 shipped and connect.2 in migration", () => {
  const design = readDoc("PROTOCOL-V4-DESIGN.md");
  assert.match(design, /shipped in the `connect\.1` release/i);
  assert.match(design, /`connect\.2` package-namespace migration candidate/i);
  assert.doesNotMatch(
    design,
    /^Status: coordinated candidate, not released or installed\.$/im,
    "protocol v4 already shipped in connect.1",
  );
});

test("component table shows canonical scoped package names", () => {
  const readme = readDoc("README.md");
  for (const pkg of ["pi", "claude", "codex", "opencode", "core", "orchestrator"]) {
    assert.match(
      readme,
      new RegExp(`\`@ctliz/agent-intercom-${pkg}\``),
      `component table must list the canonical scoped name for ${pkg}`,
    );
  }
});

test("README states the broker-capable set and the non-broker roles", () => {
  const readme = readDoc("README.md");
  assert.match(readme, /broker-capable/i);
  assert.match(
    readme,
    /Core is (?:pulled in as )?an? (?:internal )?dependency|internal dependency/i,
  );
  assert.match(readme, /Orchestrator is an optional lifecycle component/i);
  assert.match(readme, /does not implement or start a Broker/i);
});

test("Orchestrator is documented as optional and Linux/systemd only", () => {
  const readme = readDoc("README.md");
  assert.match(readme, /Linux\/systemd only/i);
  assert.match(readme, /macOS/);
  assert.match(readme, /not\*{0,2} a mixed or unsupported state/i);
});

// connect.2 renames the canonical namespace. Runtime code and docs must point
// at @ctliz/*; @dataforxyz/* may survive only as provenance or as an explicitly
// labelled migration-detection input, never as a current install instruction.
test("canonical package namespace is @ctliz outside provenance/migration text", () => {
  const legacy = new RegExp(`@${"dataforxyz"}/`);
  const provenanceLine =
    /Upstream Heritage|Package Namespace|historical|provenance|namespace migration candidate/i;
  const offenders: string[] = [];

  for (const doc of collectDocs()) {
    // Legacy names are legitimate inside an explicit migration section, which
    // must tell operators exactly what to remove. Everywhere else they are a bug.
    let inMigrationSection = false;
    for (const { line, number } of linesOf(doc)) {
      if (/^##\s/.test(line)) {
        inMigrationSection = /upgrad|migrat/i.test(line);
      }
      if (!legacy.test(line)) continue;
      if (inMigrationSection || provenanceLine.test(line)) continue;
      offenders.push(`${doc}:${number}: ${line.trim()}`);
    }
  }
  assert.deepEqual(offenders, [], `Legacy namespace used outside provenance/migration context:\n${offenders.join("\n")}`);
});

test("package identity is @ctliz and points at the ctliz repository", () => {
  const pkg = JSON.parse(readDoc("package.json")) as {
    name: string;
    repository: { url: string };
    homepage: string;
    bugs: { url: string };
  };
  assert.equal(pkg.name, "@ctliz/agent-intercom-core");
  assert.match(pkg.repository.url, /github\.com\/ctliz\/agent-intercom-core/);
  assert.match(pkg.homepage, /github\.com\/ctliz\/agent-intercom-core/);
  assert.match(pkg.bugs.url, /github\.com\/ctliz\/agent-intercom-core/);
});

test("no source or test file imports the legacy namespace", () => {
  const offenders: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      if (!/\.(ts|mjs|js|cjs)$/.test(entry)) continue;
      // This file names the legacy namespace on purpose to detect it.
      if (full === fileURLToPath(import.meta.url)) continue;
      const text = readFileSync(full, "utf8");
      if (text.includes(`@${"dataforxyz"}/`)) {
        offenders.push(relative(repoRoot, full));
      }
    }
  };
  walk(join(repoRoot, "src"));
  walk(join(repoRoot, "test"));
  assert.deepEqual(offenders, [], `Legacy namespace still imported in:\n${offenders.join("\n")}`);
});

test("migration documents uninstall-before-install and forbids side-by-side", () => {
  const readme = readDoc("README.md");
  assert.match(readme, /Side-by-side installation is not supported/i);
  assert.match(readme, /MIGRATION_REQUIRED/);
  assert.match(readme, /duplicate\/dual-load hard error/i);
  assert.match(readme, /`?connect\.1`? tags, source commits, and published release assets are immutable/i);
  // Rollback must be scoped to what was actually installed.
  assert.match(readme, /only the components that were installed/i);
});

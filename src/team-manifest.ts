import { lstatSync, readFileSync } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";
import { isProxy } from "node:util/types";

export const TMUXDECK_TEAM_MANIFEST_VERSION = "tmuxdeck.team.v1" as const;
export const TMUXDECK_TEAM_MANIFEST_BACKEND = "tmuxdeck" as const;
export const MAX_TEAM_MANIFEST_BYTES = 64 * 1024; // 64 KiB
export const MAX_TEAM_MANIFEST_MEMBERS = 64;

export type TmuxDeckTeamRole = "lead" | "worker";

export interface TmuxDeckTeamMember {
  sessionId: string;
  role: TmuxDeckTeamRole;
}

export interface TmuxDeckTeamManifest {
  version: typeof TMUXDECK_TEAM_MANIFEST_VERSION;
  backend: typeof TMUXDECK_TEAM_MANIFEST_BACKEND;
  runId: string;
  leadId: string;
  members: TmuxDeckTeamMember[];
  createdAt: number;
  capabilities: readonly [];
}

export type TeamManifestErrorCode =
  | "ERR_TEAM_MANIFEST_UNAVAILABLE"
  | "ERR_TEAM_MANIFEST_INVALID";

export class TeamManifestError extends Error {
  readonly code: TeamManifestErrorCode;

  constructor(code: TeamManifestErrorCode) {
    super(code);
    this.name = "TeamManifestError";
    this.code = code;
  }
}

const RUN_ID_PATTERN = /^team_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_ID_PATTERN = /^tmuxdeck-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TOP_LEVEL_KNOWN_KEYS = new Set([
  "version",
  "backend",
  "runId",
  "leadId",
  "members",
  "createdAt",
  "capabilities",
]);

const MEMBER_KNOWN_KEYS = new Set(["sessionId", "role"]);

function assertUnproxied(value: unknown): void {
  if (typeof value === "object" && value !== null && isProxy(value)) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }
}

function assertPlainObject(value: unknown): Record<string, unknown> {
  assertUnproxied(value);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }
  return value as Record<string, unknown>;
}

function checkObjectDescriptors(record: Record<string, unknown>, allowedKeys: Set<string>): void {
  assertUnproxied(record);
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
  }
}

function readOwnDenseArray(value: unknown): unknown[] {
  assertUnproxied(value);
  if (!Array.isArray(value)) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor === undefined || !Object.hasOwn(lengthDescriptor, "value")) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }
  const length = lengthDescriptor.value as number;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  let count = 0;
  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") continue;
    if (typeof key !== "string") {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
    const index = Number(key);
    if (!Number.isInteger(index) || index < 0 || index >= length || String(index) !== key) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
    count += 1;
  }

  if (count !== length) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  return value;
}

/**
 * Validates and parses an unverified JSON or plain object into a TmuxDeckTeamManifest.
 * Fails closed on any unknown keys, forbidden keys (scope/cwd/credentials), invalid formats,
 * proxies, accessors, sparse arrays, or structural inconsistencies without echoing file paths or raw values.
 */
export function parseTeamManifest(value: unknown): TmuxDeckTeamManifest {
  assertUnproxied(value);
  let target = value;
  if (typeof target === "string") {
    try {
      target = JSON.parse(target);
    } catch {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
  }

  const obj = assertPlainObject(target);
  checkObjectDescriptors(obj, TOP_LEVEL_KNOWN_KEYS);

  if (obj.version !== TMUXDECK_TEAM_MANIFEST_VERSION) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  if (obj.backend !== TMUXDECK_TEAM_MANIFEST_BACKEND) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  if (typeof obj.runId !== "string" || !RUN_ID_PATTERN.test(obj.runId)) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }
  const runId = obj.runId;

  if (typeof obj.leadId !== "string" || !SESSION_ID_PATTERN.test(obj.leadId)) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }
  const leadId = obj.leadId;

  const membersArray = readOwnDenseArray(obj.members);

  if (membersArray.length < 1 || membersArray.length > MAX_TEAM_MANIFEST_MEMBERS) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  const seenSessionIds = new Set<string>();
  let foundLead = false;
  const parsedMembers: TmuxDeckTeamMember[] = [];

  for (let index = 0; index < membersArray.length; index += 1) {
    const rawMember = membersArray[index];
    assertUnproxied(rawMember);
    const memberObj = assertPlainObject(rawMember);
    checkObjectDescriptors(memberObj, MEMBER_KNOWN_KEYS);

    if (typeof memberObj.sessionId !== "string" || !SESSION_ID_PATTERN.test(memberObj.sessionId)) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
    const sessionId = memberObj.sessionId;

    if (seenSessionIds.has(sessionId)) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
    seenSessionIds.add(sessionId);

    if (memberObj.role !== "lead" && memberObj.role !== "worker") {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
    }
    const role = memberObj.role as TmuxDeckTeamRole;

    if (sessionId === leadId) {
      if (role !== "lead") {
        throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
      }
      foundLead = true;
    } else {
      if (role !== "worker") {
        throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
      }
    }

    parsedMembers.push({ sessionId, role });
  }

  if (!foundLead) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  if (typeof obj.createdAt !== "number" || !Number.isSafeInteger(obj.createdAt) || obj.createdAt <= 0) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }
  const createdAt = obj.createdAt;

  const capabilitiesArray = readOwnDenseArray(obj.capabilities);
  if (capabilitiesArray.length !== 0) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  return {
    version: TMUXDECK_TEAM_MANIFEST_VERSION,
    backend: TMUXDECK_TEAM_MANIFEST_BACKEND,
    runId,
    leadId,
    members: parsedMembers,
    createdAt,
    capabilities: [],
  };
}

function validateManifestParentDir(stat: { isDirectory: () => boolean; isSymbolicLink: () => boolean; mode: number; uid: number }): void {
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }

  if (process.platform !== "win32") {
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
    }

    const permissionBits = stat.mode & 0o777;
    if (permissionBits !== 0o700) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
    }
  }
}

function validateManifestFileStat(stat: { isFile: () => boolean; isSymbolicLink: () => boolean; size: number; mode: number; uid: number }): void {
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }

  if (stat.size > MAX_TEAM_MANIFEST_BYTES) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }

  // POSIX permissions and ownership validation: exact 0600
  if (process.platform !== "win32") {
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
    }

    const permissionBits = stat.mode & 0o777;
    if (permissionBits !== 0o600) {
      throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
    }
  }
}

/**
 * Reads and parses a TmuxDeck team manifest file synchronously.
 * - If `filePath` is absent (undefined, null, or empty), returns `undefined`.
 * - If `filePath` is provided, enforces absolute path, regular non-symlink parent directory with exact 0700 permissions,
 *   regular non-symlink file with exact 0600 permissions, <=64KiB size, POSIX user ownership, and valid schema.
 * - If unreadable, missing, or invalid, throws fail-closed TeamManifestError without leaking raw paths or values.
 */
export function readTeamManifest(filePath?: string | null): TmuxDeckTeamManifest | undefined {
  if (filePath === undefined || filePath === null || typeof filePath !== "string" || !filePath.trim()) {
    return undefined;
  }

  const trimmedPath = filePath.trim();
  if (!isAbsolute(trimmedPath)) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  const parentDir = dirname(trimmedPath);
  let parentStat;
  try {
    parentStat = lstatSync(parentDir);
  } catch {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }
  validateManifestParentDir(parentStat);

  let stat;
  try {
    stat = lstatSync(trimmedPath);
  } catch {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }

  validateManifestFileStat(stat);

  let content: string;
  try {
    content = readFileSync(trimmedPath, "utf8");
  } catch {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }

  return parseTeamManifest(content);
}

/**
 * Asynchronously reads and parses a TmuxDeck team manifest file.
 */
export async function readTeamManifestAsync(filePath?: string | null): Promise<TmuxDeckTeamManifest | undefined> {
  if (filePath === undefined || filePath === null || typeof filePath !== "string" || !filePath.trim()) {
    return undefined;
  }

  const trimmedPath = filePath.trim();
  if (!isAbsolute(trimmedPath)) {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_INVALID");
  }

  const parentDir = dirname(trimmedPath);
  let parentStat;
  try {
    parentStat = await lstat(parentDir);
  } catch {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }
  validateManifestParentDir(parentStat);

  let stat;
  try {
    stat = await lstat(trimmedPath);
  } catch {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }

  validateManifestFileStat(stat);

  let content: string;
  try {
    content = await readFile(trimmedPath, "utf8");
  } catch {
    throw new TeamManifestError("ERR_TEAM_MANIFEST_UNAVAILABLE");
  }

  return parseTeamManifest(content);
}

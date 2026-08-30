import { createHash } from 'node:crypto';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import os from 'node:os';
import {
  appendFile,
  cp,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  statfs,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import {
  DEFAULT_MINECRAFT_PROPERTIES,
  GAME_SERVER_LIMITS,
  MINECRAFT_MANIFEST_URL,
  MINECRAFT_VERSIONS,
  crashRecoveryDecision,
  redactGameLogLine,
  validateGameServerJobPayload,
  type GameServerCapabilities,
  type GameServerJobType,
  type GameServerSnapshot,
  type GameServerStatus,
  type MinecraftProperties,
} from '../lib/game-servers.ts';
import type { AgentJobResult } from './runtime.ts';

const MiB = 1024 ** 2;
const MAX_METADATA_BYTES = 4 * MiB;
const MAX_SERVER_JAR_BYTES = 256 * MiB;
const WORLD_DIRECTORIES = ['world', 'world_nether', 'world_the_end'] as const;
const OFFICIAL_METADATA_HOSTS = new Set([
  'launchermeta.mojang.com',
  'piston-meta.mojang.com',
]);
const OFFICIAL_DATA_HOSTS = new Set([
  'launcher.mojang.com',
  'piston-data.mojang.com',
]);

type LocalManifest = {
  schema: 1;
  serverId: string;
  workspaceId: string;
  name: string;
  game: 'minecraft-java';
  serverType: 'vanilla';
  version: string;
  ramMb: number;
  cpuCores: number;
  diskQuotaBytes: number;
  port: number;
  properties: MinecraftProperties;
  officialSha1: string;
  binarySha256: string;
  binarySizeBytes: number;
  requiredJavaMajor: number;
  createdAt: number;
};

type ManagedServer = {
  key: string;
  manifest: LocalManifest;
  directory: string;
  child: ChildProcessWithoutNullStreams;
  startedAt: number;
  desiredRunning: boolean;
  stopping: boolean;
  crashTimes: number[];
  players: Set<string>;
  logs: string[];
};

type MojangVersionManifest = {
  versions?: { id?: unknown; type?: unknown; url?: unknown; sha1?: unknown }[];
};

type MojangVersionMetadata = {
  javaVersion?: { majorVersion?: unknown };
  downloads?: {
    server?: { url?: unknown; sha1?: unknown; size?: unknown };
  };
};

const managed = new Map<string, ManagedServer>();
let cachedJava: { expiresAt: number; value: GameServerCapabilities } | null = null;

function key(workspaceId: string, serverId: string): string {
  return `${workspaceId}:${serverId}`;
}

function safeWorkspaceId(value: string): boolean {
  return /^[A-Za-z0-9_][A-Za-z0-9_-]{2,63}$/.test(value);
}

function contained(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function serverDirectory(root: string, workspaceId: string, serverId: string): string {
  if (!safeWorkspaceId(workspaceId) || !/^gsv_[a-f0-9]{24}$/.test(serverId)) {
    throw new Error('The local server identity is invalid.');
  }
  const directory = path.resolve(root, workspaceId, 'servers', serverId);
  if (!contained(root, directory)) throw new Error('The server path escaped its sandbox.');
  return directory;
}

async function assertNoSymlinkPath(root: string, candidate: string): Promise<void> {
  if (!contained(root, candidate)) throw new Error('The local path escaped its sandbox.');
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  let current = path.resolve(root);
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      if ((await lstat(current)).isSymbolicLink()) {
        throw new Error('Symbolic links are forbidden in the Game Server sandbox.');
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') break;
      throw error;
    }
  }
}

function backupDirectory(directory: string, backupId: string): string {
  if (!/^gbk_[a-f0-9]{24}$/.test(backupId)) {
    throw new Error('The local backup identity is invalid.');
  }
  const candidate = path.resolve(directory, 'backups', backupId);
  if (!contained(directory, candidate)) throw new Error('The backup path escaped its sandbox.');
  return candidate;
}

function officialUrl(value: unknown, hosts: Set<string>): URL | null {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && hosts.has(url.hostname) && !url.port && !url.username && !url.password
      ? url
      : null;
  } catch {
    return null;
  }
}

async function boundedBytes(response: Response, maximum: number): Promise<Uint8Array> {
  if (!response.ok || !response.body) throw new Error(`Official metadata returned ${response.status}.`);
  const length = Number(response.headers.get('content-length'));
  if (Number.isFinite(length) && length > maximum) throw new Error('Official metadata exceeded its size bound.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const part = await reader.read();
    if (part.done) break;
    total += part.value.byteLength;
    if (total > maximum) {
      await reader.cancel('size-bound');
      throw new Error('Official metadata exceeded its size bound.');
    }
    chunks.push(part.value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function boundedJson<T>(response: Response, maximum = MAX_METADATA_BYTES): Promise<{ bytes: Uint8Array; value: T }> {
  const bytes = await boundedBytes(response, maximum);
  return { bytes, value: JSON.parse(new TextDecoder().decode(bytes)) as T };
}

function hexDigest(algorithm: 'sha1' | 'sha256', bytes: Uint8Array): string {
  return createHash(algorithm).update(bytes).digest('hex');
}

async function downloadOfficialServer(input: {
  version: string;
  destination: string;
  fetcher: typeof fetch;
  signal?: AbortSignal;
}): Promise<{
  officialSha1: string;
  binarySha256: string;
  sizeBytes: number;
  requiredJavaMajor: number;
}> {
  if (!MINECRAFT_VERSIONS.some((version) => version.id === input.version)) {
    throw new Error('The Minecraft version is not in the reviewed catalog.');
  }
  const manifestResponse = await input.fetcher(MINECRAFT_MANIFEST_URL, {
    signal: input.signal,
    redirect: 'error',
  });
  const manifest = (await boundedJson<MojangVersionManifest>(manifestResponse)).value;
  const release = manifest.versions?.find(
    (entry) => entry.id === input.version && entry.type === 'release',
  );
  const metadataUrl = officialUrl(release?.url, OFFICIAL_METADATA_HOSTS);
  const metadataSha1 = typeof release?.sha1 === 'string' && /^[a-f0-9]{40}$/.test(release.sha1)
    ? release.sha1
    : null;
  if (!metadataUrl || !metadataSha1) throw new Error('Mojang release metadata was invalid.');

  const metadataResponse = await input.fetcher(metadataUrl, {
    signal: input.signal,
    redirect: 'error',
  });
  const metadata = await boundedJson<MojangVersionMetadata>(metadataResponse);
  if (hexDigest('sha1', metadata.bytes) !== metadataSha1) {
    throw new Error('Mojang release metadata failed its SHA-1 check.');
  }
  const server = metadata.value.downloads?.server;
  const requiredJavaMajor = metadata.value.javaVersion?.majorVersion;
  const dataUrl = officialUrl(server?.url, OFFICIAL_DATA_HOSTS);
  const expectedSha1 = typeof server?.sha1 === 'string' && /^[a-f0-9]{40}$/.test(server.sha1)
    ? server.sha1
    : null;
  const expectedSize = typeof server?.size === 'number' && Number.isSafeInteger(server.size)
    ? server.size
    : null;
  if (
    !dataUrl ||
    !expectedSha1 ||
    !expectedSize ||
    expectedSize <= 0 ||
    expectedSize > MAX_SERVER_JAR_BYTES ||
    !Number.isSafeInteger(requiredJavaMajor) ||
    (requiredJavaMajor as number) < 17 ||
    (requiredJavaMajor as number) > 100
  ) {
    throw new Error('Mojang server download metadata was invalid.');
  }

  const response = await input.fetcher(dataUrl, { signal: input.signal, redirect: 'error' });
  if (!response.ok || !response.body) throw new Error(`Mojang server download returned ${response.status}.`);
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength !== expectedSize) {
    throw new Error('Mojang server download size did not match metadata.');
  }
  const file = await open(input.destination, 'wx');
  const sha1 = createHash('sha1');
  const sha256 = createHash('sha256');
  let size = 0;
  try {
    const reader = response.body.getReader();
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > expectedSize || size > MAX_SERVER_JAR_BYTES) {
        await reader.cancel('size-bound');
        throw new Error('Mojang server download exceeded its verified size.');
      }
      sha1.update(part.value);
      sha256.update(part.value);
      await file.write(part.value);
    }
  } finally {
    await file.close();
  }
  const actualSha1 = sha1.digest('hex');
  if (size !== expectedSize || actualSha1 !== expectedSha1) {
    await rm(input.destination, { force: true });
    throw new Error('Mojang server binary failed its size or SHA-1 integrity check.');
  }
  return {
    officialSha1: actualSha1,
    binarySha256: sha256.digest('hex'),
    sizeBytes: size,
    requiredJavaMajor: requiredJavaMajor as number,
  };
}

function propertiesText(port: number, properties: MinecraftProperties): string {
  const lines: Record<string, string | number | boolean> = {
    'server-ip': '127.0.0.1',
    'server-port': port,
    'max-players': properties.maxPlayers,
    difficulty: properties.difficulty,
    gamemode: properties.gamemode,
    'online-mode': properties.onlineMode,
    'white-list': properties.whitelist,
    'enforce-whitelist': properties.enforceWhitelist,
    motd: properties.motd,
    'view-distance': properties.viewDistance,
    'simulation-distance': properties.simulationDistance,
    pvp: properties.pvp,
    hardcore: properties.hardcore,
    'allow-flight': properties.allowFlight,
    'spawn-protection': properties.spawnProtection,
    'enable-rcon': false,
    'enable-query': false,
    'broadcast-rcon-to-ops': false,
  };
  return `${Object.entries(lines).map(([name, value]) => `${name}=${String(value)}`).join('\n')}\n`;
}

async function readManifest(directory: string): Promise<LocalManifest> {
  const directoryInfo = await lstat(directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new Error('The local server directory is not a safe directory.');
  }
  for (const name of [
    'ysd-server.json',
    'server.jar',
    'server.properties',
    'eula.txt',
    'backups',
  ]) {
    await assertNoSymlinkPath(directory, path.join(directory, name));
  }
  const value = JSON.parse(
    await readFile(path.join(directory, 'ysd-server.json'), 'utf8'),
  ) as LocalManifest;
  const properties = validateGameServerJobPayload('game-server.config', {
    operation: 'update',
    serverId: value.serverId,
    port: value.port,
    properties: value.properties,
  });
  if (
    value.schema !== 1 ||
    !/^gsv_[a-f0-9]{24}$/.test(value.serverId) ||
    !safeWorkspaceId(value.workspaceId) ||
    typeof value.name !== 'string' ||
    value.name.length < 1 ||
    value.name.length > 64 ||
    value.game !== 'minecraft-java' ||
    value.serverType !== 'vanilla' ||
    !MINECRAFT_VERSIONS.some((version) => version.id === value.version) ||
    !Number.isSafeInteger(value.ramMb) ||
    value.ramMb < GAME_SERVER_LIMITS.minimumRamMb ||
    value.ramMb > GAME_SERVER_LIMITS.maximumRamMb ||
    !Number.isSafeInteger(value.cpuCores) ||
    value.cpuCores < GAME_SERVER_LIMITS.minimumCpuCores ||
    value.cpuCores > GAME_SERVER_LIMITS.maximumCpuCores ||
    !Number.isSafeInteger(value.diskQuotaBytes) ||
    value.diskQuotaBytes < GAME_SERVER_LIMITS.minimumDiskBytes ||
    value.diskQuotaBytes > GAME_SERVER_LIMITS.maximumDiskBytes ||
    !properties.ok ||
    !/^[a-f0-9]{40}$/.test(value.officialSha1) ||
    !/^[a-f0-9]{64}$/.test(value.binarySha256) ||
    !Number.isSafeInteger(value.binarySizeBytes) ||
    value.binarySizeBytes < 1 ||
    value.binarySizeBytes > MAX_SERVER_JAR_BYTES ||
    !Number.isSafeInteger(value.requiredJavaMajor) ||
    value.requiredJavaMajor < 17 ||
    value.requiredJavaMajor > 100
  ) {
    throw new Error('The local server manifest is invalid.');
  }
  return value;
}

async function hashFile(filePath: string): Promise<{ sha1: string; sha256: string; size: number }> {
  const file = await open(filePath, 'r');
  const sha1 = createHash('sha1');
  const sha256 = createHash('sha256');
  let size = 0;
  try {
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const part = await file.read(buffer, 0, buffer.length, null);
      if (part.bytesRead === 0) break;
      const bytes = buffer.subarray(0, part.bytesRead);
      size += part.bytesRead;
      sha1.update(bytes);
      sha256.update(bytes);
    }
  } finally {
    await file.close();
  }
  return { sha1: sha1.digest('hex'), sha256: sha256.digest('hex'), size };
}

async function verifyBinary(directory: string, manifest: LocalManifest): Promise<void> {
  const digest = await hashFile(path.join(directory, 'server.jar'));
  if (
    digest.sha1 !== manifest.officialSha1 ||
    digest.sha256 !== manifest.binarySha256 ||
    digest.size !== manifest.binarySizeBytes
  ) {
    throw new Error('The local Minecraft binary failed its recorded integrity check.');
  }
}

export function fixedJavaInvocation(manifest: Pick<LocalManifest, 'ramMb' | 'cpuCores'>): {
  executable: 'java';
  args: string[];
  shell: false;
} {
  const initial = Math.min(1024, manifest.ramMb);
  return {
    executable: 'java',
    args: [
      `-Xms${initial}M`,
      `-Xmx${manifest.ramMb}M`,
      `-XX:ActiveProcessorCount=${manifest.cpuCores}`,
      '-Dlog4j2.formatMsgNoLookups=true',
      '-jar',
      'server.jar',
      'nogui',
    ],
    shell: false,
  };
}

function appendManagedLog(entry: ManagedServer, raw: string): void {
  for (const candidate of raw.split(/\r?\n/)) {
    const line = redactGameLogLine(candidate);
    if (!line) continue;
    entry.logs.push(line);
    if (entry.logs.length > GAME_SERVER_LIMITS.maximumLogLines) entry.logs.shift();
    const list = line.match(/There are \d+ of a max of \d+ players online:\s*(.*)$/i);
    if (list) {
      entry.players = new Set(
        list[1]!.split(',').map((player) => player.trim()).filter((player) => /^[A-Za-z0-9_]{1,16}$/.test(player)),
      );
    }
    const joined = line.match(/:\s*([A-Za-z0-9_]{1,16}) joined the game$/);
    if (joined) entry.players.add(joined[1]!);
    const left = line.match(/:\s*([A-Za-z0-9_]{1,16}) left the game$/);
    if (left) entry.players.delete(left[1]!);
    void appendBoundedLocalLog(entry.directory, line).catch(() => undefined);
  }
}

async function appendBoundedLocalLog(directory: string, line: string): Promise<void> {
  const file = path.join(directory, 'ysd-agent.log');
  await appendFile(file, `${line}\n`, { encoding: 'utf8' });
  const info = await stat(file);
  if (info.size <= MiB) return;
  const bytes = await readFile(file);
  const retained = bytes.subarray(Math.max(0, bytes.byteLength - 512 * 1024));
  const temporary = path.join(directory, '.ysd-agent.log.rotating');
  await writeFile(temporary, retained, { flag: 'w' });
  await rename(temporary, file);
}

function javaEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    NODE_ENV: process.env.NODE_ENV ?? 'production',
  };
  const executablePath = process.env.PATH ?? process.env.Path;
  if (executablePath) environment.PATH = executablePath;
  if (process.env.JAVA_HOME) environment.JAVA_HOME = process.env.JAVA_HOME;
  if (process.env.LANG) environment.LANG = process.env.LANG;
  return environment;
}

export function javaMajorVersion(value: string | null): number | null {
  if (!value) return null;
  const match = value.match(/(?:java|openjdk)\s+version\s+"(?:1\.)?(\d+)/i);
  const major = match ? Number(match[1]) : Number.NaN;
  return Number.isSafeInteger(major) && major >= 1 && major <= 100
    ? major
    : null;
}

async function startManaged(input: {
  root: string;
  directory: string;
  manifest: LocalManifest;
  capabilities: GameServerCapabilities;
}): Promise<ManagedServer> {
  const serverKey = key(input.manifest.workspaceId, input.manifest.serverId);
  const existing = managed.get(serverKey);
  if (existing && existing.child.exitCode === null) return existing;
  if (!input.capabilities.minecraftJavaAvailable) throw new Error('A supported local Java runtime is not available.');
  const localJavaMajor = javaMajorVersion(input.capabilities.javaVersion);
  if (!localJavaMajor || localJavaMajor < input.manifest.requiredJavaMajor) {
    throw new Error(
      `Minecraft ${input.manifest.version} requires Java ${input.manifest.requiredJavaMajor} or newer.`,
    );
  }
  const activeServers = [...managed.values()].filter(
    (candidate) => candidate.child.exitCode === null,
  );
  if (activeServers.length >= input.capabilities.maxConcurrentServers) {
    throw new Error('The local Game Server concurrency limit is reached.');
  }
  if (
    input.manifest.ramMb * MiB + GAME_SERVER_LIMITS.memoryReserveBytes >
    os.freemem()
  ) {
    throw new Error('The node does not have enough guarded free RAM.');
  }
  if (
    activeServers.some(
      (candidate) => candidate.manifest.port === input.manifest.port,
    )
  ) {
    throw new Error('Another managed server is already using this local port.');
  }
  await verifyBinary(input.directory, input.manifest);
  const stats = await statfs(input.directory);
  const freeBytes = Math.max(0, stats.bavail * stats.bsize);
  if (freeBytes < GAME_SERVER_LIMITS.diskReserveBytes) throw new Error('The node disk reserve would be crossed.');
  const invocation = fixedJavaInvocation(input.manifest);
  const child = spawn(invocation.executable, invocation.args, {
    cwd: input.directory,
    shell: invocation.shell,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: javaEnvironment(),
  });
  const entry: ManagedServer = {
    key: serverKey,
    manifest: input.manifest,
    directory: input.directory,
    child,
    startedAt: Date.now(),
    desiredRunning: true,
    stopping: false,
    crashTimes: existing?.crashTimes ?? [],
    players: new Set(),
    logs: existing?.logs ?? [],
  };
  managed.set(serverKey, entry);
  child.stdout.on('data', (value: Uint8Array) =>
    appendManagedLog(entry, new TextDecoder().decode(value)),
  );
  child.stderr.on('data', (value: Uint8Array) =>
    appendManagedLog(entry, new TextDecoder().decode(value)),
  );
  child.once('exit', () => {
    const unexpected = entry.desiredRunning && !entry.stopping;
    if (!unexpected) return;
    const now = Date.now();
    entry.crashTimes = [...entry.crashTimes.filter((time) => now - time < 10 * 60_000), now];
    appendManagedLog(entry, `YSD detected unexpected Minecraft exit ${entry.crashTimes.length}/3.`);
    const recovery = crashRecoveryDecision(entry.crashTimes.length);
    if (!recovery.restart || recovery.delayMs === null) {
      entry.desiredRunning = false;
      appendManagedLog(entry, 'YSD crash-loop protection stopped automatic restarts.');
      return;
    }
    void delay(recovery.delayMs).then(async () => {
      if (!entry.desiredRunning) return;
      try {
        await startManaged(input);
      } catch (error) {
        appendManagedLog(entry, `YSD automatic restart failed: ${error instanceof Error ? error.message : 'unknown error'}`);
      }
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      child.once('spawn', resolve);
      child.once('error', reject);
    });
  } catch (error) {
    if (managed.get(serverKey) === entry) managed.delete(serverKey);
    throw error;
  }
  return entry;
}

async function stopManaged(entry: ManagedServer): Promise<void> {
  entry.desiredRunning = false;
  entry.stopping = true;
  if (entry.child.exitCode !== null) return;
  entry.child.stdin.write('stop\n');
  const exited = new Promise<void>((resolve) => entry.child.once('exit', () => resolve()));
  const timedOut = delay(30_000).then(() => 'timeout' as const);
  if ((await Promise.race([exited.then(() => 'exit' as const), timedOut])) === 'timeout') {
    entry.child.kill('SIGTERM');
    await Promise.race([exited, delay(5_000)]);
    if (entry.child.exitCode === null) entry.child.kill('SIGKILL');
  }
}

/** Fail closed when the control plane revokes or rejects this node credential. */
export async function shutdownManagedGameServers(): Promise<void> {
  const active = [...managed.values()].filter(
    (entry) => entry.child.exitCode === null,
  );
  await Promise.all(active.map((entry) => stopManaged(entry)));
}

async function directorySize(directory: string): Promise<number> {
  const rootInfo = await lstat(directory);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new Error('Symbolic links are forbidden in server data.');
  }
  let total = 0;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    const info = await lstat(candidate);
    if (info.isSymbolicLink()) throw new Error('Symbolic links are forbidden in server data.');
    total += entry.isDirectory() ? await directorySize(candidate) : info.size;
  }
  return total;
}

type BackupEntry = { path: string; size: number; sha256: string };

async function collectBackupEntries(root: string, directory = root): Promise<BackupEntry[]> {
  const directoryInfo = await lstat(directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new Error('Backup symbolic links are forbidden.');
  }
  const entries: BackupEntry[] = [];
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, item.name);
    const relative = path.relative(root, full).split(path.sep).join('/');
    if (!contained(root, full) || relative.startsWith('../')) throw new Error('Backup traversal was blocked.');
    const info = await lstat(full);
    if (info.isSymbolicLink()) throw new Error('Backup symbolic links are forbidden.');
    if (item.isDirectory()) entries.push(...(await collectBackupEntries(root, full)));
    else {
      const digest = await hashFile(full);
      entries.push({ path: relative, size: digest.size, sha256: digest.sha256 });
    }
  }
  return entries.sort((left, right) => left.path.localeCompare(right.path));
}

async function createBackup(directory: string, manifest: LocalManifest, backupId: string, name: string): Promise<Record<string, unknown>> {
  const backupsRoot = path.join(directory, 'backups');
  await mkdir(backupsRoot, { recursive: true });
  await assertNoSymlinkPath(directory, backupsRoot);
  const existing = (await readdir(backupsRoot, { withFileTypes: true })).filter((entry) => entry.isDirectory());
  if (existing.length >= GAME_SERVER_LIMITS.maximumBackupsPerServer) throw new Error('The local backup count quota is reached.');
  const used = await directorySize(backupsRoot);
  const worldsSize = (await Promise.all(WORLD_DIRECTORIES.map(async (world) => {
    try { return await directorySize(path.join(directory, world)); } catch { return 0; }
  }))).reduce((sum, value) => sum + value, 0);
  if (used + worldsSize > manifest.diskQuotaBytes) throw new Error('The local backup byte quota would be exceeded.');
  const destination = backupDirectory(directory, backupId);
  const staging = `${destination}.creating`;
  await rm(staging, { recursive: true, force: true });
  await mkdir(path.join(staging, 'worlds'), { recursive: true });
  try {
    for (const world of WORLD_DIRECTORIES) {
      const source = path.join(directory, world);
      try {
        if ((await stat(source)).isDirectory()) await cp(source, path.join(staging, 'worlds', world), { recursive: true, errorOnExist: true });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    const entries = await collectBackupEntries(path.join(staging, 'worlds'));
    const checksum = createHash('sha256').update(JSON.stringify(entries)).digest('hex');
    const backupManifest = { schema: 1, backupId, serverId: manifest.serverId, name, entries, checksum, createdAt: Date.now() };
    await writeFile(path.join(staging, 'backup.json'), JSON.stringify(backupManifest), { encoding: 'utf8', flag: 'wx' });
    await rename(staging, destination);
    return {
      backupId,
      name,
      sizeBytes: entries.reduce((sum, entry) => sum + entry.size, 0),
      fileCount: entries.length,
      checksum: `sha256:${checksum}`,
      verified: true,
    };
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

async function verifyBackup(directory: string, backupId: string): Promise<{ root: string; manifest: { entries: BackupEntry[]; checksum: string } }> {
  const root = backupDirectory(directory, backupId);
  await assertNoSymlinkPath(directory, root);
  await assertNoSymlinkPath(root, path.join(root, 'backup.json'));
  const value = JSON.parse(await readFile(path.join(root, 'backup.json'), 'utf8')) as { schema?: unknown; backupId?: unknown; entries?: unknown; checksum?: unknown };
  if (value.schema !== 1 || value.backupId !== backupId || !Array.isArray(value.entries) || typeof value.checksum !== 'string') {
    throw new Error('The backup manifest is invalid.');
  }
  const entries = value.entries as BackupEntry[];
  if (entries.length > 100_000 || entries.some((entry) => !entry || typeof entry.path !== 'string' || path.isAbsolute(entry.path) || entry.path.includes('..') || !/^[a-f0-9]{64}$/.test(entry.sha256))) {
    throw new Error('Backup path traversal or manifest abuse was refused.');
  }
  const checksum = createHash('sha256').update(JSON.stringify(entries)).digest('hex');
  if (checksum !== value.checksum) throw new Error('The backup manifest checksum is corrupted.');
  for (const entry of entries) {
    const file = path.resolve(root, 'worlds', entry.path);
    if (!contained(path.join(root, 'worlds'), file)) throw new Error('Backup restore traversal was refused.');
    await assertNoSymlinkPath(root, file);
    const digest = await hashFile(file);
    if (digest.size !== entry.size || digest.sha256 !== entry.sha256) throw new Error('A backup file failed its integrity check.');
  }
  return { root, manifest: { entries, checksum } };
}

async function restoreBackup(directory: string, backupId: string): Promise<Record<string, unknown>> {
  const verified = await verifyBackup(directory, backupId);
  const stage = path.join(directory, '.restore-stage');
  const rollback = path.join(directory, '.restore-rollback');
  await rm(stage, { recursive: true, force: true });
  await rm(rollback, { recursive: true, force: true });
  await mkdir(stage, { recursive: true });
  for (const world of WORLD_DIRECTORIES) {
    const source = path.join(verified.root, 'worlds', world);
    try {
      if ((await stat(source)).isDirectory()) await cp(source, path.join(stage, world), { recursive: true, errorOnExist: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  await mkdir(rollback, { recursive: true });
  try {
    for (const world of WORLD_DIRECTORIES) {
      const current = path.join(directory, world);
      try { await rename(current, path.join(rollback, world)); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      const replacement = path.join(stage, world);
      try { await rename(replacement, current); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    await rm(rollback, { recursive: true, force: true });
    await rm(stage, { recursive: true, force: true });
    return { backupId, restored: true, checksum: `sha256:${verified.manifest.checksum}` };
  } catch (error) {
    for (const world of WORLD_DIRECTORIES) {
      const previous = path.join(rollback, world);
      try {
        await rm(path.join(directory, world), { recursive: true, force: true });
        await rename(previous, path.join(directory, world));
      } catch {
        // Keep the rollback directory for manual recovery if atomic recovery fails.
      }
    }
    throw error;
  }
}

async function tailLocalLogs(directory: string, maximum: number): Promise<string[]> {
  try {
    const content = await readFile(path.join(directory, 'ysd-agent.log'), 'utf8');
    return content.split(/\r?\n/).slice(-maximum).map(redactGameLogLine).filter((line): line is string => Boolean(line));
  } catch {
    return [];
  }
}

async function exposure(directory: string): Promise<'private' | 'unexpected'> {
  try {
    const properties = await readFile(path.join(directory, 'server.properties'), 'utf8');
    return /^server-ip=127\.0\.0\.1$/m.test(properties) && /^enable-rcon=false$/m.test(properties)
      ? 'private'
      : 'unexpected';
  } catch {
    return 'unexpected';
  }
}

function statusResult(entry: ManagedServer | undefined, manifest: LocalManifest, directory: string): Promise<Record<string, unknown>> {
  const running = Boolean(entry && entry.child.exitCode === null);
  const crashLoop = Boolean(entry && entry.crashTimes.length >= 3);
  return Promise.all([exposure(directory), tailLocalLogs(directory, 20)]).then(([network, logs]) => ({
    serverId: manifest.serverId,
    status: crashLoop ? 'crash_loop' : running ? 'running' : 'stopped',
    players: entry ? [...entry.players].sort() : [],
    playerCount: entry?.players.size ?? 0,
    uptimeSeconds: running && entry ? Math.max(0, Math.floor((Date.now() - entry.startedAt) / 1000)) : 0,
    cpuLoadPercent: null,
    memoryUsedBytes: null,
    exposure: network,
    binaryHash: `sha256:${manifest.binarySha256}`,
    binaryVerified: true,
    crashCount: entry?.crashTimes.length ?? 0,
    crashLoop,
    worlds: [...WORLD_DIRECTORIES],
    logs,
  }));
}

export async function discoverGameServerCapabilities(): Promise<GameServerCapabilities> {
  if (cachedJava && cachedJava.expiresAt > Date.now()) {
    return { ...cachedJava.value, activeServers: [...managed.values()].filter((entry) => entry.child.exitCode === null).length };
  }
  const maximum = Math.max(1, Math.min(
    GAME_SERVER_LIMITS.maximumServersPerNode,
    Number.parseInt(process.env.YSD_GAME_MAX_SERVERS ?? '4', 10) || 4,
  ));
  let javaVersion: string | null = null;
  try {
    const child = spawn('java', ['-version'], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: javaEnvironment(),
    });
    let output = '';
    child.stdout.on('data', (value: Uint8Array) => {
      output += new TextDecoder().decode(value).slice(0, 500);
    });
    child.stderr.on('data', (value: Uint8Array) => {
      output += new TextDecoder().decode(value).slice(0, 500);
    });
    await Promise.race([
      new Promise<void>((resolve, reject) => {
        child.once('exit', (code) => code === 0 ? resolve() : reject(new Error('java unavailable')));
        child.once('error', reject);
      }),
      delay(2_000).then(() => { child.kill(); throw new Error('java timeout'); }),
    ]);
    javaVersion = output.replace(/[\r\n]+/g, ' ').trim().slice(0, 80) || 'Java runtime';
  } catch {
    javaVersion = null;
  }
  const value: GameServerCapabilities = {
    minecraftJavaAvailable: Boolean(javaVersion),
    javaVersion,
    activeServers: [...managed.values()].filter((entry) => entry.child.exitCode === null).length,
    maxConcurrentServers: maximum,
  };
  cachedJava = { expiresAt: Date.now() + 5 * 60_000, value };
  return value;
}

export async function collectGameServerSnapshots(root: string, workspaceId: string): Promise<GameServerSnapshot[]> {
  if (!safeWorkspaceId(workspaceId)) return [];
  const serversRoot = path.resolve(root, workspaceId, 'servers');
  let ids: string[];
  try {
    ids = (await readdir(serversRoot, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory() && /^gsv_[a-f0-9]{24}$/.test(entry.name))
      .map((entry) => entry.name)
      .slice(0, GAME_SERVER_LIMITS.maximumServersPerWorkspace);
  } catch {
    return [];
  }
  const snapshots: GameServerSnapshot[] = [];
  for (const serverId of ids) {
    try {
      const directory = serverDirectory(root, workspaceId, serverId);
      await assertNoSymlinkPath(root, directory);
      const manifest = await readManifest(directory);
      if (manifest.workspaceId !== workspaceId || manifest.serverId !== serverId) {
        throw new Error('The local server tenant binding is invalid.');
      }
      const result = await statusResult(managed.get(key(workspaceId, serverId)), manifest, directory);
      snapshots.push({
        serverId,
        status: result.status as GameServerStatus,
        players: result.players as string[],
        playerCount: result.playerCount as number,
        cpuLoadPercent: null,
        memoryUsedBytes: null,
        uptimeSeconds: result.uptimeSeconds as number,
        exposure: result.exposure as 'private' | 'unexpected',
        binaryHash: result.binaryHash as string,
        binaryVerified: true,
        crashCount: result.crashCount as number,
        crashLoop: result.crashLoop as boolean,
        logTail: (result.logs as string[])
          .slice(-1)
          .map((line) => line.slice(0, 250)),
        observedAt: Date.now(),
      });
    } catch {
      // A malformed local directory is never reported as a valid server.
    }
  }
  return snapshots;
}

export async function executeGameServerJob(input: {
  type: GameServerJobType;
  payload: Record<string, unknown>;
  workspaceId: string;
  rootDirectory: string;
  capabilities: GameServerCapabilities;
  signal?: AbortSignal;
  fetcher?: typeof fetch;
}): Promise<AgentJobResult> {
  const validated = validateGameServerJobPayload(input.type, input.payload);
  if (!validated.ok) return { status: 'failed', error: validated.error, retryable: false };
  const payload = validated.payload;
  const serverId = payload.serverId as string;
  const directory = serverDirectory(input.rootDirectory, input.workspaceId, serverId);
  const serverKey = key(input.workspaceId, serverId);
  try {
    await assertNoSymlinkPath(input.rootDirectory, directory);
    if (input.signal?.aborted) return { status: 'cancelled', error: 'Game Server action was cancelled.', retryable: false };
    if (input.type === 'game-server.lifecycle' && payload.operation === 'create') {
      if (!input.capabilities.minecraftJavaAvailable) throw new Error('A supported local Java runtime is required.');
      if ((payload.ramMb as number) * MiB + GAME_SERVER_LIMITS.memoryReserveBytes > Number.MAX_SAFE_INTEGER) throw new Error('The memory request is invalid.');
      const parent = path.dirname(directory);
      const staging = path.join(parent, `.creating-${serverId}`);
      await mkdir(parent, { recursive: true });
      try {
        const existing = await readManifest(directory);
        if (existing.version === payload.version) {
          return { status: 'succeeded', result: await statusResult(managed.get(serverKey), existing, directory) };
        }
        throw new Error('A different local server already uses this identity.');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT' && !(error instanceof SyntaxError)) {
          if (error instanceof Error && /different local server/.test(error.message)) throw error;
        }
      }
      await rm(staging, { recursive: true, force: true });
      await mkdir(staging, { recursive: false });
      try {
        const disk = await statfs(staging);
        const free = Math.max(0, disk.bavail * disk.bsize);
        if (free < (payload.diskQuotaBytes as number) + GAME_SERVER_LIMITS.diskReserveBytes) {
          throw new Error('The node does not have enough guarded disk capacity.');
        }
        const downloaded = await downloadOfficialServer({
          version: payload.version as string,
          destination: path.join(staging, 'server.jar'),
          fetcher: input.fetcher ?? fetch,
          signal: input.signal,
        });
        const localJavaMajor = javaMajorVersion(input.capabilities.javaVersion);
        if (!localJavaMajor || localJavaMajor < downloaded.requiredJavaMajor) {
          throw new Error(
            `Minecraft ${String(payload.version)} requires Java ${downloaded.requiredJavaMajor} or newer.`,
          );
        }
        const manifest: LocalManifest = {
          schema: 1,
          serverId,
          workspaceId: input.workspaceId,
          name: payload.name as string,
          game: 'minecraft-java',
          serverType: 'vanilla',
          version: payload.version as string,
          ramMb: payload.ramMb as number,
          cpuCores: payload.cpuCores as number,
          diskQuotaBytes: payload.diskQuotaBytes as number,
          port: payload.port as number,
          properties: payload.properties as MinecraftProperties,
          officialSha1: downloaded.officialSha1,
          binarySha256: downloaded.binarySha256,
          binarySizeBytes: downloaded.sizeBytes,
          requiredJavaMajor: downloaded.requiredJavaMajor,
          createdAt: Date.now(),
        };
        await writeFile(path.join(staging, 'eula.txt'), 'eula=true\n', { encoding: 'utf8', flag: 'wx' });
        await writeFile(path.join(staging, 'server.properties'), propertiesText(manifest.port, manifest.properties), { encoding: 'utf8', flag: 'wx' });
        await writeFile(path.join(staging, 'ysd-server.json'), JSON.stringify(manifest), { encoding: 'utf8', flag: 'wx' });
        await mkdir(path.join(staging, 'backups'), { recursive: false });
        await rename(staging, directory);
        return {
          status: 'succeeded',
          result: {
            serverId,
            status: 'stopped',
            binaryHash: `sha256:${manifest.binarySha256}`,
            sourceHashSha1: manifest.officialSha1,
            binaryVerified: true,
            exposure: 'private',
            players: [],
            playerCount: 0,
            uptimeSeconds: 0,
            worlds: [...WORLD_DIRECTORIES],
            logs: [],
          },
        };
      } catch (error) {
        await rm(staging, { recursive: true, force: true });
        throw error;
      }
    }

    const manifest = await readManifest(directory);
    if (manifest.workspaceId !== input.workspaceId || manifest.serverId !== serverId) throw new Error('The local server tenant binding is invalid.');
    const entry = managed.get(serverKey);

    if (input.type === 'game-server.lifecycle') {
      if (payload.operation === 'start') {
        const running = await startManaged({ root: input.rootDirectory, directory, manifest, capabilities: input.capabilities });
        return { status: 'succeeded', result: await statusResult(running, manifest, directory) };
      }
      if (payload.operation === 'stop') {
        if (entry) await stopManaged(entry);
        return { status: 'succeeded', result: await statusResult(entry, manifest, directory) };
      }
      if (payload.operation === 'restart') {
        if (entry) await stopManaged(entry);
        const restarted = await startManaged({ root: input.rootDirectory, directory, manifest, capabilities: input.capabilities });
        return { status: 'succeeded', result: await statusResult(restarted, manifest, directory) };
      }
      if (payload.operation === 'status') {
        return { status: 'succeeded', result: await statusResult(entry, manifest, directory) };
      }
      if (payload.operation === 'delete') {
        if (entry) await stopManaged(entry);
        await rm(directory, { recursive: true, force: false });
        managed.delete(serverKey);
        return { status: 'succeeded', result: { serverId, status: 'deleted', deleted: true, logs: [] } };
      }
    }

    if (input.type === 'game-server.config') {
      if (entry?.child.exitCode === null) throw new Error('Stop the server before changing server.properties.');
      manifest.port = payload.port as number;
      manifest.properties = payload.properties as MinecraftProperties;
      await writeFile(path.join(directory, 'server.properties'), propertiesText(manifest.port, manifest.properties), 'utf8');
      await writeFile(path.join(directory, 'ysd-server.json'), JSON.stringify(manifest), 'utf8');
      return { status: 'succeeded', result: { serverId, status: 'stopped', properties: manifest.properties, exposure: 'private', logs: [] } };
    }

    if (input.type === 'game-server.player') {
      if (!entry || entry.child.exitCode !== null) throw new Error('The server must be running for player actions.');
      const operation = payload.operation as string;
      if (operation === 'list') entry.child.stdin.write('list\n');
      else {
        const player = payload.player as string;
        const commands: Record<string, string> = {
          kick: `kick ${player} Removed by a YSD workspace operator`,
          'whitelist-add': `whitelist add ${player}`,
          'whitelist-remove': `whitelist remove ${player}`,
          op: `op ${player}`,
          deop: `deop ${player}`,
        };
        entry.child.stdin.write(`${commands[operation]}\n`);
      }
      await delay(250, undefined, { signal: input.signal });
      return { status: 'succeeded', result: await statusResult(entry, manifest, directory) };
    }

    if (input.type === 'game-server.backup') {
      const operation = payload.operation;
      if (operation === 'create') {
        if (entry?.child.exitCode === null) {
          entry.child.stdin.write('save-off\n');
          entry.child.stdin.write('save-all flush\n');
          await delay(1_000, undefined, { signal: input.signal });
        }
        try {
          const result = await createBackup(directory, manifest, payload.backupId as string, payload.name as string);
          return { status: 'succeeded', result: { serverId, ...result, logs: [] } };
        } finally {
          if (entry?.child.exitCode === null) entry.child.stdin.write('save-on\n');
        }
      }
      if (operation === 'restore') {
        if (entry?.child.exitCode === null) throw new Error('Stop the server before restoring a backup.');
        return { status: 'succeeded', result: { serverId, ...(await restoreBackup(directory, payload.backupId as string)), status: 'stopped', logs: [] } };
      }
      if (operation === 'delete') {
        await verifyBackup(directory, payload.backupId as string);
        await rm(backupDirectory(directory, payload.backupId as string), { recursive: true, force: false });
        return { status: 'succeeded', result: { serverId, backupId: payload.backupId, deleted: true, logs: [] } };
      }
      const backupsRoot = path.join(directory, 'backups');
      await assertNoSymlinkPath(directory, backupsRoot);
      const backups = await readdir(backupsRoot, { withFileTypes: true });
      return { status: 'succeeded', result: { serverId, backups: backups.filter((item) => item.isDirectory() && /^gbk_[a-f0-9]{24}$/.test(item.name)).map((item) => item.name), logs: [] } };
    }

    if (input.type === 'game-server.logs') {
      return { status: 'succeeded', result: { serverId, logs: await tailLocalLogs(directory, payload.lines as number) } };
    }
    throw new Error('The Game Server operation is not implemented.');
  } catch (error) {
    if (input.signal?.aborted) return { status: 'cancelled', error: 'Game Server action was cancelled.', retryable: false };
    const message = redactGameLogLine(error instanceof Error ? error.message : 'Local Game Server action failed.') ?? 'Local Game Server action failed.';
    const retryable = /timeout|temporar|connection|returned 5\d\d/i.test(message);
    return { status: 'failed', error: message, retryable };
  }
}

export { DEFAULT_MINECRAFT_PROPERTIES };

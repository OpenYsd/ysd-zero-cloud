import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  access,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  statfs,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { gunzipSync } from 'node:zlib';

import {
  APP_RUNTIME_LIMITS,
  PRIVATE_PORT_CANDIDATE_LIMIT,
  privatePortInRange,
  privatePortSearchOrder,
  appCrashRecoveryDecision,
  analyzeNodeRepository,
  parseAppRuntimeSnapshots,
  redactAppRuntimeCredentials,
  validateAppRuntimeJobPayload,
  type AppPackageManager,
  type AppRuntimeCapabilities,
  type AppRuntimeJobPayload,
  type AppRuntimeSnapshot,
  type SafeBuildContract,
} from '../lib/app-runtime.ts';
import {
  availabilityFromVerificationFailure,
  selectRetainedArtifacts,
  shouldSpawnCrashReplacement,
  type RecoveryPhase,
  type RecoveryReasonCode,
  type RuntimeHealthState,
} from '../lib/runtime-recovery.ts';
import {
  constantTimeEqual,
  openNodeEnvironment,
  signText,
  stableJson,
  verifyTextSignature,
} from '../lib/nodes.ts';
import type { AgentJobResult } from './runtime.ts';
import { signedPost } from './signed-request.ts';

type ManagedApp = {
  deploymentId: string;
  projectId: string;
  artifactId: string;
  artifactDirectory: string;
  dataDirectory: string;
  entrypoint: string;
  port: number;
  healthPath: string;
  memoryMb: number;
  environment: Record<string, string>;
  secrets: string[];
  process: ChildProcess;
  startedAt: number;
  restartTimes: number[];
  restartCount: number;
  crashLoop: boolean;
  desiredRunning: boolean;
  intentionalStop: boolean;
  desiredRevision: number;
  healthState: RuntimeHealthState;
  bind: AppRuntimeSnapshot['bind'];
  logLines: string[];
  logBytes: number;
};

type ArtifactManifest = {
  version: 1;
  deploymentId: string;
  projectId: string;
  artifactId: string;
  commit: string;
  checksum: string;
  sizeBytes: number;
  contract: SafeBuildContract;
  createdAt: number;
  verifiedAt: number;
  signature: string;
};

const managedApps = new Map<string, ManagedApp>();
const MANIFEST = '.ysd-artifact.json';
const SAFE_REGISTRY = 'https://registry.npmjs.org';

/**
 * Node leaves exitCode as null when a child exits because of a signal (the
 * normal stop path on Windows) and records the termination in signalCode.
 * Treating exitCode alone as liveness makes an intentionally stopped runtime
 * reappear as healthy on the next heartbeat.
 */
export function isAppProcessRunning(
  child: Pick<ChildProcess, 'exitCode' | 'signalCode'> & { pid?: number },
): boolean {
  if (child.exitCode !== null || (child.signalCode !== null && child.signalCode !== undefined)) return false;
  if (typeof child.pid === 'number') {
    try {
      process.kill(child.pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    }
  }
  return true;
}

function safeRoot(rootDirectory: string): string {
  return path.resolve(rootDirectory);
}

function deploymentDirectory(root: string, workspaceId: string, payload: AppRuntimeJobPayload): string {
  return path.join(safeRoot(root), 'workspaces', workspaceId, 'projects', payload.projectId, 'deployments', payload.deploymentId);
}

function artifactDirectory(root: string, workspaceId: string, payload: AppRuntimeJobPayload, artifactId: string): string {
  return path.join(deploymentDirectory(root, workspaceId, payload), 'artifacts', artifactId);
}

export function assertAppRuntimePathInside(root: string, candidate: string): void {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  if (!relative || relative === '.') return;
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('A sandbox path escaped its assigned root.');
  }
}

export function redactAppRuntimeLog(value: string, secrets: readonly string[]): string {
  let safe = '';
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) safe += character;
    if (safe.length >= 2_000) break;
  }
  for (const secret of secrets) {
    if (secret.length >= 4) safe = safe.split(secret).join('[REDACTED]');
  }
  safe = redactAppRuntimeCredentials(safe);
  return safe.trim();
}

function appendLogs(app: ManagedApp, phase: string, chunk: Buffer | string): void {
  const text = String(chunk);
  const leaked = app.secrets.some((secret) => secret.length >= 4 && text.includes(secret));
  const lines = String(chunk).split(/\r?\n/);
  for (const raw of lines) {
    const line = redactAppRuntimeLog(raw, app.secrets);
    if (!line) continue;
    const output = `[${phase}] ${line}`;
    const bytes = Buffer.byteLength(output);
    app.logLines.push(output);
    app.logBytes += bytes;
    while (app.logBytes > APP_RUNTIME_LIMITS.maximumLogBytes && app.logLines.length > 1) {
      app.logBytes -= Buffer.byteLength(app.logLines.shift()!);
    }
  }
  if (leaked && !app.logLines.some((line) => line.includes('Environment leak indicator'))) {
    app.logLines.push('[shield] Environment leak indicator was redacted.');
  }
  if (/\b0\.0\.0\.0\b/.test(String(chunk))) app.bind = '0.0.0.0';
}

async function ensurePrivateDirectory(root: string, segments: readonly string[]): Promise<string> {
  let current = root;
  for (const segment of segments) {
    if (!/^[A-Za-z0-9_.-]{1,100}$/.test(segment) || segment === '.' || segment === '..') {
      throw new Error('A sandbox directory identifier is invalid.');
    }
    current = path.join(current, segment);
    assertAppRuntimePathInside(root, current);
    await mkdir(current, { recursive: false }).catch((error: unknown) => {
      if (!(error instanceof Error) || !('code' in error) || error.code !== 'EEXIST') throw error;
    });
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error('A symbolic link or special path was found in the App Runtime sandbox.');
    }
    assertAppRuntimePathInside(root, await realpath(current));
  }
  return current;
}

async function commandAvailable(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

function packageManagerCli(manager: AppPackageManager): string | null {
  const nodeDirectory = path.dirname(process.execPath);
  const candidates: Record<AppPackageManager, string[]> = {
    npm: [
      path.join(nodeDirectory, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
      path.join(nodeDirectory, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    ],
    pnpm: [path.join(nodeDirectory, 'node_modules', 'pnpm', 'bin', 'pnpm.cjs')],
    yarn: [path.join(nodeDirectory, 'node_modules', 'yarn', 'bin', 'yarn.js')],
  };
  return candidates[manager].find((candidate) => {
    try {
      return requireFile(candidate);
    } catch {
      return false;
    }
  }) ?? null;
}

function requireFile(file: string): boolean {
  // Synchronous filesystem APIs are deliberately avoided in job execution;
  // this conservative location check only recognizes the Node distribution's
  // own package-manager layout.
  try {
    const binding = process.getBuiltinModule('fs') as typeof import('node:fs');
    return binding.statSync(file).isFile();
  } catch {
    return false;
  }
}

export async function discoverAppRuntimeCapabilities(): Promise<AppRuntimeCapabilities> {
  const nodeMajor = Number.parseInt(process.versions.node.split('.')[0] ?? '0', 10);
  const managers: AppPackageManager[] = [];
  for (const manager of ['npm', 'pnpm', 'yarn'] as const) {
    const candidate = packageManagerCli(manager);
    if (candidate && await commandAvailable(candidate)) managers.push(manager);
  }
  const permissionModel = nodeMajor >= 22;
  const networkGuard = nodeMajor >= APP_RUNTIME_LIMITS.minimumNodeMajor;
  return {
    available:
      APP_RUNTIME_LIMITS.supportedNodeMajors.includes(nodeMajor) &&
      permissionModel &&
      networkGuard &&
      managers.length > 0,
    nodeVersion: process.versions.node,
    nodeMajor,
    permissionModel,
    networkGuard,
    packageManagers: managers,
    activeDeployments: [...managedApps.values()].filter((app) => isAppProcessRunning(app.process)).length,
    maxDeployments: APP_RUNTIME_LIMITS.maximumDeploymentsPerNode,
  };
}

async function readResponseBytes(response: Response, maximum: number): Promise<Uint8Array> {
  const length = Number(response.headers.get('content-length') ?? 0);
  if (length > maximum) throw new Error('The GitHub archive exceeds the compressed source quota.');
  const reader = response.body?.getReader();
  if (!reader) throw new Error('GitHub returned an empty archive.');
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximum) {
      await reader.cancel('archive-quota');
      throw new Error('The GitHub archive exceeds the compressed source quota.');
    }
    chunks.push(value);
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function downloadGithubArchive(
  source: NonNullable<AppRuntimeJobPayload['source']>,
  fetcher: typeof fetch,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const url = `https://api.github.com/repos/${encodeURIComponent(source.owner)}/${encodeURIComponent(source.repository)}/tarball/${source.commit}`;
  const response = await fetcher(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'ysd-node-agent',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: signal
      ? AbortSignal.any([signal, AbortSignal.timeout(60_000)])
      : AbortSignal.timeout(60_000),
  });
  const final = new URL(response.url);
  if (!response.ok || !['api.github.com', 'codeload.github.com'].includes(final.hostname) || final.protocol !== 'https:') {
    throw new Error('Source acquisition left the github.com archive allowlist.');
  }
  return readResponseBytes(response, APP_RUNTIME_LIMITS.compressedSourceBytes);
}

function tarString(bytes: Uint8Array, start: number, length: number): string {
  const value = Buffer.from(bytes.subarray(start, start + length)).toString('utf8');
  const terminator = value.indexOf(String.fromCharCode(0));
  return (terminator >= 0 ? value.slice(0, terminator) : value).trim();
}

function tarOctal(bytes: Uint8Array, start: number, length: number): number {
  const value = tarString(bytes, start, length).trim();
  if (!/^[0-7]*$/.test(value)) throw new Error('The archive contains an invalid size field.');
  return value ? Number.parseInt(value, 8) : 0;
}

function validTarChecksum(header: Uint8Array): boolean {
  const expected = tarOctal(header, 148, 8);
  let actual = 0;
  for (let index = 0; index < 512; index += 1) {
    actual += index >= 148 && index < 156 ? 32 : header[index]!;
  }
  return expected === actual;
}

function safeArchivePath(name: string, top: string | null): { top: string; relative: string } {
  const normalized = name.replace(/\\/g, '/').replace(/\/$/, '');
  if (!normalized || normalized.startsWith('/') || normalized.includes('\0')) throw new Error('The archive contains an invalid path.');
  const parts = normalized.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..')) throw new Error('The archive contains path traversal.');
  const root = top ?? parts[0]!;
  if (parts[0] !== root) throw new Error('The archive contains multiple source roots.');
  return { top: root, relative: parts.slice(1).join('/') };
}

export async function extractAppRuntimeArchive(compressed: Uint8Array, destination: string): Promise<void> {
  let archive: Buffer;
  try {
    archive = gunzipSync(compressed, { maxOutputLength: APP_RUNTIME_LIMITS.extractedSourceBytes });
  } catch {
    throw new Error('The GitHub archive is invalid or exceeds the extracted source quota.');
  }
  await mkdir(destination, { recursive: true });
  let offset = 0;
  let files = 0;
  let bytesWritten = 0;
  let top: string | null = null;
  const seen = new Set<string>();
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    if (!validTarChecksum(header)) throw new Error('The archive header checksum is invalid.');
    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const fullName = prefix ? `${prefix}/${name}` : name;
    const size = tarOctal(header, 124, 12);
    const type = String.fromCharCode(header[156] || 0);
    const next = offset + 512 + Math.ceil(size / 512) * 512;
    if (next > archive.length) throw new Error('The archive ended inside a file.');
    if (type === 'x' || type === 'g') {
      if (size > 64 * 1024) throw new Error('Archive metadata is too large.');
      const metadata = archive.subarray(offset + 512, offset + 512 + size);
      const metadataText = Buffer.from(metadata).toString('utf8');
      if (/(?:^|\n)\d+\s+(?:path|linkpath)=/i.test(metadataText)) {
        throw new Error('Extended archive paths and links are forbidden.');
      }
      offset = next;
      continue;
    }
    const safe = safeArchivePath(fullName, top);
    top = safe.top;
    if (safe.relative) {
      const target = path.resolve(destination, ...safe.relative.split('/'));
      assertAppRuntimePathInside(destination, target);
      if (seen.has(target)) throw new Error('The archive contains duplicate paths.');
      seen.add(target);
      if (type === '5') {
        await mkdir(target, { recursive: true });
      } else if (type === '0' || type === '\0') {
        files += 1;
        bytesWritten += size;
        if (files > APP_RUNTIME_LIMITS.extractedFiles || bytesWritten > APP_RUNTIME_LIMITS.extractedSourceBytes) {
          throw new Error('The archive exceeds the file or extracted byte quota.');
        }
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, archive.subarray(offset + 512, offset + 512 + size), { flag: 'wx' });
      } else {
        throw new Error('Links, devices, and special archive entries are forbidden.');
      }
    }
    offset = next;
  }
  if (files === 0) throw new Error('The GitHub archive contained no files.');
}

async function walkFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop()!;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const candidate = path.join(directory, entry.name);
      assertAppRuntimePathInside(root, candidate);
      if (entry.isSymbolicLink()) {
        const resolved = await realpath(candidate);
        assertAppRuntimePathInside(root, resolved);
        continue;
      }
      if (entry.isDirectory()) pending.push(candidate);
      else if (entry.isFile()) files.push(candidate);
      else throw new Error('The sandbox contains a special filesystem entry.');
      if (files.length > APP_RUNTIME_LIMITS.extractedFiles * 4) throw new Error('The installed artifact exceeds the file quota.');
    }
  }
  return files.sort();
}

async function artifactHash(root: string, maximumBytes = APP_RUNTIME_LIMITS.diskMaximumBytes): Promise<{ checksum: string; sizeBytes: number }> {
  const hash = createHash('sha256');
  let sizeBytes = 0;
  for (const file of await walkFiles(root)) {
    const relative = path.relative(root, file).replace(/\\/g, '/');
    if (relative === MANIFEST) continue;
    const info = await stat(file);
    sizeBytes += info.size;
    if (sizeBytes > maximumBytes) throw new Error('The artifact exceeds its disk quota.');
    hash.update(relative);
    hash.update('\0');
    hash.update(await readFile(file));
    hash.update('\0');
  }
  return { checksum: `sha256:${hash.digest('hex')}`, sizeBytes };
}

async function runFixedProcess(input: {
  args: string[];
  cwd: string;
  environment: Record<string, string>;
  timeoutMs: number;
  signal?: AbortSignal;
  onOutput: (phase: string, chunk: Buffer) => void;
}): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort('process-timeout'), input.timeoutMs);
    const combined = input.signal
      ? AbortSignal.any([input.signal, controller.signal])
      : controller.signal;
    const child: ChildProcess = spawn(process.execPath, input.args, {
      cwd: input.cwd,
      env: {
        ...input.environment,
        NODE_ENV: input.environment.NODE_ENV ?? 'production',
      } as NodeJS.ProcessEnv,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      signal: combined,
    });
    child.stdout?.on('data', (chunk: Buffer) => input.onOutput('build', chunk));
    child.stderr?.on('data', (chunk: Buffer) => input.onOutput('build', chunk));
    child.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('exit', (code, signal) => {
      clearTimeout(timeout);
      if (combined.aborted) reject(new Error('The build was cancelled or timed out.'));
      else if (code === 0) resolve();
      else reject(new Error(`The fixed package-manager process failed (${code ?? signal ?? 'unknown'}).`));
    });
  });
}

function minimalEnvironment(tempDirectory: string): Record<string, string> {
  const environment: Record<string, string> = {
    HOME: tempDirectory,
    USERPROFILE: tempDirectory,
    TMP: tempDirectory,
    TEMP: tempDirectory,
    CI: 'true',
    npm_config_ignore_scripts: 'true',
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_registry: SAFE_REGISTRY,
    NODE_NO_WARNINGS: '1',
  };
  for (const key of ['SystemRoot', 'WINDIR']) {
    if (process.env[key]) environment[key] = process.env[key]!;
  }
  return environment;
}

/**
 * Scratch space for one build.
 *
 * This deliberately does not sit inside the artifact directory. An artifact is
 * about two hundred characters down --
 * `workspaces/<ws>/projects/<prj>/deployments/<dpl>/artifacts/<art>` -- and the
 * package manager creates its own subdirectories beneath whatever `TMP` points
 * at. On Windows that overruns the 260-character path limit, and npm answers by
 * retrying the failing path indefinitely: one core pinned, not a single byte of
 * output, until the build timeout kills it ten minutes later and reports only
 * "The operation was aborted". Whether a machine tripped it came down to how
 * long the operator's own agent path happened to be.
 *
 * A short temp directory gives the package manager the headroom it assumes it
 * has. It still lives under the agent root, so it stays private to this node
 * and is still removed when the build finishes.
 */
function buildTempDirectory(root: string, artifactId: string): string {
  return path.join(safeRoot(root), 'tmp', artifactId);
}

async function installDependencies(input: {
  contract: SafeBuildContract;
  artifactDirectory: string;
  cacheDirectory: string;
  tempDirectory: string;
  signal?: AbortSignal;
  onOutput: (phase: string, chunk: Buffer) => void;
}): Promise<void> {
  const cli = packageManagerCli(input.contract.packageManager);
  if (!cli) throw new Error(`The fixed ${input.contract.packageManager} executable is not installed beside Node.js.`);
  const temp = input.tempDirectory;
  const userConfig = path.join(temp, 'empty-user-config');
  await rm(temp, { recursive: true, force: true });
  await mkdir(temp, { recursive: true });
  await mkdir(input.cacheDirectory, { recursive: true });
  await writeFile(userConfig, '', { flag: 'wx' });
  const managerArgs: Record<AppPackageManager, string[]> = {
    npm: ['ci', '--ignore-scripts', '--no-audit', '--no-fund', `--registry=${SAFE_REGISTRY}`, `--userconfig=${userConfig}`, `--cache=${input.cacheDirectory}`],
    pnpm: ['install', '--frozen-lockfile', '--ignore-scripts', `--registry=${SAFE_REGISTRY}`, `--store-dir=${input.cacheDirectory}`, `--config.userconfig=${userConfig}`],
    yarn: ['install', '--frozen-lockfile', '--ignore-scripts', '--non-interactive', `--registry=${SAFE_REGISTRY}`, `--cache-folder=${input.cacheDirectory}`],
  };
  await runFixedProcess({
    args: [cli, ...managerArgs[input.contract.packageManager]],
    cwd: input.artifactDirectory,
    environment: minimalEnvironment(temp),
    timeoutMs: APP_RUNTIME_LIMITS.buildTimeoutMs,
    signal: input.signal,
    onOutput: input.onOutput,
  });
  await rm(temp, { recursive: true, force: true });
}

async function verifyExtractedContract(directory: string, expected: SafeBuildContract): Promise<void> {
  const allFiles = await walkFiles(directory);
  const files = allFiles.map((file) => path.relative(directory, file).replace(/\\/g, '/'));
  const readOptional = async (name: string, maximum: number): Promise<string | null> => {
    if (!files.includes(name)) return null;
    const value = await readFile(path.join(directory, name), 'utf8');
    if (Buffer.byteLength(value) > maximum) throw new Error(`${name} exceeds its policy limit.`);
    return value;
  };
  const analysis = analyzeNodeRepository({
    packageJson: await readOptional('package.json', 256 * 1024),
    files,
    nvmrc: await readOptional('.nvmrc', 1024),
    envExample: await readOptional('.env.example', 64 * 1024),
    lockfileContent: await readOptional(expected.lockfile, 8 * 1024 * 1024),
  });
  if (!analysis.contract || !constantTimeEqual(stableJson(analysis.contract), stableJson(expected))) {
    throw new Error('The extracted repository no longer matches the signed safe build contract.');
  }
}

async function readManifest(directory: string): Promise<ArtifactManifest> {
  const parsed: unknown = JSON.parse(await readFile(path.join(directory, MANIFEST), 'utf8'));
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('The local artifact manifest is invalid.');
  return parsed as ArtifactManifest;
}

function unsignedManifest(manifest: ArtifactManifest): Omit<ArtifactManifest, 'signature'> {
  const {
    version,
    deploymentId,
    projectId,
    artifactId,
    commit,
    checksum,
    sizeBytes,
    contract,
    createdAt,
    verifiedAt,
  } = manifest;
  return {
    version,
    deploymentId,
    projectId,
    artifactId,
    commit,
    checksum,
    sizeBytes,
    contract,
    createdAt,
    verifiedAt,
  };
}

export async function verifyArtifact(
  directory: string,
  token: string,
  expectedArtifactId?: string,
): Promise<ArtifactManifest> {
  const manifest = await readManifest(directory);
  if (manifest.version !== 1 || (expectedArtifactId && manifest.artifactId !== expectedArtifactId) ||
      !/^sha256:[a-f0-9]{64}$/.test(manifest.checksum) ||
      typeof manifest.signature !== 'string' ||
      !(await verifyTextSignature(token, `ysd-app-artifact-v1\n${stableJson(unsignedManifest(manifest))}`, manifest.signature))) {
    throw new Error('The local artifact manifest is unsigned or invalid.');
  }
  const calculated = await artifactHash(directory);
  if (!constantTimeEqual(calculated.checksum, manifest.checksum) || calculated.sizeBytes !== manifest.sizeBytes) {
    throw new Error('The local artifact checksum does not match its verified manifest.');
  }
  return manifest;
}

async function ensureDiskCapacity(root: string, quotaBytes: number): Promise<void> {
  const filesystem = await statfs(root);
  const available = Math.max(0, filesystem.bavail * filesystem.bsize);
  if (available < quotaBytes + APP_RUNTIME_LIMITS.diskReserveBytes) {
    throw new Error('The node has insufficient disk for the signed artifact quota and reserve.');
  }
}

/**
 * Whether this machine will actually let the runtime have a port.
 *
 * A real exclusive bind on the same address the runtime uses, because nothing
 * weaker is true. A port with no listener on it is not necessarily available:
 * Windows reserves blocks for Hyper-V and WSL, and binding one of those fails
 * with `EACCES` while every "is anything listening?" check says it is free.
 * That is not a corner case -- it is what made a whole node undeployable, with
 * the control plane assigning 41000 out of a reserved 40947-41146 block and
 * every deployment failing before it built anything.
 *
 * Errors are classified by code, never by message text. `EADDRINUSE` and
 * `EACCES` both mean "pick another"; anything else is a genuine fault and is
 * reported as one rather than quietly costing the caller a candidate.
 */
async function probePort(port: number): Promise<'available' | 'unavailable'> {
  return await new Promise<'available' | 'unavailable'>((resolve, reject) => {
    const server = createServer();
    let settled = false;
    const finish = (outcome: 'available' | 'unavailable' | Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (outcome instanceof Error) reject(outcome);
      else resolve(outcome);
    };
    const timeout = setTimeout(() => {
      server.close();
      finish(new Error('The private App Runtime port check timed out.'));
    }, 5_000);
    server.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE' || error.code === 'EACCES') finish('unavailable');
      else finish(new Error('The private App Runtime port could not be checked.'));
    });
    server.listen({ host: '127.0.0.1', port, exclusive: true }, () => {
      server.close((error) => finish(error ? new Error('The private App Runtime port could not be released.') : 'available'));
    });
  });
}

/**
 * Ports this node can actually bind, preferring the one already assigned.
 *
 * Scans as far through the private range as it needs to, but returns only a
 * bounded set: the control plane decides which of them becomes authoritative.
 */
export async function bindablePrivatePorts(
  preferred: number,
  limit = PRIVATE_PORT_CANDIDATE_LIMIT,
): Promise<number[]> {
  const found: number[] = [];
  for (const port of privatePortSearchOrder(preferred)) {
    if (await probePort(port) === 'available') {
      found.push(port);
      if (found.length >= limit) break;
    }
  }
  return found;
}

async function assertPortAvailable(port: number): Promise<void> {
  if (await probePort(port) === 'unavailable') {
    throw new AppRuntimePortError(port);
  }
}

// Windows refuses a reserved port with EACCES while reporting nothing
// listening on it, so "already in use" was a diagnosis the Agent could not
// support. These say only what is known: the node cannot have this port.
export const PRIVATE_PORT_UNAVAILABLE =
  'The assigned private App Runtime port is unavailable on this Compute Node.';
export const NO_AVAILABLE_PRIVATE_PORT =
  'No private App Runtime port on this Compute Node is available.';

/** A private port this node cannot bind, carrying what it could bind instead. */
export class AppRuntimePortError extends Error {
  readonly reasonCode = 'private_port_unavailable';
  readonly port: number;

  constructor(port: number) {
    super(PRIVATE_PORT_UNAVAILABLE);
    this.port = port;
  }
}

function runtimeEnvironment(app: Omit<ManagedApp, 'process' | 'startedAt' | 'restartTimes' | 'restartCount' | 'crashLoop' | 'desiredRunning' | 'intentionalStop' | 'desiredRevision' | 'healthState' | 'bind' | 'logLines' | 'logBytes'>): Record<string, string> {
  const temp = path.join(app.dataDirectory, 'tmp');
  return {
    ...minimalEnvironment(temp),
    ...app.environment,
    HOST: '127.0.0.1',
    PORT: String(app.port),
    NODE_ENV: 'production',
    YSD_EXPOSURE: 'private',
  };
}

async function spawnManagedApp(input: {
  deploymentId: string;
  projectId: string;
  artifactId: string;
  artifactDirectory: string;
  dataDirectory: string;
  entrypoint: string;
  port: number;
  healthPath: string;
  memoryMb: number;
  environment: Record<string, string>;
  previousRestarts?: number;
  desiredRevision?: number;
}): Promise<ManagedApp> {
  console.error('App Runtime start: checking assigned private port.');
  await assertPortAvailable(input.port);
  console.error('App Runtime start: assigned private port is available.');
  await mkdir(input.dataDirectory, { recursive: true });
  await mkdir(path.join(input.dataDirectory, 'tmp'), { recursive: true });
  console.error('App Runtime start: private data directory is ready.');
  const values = Object.values(input.environment).filter((value) => value.length >= 4);
  const shell: Omit<ManagedApp, 'process' | 'startedAt' | 'restartTimes' | 'restartCount' | 'crashLoop' | 'desiredRunning' | 'intentionalStop' | 'desiredRevision' | 'healthState' | 'bind' | 'logLines' | 'logBytes'> = {
    ...input,
    secrets: values,
  };
  const args = [
    '--permission',
    `--allow-fs-read=${input.artifactDirectory}`,
    `--allow-fs-write=${input.dataDirectory}`,
    '--allow-net=127.0.0.1',
    `--max-old-space-size=${input.memoryMb}`,
    path.join(input.artifactDirectory, input.entrypoint),
  ];
  const child: ChildProcess = spawn(process.execPath, args, {
    cwd: input.artifactDirectory,
    env: runtimeEnvironment(shell) as NodeJS.ProcessEnv,
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const app: ManagedApp = {
    ...shell,
    process: child,
    startedAt: Date.now(),
    restartTimes: [],
    restartCount: input.previousRestarts ?? 0,
    crashLoop: false,
    desiredRunning: true,
    intentionalStop: false,
    desiredRevision: input.desiredRevision ?? 1,
    healthState: 'unknown',
    bind: '127.0.0.1',
    logLines: [],
    logBytes: 0,
  };
  child.stdout?.on('data', (chunk: Buffer) => appendLogs(app, 'runtime', chunk));
  child.stderr?.on('data', (chunk: Buffer) => appendLogs(app, 'runtime', chunk));
  child.once('error', (error) => appendLogs(app, 'runtime', Buffer.from(error.message)));
  await new Promise<void>((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', reject);
  });
  console.error('App Runtime start: child process created.');
  child.once('exit', () => {
    if (!app.intentionalStop && app.desiredRunning) {
      void restartAfterCrash(app).catch((error: unknown) => {
        app.crashLoop = true;
        appendLogs(app, 'runtime', Buffer.from(error instanceof Error ? error.message : 'Crash recovery failed.'));
      });
    }
  });
  managedApps.set(app.deploymentId, app);
  return app;
}

async function restartAfterCrash(app: ManagedApp): Promise<void> {
  const now = Date.now();
  app.restartTimes = app.restartTimes.filter((time) => now - time <= APP_RUNTIME_LIMITS.crashWindowMs);
  const decision = appCrashRecoveryDecision(app.restartTimes.length);
  if (!decision.restart || decision.delayMs === null) {
    app.crashLoop = true;
    appendLogs(app, 'runtime', Buffer.from('Crash-loop protection stopped automatic restarts.'));
    return;
  }
  app.restartTimes.push(now);
  app.restartCount += 1;
  const scheduledRevision = app.desiredRevision;
  await delay(decision.delayMs);
  if (!shouldSpawnCrashReplacement({
    scheduledRevision,
    currentRevision: app.desiredRevision,
    desiredRunning: app.desiredRunning,
    intentionalStop: app.intentionalStop,
    sameRuntime: managedApps.get(app.deploymentId) === app,
  })) return;
  const replacement = await spawnManagedApp({
    deploymentId: app.deploymentId,
    projectId: app.projectId,
    artifactId: app.artifactId,
    artifactDirectory: app.artifactDirectory,
    dataDirectory: app.dataDirectory,
    entrypoint: app.entrypoint,
    port: app.port,
    healthPath: app.healthPath,
    memoryMb: app.memoryMb,
    environment: app.environment,
    previousRestarts: app.restartCount,
    desiredRevision: scheduledRevision,
  });
  replacement.restartTimes = app.restartTimes;
  try {
    await healthCheck(replacement);
    appendLogs(replacement, 'runtime', Buffer.from('Crash replacement health check passed.'));
  } catch {
    replacement.healthState = 'unhealthy';
    appendLogs(replacement, 'runtime', Buffer.from('Crash replacement health check failed.'));
    const stillCurrent = managedApps.get(replacement.deploymentId) === replacement &&
      replacement.desiredRunning && !replacement.intentionalStop &&
      replacement.desiredRevision === scheduledRevision;
    replacement.intentionalStop = true;
    await terminateProcess(replacement);
    if (stillCurrent) {
      replacement.intentionalStop = false;
      replacement.desiredRunning = true;
      await restartAfterCrash(replacement);
    }
  }
}

async function terminateProcess(app: ManagedApp): Promise<void> {
  if (!isAppProcessRunning(app.process)) return;
  const exited = new Promise<void>((resolve) => app.process.once('exit', () => resolve()));
  app.process.kill('SIGTERM');
  await Promise.race([exited, delay(8_000)]);
  if (isAppProcessRunning(app.process)) {
    app.process.kill('SIGKILL');
    await Promise.race([exited, delay(2_000)]);
  }
}

async function stopManagedApp(deploymentId: string, desiredRevision?: number): Promise<ManagedApp | null> {
  const app = managedApps.get(deploymentId) ?? null;
  if (!app) return null;
  app.intentionalStop = true;
  app.desiredRunning = false;
  if (desiredRevision) app.desiredRevision = desiredRevision;
  await terminateProcess(app);
  return app;
}

export async function shutdownManagedApps(): Promise<void> {
  await Promise.all([...managedApps.keys()].map((id) => stopManagedApp(id)));
}

async function healthCheck(app: ManagedApp, signal?: AbortSignal): Promise<void> {
  let last = 'no response';
  for (let attempt = 0; attempt < APP_RUNTIME_LIMITS.healthAttempts; attempt += 1) {
    if (signal?.aborted) throw new Error('The health check was cancelled.');
    if (!isAppProcessRunning(app.process)) throw new Error('The application exited before becoming healthy.');
    try {
      const response = await fetch(`http://127.0.0.1:${app.port}${app.healthPath}`, {
        redirect: 'manual',
        signal: signal
          ? AbortSignal.any([signal, AbortSignal.timeout(APP_RUNTIME_LIMITS.healthTimeoutMs)])
          : AbortSignal.timeout(APP_RUNTIME_LIMITS.healthTimeoutMs),
      });
      if (response.status >= 200 && response.status < 400) {
        app.healthState = 'healthy';
        return;
      }
      last = `HTTP ${response.status}`;
    } catch (error) {
      last = error instanceof Error ? error.message : 'connection failed';
    }
    await delay(APP_RUNTIME_LIMITS.healthBackoffMs * Math.min(4, attempt + 1), undefined, { signal });
  }
  app.healthState = 'unhealthy';
  throw new Error(`The localhost health check failed: ${last}.`);
}

/**
 * Drop artifact directories beyond the retention window.
 *
 * The removed ids are returned so the control plane can stop advertising them
 * as restorable. Without that, D1 keeps a row marked `verified` long after
 * the bytes it describes were deleted here, and a rollback offered against
 * that row could only ever fail at activation.
 */
export async function pruneArtifacts(
  parent: string,
  retain: number,
  activeArtifact: string,
  protectedArtifactIds: readonly string[] = [],
): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(parent, { withFileTypes: true });
  } catch {
    return [];
  }
  const artifacts = await Promise.all(entries.filter((entry) => entry.isDirectory()).map(async (entry) => ({
    name: entry.name,
    directory: path.join(parent, entry.name),
    time: (await lstat(path.join(parent, entry.name))).mtimeMs,
  })));
  artifacts.sort((a, b) => b.time - a.time);
  const keep = selectRetainedArtifacts({
    currentArtifactId: activeArtifact,
    previousVerifiedArtifactId: protectedArtifactIds.find((id) => id !== activeArtifact) ?? null,
    cap: retain,
    artifacts: artifacts.map((entry) => ({
      id: entry.name,
      modifiedAt: entry.time,
      verified: /^art_[a-f0-9]{24}$/.test(entry.name),
    })),
  });
  const pruned: string[] = [];
  for (const artifact of artifacts) {
    if (keep.has(artifact.name)) continue;
    await rm(artifact.directory, { recursive: true, force: true });
    // Only ids this node actually removed, from a directory it owns.
    if (/^art_[a-f0-9]{24}$/.test(artifact.name)) pruned.push(artifact.name);
  }
  return pruned;
}

function snapshot(app: ManagedApp): AppRuntimeSnapshot {
  const running = isAppProcessRunning(app.process) && !app.crashLoop;
  return {
    deploymentId: app.deploymentId,
    projectId: app.projectId,
    artifactId: app.artifactId,
    state: app.crashLoop ? 'crash_loop' : running ? 'running' : 'stopped',
    port: app.port,
    bind: app.bind,
    pid: running ? app.process.pid ?? null : null,
    uptimeSeconds: running ? Math.max(0, Math.floor((Date.now() - app.startedAt) / 1000)) : 0,
    restartCount: app.restartCount,
    crashLoop: app.crashLoop,
    memoryUsedBytes: null,
    observedAt: Date.now(),
    healthState: app.healthState,
  };
}

export function collectAppRuntimeSnapshots(): AppRuntimeSnapshot[] {
  const values = [...managedApps.values()].map(snapshot);
  return parseAppRuntimeSnapshots(values) ?? [];
}

function resultFor(app: ManagedApp, extra: Record<string, unknown> = {}): AgentJobResult {
  const unexpectedOutbound = app.logLines.some((line) =>
    /ERR_ACCESS_DENIED|network access|allow-net/i.test(line),
  );
  return {
    status: 'succeeded',
    result: {
      ...snapshot(app),
      exposure: 'private',
      localAddress: `http://127.0.0.1:${app.port}`,
      logs: app.logLines.slice(-APP_RUNTIME_LIMITS.maximumResultLogLines),
      networkGuard: true,
      unexpectedOutbound,
      ...extra,
    },
  };
}

/**
 * Agrees a private port this node can actually bind.
 *
 * The control plane stays authoritative: the node only reports which ports it
 * can bind, and the server decides which one this deployment gets. A node that
 * quietly moved itself from 41000 to 41200 would leave the UI, health checks,
 * runtime recovery and release evidence all pointing at a port nothing is
 * listening on.
 */
export async function negotiatePrivatePort(input: {
  origin: string;
  token: string;
  deploymentId: string;
  currentPort: number;
  signal?: AbortSignal;
}): Promise<number> {
  const candidates = await bindablePrivatePorts(input.currentPort);
  if (candidates.length === 0) throw new Error('no_available_private_port');
  const answer = await signedPost<{ localPort?: unknown }>({
    origin: input.origin,
    token: input.token,
    pathname: `/api/nodes/agent/deployments/${input.deploymentId}/private-port`,
    body: { expectedCurrentPort: input.currentPort, candidatePorts: candidates },
    signal: input.signal,
  });
  const granted = answer.localPort;
  // Trust, then verify: the port has to be one this node offered, and it has to
  // still bind before anything is built against it.
  if (!privatePortInRange(granted) || !candidates.includes(granted as number)) {
    throw new Error('private_port_rejected');
  }
  if (await probePort(granted as number) === 'unavailable') {
    throw new Error('private_port_unavailable');
  }
  return granted as number;
}

export async function executeAppRuntimeJob(input: {
  payload: Record<string, unknown>;
  workspaceId: string;
  token: string;
  origin?: string;
  capabilities: AppRuntimeCapabilities;
  rootDirectory: string;
  signal?: AbortSignal;
  fetcher?: typeof fetch;
}): Promise<AgentJobResult> {
  const validated = validateAppRuntimeJobPayload(input.payload);
  if (!validated.ok) return { status: 'failed', error: validated.error, retryable: false };
  const payload = validated.payload;
  // The port has to be settled before anything is fetched, installed or built.
  // A node whose assigned port is reserved by the operating system would
  // otherwise spend a whole build only to fail at the last step, every time.
  let activePort = payload.port;
  // Recovery is deliberately absent. Phase 18 restores an application in
  // place -- same deployment, same node, same artifact, same port -- and a
  // recovery that quietly moved the port would break that promise and the
  // 'same port' guarantee the artifact restore acceptance depends on. A port
  // blocked during recovery stays a recovery diagnostic (`port_in_use`), which
  // is what the control plane already understands. Negotiation belongs to the
  // first activation, before anything depends on the port.
  if (['deploy', 'redeploy', 'start', 'restart', 'rollback'].includes(payload.operation)) {
    // This runs before the job's own try/catch, so it has to produce a result
    // rather than throw: `executeAppRuntimeJob` always answers with an
    // `AgentJobResult`, and a job that escapes with an exception takes the
    // Agent's job loop with it instead of failing one deployment.
    try {
      if (await probePort(activePort) === 'unavailable') {
        if (!input.origin) {
          return {
            status: 'failed',
            error: PRIVATE_PORT_UNAVAILABLE,
            retryable: false,
            result: { phase: 'reconcile', reasonCode: 'private_port_unavailable' },
          };
        }
        console.error('App Runtime start: the assigned private port is unavailable; negotiating another.');
        activePort = await negotiatePrivatePort({
          origin: input.origin,
          token: input.token,
          deploymentId: payload.deploymentId,
          currentPort: activePort,
          signal: input.signal,
        });
        console.error('App Runtime start: the control plane assigned a usable private port.');
      }
    } catch (error) {
      const exhausted = error instanceof Error && error.message === 'no_available_private_port';
      return {
        status: 'failed',
        error: exhausted ? NO_AVAILABLE_PRIVATE_PORT : PRIVATE_PORT_UNAVAILABLE,
        retryable: false,
        result: {
          phase: 'reconcile',
          reasonCode: exhausted ? 'no_available_private_port' : 'private_port_unavailable',
        },
      };
    }
  }
  let phase: RecoveryPhase | 'source_fetch' | 'extract' | 'dependency_install' | 'build' = 'reconcile';
  const enterRecoveryPhase = (next: RecoveryPhase): void => {
    phase = next;
    if (payload.operation === 'recover') console.error(`App Runtime recovery phase: ${next}.`);
  };
  const started = Date.now();
  const refuse = (error: string, reasonCode: RecoveryReasonCode): AgentJobResult => ({
    status: 'failed', error, retryable: false,
    result: {
      phase, reasonCode, elapsedMs: Date.now() - started,
      observedState: 'blocked', artifactId: payload.artifactId,
      restarted: false, availabilityState: 'unknown',
    },
  });
  if (input.signal?.aborted) {
    return { status: 'cancelled', error: 'The App Runtime action was cancelled.', retryable: false };
  }
  if (!/^ws_[a-f0-9]{24}$/.test(input.workspaceId)) {
    return refuse('The signed workspace scope is invalid.', 'reconciliation_failed');
  }
  if (!input.capabilities.available || !input.capabilities.networkGuard || !input.capabilities.permissionModel) {
    return refuse('Node.js 25/26 with enforced filesystem and network permissions is required.', 'runtime_incompatible');
  }
  if (payload.contract && payload.contract.nodeMajor !== input.capabilities.nodeMajor) {
    return refuse('The node version does not match the signed build contract.', 'runtime_incompatible');
  }
  if (payload.contract && !input.capabilities.packageManagers.includes(payload.contract.packageManager)) {
    return refuse('The fixed package manager is unavailable on this node.', 'runtime_incompatible');
  }
  try {
    enterRecoveryPhase('reconcile');
    const requestedRoot = safeRoot(input.rootDirectory);
    await mkdir(requestedRoot, { recursive: true });
    const root = await realpath(requestedRoot);
    const deployDirectory = await ensurePrivateDirectory(root, [
      'workspaces',
      input.workspaceId,
      'projects',
      payload.projectId,
      'deployments',
      payload.deploymentId,
    ]);
    assertAppRuntimePathInside(root, deployDirectory);
    await ensureDiskCapacity(root, payload.diskQuotaBytes);
    const environment = await openNodeEnvironment(input.token, payload.environmentCiphertext);
    const allowedEnvironment = Object.fromEntries(
      Object.entries(environment).filter(([name]) => payload.contract?.envNames.includes(name) ?? true),
    );
    if (payload.operation === 'deploy' || payload.operation === 'redeploy') {
      const source = payload.source!;
      const contract = payload.contract!;
      const artifactId = payload.artifactId!;
      const artifacts = await ensurePrivateDirectory(deployDirectory, ['artifacts']);
      const artifact = artifactDirectory(root, input.workspaceId, payload, artifactId);
      assertAppRuntimePathInside(deployDirectory, artifact);
      const startedAt = Date.now();
      let logApp: ManagedApp | null = null;
      try {
        await verifyArtifact(artifact, input.token, artifactId);
      } catch {
        await rm(artifact, { recursive: true, force: true });
        await ensurePrivateDirectory(artifacts, [artifactId]);
        phase = 'source_fetch';
        const archive = await downloadGithubArchive(source, input.fetcher ?? fetch, input.signal);
        phase = 'extract';
        await extractAppRuntimeArchive(archive, artifact);
        await verifyExtractedContract(artifact, contract);
        const fakeProcess = { exitCode: 0 } as ChildProcess;
        logApp = {
          deploymentId: payload.deploymentId, projectId: payload.projectId, artifactId,
          artifactDirectory: artifact, dataDirectory: path.join(deployDirectory, 'data'),
          entrypoint: contract.entrypoint, port: activePort, healthPath: payload.healthPath,
          memoryMb: payload.memoryMb, environment: allowedEnvironment,
          secrets: Object.values(allowedEnvironment), process: fakeProcess,
          startedAt, restartTimes: [], restartCount: 0, crashLoop: false,
          desiredRunning: false, intentionalStop: true, desiredRevision: 1,
          healthState: 'unknown', bind: '127.0.0.1',
          logLines: [], logBytes: 0,
        };
        const cacheDirectory = await ensurePrivateDirectory(root, ['cache', contract.packageManager]);
        phase = 'dependency_install';
        await installDependencies({
          contract,
          artifactDirectory: artifact,
          cacheDirectory,
          tempDirectory: buildTempDirectory(root, artifactId),
          signal: input.signal,
          onOutput: (phase, chunk) => appendLogs(logApp!, phase, chunk),
        });
        phase = 'build';
        await walkFiles(artifact);
        const verified = await artifactHash(artifact, payload.diskQuotaBytes);
        const unsigned: Omit<ArtifactManifest, 'signature'> = {
          version: 1,
          deploymentId: payload.deploymentId,
          projectId: payload.projectId,
          artifactId,
          commit: source.commit,
          checksum: verified.checksum,
          sizeBytes: verified.sizeBytes,
          contract,
          createdAt: startedAt,
          verifiedAt: Date.now(),
        };
        const manifest: ArtifactManifest = {
          ...unsigned,
          signature: await signText(
            input.token,
            `ysd-app-artifact-v1\n${stableJson(unsigned)}`,
          ),
        };
        await writeFile(path.join(artifact, MANIFEST), stableJson(manifest), { flag: 'wx' });
      }
      phase = 'artifact_verify';
      const manifest = await verifyArtifact(artifact, input.token, artifactId);
      await stopManagedApp(payload.deploymentId);
      const dataDirectory = await ensurePrivateDirectory(deployDirectory, ['data']);
      const app = await spawnManagedApp({
        deploymentId: payload.deploymentId,
        projectId: payload.projectId,
        artifactId,
        artifactDirectory: artifact,
        dataDirectory,
        entrypoint: contract.entrypoint,
        port: activePort,
        healthPath: payload.healthPath,
        memoryMb: payload.memoryMb,
        environment: allowedEnvironment,
        desiredRevision: payload.expectedDesiredRevision ?? 1,
      });
      if (logApp) {
        app.logLines.unshift(...logApp.logLines.slice(-APP_RUNTIME_LIMITS.maximumResultLogLines));
        app.logBytes = app.logLines.reduce((total, line) => total + Buffer.byteLength(line), 0);
      }
      try {
        phase = 'health';
        await healthCheck(app, input.signal);
      } catch (error) {
        await stopManagedApp(payload.deploymentId);
        if (app.logLines.some((line) => /ERR_ACCESS_DENIED|network access|allow-net/i.test(line))) {
          throw new Error('An unexpected outbound network attempt was blocked by the App Runtime permission policy.');
        }
        throw error;
      }
      const prunedArtifactIds = await pruneArtifacts(
        path.join(deployDirectory, 'artifacts'),
        payload.retainArtifacts,
        artifactId,
        payload.protectedArtifactIds,
      );
      return resultFor(app, {
        prunedArtifactIds,
        checksum: manifest.checksum,
        sizeBytes: manifest.sizeBytes,
        buildDurationMs: Date.now() - startedAt,
        deployDurationMs: Date.now() - startedAt,
        verifiedAt: manifest.verifiedAt,
      });
    }

    if (payload.operation === 'stop') {
      const app = await stopManagedApp(payload.deploymentId, payload.expectedDesiredRevision ?? undefined);
      if (!app) return { status: 'succeeded', result: { deploymentId: payload.deploymentId, state: 'stopped', logs: [] } };
      return resultFor(app, { state: 'stopped' });
    }
    if (payload.operation === 'delete') {
      const app = await stopManagedApp(payload.deploymentId);
      const logs = app?.logLines.slice(-APP_RUNTIME_LIMITS.maximumResultLogLines) ?? [];
      managedApps.delete(payload.deploymentId);
      await rm(deployDirectory, { recursive: true, force: true });
      return { status: 'succeeded', result: { deploymentId: payload.deploymentId, state: 'deleted', logs } };
    }
    if (payload.operation === 'status') {
      const app = managedApps.get(payload.deploymentId);
      if (!app) return { status: 'succeeded', result: { deploymentId: payload.deploymentId, state: 'stopped', logs: [] } };
      return resultFor(app);
    }

    const selectedArtifact = payload.operation === 'rollback' ? payload.targetArtifactId : payload.artifactId;
    if (!selectedArtifact) throw new Error('The action has no verified local artifact.');
    const artifact = artifactDirectory(root, input.workspaceId, payload, selectedArtifact);
    enterRecoveryPhase('artifact_verify');
    const manifest = await verifyArtifact(artifact, input.token, selectedArtifact);
    enterRecoveryPhase('activate');
    await stopManagedApp(payload.deploymentId);
    const dataDirectory = await ensurePrivateDirectory(deployDirectory, ['data']);
    enterRecoveryPhase('start');
    const app = await spawnManagedApp({
      deploymentId: payload.deploymentId,
      projectId: payload.projectId,
      artifactId: selectedArtifact,
      artifactDirectory: artifact,
      dataDirectory,
      entrypoint: manifest.contract.entrypoint,
      port: activePort,
      healthPath: payload.healthPath,
      memoryMb: payload.memoryMb,
      environment: allowedEnvironment,
      desiredRevision: payload.expectedDesiredRevision ?? 1,
    });
    enterRecoveryPhase('health');
    try {
      await healthCheck(app, input.signal);
    } catch (error) {
      if (payload.operation === 'recover') {
        const diagnostic = app.logLines.some((line) => /ERR_ACCESS_DENIED|network access|allow-net/i.test(line))
          ? 'permission_refused'
          : app.logLines.some((line) => /MODULE_NOT_FOUND|Cannot find module/i.test(line))
            ? 'dependency_missing'
            : app.logLines.some((line) => /EADDRINUSE/i.test(line))
              ? 'port_in_use'
              : 'health_failed';
        console.error(`App Runtime recovery diagnostic: ${diagnostic}.`);
        await stopManagedApp(payload.deploymentId);
      }
      throw error;
    }
    return resultFor(app, {
      checksum: manifest.checksum,
      sizeBytes: manifest.sizeBytes,
      rolledBack: payload.operation === 'rollback',
      phase: payload.operation === 'recover' ? 'health' : undefined,
      reasonCode: payload.operation === 'recover' ? 'recovery_succeeded' : undefined,
      elapsedMs: Date.now() - started,
      observedState: 'healthy',
      restarted: payload.operation === 'recover',
      availabilityState: 'present',
      lastVerifiedOnNodeAt: Date.now(),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'The App Runtime action failed.';
    const code = error instanceof Error && 'code' in error && typeof error.code === 'string' ? error.code : null;
    const integrityFailure = /manifest|checksum|integrity|unsigned/i.test(message);
    const availability = availabilityFromVerificationFailure({ code, integrityFailure });
    // The port failure is recognised by its type, not by matching words in a
    // message. The message became truthful -- a port Windows reserves is not
    // "in use" -- and a classifier reading English would have silently
    // reclassified it the moment that wording changed. `port_in_use` remains
    // the recovery vocabulary the control plane already understands.
    const reasonCode: RecoveryReasonCode =
      error instanceof AppRuntimePortError ? 'port_in_use'
        : code === 'ENOENT' ? 'artifact_missing'
          : integrityFailure ? 'artifact_corrupted'
            : /port.*use/i.test(message) ? 'port_in_use'
            : /health/i.test(message) ? 'health_failed'
              : /insufficient disk|disk quota/i.test(message) ? 'disk_low'
                : /node version|package manager|permission/i.test(message) ? 'runtime_incompatible'
                  : 'reconciliation_failed';
    return {
      status: input.signal?.aborted ? 'cancelled' : 'failed',
      error: payload.operation === 'recover'
        ? 'Runtime recovery could not complete safely.'
        : redactAppRuntimeLog(message, []),
      retryable: false,
      result: payload.operation === 'recover' ? {
        phase,
        reasonCode,
        elapsedMs: Date.now() - started,
        observedState: reasonCode === 'health_failed' ? 'unhealthy' : 'blocked',
        artifactId: payload.artifactId,
        restarted: false,
        availabilityState: availability,
      } : { phase, elapsedMs: Date.now() - started },
    };
  }
}

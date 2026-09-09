/**
 * Artifact backup: writing, verifying and rehydrating one immutable artifact.
 *
 * Everything streams. An artifact may be two gigabytes, so nothing here reads a
 * payload, an archive or a bundle into memory -- the only thing fully parsed is
 * the manifest, which is bounded to 8 MiB and checked before a single payload
 * byte is touched.
 *
 * The container is plain uncompressed tar with numbered members, so the archive
 * layer never handles a path; see `lib/artifact-backup.ts` for why. Headers are
 * written with fixed mode, owner and mtime, which makes two backups of the same
 * artifact byte-identical.
 */
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  statfs,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';

import {
  BACKUP_FORMAT_VERSION,
  BACKUP_LIMITS,
  BACKUP_MANIFEST_ENTRY,
  RUNTIME_MANIFEST_NAME,
  backupFileName,
  canonicalBackupPath,
  evaluateArtifactCollision,
  evaluateBackupCompatibility,
  evaluateRestoreIdentity,
  findPathCollisions,
  payloadEntryName,
  validateBackupManifest,
  type BackupFileRecord,
  type BackupManifest,
  type BackupReasonCode,
  type RestoreIdentity,
} from '../lib/artifact-backup.ts';
import { APP_RUNTIME_LIMITS } from '../lib/app-runtime.ts';
import { CURRENT_AGENT_VERSION, signText, stableJson } from '../lib/nodes.ts';

const BLOCK = 512;
const CHUNK = 256 * 1024;

/** A fixed failure with a stable machine-readable reason. */
export class BackupError extends Error {
  readonly reason: BackupReasonCode;

  constructor(reason: BackupReasonCode) {
    super(reason);
    this.reason = reason;
  }
}

function fail(reason: BackupReasonCode): never {
  throw new BackupError(reason);
}

// ---------------------------------------------------------------------------
// Tar, restricted to what this format uses.
// ---------------------------------------------------------------------------

function octal(value: number, width: number): string {
  return value.toString(8).padStart(width - 1, '0') + '\0';
}

/**
 * A ustar header with no variable metadata.
 *
 * Mode, owner and mtime are constants rather than the source file's, so the
 * bytes depend only on the artifact's contents and names. The executable bit
 * lives in the manifest instead, where it is a bounded boolean.
 */
function tarHeader(name: string, size: number): Buffer {
  const header = Buffer.alloc(BLOCK);
  const encoded = Buffer.from(name, 'utf8');
  if (encoded.length > 100) throw new Error('backup entry name is too long');
  encoded.copy(header, 0);
  header.write(octal(0o644, 8), 100, 'ascii');
  header.write(octal(0, 8), 108, 'ascii');
  header.write(octal(0, 8), 116, 'ascii');
  header.write(octal(size, 12), 124, 'ascii');
  header.write(octal(0, 12), 136, 'ascii');
  header.write('        ', 148, 'ascii');
  header.write('0', 156, 'ascii');
  header.write('ustar\0', 257, 'ascii');
  header.write('00', 263, 'ascii');
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return header;
}

function tarString(block: Uint8Array, offset: number, length: number): string {
  // Header fields are ASCII and NUL-padded, so this decodes them exactly
  // without depending on a Buffer.toString overload.
  let text = '';
  for (let index = offset; index < offset + length; index += 1) {
    const byte = block[index]!;
    if (byte === 0) break;
    text += String.fromCharCode(byte);
  }
  return text;
}

function tarOctal(block: Uint8Array, offset: number, length: number): number {
  const text = tarString(block, offset, length).trim();
  if (!/^[0-7]*$/u.test(text)) fail('bundle_malformed');
  return text ? Number.parseInt(text, 8) : 0;
}

function validTarChecksum(block: Uint8Array): boolean {
  const declared = tarOctal(block, 148, 8);
  let sum = 0;
  for (let index = 0; index < BLOCK; index += 1) {
    sum += index >= 148 && index < 156 ? 0x20 : block[index]!;
  }
  return sum === declared;
}

/** Pulls exact byte counts from a byte stream without buffering the whole file. */
class ByteReader {
  private queue: Buffer[] = [];
  private buffered = 0;
  private done = false;
  private readonly source: AsyncIterator<Buffer>;

  constructor(source: AsyncIterator<Buffer>) {
    this.source = source;
  }

  private async fill(target: number): Promise<void> {
    while (this.buffered < target && !this.done) {
      const next = await this.source.next();
      if (next.done) {
        this.done = true;
        break;
      }
      const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
      this.queue.push(chunk);
      this.buffered += chunk.length;
    }
  }

  private take(count: number): Buffer {
    const parts: Buffer[] = [];
    let remaining = count;
    while (remaining > 0) {
      const head = this.queue[0]!;
      if (head.length <= remaining) {
        parts.push(head);
        remaining -= head.length;
        this.queue.shift();
      } else {
        parts.push(head.subarray(0, remaining));
        this.queue[0] = head.subarray(remaining);
        remaining = 0;
      }
    }
    this.buffered -= count;
    return parts.length === 1 ? parts[0]! : Buffer.concat(parts, count);
  }

  /** Exactly `count` bytes, or `null` at a clean end of stream. */
  async read(count: number): Promise<Buffer | null> {
    await this.fill(count);
    if (this.buffered === 0 && this.done) return null;
    if (this.buffered < count) fail('bundle_truncated');
    return this.take(count);
  }

  /** Streams `count` bytes through `sink` in bounded pieces. */
  async drain(count: number, sink: (chunk: Buffer) => Promise<void> | void): Promise<void> {
    let remaining = count;
    while (remaining > 0) {
      await this.fill(Math.min(remaining, 1));
      if (this.buffered === 0) fail('bundle_truncated');
      const piece = this.take(Math.min(remaining, this.buffered, CHUNK));
      await sink(piece);
      remaining -= piece.length;
    }
  }
}

// ---------------------------------------------------------------------------
// Artifact inspection.
// ---------------------------------------------------------------------------

function assertInside(root: string, candidate: string): void {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  if (relative && (relative.startsWith('..') || path.isAbsolute(relative))) {
    fail('destination_overlap');
  }
}

/**
 * Every payload file, in canonical order.
 *
 * Symlinks are refused rather than followed or skipped. Builds run with
 * `--ignore-scripts` and the runtime's own hash walk ignores links entirely, so
 * a link inside an artifact is already outside what this system reasons about;
 * carrying one into a portable bundle would only invent a new escape route.
 */
async function collectPayload(root: string): Promise<BackupFileRecord[]> {
  const records: BackupFileRecord[] = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop()!;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      assertInside(root, full);
      const info = await lstat(full);
      if (info.isSymbolicLink()) fail('entry_unsupported');
      if (info.isDirectory()) {
        pending.push(full);
        continue;
      }
      if (!info.isFile()) fail('entry_unsupported');
      if (info.nlink > 1) fail('entry_unsupported');
      const relative = path.relative(root, full).split(path.sep).join('/');
      if (relative === RUNTIME_MANIFEST_NAME) continue;
      const canonical = canonicalBackupPath(relative);
      if (canonical !== relative) fail('path_unsafe');
      records.push({
        path: canonical,
        size: info.size,
        sha256: await hashFile(full),
        executable: process.platform !== 'win32' && (info.mode & 0o111) !== 0,
      });
      if (records.length > BACKUP_LIMITS.fileCount) fail('manifest_invalid');
    }
  }
  records.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  if (findPathCollisions(records.map((record) => record.path)).length > 0) fail('path_collision');
  return records;
}

async function hashFile(file: string): Promise<string> {
  const hash = createHash('sha256');
  await pipeline(createReadStream(file, { highWaterMark: CHUNK }), async function* (source) {
    for await (const chunk of source) {
      hash.update(chunk as Buffer);
      yield chunk as Buffer;
    }
  }, async (source) => { for await (const _ of source) { /* drained */ } });
  return hash.digest('hex');
}

/**
 * The runtime artifact checksum, recomputed exactly as the App Runtime does:
 * canonical path, NUL, contents, NUL, over sorted files, manifest excluded.
 */
async function payloadChecksum(
  files: readonly BackupFileRecord[],
  read: (record: BackupFileRecord) => AsyncIterable<Buffer>,
): Promise<{ checksum: string; sizeBytes: number }> {
  const hash = createHash('sha256');
  let sizeBytes = 0;
  for (const record of files) {
    hash.update(record.path);
    hash.update('\0');
    for await (const chunk of read(record)) {
      hash.update(chunk);
      sizeBytes += chunk.length;
    }
    hash.update('\0');
  }
  return { checksum: `sha256:${hash.digest('hex')}`, sizeBytes };
}

async function freeBytes(directory: string): Promise<number> {
  const info = await statfs(directory);
  return Number(info.bsize) * Number(info.bavail);
}

// ---------------------------------------------------------------------------
// Create.
// ---------------------------------------------------------------------------

export type BackupCreateResult = {
  outcome: 'created';
  bundle: string;
  bundleSha256: string;
  artifactId: string;
  artifactChecksum: string;
  fileCount: number;
  payloadBytes: number;
  bundleBytes: number;
};

/**
 * Writes one artifact to a bundle in a directory the user controls.
 *
 * The source artifact is verified with the node's own credential first: a
 * backup of an artifact that already fails its runtime check would be a
 * faithful copy of something broken.
 */
export async function createArtifactBackup(input: {
  artifactDirectory: string;
  destinationDirectory: string;
  excludedRoots: readonly string[];
  runtimeManifest: {
    deploymentId: string;
    projectId: string;
    artifactId: string;
    commit: string;
    checksum: string;
    sizeBytes: number;
    contract: Record<string, unknown>;
    createdAt: number;
    verifiedAt: number;
  };
  workspaceId: string;
  entrypoint: string;
}): Promise<BackupCreateResult> {
  const artifactRoot = await realpath(input.artifactDirectory).catch(() => fail('artifact_not_found'));
  const destination = path.resolve(input.destinationDirectory);
  if (!path.isAbsolute(input.destinationDirectory)) fail('destination_invalid');
  const destinationInfo = await lstat(destination).catch(() => fail('destination_invalid'));
  if (!destinationInfo.isDirectory() || destinationInfo.isSymbolicLink()) fail('destination_invalid');
  const destinationReal = await realpath(destination);
  // The destination must not live inside anything the Agent manages, and must
  // not contain the artifact it is copying.
  for (const guarded of [...input.excludedRoots, artifactRoot]) {
    const resolved = path.resolve(guarded);
    const inward = path.relative(resolved, destinationReal);
    const outward = path.relative(destinationReal, resolved);
    if (inward === '' || (inward && !inward.startsWith('..') && !path.isAbsolute(inward))) fail('destination_overlap');
    if (outward && !outward.startsWith('..') && !path.isAbsolute(outward)) fail('destination_overlap');
  }

  const files = await collectPayload(artifactRoot);
  const recomputed = await payloadChecksum(files, (record) =>
    createReadStream(path.join(artifactRoot, ...record.path.split('/')), { highWaterMark: CHUNK }) as AsyncIterable<Buffer>);
  if (recomputed.checksum !== input.runtimeManifest.checksum) fail('artifact_corrupted');

  const manifest: BackupManifest = {
    formatVersion: BACKUP_FORMAT_VERSION,
    artifactId: input.runtimeManifest.artifactId,
    deploymentId: input.runtimeManifest.deploymentId,
    projectId: input.runtimeManifest.projectId,
    workspaceId: input.workspaceId,
    artifactChecksum: recomputed.checksum,
    artifactSizeBytes: recomputed.sizeBytes,
    fileCount: files.length,
    files,
    createdAt: Date.now(),
    createdByAgentVersion: CURRENT_AGENT_VERSION,
    platform: process.platform,
    arch: process.arch,
    nodeMajor: Number(process.versions.node.split('.')[0]),
    entrypoint: input.entrypoint,
    commit: input.runtimeManifest.commit,
    runtime: {
      contract: input.runtimeManifest.contract,
      createdAt: input.runtimeManifest.createdAt,
      verifiedAt: input.runtimeManifest.verifiedAt,
    },
  };
  if (!validateBackupManifest(JSON.parse(JSON.stringify(manifest)))) fail('manifest_invalid');

  const bundle = path.join(destinationReal, backupFileName(manifest.artifactId, manifest.artifactChecksum));
  if (await stat(bundle).then(() => true).catch(() => false)) fail('already_exists');
  const free = await freeBytes(destinationReal).catch(() => Number.MAX_SAFE_INTEGER);
  if (free < recomputed.sizeBytes + BACKUP_LIMITS.reserveBytes) fail('low_disk');

  const manifestBytes = Buffer.from(`${stableJson(manifest as unknown as Record<string, unknown>)}\n`, 'utf8');
  if (manifestBytes.length > BACKUP_LIMITS.manifestBytes) fail('manifest_invalid');

  // A partial write never carries the final name.
  const temporary = `${bundle}.partial-${process.pid.toString(16)}${Date.now().toString(16)}`;
  const outer = createHash('sha256');
  let bundleBytes = 0;
  const handle = await open(temporary, 'wx', 0o600);
  try {
    const put = async (chunk: Buffer) => {
      outer.update(chunk);
      bundleBytes += chunk.length;
      await handle.write(chunk);
    };
    const pad = async (size: number) => {
      const remainder = size % BLOCK;
      if (remainder !== 0) await put(Buffer.alloc(BLOCK - remainder));
    };
    await put(tarHeader(BACKUP_MANIFEST_ENTRY, manifestBytes.length));
    await put(manifestBytes);
    await pad(manifestBytes.length);
    for (const [index, record] of files.entries()) {
      const source = path.join(artifactRoot, ...record.path.split('/'));
      const live = await lstat(source).catch(() => fail('source_changed'));
      if (!live.isFile() || live.size !== record.size) fail('source_changed');
      await put(tarHeader(payloadEntryName(index), record.size));
      let written = 0;
      for await (const chunk of createReadStream(source, { highWaterMark: CHUNK })) {
        written += (chunk as Buffer).length;
        if (written > record.size) fail('source_changed');
        await put(chunk as Buffer);
      }
      if (written !== record.size) fail('source_changed');
      await pad(record.size);
    }
    await put(Buffer.alloc(BLOCK * 2));
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => {});
    await rm(temporary, { force: true });
    throw error;
  }
  await handle.close();
  await rename(temporary, bundle);
  await syncDirectory(destinationReal);
  return {
    outcome: 'created',
    bundle,
    bundleSha256: outer.digest('hex'),
    artifactId: manifest.artifactId,
    artifactChecksum: manifest.artifactChecksum,
    fileCount: manifest.fileCount,
    payloadBytes: manifest.artifactSizeBytes,
    bundleBytes,
  };
}

/**
 * Best-effort directory flush after a rename.
 *
 * POSIX makes the rename durable only once the directory itself is synced.
 * Windows has no equivalent and returns EPERM/EISDIR here, which is not a
 * failure -- the rename is already ordered after the file's own sync.
 */
async function syncDirectory(directory: string): Promise<void> {
  try {
    const handle = await open(directory, 'r');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch { /* Not supported on this platform. */ }
}

// ---------------------------------------------------------------------------
// Verify (offline).
// ---------------------------------------------------------------------------

export type BackupVerifyResult = {
  outcome: 'verified';
  artifactId: string;
  deploymentId: string;
  projectId: string;
  workspaceId: string;
  artifactChecksum: string;
  fileCount: number;
  payloadBytes: number;
  createdAt: number;
  createdByAgentVersion: string;
  platform: string;
  arch: string;
  nodeMajor: number;
  bundleSha256: string;
  compatibleHere: boolean;
  compatibility: BackupReasonCode | null;
};

/**
 * Reads a bundle and proves it is internally consistent.
 *
 * No credential, no control plane, no network. This checks integrity and
 * self-consistency -- that the payload is exactly what the manifest describes
 * and nothing has been truncated or altered. It is deliberately not a proof of
 * origin: nothing in a bundle could only have been produced by YSD.
 */
export async function verifyArtifactBackup(
  bundlePath: string,
  sink?: (record: BackupFileRecord, chunk: Buffer) => Promise<void> | void,
): Promise<{ result: BackupVerifyResult; manifest: BackupManifest }> {
  const info = await lstat(bundlePath).catch(() => fail('bundle_unreadable'));
  if (!info.isFile() || info.isSymbolicLink()) fail('bundle_unreadable');
  const outer = createHash('sha256');
  const stream = createReadStream(bundlePath, { highWaterMark: CHUNK });
  const reader = new ByteReader((async function* () {
    for await (const chunk of stream) {
      outer.update(chunk as Buffer);
      yield chunk as Buffer;
    }
  })()[Symbol.asyncIterator]());

  const readEntry = async (): Promise<{ name: string; size: number } | 'terminator' | 'eof'> => {
    const header = await reader.read(BLOCK);
    // Running out of bytes is not the same as being told the archive ended.
    if (header === null) return 'eof';
    if (header.every((byte) => byte === 0)) return 'terminator';
    if (!validTarChecksum(header)) fail('bundle_malformed');
    const type = String.fromCharCode(header[156] || 0);
    if (type !== '0' && type !== '\0') fail('entry_unsupported');
    if (tarString(header, 345, 155) !== '') fail('entry_unsupported');
    if (tarString(header, 157, 100) !== '') fail('entry_unsupported');
    return { name: tarString(header, 0, 100), size: tarOctal(header, 124, 12) };
  };
  const skipPadding = async (size: number) => {
    const remainder = size % BLOCK;
    if (remainder !== 0) await reader.drain(BLOCK - remainder, () => {});
  };

  const first = await readEntry();
  if (first === 'eof') fail('bundle_truncated');
  if (first === 'terminator' || first.name !== BACKUP_MANIFEST_ENTRY) fail('bundle_malformed');
  if (first.size > BACKUP_LIMITS.manifestBytes) fail('manifest_invalid');
  const manifestChunks: Buffer[] = [];
  await reader.drain(first.size, (chunk) => { manifestChunks.push(chunk); });
  await skipPadding(first.size);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(Buffer.concat(manifestChunks)));
  } catch {
    fail('manifest_invalid');
  }
  if (isRecordLike(parsed) && parsed.formatVersion !== BACKUP_FORMAT_VERSION) fail('manifest_unsupported');
  const manifest = validateBackupManifest(parsed);
  if (!manifest) fail('manifest_invalid');

  const hash = createHash('sha256');
  let sizeBytes = 0;
  for (const [index, record] of manifest.files.entries()) {
    const entry = await readEntry();
    if (entry === 'eof' || entry === 'terminator') fail('bundle_truncated');
    if (entry.name !== payloadEntryName(index) || entry.size !== record.size) fail('bundle_malformed');
    const perFile = createHash('sha256');
    hash.update(record.path);
    hash.update('\0');
    await reader.drain(entry.size, async (chunk) => {
      perFile.update(chunk);
      hash.update(chunk);
      sizeBytes += chunk.length;
      if (sink) await sink(record, chunk);
    });
    hash.update('\0');
    if (perFile.digest('hex') !== record.sha256) fail('payload_mismatch');
    await skipPadding(entry.size);
  }
  if (sizeBytes !== manifest.artifactSizeBytes) fail('payload_mismatch');
  if (`sha256:${hash.digest('hex')}` !== manifest.artifactChecksum) fail('payload_mismatch');
  // The archive must say it ended. Trailing members would mean the bundle
  // describes more than its manifest declares; a bare end of file means the
  // terminator was lost, which is a truncated bundle rather than a complete one.
  const closing = await readEntry();
  if (closing === 'eof') fail('bundle_truncated');
  if (closing !== 'terminator') fail('bundle_malformed');
  for await (const _ of stream) { /* drain the terminator padding */ }

  const compatibility = evaluateBackupCompatibility({
    manifest,
    platform: process.platform,
    arch: process.arch,
    nodeMajor: Number(process.versions.node.split('.')[0]),
    supportedNodeMajors: APP_RUNTIME_LIMITS.supportedNodeMajors,
  });
  return {
    manifest,
    result: {
      outcome: 'verified',
      artifactId: manifest.artifactId,
      deploymentId: manifest.deploymentId,
      projectId: manifest.projectId,
      workspaceId: manifest.workspaceId,
      artifactChecksum: manifest.artifactChecksum,
      fileCount: manifest.fileCount,
      payloadBytes: manifest.artifactSizeBytes,
      createdAt: manifest.createdAt,
      createdByAgentVersion: manifest.createdByAgentVersion,
      platform: manifest.platform,
      arch: manifest.arch,
      nodeMajor: manifest.nodeMajor,
      bundleSha256: outer.digest('hex'),
      compatibleHere: compatibility.compatible,
      compatibility: compatibility.reason,
    },
  };
}

function isRecordLike(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Restore.
// ---------------------------------------------------------------------------

export type BackupRestoreResult = {
  outcome: 'restored' | 'already_restored';
  artifactId: string;
  deploymentId: string;
  artifactChecksum: string;
  fileCount: number;
  payloadBytes: number;
};

/**
 * Rehydrates one missing artifact on the node that already owns it.
 *
 * The bundle supplies bytes and nothing else. Identity comes from the control
 * plane, the runtime manifest is rebuilt and re-signed with this node's own
 * token, and the artifact only becomes visible to the rest of the system in the
 * final rename -- so an interrupted restore leaves a directory the retention
 * pass never looks at, not a half-formed artifact.
 */
export async function restoreArtifactBackup(input: {
  bundlePath: string;
  deploymentDirectory: string;
  authoritative: RestoreIdentity;
  authenticatedNodeId: string;
  token: string;
}): Promise<BackupRestoreResult> {
  const { manifest } = await verifyArtifactBackup(input.bundlePath);

  const identity = evaluateRestoreIdentity({
    manifest,
    authoritative: input.authoritative,
    authenticatedNodeId: input.authenticatedNodeId,
  });
  if (!identity.allowed) fail(identity.reason!);

  const compatibility = evaluateBackupCompatibility({
    manifest,
    platform: process.platform,
    arch: process.arch,
    nodeMajor: Number(process.versions.node.split('.')[0]),
    supportedNodeMajors: APP_RUNTIME_LIMITS.supportedNodeMajors,
  });
  if (!compatibility.compatible) fail(compatibility.reason!);

  const deploymentRoot = path.resolve(input.deploymentDirectory);
  const artifactsRoot = path.join(deploymentRoot, 'artifacts');
  const finalPath = path.join(artifactsRoot, manifest.artifactId);
  assertInside(deploymentRoot, finalPath);

  const existing = await readExistingChecksum(finalPath);
  const collision = evaluateArtifactCollision({
    existingChecksum: existing,
    bundleChecksum: manifest.artifactChecksum,
  });
  if (collision.action === 'refuse') fail('artifact_conflict');
  if (collision.action === 'already_restored') {
    return {
      outcome: 'already_restored',
      artifactId: manifest.artifactId,
      deploymentId: manifest.deploymentId,
      artifactChecksum: manifest.artifactChecksum,
      fileCount: manifest.fileCount,
      payloadBytes: manifest.artifactSizeBytes,
    };
  }

  const free = await freeBytes(deploymentRoot).catch(() => Number.MAX_SAFE_INTEGER);
  if (free < manifest.artifactSizeBytes + BACKUP_LIMITS.reserveBytes) fail('low_disk');

  // Staging lives outside `artifacts/` on purpose: retention prunes any
  // directory it finds there, whatever the name.
  const stagingRoot = path.join(deploymentRoot, '.restore-tmp');
  await mkdir(stagingRoot, { recursive: true, mode: 0o700 });
  const lock = path.join(stagingRoot, `${manifest.artifactId}.lock`);
  const lockHandle = await open(lock, 'wx').catch(() => fail('restore_busy'));
  const staging = path.join(stagingRoot, `${manifest.artifactId}.incoming`);
  try {
    await rm(staging, { recursive: true, force: true });
    await mkdir(staging, { recursive: true, mode: 0o700 });

    let handle: Awaited<ReturnType<typeof open>> | null = null;
    let openPath = '';
    await verifyArtifactBackup(input.bundlePath, async (record, chunk) => {
      const target = path.join(staging, ...record.path.split('/'));
      assertInside(staging, target);
      if (openPath !== record.path) {
        if (handle) await handle.close();
        await mkdir(path.dirname(target), { recursive: true });
        handle = await open(target, 'wx', record.executable ? 0o700 : 0o600);
        openPath = record.path;
      }
      await handle!.write(chunk);
    });
    if (handle) await (handle as Awaited<ReturnType<typeof open>>).close();
    // Zero-byte files never reach the sink, so create whatever is still absent.
    for (const record of manifest.files) {
      const target = path.join(staging, ...record.path.split('/'));
      if (!(await stat(target).then(() => true).catch(() => false))) {
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, Buffer.alloc(0), { flag: 'wx', mode: record.executable ? 0o700 : 0o600 });
      }
    }

    const staged = await payloadChecksum(manifest.files, (record) =>
      createReadStream(path.join(staging, ...record.path.split('/')), { highWaterMark: CHUNK }) as AsyncIterable<Buffer>);
    if (staged.checksum !== manifest.artifactChecksum || staged.sizeBytes !== manifest.artifactSizeBytes) {
      fail('payload_mismatch');
    }

    // The runtime manifest is rebuilt here, never copied: its signature is an
    // HMAC over a node token, and the only token that may sign an artifact this
    // node will run is this node's own.
    const runtimeManifest = {
      version: 1 as const,
      deploymentId: manifest.deploymentId,
      projectId: manifest.projectId,
      artifactId: manifest.artifactId,
      commit: manifest.commit,
      checksum: manifest.artifactChecksum,
      sizeBytes: manifest.artifactSizeBytes,
      contract: manifest.runtime.contract,
      createdAt: manifest.runtime.createdAt,
      verifiedAt: manifest.runtime.verifiedAt,
    };
    const signature = await signText(
      input.token,
      `ysd-app-artifact-v1\n${stableJson(runtimeManifest as unknown as Record<string, unknown>)}`,
    );
    await writeFile(
      path.join(staging, RUNTIME_MANIFEST_NAME),
      stableJson({ ...runtimeManifest, signature } as unknown as Record<string, unknown>),
      { flag: 'wx', mode: 0o600 },
    );

    await mkdir(artifactsRoot, { recursive: true, mode: 0o700 });
    if (await stat(finalPath).then(() => true).catch(() => false)) fail('artifact_conflict');
    await rename(staging, finalPath);
    await syncDirectory(artifactsRoot);
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => {});
    await lockHandle.close().catch(() => {});
    await rm(lock, { force: true }).catch(() => {});
  }

  return {
    outcome: 'restored',
    artifactId: manifest.artifactId,
    deploymentId: manifest.deploymentId,
    artifactChecksum: manifest.artifactChecksum,
    fileCount: manifest.fileCount,
    payloadBytes: manifest.artifactSizeBytes,
  };
}

/** The checksum an already-present artifact reports, or `null` if absent. */
async function readExistingChecksum(artifactPath: string): Promise<string | null> {
  const info = await lstat(artifactPath).catch(() => null);
  if (!info) return null;
  if (!info.isDirectory()) fail('artifact_conflict');
  try {
    const parsed: unknown = JSON.parse(await readFile(path.join(artifactPath, RUNTIME_MANIFEST_NAME), 'utf8'));
    if (isRecordLike(parsed) && typeof parsed.checksum === 'string') return parsed.checksum;
  } catch { /* Fall through to recomputing. */ }
  const files = await collectPayload(artifactPath);
  const recomputed = await payloadChecksum(files, (record) =>
    createReadStream(path.join(artifactPath, ...record.path.split('/')), { highWaterMark: CHUNK }) as AsyncIterable<Buffer>);
  return recomputed.checksum;
}

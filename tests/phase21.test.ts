/**
 * Phase 21: portable artifact backup, offline verification, same-node restore.
 *
 * These exercise the real streaming writer and reader against real files on
 * disk. A backup is only interesting if it survives being attacked, so most of
 * this file is about what must *not* happen: no path escaping the staging
 * directory, no reserved device name, no collision on a case-insensitive
 * filesystem, no artifact overwritten with different bytes, and no bundle
 * claiming an authenticity it cannot have.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';


import {
  BACKUP_EXTENSION,
  BACKUP_FORMAT_VERSION,
  BACKUP_LIMITS,
  RUNTIME_MANIFEST_NAME,
  backupFileName,
  canonicalBackupPath,
  evaluateArtifactCollision,
  evaluateBackupCompatibility,
  evaluateRestoreIdentity,
  findPathCollisions,
  validateBackupManifest,
} from '../lib/artifact-backup.ts';
import {
  BackupError,
  createArtifactBackup,
  restoreArtifactBackup,
  verifyArtifactBackup,
} from '../agent/artifact-backup.ts';
import { APP_RUNTIME_LIMITS } from '../lib/app-runtime.ts';
import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  parseArtifactBackupCapability,
  signText,
  stableJson,
} from '../lib/nodes.ts';

const NUL = String.fromCharCode(0);
const LF = String.fromCharCode(10);
const TOKEN = `node_${'a'.repeat(40)}`;
const IDS = {
  artifactId: `art_${'a'.repeat(24)}`,
  deploymentId: `dpl_${'b'.repeat(24)}`,
  projectId: `prj_${'c'.repeat(24)}`,
  workspaceId: `ws_${'d'.repeat(24)}`,
};
const NODE_ID = `node_${'e'.repeat(24)}`;

const repoRoot = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/(.:)/, '$1'));

/** The App Runtime's own checksum: sorted path, NUL, bytes, NUL. */
async function runtimeChecksum(root: string, files: readonly string[]) {
  const hash = createHash('sha256');
  let sizeBytes = 0;
  for (const relative of [...files].sort()) {
    const bytes = await readFile(path.join(root, ...relative.split('/')));
    hash.update(relative);
    hash.update(NUL);
    hash.update(bytes);
    hash.update(NUL);
    sizeBytes += bytes.length;
  }
  return { checksum: `sha256:${hash.digest('hex')}`, sizeBytes };
}

/** A real artifact directory with a real, correctly signed runtime manifest. */
async function makeArtifact(root: string, contents: Record<string, string>) {
  const deployment = path.join(root, 'deployments', IDS.deploymentId);
  const artifact = path.join(deployment, 'artifacts', IDS.artifactId);
  for (const [relative, body] of Object.entries(contents)) {
    const target = path.join(artifact, ...relative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, body);
  }
  const { checksum, sizeBytes } = await runtimeChecksum(artifact, Object.keys(contents));
  const runtime = {
    version: 1 as const,
    deploymentId: IDS.deploymentId,
    projectId: IDS.projectId,
    artifactId: IDS.artifactId,
    commit: 'f'.repeat(40),
    checksum,
    sizeBytes,
    contract: { version: 1, packageManager: 'npm', entrypoint: 'index.js' } as Record<string, unknown>,
    createdAt: 1_700_000_000_000,
    verifiedAt: 1_700_000_000_001,
  };
  await writeFile(
    path.join(artifact, RUNTIME_MANIFEST_NAME),
    stableJson({
      ...runtime,
      signature: await signText(TOKEN, `ysd-app-artifact-v1${LF}${stableJson(runtime)}`),
    } as unknown as Record<string, unknown>),
  );
  return { deployment, artifact, runtime, checksum, sizeBytes };
}

function authoritative(checksum: string) {
  return {
    workspaceId: IDS.workspaceId,
    projectId: IDS.projectId,
    deploymentId: IDS.deploymentId,
    nodeId: NODE_ID,
    currentArtifactId: IDS.artifactId,
    checksum,
  };
}

async function reason(action: () => Promise<unknown>): Promise<string> {
  try {
    await action();
  } catch (error) {
    if (error instanceof BackupError) return error.reason;
    return `unexpected:${(error as Error).message}`;
  }
  return 'no-error';
}

/**
 * Restore refuses to install an artifact onto a Node major the App Runtime
 * cannot run, which is correct and is exactly what these three tests would
 * trip over on an unsupported runner. They run for real under the prepared
 * Node.js 26 runtime, alongside the rest of the acceptance suite.
 */
const HOST_NODE_MAJOR = Number(process.versions.node.split('.')[0]);
const RUNTIME_SUPPORTED = APP_RUNTIME_LIMITS.supportedNodeMajors.includes(HOST_NODE_MAJOR);
const NEEDS_RUNTIME = RUNTIME_SUPPORTED
  ? undefined
  : { skip: `restore needs a Node.js runtime the App Runtime supports (${APP_RUNTIME_LIMITS.supportedNodeMajors.join(' or ')})` };

async function temporary(label: string): Promise<string> {
  return await mkdtemp(path.join(os.tmpdir(), `ysd-phase21-${label}-`));
}

// ---------------------------------------------------------------------------
// Path rules. These run everywhere, so they are checked on their own.
// ---------------------------------------------------------------------------

void test('a backup path may only be a plain relative path', () => {
  for (const safe of ['index.js', 'src/a.js', 'node_modules/.package-lock.json', 'a/b/c/d.txt']) {
    assert.equal(canonicalBackupPath(safe), safe, safe);
  }
  const hostile = [
    '../escape', 'a/../b', './a', '/absolute', 'C:\\escape', 'C:/escape',
    '\\\\server\\share', '\\\\?\\C:\\x', 'foo:bar', 'a//b', '',
    'NUL', 'NUL.txt', 'nul.TXT', 'con.js', 'CON', 'COM1', 'com9.log', 'LPT9.log', 'AUX', 'PRN',
    'foo.', 'foo ', 'a/foo.', `a${NUL}b`, `line${LF}break`,
  ];
  for (const value of hostile) {
    assert.equal(canonicalBackupPath(value), null, JSON.stringify(value));
  }
  // A backslash is a separator, not a name, so these are the same path -- which
  // is exactly why they must not both appear in one bundle.
  assert.equal(canonicalBackupPath('a\\b'), 'a/b');
  assert.equal(Buffer.byteLength('x'.repeat(BACKUP_LIMITS.pathBytes + 1)), BACKUP_LIMITS.pathBytes + 1);
  assert.equal(canonicalBackupPath('x'.repeat(BACKUP_LIMITS.pathBytes + 1)), null);
});

void test('paths that a case-insensitive filesystem would merge are collisions', () => {
  assert.deepEqual(findPathCollisions(['Foo.js', 'foo.js']), ['foo.js']);
  assert.deepEqual(findPathCollisions(['a/b', 'a/B']), ['a/B']);
  assert.deepEqual(findPathCollisions(['a.js', 'b.js']), []);
});

// ---------------------------------------------------------------------------
// Manifest.
// ---------------------------------------------------------------------------

function sampleManifest() {
  return {
    formatVersion: BACKUP_FORMAT_VERSION,
    artifactId: IDS.artifactId,
    deploymentId: IDS.deploymentId,
    projectId: IDS.projectId,
    workspaceId: IDS.workspaceId,
    artifactChecksum: `sha256:${'a'.repeat(64)}`,
    artifactSizeBytes: 3,
    fileCount: 1,
    files: [{ path: 'index.js', size: 3, sha256: 'b'.repeat(64), executable: false }],
    createdAt: 1,
    createdByAgentVersion: '0.8.0',
    platform: 'win32',
    arch: 'x64',
    nodeMajor: 26,
    entrypoint: 'index.js',
    commit: 'c'.repeat(40),
    runtime: { contract: { packageManager: 'npm' }, createdAt: 1, verifiedAt: 2 },
  };
}

void test('the backup manifest is strict, bounded, and never carries a secret', () => {
  assert.ok(validateBackupManifest(sampleManifest()));
  // A credential smuggled into the manifest is an unknown key, and unknown keys
  // are refused outright rather than ignored.
  assert.equal(validateBackupManifest({ ...sampleManifest(), token: TOKEN }), null);
  assert.equal(validateBackupManifest({ ...sampleManifest(), formatVersion: 2 }), null);
  assert.equal(validateBackupManifest({ ...sampleManifest(), workspaceId: 'ws_nothex' }), null);
  // Declared totals must agree with the records they summarise.
  assert.equal(validateBackupManifest({ ...sampleManifest(), fileCount: 2 }), null);
  assert.equal(validateBackupManifest({ ...sampleManifest(), artifactSizeBytes: 4 }), null);
  // The runtime manifest never travels as a payload file.
  assert.equal(validateBackupManifest({
    ...sampleManifest(),
    files: [{ path: RUNTIME_MANIFEST_NAME, size: 3, sha256: 'b'.repeat(64), executable: false }],
  }), null);
  // Unsafe and colliding paths are rejected at the manifest, before any I/O.
  assert.equal(validateBackupManifest({
    ...sampleManifest(),
    files: [{ path: '../escape', size: 3, sha256: 'b'.repeat(64), executable: false }],
  }), null);
  assert.equal(validateBackupManifest({
    ...sampleManifest(), fileCount: 2, artifactSizeBytes: 6,
    files: [
      { path: 'Foo.js', size: 3, sha256: 'b'.repeat(64), executable: false },
      { path: 'foo.js', size: 3, sha256: 'c'.repeat(64), executable: false },
    ],
  }), null);
  // Canonical ordering, so one artifact always describes itself identically.
  assert.equal(validateBackupManifest({
    ...sampleManifest(), fileCount: 2, artifactSizeBytes: 6,
    files: [
      { path: 'z.js', size: 3, sha256: 'b'.repeat(64), executable: false },
      { path: 'a.js', size: 3, sha256: 'c'.repeat(64), executable: false },
    ],
  }), null);
});

void test('the bundle filename is built only from identifiers the node trusts', () => {
  const name = backupFileName(IDS.artifactId, `sha256:${'a'.repeat(64)}`);
  assert.equal(name, `ysd-artifact-${IDS.artifactId}-${'a'.repeat(12)}${BACKUP_EXTENSION}`);
  assert.doesNotMatch(name, /[\\/:*?"<>|]/);
  assert.throws(() => backupFileName('../evil', `sha256:${'a'.repeat(64)}`));
});

// ---------------------------------------------------------------------------
// Decision rules.
// ---------------------------------------------------------------------------

void test('restore is refused unless the bundle is this deployment on this node', () => {
  const manifest = sampleManifest();
  const base = authoritative(manifest.artifactChecksum);
  assert.equal(evaluateRestoreIdentity({ manifest, authoritative: base, authenticatedNodeId: NODE_ID }).allowed, true);
  // The node gate comes first: a deployment owned elsewhere is never this
  // Agent's to rehydrate, whatever the bundle says.
  assert.equal(evaluateRestoreIdentity({
    manifest, authoritative: base, authenticatedNodeId: `node_${'9'.repeat(24)}`,
  }).reason, 'wrong_node');
  for (const [field, value] of [
    ['workspaceId', `ws_${'9'.repeat(24)}`],
    ['projectId', `prj_${'9'.repeat(24)}`],
    ['deploymentId', `dpl_${'9'.repeat(24)}`],
    ['currentArtifactId', `art_${'9'.repeat(24)}`],
    ['checksum', `sha256:${'9'.repeat(64)}`],
  ] as const) {
    assert.equal(evaluateRestoreIdentity({
      manifest,
      authoritative: { ...base, [field]: value },
      authenticatedNodeId: NODE_ID,
    }).reason, 'identity_mismatch', field);
  }
});

void test('an existing artifact is never overwritten with different bytes', () => {
  const mine = `sha256:${'a'.repeat(64)}`;
  assert.equal(evaluateArtifactCollision({ existingChecksum: null, bundleChecksum: mine }).action, 'restore');
  assert.equal(evaluateArtifactCollision({ existingChecksum: mine, bundleChecksum: mine }).action, 'already_restored');
  const other = evaluateArtifactCollision({ existingChecksum: `sha256:${'b'.repeat(64)}`, bundleChecksum: mine });
  assert.equal(other.action, 'refuse');
  assert.equal(other.reason, 'artifact_conflict');
});

void test('a backup only restores where its build can actually run', () => {
  const here = { platform: 'win32', arch: 'x64', nodeMajor: 26 };
  const supported = APP_RUNTIME_LIMITS.supportedNodeMajors;
  assert.equal(evaluateBackupCompatibility({ manifest: here, ...here, supportedNodeMajors: supported }).compatible, true);
  assert.equal(evaluateBackupCompatibility({
    manifest: { ...here, platform: 'linux' }, ...here, supportedNodeMajors: supported,
  }).reason, 'incompatible_platform');
  assert.equal(evaluateBackupCompatibility({
    manifest: { ...here, arch: 'arm64' }, ...here, supportedNodeMajors: supported,
  }).reason, 'incompatible_platform');
  assert.equal(evaluateBackupCompatibility({
    manifest: { ...here, nodeMajor: 18 }, ...here, supportedNodeMajors: supported,
  }).reason, 'incompatible_runtime');
});

// ---------------------------------------------------------------------------
// The real thing, on disk.
// ---------------------------------------------------------------------------

void test('a backup round-trips: create, verify offline, restore, re-sign', NEEDS_RUNTIME, async () => {
  const root = await temporary('roundtrip');
  try {
    const made = await makeArtifact(root, {
      'index.js': 'console.log(1);\n',
      'src/a.js': 'export const a = 1;\n',
      'empty.txt': '',
      'node_modules/left-pad/package.json': '{"name":"left-pad"}\n',
    });
    const output = path.join(root, 'external');
    await mkdir(output);

    const created = await createArtifactBackup({
      artifactDirectory: made.artifact,
      destinationDirectory: output,
      excludedRoots: [path.join(root, 'deployments')],
      runtimeManifest: made.runtime,
      workspaceId: IDS.workspaceId,
      entrypoint: 'index.js',
    });
    assert.equal(created.outcome, 'created');
    assert.equal(created.artifactChecksum, made.checksum);
    assert.equal(created.fileCount, 4);
    assert.match(path.basename(created.bundle), /^ysd-artifact-art_[a-f0-9]{24}-[a-f0-9]{12}\.ysdbak$/);
    // Nothing partial is left behind under the final name or beside it.
    assert.deepEqual((await readdir(output)).sort(), [path.basename(created.bundle)]);

    const verified = await verifyArtifactBackup(created.bundle);
    assert.equal(verified.result.outcome, 'verified');
    assert.equal(verified.result.artifactChecksum, made.checksum);
    assert.equal(verified.result.bundleSha256, created.bundleSha256);
    // The verify result names no path and carries no credential.
    const summary = JSON.stringify(verified.result);
    assert.doesNotMatch(summary, /node_[a-f0-9]{40}|[A-Za-z]:\\\\|\/tmp\//);

    // Lose the artifact, then put it back.
    await rm(made.artifact, { recursive: true, force: true });
    const restored = await restoreArtifactBackup({
      bundlePath: created.bundle,
      deploymentDirectory: made.deployment,
      authoritative: authoritative(made.checksum),
      authenticatedNodeId: NODE_ID,
      token: TOKEN,
    });
    assert.equal(restored.outcome, 'restored');

    // Every byte is back, and the checksum the App Runtime computes agrees.
    const after = await runtimeChecksum(made.artifact, [
      'empty.txt', 'index.js', 'node_modules/left-pad/package.json', 'src/a.js',
    ]);
    assert.equal(after.checksum, made.checksum);

    // The runtime manifest was rebuilt and signed with THIS node's token --
    // the backup never carried the original signature.
    const rebuilt = JSON.parse(await readFile(path.join(made.artifact, RUNTIME_MANIFEST_NAME), 'utf8'));
    assert.equal(rebuilt.checksum, made.checksum);
    assert.equal(typeof rebuilt.signature, 'string');
    const { signature, ...unsigned } = rebuilt;
    const { verifyTextSignature } = await import('../lib/nodes.ts');
    assert.equal(await verifyTextSignature(TOKEN, `ysd-app-artifact-v1${LF}${stableJson(unsigned)}`, signature), true);
    assert.equal(await verifyTextSignature(`node_${'z'.repeat(40)}`, `ysd-app-artifact-v1${LF}${stableJson(unsigned)}`, signature), false);

    // Restoring again is a no-op, not a rewrite.
    const again = await restoreArtifactBackup({
      bundlePath: created.bundle,
      deploymentDirectory: made.deployment,
      authoritative: authoritative(made.checksum),
      authenticatedNodeId: NODE_ID,
      token: TOKEN,
    });
    assert.equal(again.outcome, 'already_restored');
    // And no staging survives a completed restore.
    assert.deepEqual(await readdir(path.join(made.deployment, '.restore-tmp')), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('the backup carries the payload and refuses to include the runtime manifest', async () => {
  const root = await temporary('payload');
  try {
    const made = await makeArtifact(root, { 'index.js': 'console.log(1);\n' });
    const output = path.join(root, 'external');
    await mkdir(output);
    const created = await createArtifactBackup({
      artifactDirectory: made.artifact,
      destinationDirectory: output,
      excludedRoots: [path.join(root, 'deployments')],
      runtimeManifest: made.runtime,
      workspaceId: IDS.workspaceId,
      entrypoint: 'index.js',
    });
    const { manifest } = await verifyArtifactBackup(created.bundle);
    assert.deepEqual(manifest.files.map((file) => file.path), ['index.js']);
    // The signature that only the source node could produce is not in the file.
    const bytes = await readFile(created.bundle, 'utf8');
    assert.doesNotMatch(bytes, new RegExp(RUNTIME_MANIFEST_NAME.replace('.', '\\.')));
    assert.doesNotMatch(bytes, new RegExp(TOKEN));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('a backup destination inside Agent storage is refused', async () => {
  const root = await temporary('overlap');
  try {
    const made = await makeArtifact(root, { 'index.js': 'x\n' });
    const inside = path.join(root, 'deployments', 'inside');
    await mkdir(inside, { recursive: true });
    const create = (destinationDirectory: string) => createArtifactBackup({
      artifactDirectory: made.artifact,
      destinationDirectory,
      excludedRoots: [path.join(root, 'deployments')],
      runtimeManifest: made.runtime,
      workspaceId: IDS.workspaceId,
      entrypoint: 'index.js',
    });
    assert.equal(await reason(() => create(inside)), 'destination_overlap');
    assert.equal(await reason(() => create(made.artifact)), 'destination_overlap');
    assert.equal(await reason(() => create(path.join(root, 'missing'))), 'destination_invalid');
    assert.equal(await reason(() => create('relative/path')), 'destination_invalid');

    // A second backup to the same place does not silently replace the first.
    const output = path.join(root, 'external');
    await mkdir(output);
    await create(output);
    assert.equal(await reason(() => create(output)), 'already_exists');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('a corrupted or truncated bundle never verifies', async () => {
  const root = await temporary('corrupt');
  try {
    const made = await makeArtifact(root, { 'index.js': 'console.log(1);\n', 'b.js': 'export const b = 2;\n' });
    const output = path.join(root, 'external');
    await mkdir(output);
    const created = await createArtifactBackup({
      artifactDirectory: made.artifact,
      destinationDirectory: output,
      excludedRoots: [path.join(root, 'deployments')],
      runtimeManifest: made.runtime,
      workspaceId: IDS.workspaceId,
      entrypoint: 'index.js',
    });
    const original = await readFile(created.bundle);

    // One byte of payload.
    const flipped = Buffer.from(original);
    const marker = flipped.indexOf(Buffer.from('console.log(1);'));
    assert.ok(marker > 0);
    flipped[marker] = flipped[marker]! ^ 0x01;
    const flippedPath = path.join(output, `flipped${BACKUP_EXTENSION}`);
    await writeFile(flippedPath, flipped);
    assert.equal(await reason(() => verifyArtifactBackup(flippedPath)), 'payload_mismatch');

    // Cut short.
    // Losing only the terminator still means the file stopped early.
    const cut = path.join(output, `cut${BACKUP_EXTENSION}`);
    await writeFile(cut, original.subarray(0, original.length - 1024));
    assert.equal(await reason(() => verifyArtifactBackup(cut)), 'bundle_truncated');

    // And losing part of the payload as well.
    const deepCut = path.join(output, `deep${BACKUP_EXTENSION}`);
    await writeFile(deepCut, original.subarray(0, original.length - 1536));
    assert.equal(await reason(() => verifyArtifactBackup(deepCut)), 'bundle_truncated');

    // Not a bundle at all.
    const junk = path.join(output, `junk${BACKUP_EXTENSION}`);
    await writeFile(junk, Buffer.alloc(2048, 0x41));
    assert.equal(await reason(() => verifyArtifactBackup(junk)), 'bundle_malformed');

    // Missing entirely.
    assert.equal(await reason(() => verifyArtifactBackup(path.join(output, `gone${BACKUP_EXTENSION}`))), 'bundle_unreadable');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('restore refuses before it writes anything', async () => {
  const root = await temporary('refuse');
  try {
    const made = await makeArtifact(root, { 'index.js': 'console.log(1);\n' });
    const output = path.join(root, 'external');
    await mkdir(output);
    const created = await createArtifactBackup({
      artifactDirectory: made.artifact,
      destinationDirectory: output,
      excludedRoots: [path.join(root, 'deployments')],
      runtimeManifest: made.runtime,
      workspaceId: IDS.workspaceId,
      entrypoint: 'index.js',
    });
    await rm(made.artifact, { recursive: true, force: true });
    const restore = (overrides: Record<string, unknown>, nodeId = NODE_ID) => restoreArtifactBackup({
      bundlePath: created.bundle,
      deploymentDirectory: made.deployment,
      authoritative: { ...authoritative(made.checksum), ...overrides },
      authenticatedNodeId: nodeId,
      token: TOKEN,
    });

    assert.equal(await reason(() => restore({}, `node_${'9'.repeat(24)}`)), 'wrong_node');
    assert.equal(await reason(() => restore({ workspaceId: `ws_${'9'.repeat(24)}` })), 'identity_mismatch');
    assert.equal(await reason(() => restore({ projectId: `prj_${'9'.repeat(24)}` })), 'identity_mismatch');
    assert.equal(await reason(() => restore({ deploymentId: `dpl_${'9'.repeat(24)}` })), 'identity_mismatch');
    assert.equal(await reason(() => restore({ currentArtifactId: `art_${'9'.repeat(24)}` })), 'identity_mismatch');
    assert.equal(await reason(() => restore({ checksum: `sha256:${'9'.repeat(64)}` })), 'identity_mismatch');

    // Every one of those refused before creating the artifact.
    assert.equal(await stat(made.artifact).then(() => true).catch(() => false), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('an artifact already present with different bytes is never replaced', NEEDS_RUNTIME, async () => {
  const root = await temporary('conflict');
  try {
    const made = await makeArtifact(root, { 'index.js': 'console.log(1);\n' });
    const output = path.join(root, 'external');
    await mkdir(output);
    const created = await createArtifactBackup({
      artifactDirectory: made.artifact,
      destinationDirectory: output,
      excludedRoots: [path.join(root, 'deployments')],
      runtimeManifest: made.runtime,
      workspaceId: IDS.workspaceId,
      entrypoint: 'index.js',
    });
    // Replace the on-disk artifact with different contents.
    await rm(made.artifact, { recursive: true, force: true });
    await mkdir(made.artifact, { recursive: true });
    await writeFile(path.join(made.artifact, 'index.js'), 'console.log(2);\n');

    assert.equal(await reason(() => restoreArtifactBackup({
      bundlePath: created.bundle,
      deploymentDirectory: made.deployment,
      authoritative: authoritative(made.checksum),
      authenticatedNodeId: NODE_ID,
      token: TOKEN,
    })), 'artifact_conflict');
    // The bytes that were there are still there.
    assert.equal(await readFile(path.join(made.artifact, 'index.js'), 'utf8'), 'console.log(2);\n');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('restore staging sits outside the directory retention prunes', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'artifact-backup.ts'), 'utf8');
  // Retention deletes any directory under `artifacts/` it does not recognise,
  // so a half-written restore must never be staged there.
  assert.match(source, /'\.restore-tmp'/);
  const staging = source.slice(source.indexOf('const stagingRoot'), source.indexOf('await rename(staging, finalPath)'));
  assert.doesNotMatch(staging, /path\.join\(artifactsRoot/);
  // And the artifact only exists after one atomic rename.
  assert.match(source, /await rename\(staging, finalPath\)/);
});

void test('the payload streams rather than being buffered', async () => {
  const source = await readFile(path.join(repoRoot, 'agent', 'artifact-backup.ts'), 'utf8');
  // A two-gigabyte artifact must not become a two-gigabyte Buffer.
  assert.doesNotMatch(source, /gunzipSync|readFileSync/);
  assert.doesNotMatch(source, /await readFile\(input\.bundlePath/);
  assert.match(source, /createReadStream/);
  assert.match(source, /highWaterMark: CHUNK/);
  // The one thing read whole is the manifest, and it is bounded first.
  assert.match(source, /if \(first\.size > BACKUP_LIMITS\.manifestBytes\) fail\('manifest_invalid'\)/);
});

void test('a large artifact backs up and restores without buffering it', NEEDS_RUNTIME, async () => {
  const root = await temporary('large');
  try {
    // Big enough that a full-buffer implementation would show up in the heap,
    // small enough not to waste the disk: 48 MiB of incompressible data.
    const block = Buffer.alloc(1024 * 1024);
    for (let index = 0; index < block.length; index += 1) block[index] = (index * 31 + 7) & 0xff;
    const deployment = path.join(root, 'deployments', IDS.deploymentId);
    const artifact = path.join(deployment, 'artifacts', IDS.artifactId);
    await mkdir(artifact, { recursive: true });
    const names: string[] = [];
    for (let file = 0; file < 48; file += 1) {
      const name = `chunk-${String(file).padStart(3, '0')}.bin`;
      await writeFile(path.join(artifact, name), block);
      names.push(name);
    }
    await writeFile(path.join(artifact, 'index.js'), 'console.log(1);\n');
    names.push('index.js');
    const { checksum, sizeBytes } = await runtimeChecksum(artifact, names);
    const runtime = {
      version: 1 as const, deploymentId: IDS.deploymentId, projectId: IDS.projectId,
      artifactId: IDS.artifactId, commit: 'f'.repeat(40), checksum, sizeBytes,
      contract: { version: 1, packageManager: 'npm', entrypoint: 'index.js' } as Record<string, unknown>,
      createdAt: 1, verifiedAt: 2,
    };
    await writeFile(path.join(artifact, RUNTIME_MANIFEST_NAME), stableJson({
      ...runtime,
      signature: await signText(TOKEN, `ysd-app-artifact-v1${LF}${stableJson(runtime)}`),
    } as unknown as Record<string, unknown>));

    const output = path.join(root, 'external');
    await mkdir(output);
    const before = process.memoryUsage().heapUsed;
    const created = await createArtifactBackup({
      artifactDirectory: artifact, destinationDirectory: output,
      excludedRoots: [path.join(root, 'deployments')], runtimeManifest: runtime,
      workspaceId: IDS.workspaceId, entrypoint: 'index.js',
    });
    await rm(artifact, { recursive: true, force: true });
    const restored = await restoreArtifactBackup({
      bundlePath: created.bundle, deploymentDirectory: deployment,
      authoritative: authoritative(checksum), authenticatedNodeId: NODE_ID, token: TOKEN,
    });
    const growth = process.memoryUsage().heapUsed - before;

    assert.equal(restored.outcome, 'restored');
    assert.equal(created.payloadBytes, sizeBytes);
    assert.ok(sizeBytes >= 48 * 1024 * 1024, `payload was ${sizeBytes} bytes`);
    assert.equal((await runtimeChecksum(artifact, names)).checksum, checksum);
    // Heap growth must be a small fraction of the payload, not proportional.
    assert.ok(growth < sizeBytes / 4, `heap grew ${growth} bytes for a ${sizeBytes} byte payload`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Scope and wording.
// ---------------------------------------------------------------------------

void test('the capability says what it can do and nothing about where backups live', () => {
  const capability = { version: 1 as const, supported: true, offlineVerify: true, sameNodeRestore: true };
  assert.deepEqual(parseArtifactBackupCapability(capability), capability);
  // No path, device or filename may ride along.
  assert.equal(parseArtifactBackupCapability({ ...capability, lastBackupPath: 'D:\\backups' }), null);
  // A node cannot claim support without the two things support means.
  assert.equal(parseArtifactBackupCapability({ ...capability, sameNodeRestore: false }), null);
  assert.equal(parseArtifactBackupCapability({ version: 1, supported: false, offlineVerify: true, sameNodeRestore: false }), null);
  assert.ok(parseArtifactBackupCapability({ version: 1, supported: false, offlineVerify: false, sameNodeRestore: false }));
  assert.equal(parseArtifactBackupCapability(undefined), null);
});

void test('Phase 21 adds no migration and claims no authenticity it cannot prove', async () => {
  const migrations = await readdir(path.join(repoRoot, 'db', 'migrations'));
  assert.equal(migrations.at(-1), '0020_runtime_recovery.sql');
  assert.equal(migrations.some((name) => name.startsWith('0021')), false);
  assert.equal(CURRENT_AGENT_VERSION, '0.9.0');
  assert.equal(NODE_PROTOCOL_VERSION, 1);
  assert.equal(JSON.parse(await readFile(path.join(repoRoot, 'package.json'), 'utf8')).version, '0.22.0');

  // Offline verification proves integrity, not provenance. Anything stronger
  // would be a claim about who wrote the bytes, which nothing here can support.
  for (const file of ['lib/artifact-backup.ts', 'agent/artifact-backup.ts']) {
    const source = await readFile(path.join(repoRoot, file), 'utf8');
    assert.doesNotMatch(source, /publisher.signed|authenticated backup|trusted backup|tamper.proof/i);
  }
  // The restore preflight is read-only.
  const preflight = await readFile(
    path.join(repoRoot, 'app', 'api', 'nodes', 'agent', 'deployments', '[id]', 'restore-preflight', 'route.ts'),
    'utf8',
  );
  assert.doesNotMatch(preflight, /INSERT|UPDATE|DELETE/i);
  const server = await readFile(path.join(repoRoot, 'lib', 'server', 'nodes.ts'), 'utf8');
  const block = server.slice(
    server.indexOf('export async function readArtifactRestorePreflight'),
    server.indexOf('export async function confirmArtifactRestore'),
  );
  assert.doesNotMatch(block, /INSERT |UPDATE |DELETE |recordAudit|enqueue/i);
  assert.match(block, /d\.nodeId = \?/);
});

void test('the Nodes page states the backup scope without offering to do it remotely', async () => {
  const view = await readFile(path.join(repoRoot, 'components', 'nodes-view.tsx'), 'utf8');
  assert.match(view, /Artifact backup · Supported/);
  assert.match(view, /Restores on this node only/);
  assert.match(view, /Offline verification supported/);
  // No control that would make the control plane touch a local filesystem.
  assert.doesNotMatch(view, /Back ?up now|Choose (a )?(local )?path|Restore file|browse/i);
  assert.doesNotMatch(view, /Restore to any node|cloud backup|encrypted backup/i);
});

void test('a healthy application stops advertising a recovery condition', async () => {
  const control = await readFile(path.join(repoRoot, 'lib', 'server', 'app-runtime-control.ts'), 'utf8');
  const update = control.slice(control.indexOf('`UPDATE deployment'));
  const sql = update.slice(1, update.indexOf('`', 1));
  // Restoring an artifact leaves the blocked recovery on record, and the
  // operator clears it by starting the deployment. A dashboard still reporting
  // `artifact_missing` beside a healthy service would be describing a state
  // that had ended. Recovery's own outcome still wins the first branch.
  assert.match(sql, /recoveryStatus = CASE WHEN \? = 'recover' THEN \?\s+WHEN \? = 1 AND \? = 'healthy' THEN NULL ELSE recoveryStatus END/);
  assert.match(sql, /recoveryReasonCode = CASE WHEN \? = 'recover' THEN \?\s+WHEN \? = 1 AND \? = 'healthy' THEN NULL ELSE recoveryReasonCode END/);
  // Placeholders and binds have to agree: a statement this long would
  // otherwise read every later value out of the wrong column, silently.
  const binds = update.slice(update.indexOf('.bind(') + '.bind('.length);
  let depth = 1;
  let end = 0;
  for (let i = 0; i < binds.length; i += 1) {
    if (binds[i] === '(') depth += 1;
    else if (binds[i] === ')') {
      depth -= 1;
      if (depth === 0) { end = i; break; }
    }
  }
  const written = binds.slice(0, end)
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
  let commas = 0;
  let nesting = 0;
  for (const character of written) {
    if ('([{'.includes(character)) nesting += 1;
    else if (')]}'.includes(character)) nesting -= 1;
    else if (character === ',' && nesting === 0) commas += 1;
  }
  assert.equal(commas, (sql.match(/\?/gu) ?? []).length);
});

void test('only a checked restore confirmation may call a lost artifact present again', async () => {
  const server = await readFile(path.join(repoRoot, 'lib', 'server', 'nodes.ts'), 'utf8');
  const block = server.slice(
    server.indexOf('export async function confirmArtifactRestore'),
    server.indexOf('export async function negotiatePrivatePort'),
  );
  assert.ok(block.length > 0, 'the restore confirmation is missing');

  // Identity comes from the database, scoped to the authenticated node, and
  // every supplied value has to agree with it.
  assert.match(block, /d\.nodeId = \?/);
  assert.match(block, /row\.nodeId !== context\.node\.id/);
  assert.match(block, /row\.artifactNodeId !== context\.node\.id/);
  assert.match(block, /row\.currentArtifactId !== artifactId/);
  assert.match(block, /row\.artifactState !== 'verified'/);
  assert.match(block, /constantTimeEqual\(checksum, row\.artifactChecksum\)/);
  assert.match(block, /\^dpl_\[a-f0-9\]\{24\}\$/);
  assert.match(block, /\^art_\[a-f0-9\]\{24\}\$/);
  assert.match(block, /\^sha256:\[a-f0-9\]\{64\}\$/);

  // The mutation is an availability projection and the condition it refutes.
  // Nothing that decides identity, ownership or intent may move.
  const writes = block.split('UPDATE ').slice(1).map((piece) => piece.slice(0, piece.indexOf('`')));
  assert.equal(writes.length, 2, 'restore confirmation should make exactly two writes');
  for (const write of writes) {
    // What a statement assigns is the question; scoping its WHERE clause by
    // node and deployment is the protection, not a violation of it.
    const assigns = write.slice(0, write.indexOf('WHERE'));
    for (const forbidden of [
      'nodeId =', 'currentArtifactId =', 'desiredState =', 'desiredRevision =',
      'checksum =', 'projectId =', 'workspaceId =', 'state =', 'deletedAt =',
      'commitSha =', 'localPort =',
    ]) {
      assert.ok(!assigns.includes(forbidden), `restore confirmation must not write ${forbidden}`);
    }
    const scope = write.slice(write.indexOf('WHERE'));
    assert.match(scope, /nodeId = \?/);
    assert.match(scope, /deletedAt IS NULL/);
  }
  assert.match(writes[0]!, /availabilityState = 'present'/);
  assert.match(writes[0]!, /AND checksum = \?/);
  assert.match(writes[1]!, /recoveryStatus = NULL/);
  assert.match(writes[1]!, /recoveryGeneration = NULL/);
  // No INSERT anywhere: confirming a restore never creates a row.
  assert.doesNotMatch(block, /INSERT INTO/);
});

void test('a restore confirmation only retires the condition it actually answers', async () => {
  const server = await readFile(path.join(repoRoot, 'lib', 'server', 'nodes.ts'), 'utf8');
  const block = server.slice(
    server.indexOf('export async function confirmArtifactRestore'),
    server.indexOf('export async function negotiatePrivatePort'),
  );
  // Bytes reappearing answers "the artifact is gone". It says nothing about a
  // port already in use or a runtime that will not start, and those conditions
  // must survive.
  assert.match(
    block,
    /availabilityCondition = new Set\(\['artifact_missing', 'artifact_corrupted', 'artifact_unavailable'\]\)/,
  );
  assert.match(block, /availabilityCondition\.has\(row\.recoveryReasonCode \?\? ''\)/);
  // Evidence is recorded as what it is: a node observation the control plane
  // acted on, never a person clicking something in a browser.
  assert.match(block, /actorType: 'system'/);
  assert.match(block, /actorId: 'system:artifact-restore'/);
  assert.doesNotMatch(block, /actorType: 'user'/);
  const catalog = await readFile(path.join(repoRoot, 'lib', 'audit-actions.ts'), 'utf8');
  const entry = catalog.slice(
    catalog.indexOf("action: 'deployment.artifact_restore'"),
    catalog.indexOf('},', catalog.indexOf("action: 'deployment.artifact_restore'")),
  );
  assert.match(entry, /critical: true/);
  for (const forbidden of ['path', 'file', 'destination', 'token', 'pid', 'user', 'bundle']) {
    assert.ok(!entry.includes(`'${forbidden}'`), `restore evidence must not carry ${forbidden}`);
  }
});

void test('restore reports success to the control plane only after the artifact verifies', async () => {
  const cli = await readFile(path.join(repoRoot, 'agent', 'cli.ts'), 'utf8');
  const block = cli.slice(cli.indexOf('async function runBackupRestore'));
  const body = block.slice(0, block.indexOf('\n}'));
  const verifyAt = body.indexOf('await verifyArtifact(');
  const confirmAt = body.indexOf('restore-complete');
  const renameAt = body.indexOf('await restoreArtifactBackup(');
  assert.ok(renameAt >= 0 && verifyAt > renameAt, 'the artifact is verified after it is put in place');
  assert.ok(confirmAt > verifyAt, 'the control plane is told only after verification');
  // Restore never starts anything: recovery stays Phase 18's job.
  for (const forbidden of ['startManagedApp', 'spawnManagedApp', "operation: 'start'", "'restart'"]) {
    assert.ok(!body.includes(forbidden), `restore must not call ${forbidden}`);
  }
});

void test('offline verification still needs nothing but the file', async () => {
  const cli = await readFile(path.join(repoRoot, 'agent', 'cli.ts'), 'utf8');
  const verify = cli.slice(
    cli.indexOf("} else if (arguments_.backupAction === 'verify') {"),
    cli.indexOf("} else if (arguments_.backupAction === 'create') {"),
  );
  // Adding a confirmation to restore must not have leaked a credential or a
  // network call into verify.
  for (const forbidden of ['loadCredentials', 'signedPost', 'credentials.', 'fetch(', 'origin']) {
    assert.ok(!verify.includes(forbidden), `offline verify must not use ${forbidden}`);
  }
});

void test('the restore confirmation only writes columns that exist', async () => {
  // A column that is not there is a runtime SQL error, and the Agent can only
  // report it as "the control plane could not be told" -- which reads like a
  // network problem and is not one. Cheaper to fail here than in an end-to-end
  // run. Built from string operations on purpose: an earlier version of this
  // check used nested regex literals, matched nothing, and passed anyway.
  const server = await readFile(path.join(repoRoot, 'lib', 'server', 'nodes.ts'), 'utf8');
  const block = server.slice(
    server.indexOf('export async function confirmArtifactRestore'),
    server.indexOf('export async function negotiatePrivatePort'),
  );
  const migrations = path.join(repoRoot, 'db', 'migrations');
  const files = (await readdir(migrations)).filter((name) => name.endsWith('.sql')).sort();
  const schema = (await Promise.all(
    files.map((name) => readFile(path.join(migrations, name), 'utf8')),
  )).join('\n').split('\r\n').join('\n');

  const columnsOf = (table: string): Set<string> => {
    const columns = new Set<string>();
    for (const opening of [`CREATE TABLE IF NOT EXISTS ${table} (`, `CREATE TABLE ${table} (`]) {
      let at = schema.indexOf(opening);
      while (at !== -1) {
        const body = schema.slice(at + opening.length, schema.indexOf('\n);', at));
        for (const line of body.split('\n')) {
          const word = line.trim().split(' ')[0] ?? '';
          const name = word.endsWith(',') ? word.slice(0, -1) : word;
          if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) &&
              !['PRIMARY', 'FOREIGN', 'UNIQUE', 'CHECK', 'CONSTRAINT'].includes(name.toUpperCase())) {
            columns.add(name);
          }
        }
        at = schema.indexOf(opening, at + 1);
      }
    }
    const added = `ALTER TABLE ${table} ADD COLUMN `;
    let at = schema.indexOf(added);
    while (at !== -1) {
      const name = schema.slice(at + added.length).split(' ')[0] ?? '';
      if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) columns.add(name);
      at = schema.indexOf(added, at + 1);
    }
    return columns;
  };

  // The scanner has to be working for the rest of this to mean anything.
  const artifactColumns = columnsOf('app_artifact');
  assert.ok(artifactColumns.has('checksum'), 'the column scanner did not read the table body');
  assert.ok(artifactColumns.has('availabilityState'), 'the column scanner did not read ALTER columns');
  assert.ok(!artifactColumns.has('updatedAt'), 'app_artifact is not supposed to have updatedAt');

  for (const [table, marker] of [
    ['app_artifact', 'UPDATE app_artifact'],
    ['deployment', 'UPDATE deployment'],
  ] as const) {
    const known = columnsOf(table);
    const statement = block.slice(block.indexOf(marker));
    const assigns = statement.slice(0, statement.indexOf('WHERE'));
    for (const assignment of assigns.split(',')) {
      const name = assignment.split('=')[0]?.trim().split(' ').pop() ?? '';
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) || name === 'SET') continue;
      assert.ok(known.has(name), `${table} has no column ${name}`);
    }
  }
});

void test('a restored artifact is a new recovery attempt, not a duplicate of the failed one', async () => {
  const server = await readFile(path.join(repoRoot, 'lib', 'server', 'nodes.ts'), 'utf8');
  const block = server.slice(
    server.indexOf('async function reconcileAppRuntimes'),
    server.indexOf('export async function recordHeartbeat'),
  );
  // Recovery is enqueued under a key that says which attempt this is. Before
  // Phase 21 that key was deployment + intent revision + Agent generation --
  // all three unchanged by a restore, so the attempt that failed while the
  // artifact was missing kept the key and the restored one was deduplicated
  // into silence: available artifact, willing reconciler, no job, forever.
  const keys = [...block.matchAll(/recover:\$\{[^`]*/gu)].map((match) => match[0]);
  assert.ok(keys.length >= 2, 'expected the idempotency key and its action record');
  for (const key of keys) {
    assert.match(key, /\$\{confirmedAt\}/);
  }
  // It has to come from the artifact row, so only a real confirmation moves it.
  assert.match(block, /const confirmedAt = artifact\.lastVerifiedOnNodeAt \?\? 0;/);
  assert.match(block, /SELECT id, state, availabilityState, lastVerifiedOnNodeAt FROM app_artifact/);
  // And the availability gate still stands in front of it, which is what keeps
  // this from turning into a retry loop: a failed recovery marks the artifact
  // missing, and a missing artifact never reaches the enqueue at all.
  const gate = block.indexOf("availabilityState === 'missing'");
  assert.ok(gate > 0 && gate < block.indexOf('const confirmedAt'));
});

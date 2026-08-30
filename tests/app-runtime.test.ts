import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createServer } from 'node:net';
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

import {
  assertAppRuntimePathInside,
  discoverAppRuntimeCapabilities,
  extractAppRuntimeArchive,
  redactAppRuntimeLog,
  shutdownManagedApps,
} from '../agent/app-runtime.ts';
import { executeSignedJob } from '../agent/runtime.ts';
import {
  APP_RUNTIME_JOB_TYPE,
  APP_RUNTIME_LIMITS,
  appCrashRecoveryDecision,
  validateAppRuntimeJobPayload,
  type AppRuntimeJobPayload,
  type SafeBuildContract,
} from '../lib/app-runtime.ts';
import {
  NODE_PROTOCOL_VERSION,
  sealNodeEnvironment,
  sha256,
  signJobClaim,
  stableJson,
  type NodeCapabilities,
  type SignedJobClaim,
} from '../lib/nodes.ts';
import { runShieldRules, type ShieldSnapshot } from '../lib/shield.ts';
import { inspectRepositoryForDeploy } from '../lib/server/github.ts';

const TOKEN = `node_${'a'.repeat(24)}.app-runtime-test-token`;
const WORKSPACE_ID = `ws_${'1'.repeat(24)}`;
const PROJECT_ID = `prj_${'2'.repeat(24)}`;
const DEPLOYMENT_ID = `dpl_${'3'.repeat(24)}`;
const ARTIFACT_ID = `art_${'4'.repeat(24)}`;
const TARGET_ARTIFACT_ID = `art_${'5'.repeat(24)}`;
const ACTION_ID = `dact_${'6'.repeat(24)}`;
const GiB = 1024 ** 3;

const CONTRACT: SafeBuildContract = {
  version: 1,
  framework: 'Node.js',
  packageManager: 'npm',
  lockfile: 'package-lock.json',
  nodeMajor: 26,
  installPolicy: 'frozen-lockfile-ignore-scripts',
  buildPolicy: 'none',
  startPolicy: 'node-entry',
  entrypoint: 'server.js',
  envNames: ['API_TOKEN'],
};

const CAPABILITIES: NodeCapabilities = {
  cpu: { cores: 8, model: 'Test CPU' },
  memory: { totalBytes: 16 * GiB, freeBytes: 12 * GiB },
  gpu: { available: false, model: null, vramBytes: null },
  disk: { totalBytes: 100 * GiB, freeBytes: 80 * GiB },
  docker: { available: false },
  ai: { runtimes: [], cachedModels: [], maxConcurrentJobs: 1 },
  gameServers: {
    minecraftJavaAvailable: false,
    javaVersion: null,
    activeServers: 0,
    maxConcurrentServers: 1,
  },
  appRuntime: {
    available: true,
    nodeVersion: '26.0.0',
    nodeMajor: 26,
    permissionModel: true,
    networkGuard: true,
    packageManagers: ['npm'],
    activeDeployments: 0,
    maxDeployments: APP_RUNTIME_LIMITS.maximumDeploymentsPerNode,
  },
  contracts: { ai: false, gameServers: false, appRuntime: true },
};

function payload(overrides: Partial<AppRuntimeJobPayload> = {}): AppRuntimeJobPayload {
  return {
    operation: 'deploy',
    deploymentId: DEPLOYMENT_ID,
    projectId: PROJECT_ID,
    actionId: ACTION_ID,
    artifactId: ARTIFACT_ID,
    targetArtifactId: null,
    source: {
      owner: 'OpenYsd',
      repository: 'safe-api',
      commit: 'a'.repeat(40),
    },
    contract: CONTRACT,
    environment: 'Production',
    environmentCiphertext: null,
    port: 41_321,
    healthPath: '/health',
    memoryMb: 256,
    diskQuotaBytes: APP_RUNTIME_LIMITS.diskMinimumBytes,
    retainArtifacts: 3,
    ...overrides,
  };
}

async function signedRun(input: {
  payload: AppRuntimeJobPayload | Record<string, unknown>;
  root: string;
  token?: string;
  workspaceId?: string;
  capabilities?: NodeCapabilities;
  signal?: AbortSignal;
  fetcher?: typeof fetch;
  now?: number;
  expired?: boolean;
}) {
  const now = input.now ?? Date.now();
  const claim: SignedJobClaim = {
    protocolVersion: NODE_PROTOCOL_VERSION,
    jobId: `job_app_${crypto.randomUUID()}`,
    workspaceId: input.workspaceId ?? WORKSPACE_ID,
    nodeId: `node_${'7'.repeat(24)}`,
    type: APP_RUNTIME_JOB_TYPE,
    payload: input.payload,
    payloadHash: await sha256(stableJson(input.payload)),
    leaseId: `lease_app_${crypto.randomUUID()}`,
    leaseExpiresAt: input.expired ? now - 1 : now + 15 * 60_000,
    attempt: 1,
  };
  const signature = await signJobClaim(TOKEN, claim);
  return executeSignedJob({
    token: input.token ?? TOKEN,
    claim,
    signature,
    capabilities: input.capabilities ?? CAPABILITIES,
    appRootDirectory: input.root,
    signal: input.signal,
    fetcher: input.fetcher,
    now,
  });
}

function writeOctal(header: Uint8Array, offset: number, length: number, value: number): void {
  header.set(Buffer.from(`${value.toString(8).padStart(length - 1, '0')}\0`, 'ascii'), offset);
}

function tarEntry(name: string, content: string | Buffer, type = '0'): Buffer {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  writeOctal(header, 100, 8, 0o755);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, type === '0' ? body.length : 0);
  writeOctal(header, 136, 12, 0);
  header.fill(32, 148, 156);
  header.write(type, 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  const padding = Buffer.alloc(Math.ceil(body.length / 512) * 512 - body.length);
  return Buffer.concat([header, type === '0' ? body : Buffer.alloc(0), padding]);
}

function tarball(entries: { name: string; content?: string; type?: string }[]): Uint8Array {
  return gzipSync(Buffer.concat([
    ...entries.map((entry) => tarEntry(entry.name, entry.content ?? '', entry.type ?? '0')),
    Buffer.alloc(1_024),
  ]));
}

function safeFixture(serverSource?: string): Uint8Array {
  const packageJson = JSON.stringify({
    name: 'safe-api',
    version: '1.0.0',
    engines: { node: '26' },
    scripts: { start: 'node server.js' },
  });
  const lockfile = JSON.stringify({
    name: 'safe-api',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: { '': { name: 'safe-api', version: '1.0.0' } },
  });
  const server = serverSource ?? [
    "const http = require('node:http');",
    "console.log('token=' + process.env.API_TOKEN);",
    "http.createServer((request, response) => { response.statusCode = 200; response.end('ok'); })",
    "  .listen(Number(process.env.PORT), process.env.HOST);",
  ].join('\n');
  return tarball([
    { name: 'safe-api-root/package.json', content: packageJson },
    { name: 'safe-api-root/package-lock.json', content: lockfile },
    { name: 'safe-api-root/server.js', content: server },
    { name: 'safe-api-root/.env.example', content: 'API_TOKEN=write-only' },
  ]);
}

function archiveFetcher(archive: Uint8Array): typeof fetch {
  return async () => {
    const response = new Response(archive as BodyInit, {
      status: 200,
      headers: { 'content-length': String(archive.byteLength) },
    });
    Object.defineProperty(response, 'url', {
      value: 'https://codeload.github.com/OpenYsd/safe-api/legacy.tar.gz/fixture',
    });
    return response;
  };
}

void test('App Runtime payloads reject arbitrary execution, providers, paths, and malformed contracts', () => {
  assert.equal(validateAppRuntimeJobPayload(payload()).ok, true);
  for (const mutation of [
    { command: 'whoami' },
    { args: ['--inspect'] },
    { executablePath: 'C:\\Windows\\System32\\cmd.exe' },
    { url: 'https://evil.invalid/source.tgz' },
    { provider: 'paid' },
    { tunnel: 'argo' },
    { zeroMode: false },
    { path: '../../escape' },
  ]) {
    assert.equal(
      validateAppRuntimeJobPayload({ ...payload(), ...mutation }).ok,
      false,
      JSON.stringify(mutation),
    );
  }
  assert.equal(
    validateAppRuntimeJobPayload(payload({
      contract: { ...CONTRACT, packageManager: 'npm', lockfile: 'yarn.lock' },
    })).ok,
    false,
  );
  assert.equal(
    validateAppRuntimeJobPayload(payload({
      source: { owner: '..', repository: 'safe-api', commit: 'a'.repeat(40) },
    })).ok,
    false,
  );
});

void test('encrypted deployment values are write-only and logs redact both values and credential-shaped fields', async () => {
  const secret = 'super-secret-runtime-value';
  const envelope = await sealNodeEnvironment(TOKEN, { API_TOKEN: secret });
  assert.doesNotMatch(envelope, new RegExp(secret));
  const redacted = redactAppRuntimeLog(`token=${TOKEN} API_TOKEN=${secret} ready`, [secret, TOKEN]);
  assert.doesNotMatch(redacted, /runtime-value|app-runtime-test-token/);
  assert.match(redacted, /REDACTED/);
  assert.match(redacted, /ready/);
  assert.equal(
    redactAppRuntimeLog('API_TOKEN=unknown-value ready', []),
    'API_TOKEN=[REDACTED] ready',
  );
});

void test('archive extraction rejects traversal, symlinks, duplicate paths, and damaged headers', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ysd-app-archive-'));
  try {
    await assert.rejects(
      extractAppRuntimeArchive(tarball([{ name: 'root/../escape.js', content: 'bad' }]), path.join(root, 'traversal')),
      /traversal/,
    );
    await assert.rejects(
      extractAppRuntimeArchive(tarball([{ name: 'root/link', type: '2' }]), path.join(root, 'symlink')),
      /Links|special/i,
    );
    await assert.rejects(
      extractAppRuntimeArchive(tarball([
        { name: 'root/server.js', content: 'one' },
        { name: 'root/server.js', content: 'two' },
      ]), path.join(root, 'duplicate')),
      /duplicate/,
    );
    const damaged = safeFixture();
    const uncompressed = Buffer.from(await import('node:zlib').then(({ gunzipSync }) => gunzipSync(damaged)));
    uncompressed[0] ^= 1;
    await assert.rejects(
      extractAppRuntimeArchive(gzipSync(uncompressed), path.join(root, 'damaged')),
      /checksum/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('lexical and real sandbox boundaries reject outside paths and tenant symlink escapes', async () => {
  const lexicalRoot = path.resolve(os.tmpdir(), 'ysd-app-lexical-root');
  assert.throws(() => assertAppRuntimePathInside(lexicalRoot, path.resolve(os.tmpdir(), 'ysd-app-lexical-outside')), /escaped/);
  const root = await mkdtemp(path.join(os.tmpdir(), 'ysd-app-symlink-root-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'ysd-app-symlink-outside-'));
  try {
    const workspace = path.join(root, 'workspaces', WORKSPACE_ID);
    await mkdir(workspace, { recursive: true });
    await symlink(outside, path.join(workspace, 'projects'), process.platform === 'win32' ? 'junction' : 'dir');
    const result = await signedRun({
      root,
      payload: payload({
        operation: 'rollback',
        source: null,
        artifactId: ARTIFACT_ID,
        targetArtifactId: TARGET_ARTIFACT_ID,
      }),
    });
    assert.equal(result.status, 'failed');
    if (result.status === 'failed') assert.match(result.error, /symbolic link|special path/i);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

void test('forged claims, expired leases, cross-workspace artifacts, and pre-cancelled actions fail closed', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ysd-app-claims-'));
  try {
    assert.equal((await signedRun({ root, payload: payload(), expired: true })).status, 'failed');
    assert.equal((await signedRun({ root, payload: payload(), token: `${TOKEN}-forged` })).status, 'failed');
    const controller = new AbortController();
    controller.abort('test-cancel');
    assert.equal((await signedRun({ root, payload: payload(), signal: controller.signal })).status, 'cancelled');

    const wrongWorkspace = await signedRun({
      root,
      workspaceId: `ws_${'9'.repeat(24)}`,
      payload: payload({
        operation: 'rollback', source: null, artifactId: ARTIFACT_ID,
        targetArtifactId: TARGET_ARTIFACT_ID,
      }),
    });
    assert.equal(wrongWorkspace.status, 'failed');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('resource, crash-loop, and localhost health policies are deterministic', () => {
  assert.deepEqual(appCrashRecoveryDecision(0), { restart: true, delayMs: 1_000 });
  assert.deepEqual(appCrashRecoveryDecision(1), { restart: true, delayMs: 2_000 });
  assert.deepEqual(appCrashRecoveryDecision(2), { restart: true, delayMs: 4_000 });
  assert.deepEqual(appCrashRecoveryDecision(3), { restart: false, delayMs: null });
  assert.equal(validateAppRuntimeJobPayload(payload({ port: 40_999 })).ok, false);
  assert.equal(validateAppRuntimeJobPayload(payload({ memoryMb: 64 })).ok, false);
  assert.equal(validateAppRuntimeJobPayload(payload({ diskQuotaBytes: 1 })).ok, false);
  assert.equal(validateAppRuntimeJobPayload(payload({ healthPath: 'https://evil.invalid' })).ok, false);
});

void test('GitHub inspection rejects private repositories, submodules, and LFS source policy', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const json = (value: unknown) => new Response(JSON.stringify(value), { status: 200 });
      if (url.endsWith('/repos/OpenYsd/private-api')) return json({ private: true, default_branch: 'main' });
      if (url.endsWith('/repos/OpenYsd/risky-api')) return json({ private: false, default_branch: 'main' });
      if (url.includes('/commits/main')) return json({ sha: 'b'.repeat(40) });
      if (url.includes('/git/trees/')) {
        return json({
          truncated: false,
          tree: [
            { path: 'package.json', type: 'blob', sha: 'c'.repeat(40), size: 2 },
            { path: '.gitmodules', type: 'blob', sha: 'd'.repeat(40), size: 1 },
            { path: 'vendor/module', type: 'commit' },
            { path: '.gitattributes', type: 'blob', sha: 'e'.repeat(40), size: 42 },
          ],
        });
      }
      if (url.endsWith(`/git/blobs/${'c'.repeat(40)}`)) {
        return json({ content: Buffer.from('{}').toString('base64'), encoding: 'base64', size: 2, sha: 'c'.repeat(40) });
      }
      if (url.endsWith(`/git/blobs/${'e'.repeat(40)}`)) {
        const content = '*.bin filter=lfs diff=lfs merge=lfs -text';
        return json({ content: Buffer.from(content).toString('base64'), encoding: 'base64', size: content.length, sha: 'e'.repeat(40) });
      }
      return new Response('missing', { status: 404 });
    }) as typeof fetch;
    const privateResult = await inspectRepositoryForDeploy({ repository: 'OpenYsd/private-api' });
    assert.equal(privateResult.ok, false);
    if (!privateResult.ok) assert.match(privateResult.error, /public GitHub archives only/);

    const risky = await inspectRepositoryForDeploy({ repository: 'OpenYsd/risky-api' });
    assert.equal(risky.ok, true);
    if (risky.ok) {
      assert.ok(risky.value.analysis.blockedReasons.some((reason) => /submodule/i.test(reason)));
      assert.ok(risky.value.analysis.blockedReasons.some((reason) => /LFS/i.test(reason)));
      assert.equal(risky.value.analysis.contract, null);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

void test('YSD Shield covers every App Runtime execution and Zero Mode boundary', () => {
  const snapshot: ShieldSnapshot = {
    zeroModeEnabled: true,
    protections: {
      turnstileConfigured: true,
      emailProviderConfigured: true,
      emailVerificationRequired: true,
      rateLimitEnabled: true,
      recentBlocks: 0,
      failingNetworks: 0,
      owners: 1,
      admins: 0,
      suspended: 0,
      unverifiedPrivileged: 0,
      securityHeaders: { present: [], missing: [], observed: true },
      orphanRoles: 0,
      suspendedPrivileged: 0,
      unscopedTables: [],
      sqlEditorRestricted: true,
    },
    billableResources: 0,
    secrets: [],
    users: { total: 1, unverified: 0 },
    sessions: { total: 0, expired: 0 },
    tables: [],
    integrations: [],
    publicProjects: [],
    appRuntime: {
      unsafeScripts: 1,
      lifecycleHooks: 1,
      unsafeRegistry: 1,
      pathAbuse: 1,
      unsignedArtifacts: 1,
      checksumMismatch: 1,
      exposedBind: 1,
      crashLoops: 1,
      staleNodes: 1,
      revokedActivity: 1,
      resourceExhaustion: 1,
      envLeak: 1,
      unexpectedOutbound: 1,
      forbiddenProvider: 1,
      suspiciousVolume: 30,
    },
    now: Date.now(),
  };
  const codes = new Set(runShieldRules(snapshot).findings.map((finding) => finding.code));
  for (const code of [
    'app-execution-boundary-violation',
    'app-artifact-integrity-failure',
    'app-network-boundary-violation',
    'app-environment-leak',
    'app-revoked-node-activity',
    'app-operational-anomaly',
  ]) assert.equal(codes.has(code), true, code);
});

void test('App Runtime D1 metadata is tenant-scoped, idempotent, private, and adds no paid resource', async () => {
  const migration = await readFile(new URL('../db/migrations/0009_app_runtime.sql', import.meta.url), 'utf8');
  for (const table of ['app_deployment_action', 'app_artifact', 'app_deployment_log', 'app_deployment_metric']) {
    const block = migration.split(`CREATE TABLE IF NOT EXISTS ${table} (`)[1];
    assert.match(block ?? '', /workspaceId TEXT NOT NULL/);
  }
  assert.match(migration, /deployment_node_port_uidx/);
  assert.match(migration, /app_deployment_action_idempotency_uidx/);
  assert.match(migration, /exposure TEXT NOT NULL DEFAULT 'private'/);
  assert.doesNotMatch(migration, /CREATE TABLE[^;]*(?:billing|provider|tunnel|r2)/i);

  const runtime = await readFile(new URL('../agent/app-runtime.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(runtime, /shell\s*:\s*true|child_process\.exec|\beval\s*\(|\bsudo\b|npm\s+install\s+-g/i);
  assert.match(runtime, /spawn\(process\.execPath/);
  assert.match(runtime, /--ignore-scripts/);
  assert.match(runtime, /--allow-net=127\.0\.0\.1/);
  assert.match(runtime, /ysd-app-artifact-v1/);
  assert.match(runtime, /shutdownManagedApps/);
  const cli = await readFile(new URL('../agent/cli.ts', import.meta.url), 'utf8');
  assert.match(cli, /status === 401[\s\S]*status === 403[\s\S]*shutdownManagedApps/);
});

void test('real safe deploy, lifecycle, rollback integrity, port conflict, and cancellation run on Node 25/26', async (context) => {
  const discovered = await discoverAppRuntimeCapabilities();
  if (!discovered.available || discovered.nodeMajor !== 26 || !discovered.packageManagers.includes('npm')) {
    context.skip('Run the App Runtime acceptance suite with the prepared Node.js 26 runtime.');
    return;
  }
  const root = await mkdtemp(path.join(os.tmpdir(), 'ysd-app-live-'));
  const secret = 'acceptance-secret-value';
  const environmentCiphertext = await sealNodeEnvironment(TOKEN, { API_TOKEN: secret });
  const livePayload = payload({ environmentCiphertext });
  const actualCapabilities: NodeCapabilities = {
    ...CAPABILITIES,
    appRuntime: discovered,
    contracts: { ...CAPABILITIES.contracts, appRuntime: true },
  };
  try {
    const deployed = await signedRun({
      root,
      payload: livePayload,
      capabilities: actualCapabilities,
      fetcher: archiveFetcher(safeFixture()),
    });
    assert.equal(deployed.status, 'succeeded');
    if (deployed.status === 'succeeded') {
      assert.match(String(deployed.result.checksum), /^sha256:[a-f0-9]{64}$/);
      assert.equal(deployed.result.localAddress, 'http://127.0.0.1:41321');
      assert.doesNotMatch(JSON.stringify(deployed.result), new RegExp(secret));
      assert.match(JSON.stringify(deployed.result), /Environment leak indicator/);
    }

    const stopped = await signedRun({
      root,
      capabilities: actualCapabilities,
      payload: payload({
        operation: 'stop', source: null, contract: CONTRACT,
        environmentCiphertext, artifactId: ARTIFACT_ID,
      }),
    });
    assert.equal(stopped.status, 'succeeded');

    const rolledBack = await signedRun({
      root,
      capabilities: actualCapabilities,
      payload: payload({
        operation: 'rollback', source: null, contract: CONTRACT,
        environmentCiphertext, artifactId: ARTIFACT_ID,
        targetArtifactId: ARTIFACT_ID,
      }),
    });
    assert.equal(rolledBack.status, 'succeeded');

    await signedRun({
      root,
      capabilities: actualCapabilities,
      payload: payload({ operation: 'stop', source: null, environmentCiphertext }),
    });
    const artifactPath = path.join(
      root, 'workspaces', WORKSPACE_ID, 'projects', PROJECT_ID, 'deployments',
      DEPLOYMENT_ID, 'artifacts', ARTIFACT_ID, 'server.js',
    );
    await writeFile(artifactPath, 'tampered');
    const refusedRollback = await signedRun({
      root,
      capabilities: actualCapabilities,
      payload: payload({
        operation: 'rollback', source: null, contract: CONTRACT,
        environmentCiphertext, artifactId: ARTIFACT_ID,
        targetArtifactId: ARTIFACT_ID,
      }),
    });
    assert.equal(refusedRollback.status, 'failed');
    if (refusedRollback.status === 'failed') assert.match(refusedRollback.error, /checksum/);

    const conflictServer = createServer();
    await new Promise<void>((resolve, reject) => {
      conflictServer.once('error', reject);
      conflictServer.listen(41_322, '127.0.0.1', resolve);
    });
    const conflict = await signedRun({
      root,
      capabilities: actualCapabilities,
      payload: payload({
        deploymentId: `dpl_${'8'.repeat(24)}`,
        actionId: `dact_${'8'.repeat(24)}`,
        artifactId: `art_${'8'.repeat(24)}`,
        port: 41_322,
        environmentCiphertext,
      }),
      fetcher: archiveFetcher(safeFixture()),
    });
    conflictServer.close();
    assert.equal(conflict.status, 'failed');
    if (conflict.status === 'failed') assert.match(conflict.error, /port is already in use/);

    const cancellation = new AbortController();
    const slowFetch: typeof fetch = async (_source, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('cancelled fetch')), { once: true });
    });
    const pending = signedRun({
      root,
      capabilities: actualCapabilities,
      payload: payload({
        deploymentId: `dpl_${'9'.repeat(24)}`,
        actionId: `dact_${'9'.repeat(24)}`,
        artifactId: `art_${'9'.repeat(24)}`,
        port: 41_323,
      }),
      fetcher: slowFetch,
      signal: cancellation.signal,
    });
    setTimeout(() => cancellation.abort('acceptance cancellation'), 50);
    assert.equal((await pending).status, 'cancelled');

    const deleted = await signedRun({
      root,
      capabilities: actualCapabilities,
      payload: payload({ operation: 'delete', source: null, contract: CONTRACT }),
    });
    assert.equal(deleted.status, 'succeeded');
    await assert.rejects(access(path.join(root, 'workspaces', WORKSPACE_ID, 'projects', PROJECT_ID, 'deployments', DEPLOYMENT_ID)));
  } finally {
    await shutdownManagedApps();
    await rm(root, { recursive: true, force: true });
  }
});

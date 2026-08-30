import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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

import { executeSignedJob } from '../agent/runtime.ts';
import {
  fixedJavaInvocation,
  javaMajorVersion,
} from '../agent/game-runtime.ts';
import {
  DEFAULT_MINECRAFT_PROPERTIES,
  GAME_SERVER_LIMITS,
  MINECRAFT_MANIFEST_URL,
  MINECRAFT_VERSIONS,
  containsGameServerAbuse,
  crashRecoveryDecision,
  gameServerResourceEligible,
  redactGameLogLine,
  validateGameServerJobPayload,
  validateMinecraftProperties,
  type GameServerJobType,
} from '../lib/game-servers.ts';
import {
  NODE_PROTOCOL_VERSION,
  sha256,
  signJobClaim,
  stableJson,
  type NodeCapabilities,
  type SignedJobClaim,
} from '../lib/nodes.ts';
import { runShieldRules, type ShieldSnapshot } from '../lib/shield.ts';

const GiB = 1024 ** 3;
const TOKEN = `node_${'d'.repeat(24)}.game-agent-secret`;
const SERVER_ID = `gsv_${'a'.repeat(24)}`;
const BACKUP_ONE = `gbk_${'b'.repeat(24)}`;
const BACKUP_TWO = `gbk_${'c'.repeat(24)}`;
const BACKUP_BAD = `gbk_${'d'.repeat(24)}`;
const VERSION = MINECRAFT_VERSIONS[0].id;

const CAPABILITIES: NodeCapabilities = {
  cpu: { cores: 8, model: 'Test CPU' },
  memory: { totalBytes: 16 * GiB, freeBytes: 12 * GiB },
  gpu: { available: false, model: null, vramBytes: null },
  disk: { totalBytes: 100 * GiB, freeBytes: 80 * GiB },
  docker: { available: false },
  ai: { runtimes: [], cachedModels: [], maxConcurrentJobs: 1 },
  gameServers: {
    minecraftJavaAvailable: true,
    javaVersion: 'openjdk version "21.0.8" 2025-07-15',
    activeServers: 0,
    maxConcurrentServers: 4,
  },
  contracts: { ai: false, gameServers: true },
};

function createPayload() {
  return {
    operation: 'create',
    serverId: SERVER_ID,
    name: 'Secure Vanilla',
    game: 'minecraft-java',
    serverType: 'vanilla',
    version: VERSION,
    ramMb: 1024,
    cpuCores: 2,
    diskQuotaBytes: 2 * GiB,
    port: 25_565,
    properties: DEFAULT_MINECRAFT_PROPERTIES,
    eulaAccepted: true,
    provider: 'local-node',
    zeroMode: true,
    exposure: 'private',
  };
}

async function signedRun(input: {
  type: GameServerJobType;
  payload: Record<string, unknown>;
  root: string;
  workspaceId?: string;
  fetcher?: typeof fetch;
  now?: number;
}) {
  const workspaceId = input.workspaceId ?? 'ws_one';
  const now = input.now ?? Date.now();
  const claim: SignedJobClaim = {
    protocolVersion: NODE_PROTOCOL_VERSION,
    jobId: `job_game_${crypto.randomUUID()}`,
    workspaceId,
    nodeId: 'node_one',
    type: input.type,
    payload: input.payload,
    payloadHash: await sha256(stableJson(input.payload)),
    leaseId: `lease_game_${crypto.randomUUID()}`,
    leaseExpiresAt: now + 60_000,
    attempt: 1,
  };
  const signature = await signJobClaim(TOKEN, claim);
  return executeSignedJob({
    token: TOKEN,
    claim,
    signature,
    capabilities: CAPABILITIES,
    gameRootDirectory: input.root,
    fetcher: input.fetcher,
    now,
  });
}

function officialFixture(): { fetcher: typeof fetch; requested: string[] } {
  const jar = new TextEncoder().encode('reviewed-minecraft-server-jar-fixture');
  const jarSha1 = createHash('sha1').update(jar).digest('hex');
  const metadataUrl =
    'https://piston-meta.mojang.com/v1/packages/fixture/server.json';
  const dataUrl =
    'https://piston-data.mojang.com/v1/objects/fixture/server.jar';
  const metadata = new TextEncoder().encode(
    JSON.stringify({
      javaVersion: { majorVersion: 21 },
      downloads: {
        server: { url: dataUrl, sha1: jarSha1, size: jar.byteLength },
      },
    }),
  );
  const metadataSha1 = createHash('sha1').update(metadata).digest('hex');
  const manifest = new TextEncoder().encode(
    JSON.stringify({
      versions: [
        {
          id: VERSION,
          type: 'release',
          url: metadataUrl,
          sha1: metadataSha1,
        },
      ],
    }),
  );
  const requested: string[] = [];
  const response = (bytes: Uint8Array) =>
    new Response(bytes.buffer as ArrayBuffer, {
      status: 200,
      headers: { 'content-length': String(bytes.byteLength) },
    });
  const fetcher: typeof fetch = async (input) => {
    const url =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    requested.push(url);
    if (url === MINECRAFT_MANIFEST_URL) return response(manifest);
    if (url === metadataUrl) return response(metadata);
    if (url === dataUrl) return response(jar);
    return new Response('refused', { status: 404 });
  };
  return { fetcher, requested };
}

void test('Game Server contracts allow only fixed local Vanilla actions', () => {
  assert.equal(
    validateGameServerJobPayload('game-server.lifecycle', createPayload()).ok,
    true,
  );
  for (const operation of ['start', 'stop', 'restart', 'status']) {
    assert.equal(
      validateGameServerJobPayload('game-server.lifecycle', {
        operation,
        serverId: SERVER_ID,
      }).ok,
      true,
      operation,
    );
  }
  assert.equal(
    validateGameServerJobPayload('game-server.lifecycle', {
      operation: 'delete',
      serverId: SERVER_ID,
      confirmDelete: true,
    }).ok,
    true,
  );
  const invocation = fixedJavaInvocation({ ramMb: 2048, cpuCores: 2 });
  assert.deepEqual(invocation, {
    executable: 'java',
    args: [
      '-Xms1024M',
      '-Xmx2048M',
      '-XX:ActiveProcessorCount=2',
      '-Dlog4j2.formatMsgNoLookups=true',
      '-jar',
      'server.jar',
      'nogui',
    ],
    shell: false,
  });
  assert.equal(javaMajorVersion('openjdk version "21.0.8" 2025-07-15'), 21);
  assert.equal(javaMajorVersion('java version "1.8.0_451"'), 8);
  assert.equal(javaMajorVersion('untrusted output'), null);
  for (const operation of [
    'kick',
    'whitelist-add',
    'whitelist-remove',
    'op',
    'deop',
  ]) {
    assert.equal(
      validateGameServerJobPayload('game-server.player', {
        operation,
        serverId: SERVER_ID,
        player: 'Safe_Player1',
      }).ok,
      true,
    );
  }
  assert.equal(
    validateGameServerJobPayload('game-server.player', {
      operation: 'kick',
      serverId: SERVER_ID,
      player: 'name\nstop',
    }).ok,
    false,
  );
});

void test('paths, URLs, shell fields, invalid ports, paid providers, and property injection fail closed', () => {
  for (const mutation of [
    { command: 'whoami' },
    { jvmArgs: ['-javaagent:evil.jar'] },
    { executablePath: 'C:\\evil\\java.exe' },
    { downloadUrl: 'https://evil.example/server.jar' },
    { path: '../../outside' },
    { provider: 'paid-provider' },
    { zeroMode: false },
    { exposure: 'public' },
    { port: 80 },
  ]) {
    assert.equal(
      validateGameServerJobPayload('game-server.lifecycle', {
        ...createPayload(),
        ...mutation,
      }).ok,
      false,
      JSON.stringify(mutation),
    );
  }
  assert.equal(
    containsGameServerAbuse({ url: 'http://169.254.169.254/latest' }),
    true,
  );
  assert.equal(
    validateMinecraftProperties({
      ...DEFAULT_MINECRAFT_PROPERTIES,
      motd: 'safe\nlevel-name=../../escape',
    }).ok,
    false,
  );
  assert.equal(
    validateMinecraftProperties({
      ...DEFAULT_MINECRAFT_PROPERTIES,
      'enable-rcon': true,
    }).ok,
    false,
  );
});

void test('RAM, disk, concurrency, and crash-loop decisions are deterministic', () => {
  assert.equal(
    gameServerResourceEligible({
      freeMemoryBytes:
        1024 * 1024 ** 2 + GAME_SERVER_LIMITS.memoryReserveBytes,
      freeDiskBytes: 3 * GiB,
      ramMb: 1024,
      diskQuotaBytes: 2 * GiB,
      activeServers: 0,
      maximumServers: 1,
    }),
    true,
  );
  assert.equal(
    gameServerResourceEligible({
      freeMemoryBytes: 512 * 1024 ** 2,
      freeDiskBytes: 3 * GiB,
      ramMb: 1024,
      diskQuotaBytes: 2 * GiB,
      activeServers: 0,
      maximumServers: 1,
    }),
    false,
  );
  assert.equal(
    gameServerResourceEligible({
      freeMemoryBytes: 16 * GiB,
      freeDiskBytes: 2 * GiB,
      ramMb: 1024,
      diskQuotaBytes: 2 * GiB,
      activeServers: 0,
      maximumServers: 1,
    }),
    false,
  );
  assert.deepEqual(crashRecoveryDecision(1), {
    restart: true,
    delayMs: 5_000,
  });
  assert.deepEqual(crashRecoveryDecision(2), {
    restart: true,
    delayMs: 15_000,
  });
  assert.deepEqual(crashRecoveryDecision(3), {
    restart: false,
    delayMs: null,
  });
});

void test('signed local provisioning, config, backups, logs, tenant binding, and deletion work without Java start', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ysd-game-runtime-'));
  const serverDirectory = path.join(root, 'ws_one', 'servers', SERVER_ID);
  const fixture = officialFixture();
  try {
    const created = await signedRun({
      type: 'game-server.lifecycle',
      payload: createPayload(),
      root,
      fetcher: fixture.fetcher,
    });
    assert.equal(created.status, 'succeeded');
    assert.deepEqual(fixture.requested, [
      MINECRAFT_MANIFEST_URL,
      'https://piston-meta.mojang.com/v1/packages/fixture/server.json',
      'https://piston-data.mojang.com/v1/objects/fixture/server.jar',
    ]);
    assert.match(
      await readFile(path.join(serverDirectory, 'server.properties'), 'utf8'),
      /^server-ip=127\.0\.0\.1$/m,
    );
    const repeated = await signedRun({
      type: 'game-server.lifecycle',
      payload: createPayload(),
      root,
      fetcher: async () => {
        throw new Error('Idempotent create must not download again.');
      },
    });
    assert.equal(repeated.status, 'succeeded');

    const updatedProperties = {
      ...DEFAULT_MINECRAFT_PROPERTIES,
      maxPlayers: 12,
      motd: 'اختبار YSD آمن',
    };
    const configured = await signedRun({
      type: 'game-server.config',
      payload: {
        operation: 'update',
        serverId: SERVER_ID,
        port: 25_566,
        properties: updatedProperties,
      },
      root,
    });
    assert.equal(configured.status, 'succeeded');
    assert.match(
      await readFile(path.join(serverDirectory, 'server.properties'), 'utf8'),
      /^server-port=25566$/m,
    );

    await mkdir(path.join(serverDirectory, 'world'), { recursive: true });
    await writeFile(path.join(serverDirectory, 'world', 'level.dat'), 'before');
    const backupOne = await signedRun({
      type: 'game-server.backup',
      payload: {
        operation: 'create',
        serverId: SERVER_ID,
        backupId: BACKUP_ONE,
        name: 'Verified backup',
      },
      root,
    });
    assert.equal(backupOne.status, 'succeeded');
    await writeFile(path.join(serverDirectory, 'world', 'level.dat'), 'after');
    const restored = await signedRun({
      type: 'game-server.backup',
      payload: {
        operation: 'restore',
        serverId: SERVER_ID,
        backupId: BACKUP_ONE,
        confirmRestore: true,
      },
      root,
    });
    assert.equal(restored.status, 'succeeded');
    assert.equal(
      await readFile(path.join(serverDirectory, 'world', 'level.dat'), 'utf8'),
      'before',
    );

    for (const backupId of [BACKUP_TWO, BACKUP_BAD]) {
      assert.equal(
        (
          await signedRun({
            type: 'game-server.backup',
            payload: {
              operation: 'create',
              serverId: SERVER_ID,
              backupId,
              name: `Backup ${backupId}`,
            },
            root,
          })
        ).status,
        'succeeded',
      );
    }
    const deletedBackup = await signedRun({
      type: 'game-server.backup',
      payload: {
        operation: 'delete',
        serverId: SERVER_ID,
        backupId: BACKUP_TWO,
        confirmDelete: true,
      },
      root,
    });
    assert.equal(deletedBackup.status, 'succeeded');
    await assert.rejects(
      access(path.join(serverDirectory, 'backups', BACKUP_TWO)),
    );

    const badManifestPath = path.join(
      serverDirectory,
      'backups',
      BACKUP_BAD,
      'backup.json',
    );
    const badManifest = JSON.parse(
      await readFile(badManifestPath, 'utf8'),
    ) as { entries: { path: string }[] };
    badManifest.entries[0]!.path = '../outside';
    await writeFile(badManifestPath, JSON.stringify(badManifest));
    const refusedRestore = await signedRun({
      type: 'game-server.backup',
      payload: {
        operation: 'restore',
        serverId: SERVER_ID,
        backupId: BACKUP_BAD,
        confirmRestore: true,
      },
      root,
    });
    assert.equal(refusedRestore.status, 'failed');
    if (refusedRestore.status === 'failed') {
      assert.match(refusedRestore.error, /traversal|manifest/i);
    }

    await writeFile(
      path.join(serverDirectory, 'ysd-agent.log'),
      `authorization: Bearer hidden\ntoken=${TOKEN}\nserver ready\n`,
    );
    const logs = await signedRun({
      type: 'game-server.logs',
      payload: { operation: 'tail', serverId: SERVER_ID, lines: 20 },
      root,
    });
    assert.equal(logs.status, 'succeeded');
    assert.doesNotMatch(JSON.stringify(logs), /game-agent-secret/);
    assert.match(JSON.stringify(logs), /REDACTED/);

    const crossWorkspace = await signedRun({
      type: 'game-server.lifecycle',
      payload: { operation: 'status', serverId: SERVER_ID },
      workspaceId: 'ws_two',
      root,
    });
    assert.equal(crossWorkspace.status, 'failed');

    const removed = await signedRun({
      type: 'game-server.lifecycle',
      payload: {
        operation: 'delete',
        serverId: SERVER_ID,
        confirmDelete: true,
      },
      root,
    });
    assert.equal(removed.status, 'succeeded');
    await assert.rejects(access(serverDirectory));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('a symlinked tenant directory cannot escape the local sandbox', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ysd-game-symlink-root-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'ysd-game-symlink-outside-'));
  try {
    await mkdir(path.join(root, 'ws_one'), { recursive: true });
    await symlink(
      outside,
      path.join(root, 'ws_one', 'servers'),
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    const result = await signedRun({
      type: 'game-server.lifecycle',
      payload: { operation: 'status', serverId: SERVER_ID },
      root,
    });
    assert.equal(result.status, 'failed');
    if (result.status === 'failed') assert.match(result.error, /symbolic link/i);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

void test('forged and expired signed Game Server claims never reach the runtime', async () => {
  const payload = { operation: 'status', serverId: SERVER_ID };
  const now = Date.now();
  const claim: SignedJobClaim = {
    protocolVersion: NODE_PROTOCOL_VERSION,
    jobId: 'job_game_forged',
    workspaceId: 'ws_one',
    nodeId: 'node_one',
    type: 'game-server.lifecycle',
    payload,
    payloadHash: await sha256(stableJson(payload)),
    leaseId: 'lease_game_forged',
    leaseExpiresAt: now - 1,
    attempt: 1,
  };
  const signature = await signJobClaim(TOKEN, claim);
  const root = await mkdtemp(path.join(os.tmpdir(), 'ysd-game-claim-'));
  try {
    assert.equal(
      (
        await executeSignedJob({
          token: TOKEN,
          claim,
          signature,
          capabilities: CAPABILITIES,
          gameRootDirectory: root,
          now,
        })
      ).status,
      'failed',
    );
    assert.equal(
      (
        await executeSignedJob({
          token: `${TOKEN}forged`,
          claim: { ...claim, leaseExpiresAt: now + 60_000 },
          signature,
          capabilities: CAPABILITIES,
          gameRootDirectory: root,
          now,
        })
      ).status,
      'failed',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test('Game Server log redaction removes credentials without hiding ordinary lines', () => {
  assert.equal(redactGameLogLine('server ready'), 'server ready');
  assert.equal(
    redactGameLogLine(`token=${TOKEN}`),
    'token=[REDACTED]',
  );
  assert.doesNotMatch(
    redactGameLogLine(`authorization: Bearer ${TOKEN}`) ?? '',
    /game-agent-secret/,
  );
});

void test('YSD Shield reports exposure, unsafe identity, integrity, replay, revocation, and Zero Mode abuse', () => {
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
    gameServers: {
      total: 2,
      eligibleOnlineNodes: 0,
      staleNodes: 1,
      revokedNodes: 1,
      unexpectedExposure: 1,
      onlineModeDisabled: 1,
      whitelistDisabled: 1,
      outdatedVersions: 1,
      unverifiedBinaries: 1,
      excessiveRam: 1,
      crashLoops: 1,
      unsafeConfig: 1,
      corruptedBackups: 1,
      unsignedJobs: 1,
      expiredLeases: 1,
      suspiciousVolume: 60,
      forgedClaims: 1,
      replayedJobs: 1,
      revokedActivity: 1,
      resourceExhaustion: 1,
      zeroModeBypass: 1,
      payloadAbuse: 1,
    },
    now: Date.now(),
  };
  const codes = new Set(
    runShieldRules(snapshot).findings.map((finding) => finding.code),
  );
  for (const code of [
    'game-no-eligible-node',
    'game-node-readiness',
    'game-unexpected-network-exposure',
    'game-online-mode-disabled',
    'game-whitelist-disabled',
    'game-integrity-failure',
    'game-execution-boundary-violation',
    'game-revoked-node-activity',
    'game-operational-anomaly',
  ]) {
    assert.equal(codes.has(code), true, code);
  }
});

void test('Game Server D1 schema is tenant-scoped and adds no paid resource', async () => {
  const migration = await readFile(
    new URL('../db/migrations/0008_game_servers.sql', import.meta.url),
    'utf8',
  );
  for (const table of [
    'game_server',
    'game_server_action',
    'game_server_backup',
    'game_server_log',
  ]) {
    const block = migration.split(`CREATE TABLE IF NOT EXISTS ${table} (`)[1];
    assert.match(block ?? '', /workspaceId TEXT NOT NULL/);
  }
  assert.match(migration, /UNIQUE INDEX IF NOT EXISTS game_server_node_port_uidx/);
  assert.match(
    migration,
    /UNIQUE INDEX IF NOT EXISTS game_server_action_idempotency_uidx/,
  );
  assert.doesNotMatch(
    migration,
    /r2|billing|paid|tunnel|spectrum|argo|upnp/i,
  );
  const runtime = await readFile(
    new URL('../agent/game-runtime.ts', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(runtime, /shell\s*:\s*true|child_process\.exec|\beval\s*\(/);
  assert.doesNotMatch(runtime, /upnp|cloudflare tunnel|spectrum|argo/i);
  assert.match(runtime, /shutdownManagedGameServers/);
  const agentCli = await readFile(
    new URL('../agent/cli.ts', import.meta.url),
    'utf8',
  );
  assert.match(
    agentCli,
    /status === 401[\s\S]*status === 403[\s\S]*shutdownManagedGameServers/,
  );
  const controlPlane = await readFile(
    new URL('../lib/server/nodes.ts', import.meta.url),
    'utf8',
  );
  assert.match(
    controlPlane,
    /type LIKE 'game-server\.%' AND targetNodeId = \?/,
  );
  assert.match(controlPlane, /ORDER BY createdAt DESC LIMIT 2000/);
});

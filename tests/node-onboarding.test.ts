import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { EVIDENCE_ACTIONS, narrowEvidenceMetadata } from '../lib/audit-actions.ts';
import {
  AGENT_PLATFORMS,
  agentArtifactName,
  agentDownloadPath,
  buildInstallCommand,
  buildInstallCommands,
  isSha256,
  meetsMinimumNodeVersion,
  MINIMUM_NODE_VERSION,
  parseAgentManifest,
  powerShellLiteral,
  shellLiteral,
} from '../lib/agent-release.ts';
import {
  compatibilityLabel,
  deploymentBlockers,
  evaluateCompatibility,
  evaluatePreflight,
  failedCheckCodes,
  PREFLIGHT_VERSION,
  type PreflightInput,
} from '../lib/node-preflight.ts';
import {
  CURRENT_AGENT_VERSION,
  MINIMUM_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  NODE_TIMING,
  type NodeCapabilities,
} from '../lib/nodes.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

const MINUTE = 60_000;

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function code(path: string): string {
  return source(path)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/(^|\s)\/\/.*$/, '$1'))
    .join('\n');
}

function capabilities(overrides: Partial<NodeCapabilities> = {}): NodeCapabilities {
  return {
    cpu: { cores: 8, model: 'Test CPU' },
    memory: { totalBytes: 16 * 1024 ** 3, freeBytes: 12 * 1024 ** 3 },
    gpu: { available: false, model: null, vramBytes: null },
    disk: { totalBytes: 100 * 1024 ** 3, freeBytes: 80 * 1024 ** 3 },
    docker: { available: false },
    ai: { runtimes: [], cachedModels: [], maxConcurrentJobs: 1 },
    gameServers: {
      minecraftJavaAvailable: false, javaVersion: null,
      activeServers: 0, maxConcurrentServers: 1,
    },
    appRuntime: {
      available: true, nodeVersion: '26.8.1', nodeMajor: 26,
      permissionModel: true, networkGuard: true,
      packageManagers: ['npm'], activeDeployments: 0, maxDeployments: 12,
    },
    contracts: { ai: false, gameServers: false, appRuntime: true },
    ...overrides,
  };
}

function healthy(overrides: Partial<PreflightInput> = {}): PreflightInput {
  return {
    belongsToWorkspace: true,
    status: 'online',
    agentVersion: CURRENT_AGENT_VERSION,
    protocolVersion: NODE_PROTOCOL_VERSION,
    capabilities: capabilities(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Distribution: the artifact must stand on its own.
// ---------------------------------------------------------------------------

void test('the agent depends on node built-ins and nothing else', () => {
  // The premise the whole distribution model rests on. If a dependency ever
  // appears, a downloaded single file stops being runnable and this fails
  // here rather than on a stranger's machine.
  const graph = [
    'agent/cli.ts', 'agent/runtime.ts', 'agent/credentials.ts', 'agent/agent-key.ts',
    'agent/app-runtime.ts', 'agent/game-runtime.ts', 'agent/ai-runtime.ts',
    'lib/nodes.ts', 'lib/app-runtime.ts', 'lib/game-servers.ts', 'lib/ai.ts',
  ];
  for (const file of graph) {
    for (const match of source(file).matchAll(/(?:^|\n)\s*(?:import|export)[\s\S]*?from\s+'([^']+)'/g)) {
      const spec = match[1]!;
      assert.ok(
        spec.startsWith('node:') || spec.startsWith('.') || spec.startsWith('@/'),
        `${file} imports the package "${spec}"; the agent bundle must use node: built-ins only`,
      );
    }
  }
});

void test('the built artifact exists, matches its manifest, and runs alone', () => {
  const manifestPath = new URL('../public/agent/manifest.json', import.meta.url);
  if (!existsSync(manifestPath)) {
    assert.fail('Run `npm run agent:build` first: the release artifact is missing.');
  }
  const manifest = parseAgentManifest(JSON.parse(readFileSync(manifestPath, 'utf8')));
  assert.ok(manifest, 'the manifest must satisfy its own parser');

  const artifact = new URL(`../public/agent/${manifest.filename}`, import.meta.url);
  const text = readFileSync(artifact, 'utf8');
  assert.equal(createHash('sha256').update(text, 'utf8').digest('hex'), manifest.sha256);
  assert.equal(Buffer.byteLength(text, 'utf8'), manifest.size);
  assert.equal(manifest.filename, agentArtifactName(CURRENT_AGENT_VERSION));
  assert.equal(manifest.downloadPath, agentDownloadPath(CURRENT_AGENT_VERSION));
  assert.equal(manifest.protocolVersion, NODE_PROTOCOL_VERSION);

  for (const [label, pattern] of [
    ['a non-builtin import', /from\s*["'](?!node:)[^."'][^"']*["']/],
    ['a build-machine path', /[A-Za-z]:\\\\?Users|\/(?:home|Users)\/[A-Za-z0-9_.-]+\//],
    ['a sourcemap link', /\/\/# sourceMappingURL=/],
  ] as const) {
    assert.doesNotMatch(text, pattern, `the shipped bundle contains ${label}`);
  }

  // It has to actually start, from a directory that is not this repository.
  const reported = execFileSync(process.execPath, [artifact.pathname.replace(/^\//, ''), '--version'], {
    encoding: 'utf8',
  }).trim();
  assert.match(reported, new RegExp(`YSD Node Agent ${CURRENT_AGENT_VERSION}`));
  assert.match(reported, new RegExp(`Protocol ${NODE_PROTOCOL_VERSION}`));
  // --version must not leak anything about the machine it ran on.
  assert.doesNotMatch(reported, /[A-Za-z]:\\|\/home\/|\/Users\/|win32|linux|darwin/);
});

void test('the build refuses an artifact that could not run', () => {
  const build = code('scripts/build-agent.mjs');
  assert.match(build, /must depend on node: built-ins only/);
  assert.match(build, /embeds the build machine path/);
  assert.match(build, /--version/);
  // No timestamp, or two builds of identical source would differ.
  assert.doesNotMatch(build, /builtAt:|Date\.now\(\)|new Date\(\)/);
});

void test('a manifest that has been tampered with is refused', () => {
  const good = {
    version: CURRENT_AGENT_VERSION,
    protocolVersion: NODE_PROTOCOL_VERSION,
    minimumNodeVersion: MINIMUM_NODE_VERSION,
    filename: agentArtifactName(),
    downloadPath: agentDownloadPath(),
    sha256: 'a'.repeat(64),
    size: 1234,
  };
  assert.ok(parseAgentManifest(good));

  for (const [label, mutation] of [
    ['a short digest', { sha256: 'abc' }],
    ['an uppercase digest', { sha256: 'A'.repeat(64) }],
    ['a mismatched filename', { filename: 'ysd-node-agent-9.9.9.mjs' }],
    ['a redirected download path', { downloadPath: 'https://evil.test/agent.mjs' }],
    ['a wrong protocol', { protocolVersion: 99 }],
    ['a zero size', { size: 0 }],
    ['a negative size', { size: -1 }],
  ] as const) {
    assert.equal(
      parseAgentManifest({ ...good, ...mutation }),
      null,
      `a manifest with ${label} must be refused`,
    );
  }
});

void test('digests are recognised only in the exact form the build writes', () => {
  assert.ok(isSha256('0'.repeat(64)));
  assert.ok(!isSha256('0'.repeat(63)));
  assert.ok(!isSha256('X'.repeat(64)));
  assert.ok(!isSha256(null));
});

// ---------------------------------------------------------------------------
// Install commands: quoting, integrity, and what must not be in them.
// ---------------------------------------------------------------------------

void test('shell quoting survives every metacharacter', () => {
  const nasty = [
    "it's", 'a "quoted" b', 'a & b', 'a; rm -rf /', 'a | b', 'a `cmd` b',
    'a $VAR b', 'a\nb', 'a\r\nb', 'a\tb',
  ];
  for (const value of nasty) {
    const ps = powerShellLiteral(value);
    assert.ok(ps.startsWith("'") && ps.endsWith("'"), value);
    // A newline would turn one command into two.
    assert.doesNotMatch(ps, /[\n\r]/);
    // Every embedded quote is doubled, so the literal cannot be closed early.
    assert.equal((ps.slice(1, -1).match(/'/g) ?? []).length % 2, 0);

    const sh = shellLiteral(value);
    assert.ok(sh.startsWith("'") && sh.endsWith("'"), value);
    assert.doesNotMatch(sh, /[\n\r]/);
  }
});

void test('every platform gets a command that verifies before it executes', () => {
  const manifest = parseAgentManifest({
    version: CURRENT_AGENT_VERSION,
    protocolVersion: NODE_PROTOCOL_VERSION,
    minimumNodeVersion: MINIMUM_NODE_VERSION,
    filename: agentArtifactName(),
    downloadPath: agentDownloadPath(),
    sha256: 'b'.repeat(64),
    size: 100,
  })!;
  const commands = buildInstallCommands('https://example.test', manifest);
  assert.equal(commands.length, AGENT_PLATFORMS.length);

  for (const command of commands) {
    // Pinned to an exact version. "latest" would defeat the digest.
    assert.match(command.script, new RegExp(CURRENT_AGENT_VERSION.replace(/\./g, '\\.')));
    assert.doesNotMatch(command.script, /latest/);

    // The digest is compared, and a mismatch stops the script.
    assert.ok(command.script.includes('b'.repeat(64)));
    assert.match(command.script, /Checksum mismatch/);

    // Verification happens BEFORE the agent is executed.
    assert.ok(
      command.script.indexOf('Checksum mismatch') < command.script.indexOf('pair --url'),
      `${command.platform} runs the agent before checking it`,
    );

    // Never pipe the network straight into a shell.
    assert.doesNotMatch(command.script, /\|\s*iex|\|\s*(?:ba)?sh\b/);

    // The one-time code is typed at a prompt, never placed in the command.
    assert.doesNotMatch(command.script, /ysdp_/i);
    assert.doesNotMatch(command.script, /PAIRING_CODE/);
  }
});

void test('the Windows script discards a bad download instead of keeping it', () => {
  const manifest = parseAgentManifest({
    version: CURRENT_AGENT_VERSION, protocolVersion: NODE_PROTOCOL_VERSION,
    minimumNodeVersion: MINIMUM_NODE_VERSION, filename: agentArtifactName(),
    downloadPath: agentDownloadPath(), sha256: 'c'.repeat(64), size: 100,
  })!;
  const windows = buildInstallCommand({ origin: 'https://example.test', manifest, platform: 'windows' });
  assert.match(windows.script, /ErrorActionPreference = 'Stop'/);
  assert.match(windows.script, /Get-FileHash/);
  assert.match(windows.script, /\.ToLower\(\)/);
  assert.match(windows.script, /Remove-Item \$file -Force; throw/);

  const linux = buildInstallCommand({ origin: 'https://example.test', manifest, platform: 'linux' });
  assert.match(linux.script, /set -eu/);
  assert.match(linux.script, /sha256sum/);
  assert.match(linux.script, /rm -f "\$file"/);

  const macos = buildInstallCommand({ origin: 'https://example.test', manifest, platform: 'macos' });
  assert.match(macos.script, /shasum -a 256/);
});

void test('a hostile origin cannot break out of the generated command', () => {
  const manifest = parseAgentManifest({
    version: CURRENT_AGENT_VERSION, protocolVersion: NODE_PROTOCOL_VERSION,
    minimumNodeVersion: MINIMUM_NODE_VERSION, filename: agentArtifactName(),
    downloadPath: agentDownloadPath(), sha256: 'd'.repeat(64), size: 100,
  })!;
  // The origin is server-resolved today, which is exactly the assumption that
  // rots. The builder must hold even if that stops being true.
  const origin = "https://x.test'; Remove-Item C:\\ -Recurse; echo '";
  for (const platform of AGENT_PLATFORMS) {
    const command = buildInstallCommand({ origin, manifest, platform });
    assert.doesNotMatch(command.script, /[\n\r]\s*Remove-Item C/);
    const lines = command.script.split('\n');
    // Injection would add lines; the shape is fixed.
    assert.ok(lines.length <= 10, `${platform} produced ${lines.length} lines`);
  }
});

// ---------------------------------------------------------------------------
// Compatibility.
// ---------------------------------------------------------------------------

void test('online is not the same as ready', () => {
  assert.equal(compatibilityLabel('online', 'compatible'), 'Online — ready');
  assert.equal(compatibilityLabel('online', 'upgrade_required'), 'Online — upgrade required');
  assert.equal(compatibilityLabel('online', 'protocol_mismatch'), 'Online — incompatible protocol');
  assert.equal(compatibilityLabel('online', 'unknown'), 'Online — capabilities unknown');
  assert.equal(compatibilityLabel('offline', 'compatible'), 'Offline');
  assert.equal(compatibilityLabel('revoked', 'compatible'), 'Revoked');
});

void test('compatibility is decided from the shared constants', () => {
  assert.equal(
    evaluateCompatibility({ agentVersion: CURRENT_AGENT_VERSION, protocolVersion: NODE_PROTOCOL_VERSION }),
    'compatible',
  );
  assert.equal(
    evaluateCompatibility({ agentVersion: '0.0.1', protocolVersion: NODE_PROTOCOL_VERSION }),
    'upgrade_required',
  );
  assert.equal(
    evaluateCompatibility({ agentVersion: CURRENT_AGENT_VERSION, protocolVersion: NODE_PROTOCOL_VERSION + 1 }),
    'protocol_mismatch',
  );
  assert.equal(evaluateCompatibility({ agentVersion: null, protocolVersion: null }), 'unknown');
  // The minimum is exactly inclusive.
  assert.equal(
    evaluateCompatibility({ agentVersion: MINIMUM_AGENT_VERSION, protocolVersion: NODE_PROTOCOL_VERSION }),
    'compatible',
  );
});

void test('the Node.js floor is compared numerically, not lexically', () => {
  assert.ok(meetsMinimumNodeVersion('22.13.0'));
  assert.ok(meetsMinimumNodeVersion('v24.16.0'));
  assert.ok(meetsMinimumNodeVersion('100.0.0'));
  assert.ok(!meetsMinimumNodeVersion('22.12.9'));
  assert.ok(!meetsMinimumNodeVersion('18.0.0'));
  // "9" > "22" lexically; it must not be treated as newer.
  assert.ok(!meetsMinimumNodeVersion('9.99.99'));
  assert.ok(!meetsMinimumNodeVersion('not-a-version'));
});

// ---------------------------------------------------------------------------
// Preflight.
// ---------------------------------------------------------------------------

void test('a healthy node is ready and every check passes', () => {
  const report = evaluatePreflight(healthy());
  assert.equal(report.version, PREFLIGHT_VERSION);
  assert.equal(report.verdict, 'ready');
  assert.deepEqual(failedCheckCodes(report), []);
  assert.ok(report.checks.length >= 7);
});

void test('each unhealthy condition blocks with its own code', () => {
  const cases: [string, PreflightInput, string][] = [
    ['foreign workspace', healthy({ belongsToWorkspace: false }), 'node-workspace'],
    ['offline', healthy({ status: 'offline' }), 'node-heartbeat'],
    ['stale', healthy({ status: 'stale' }), 'node-heartbeat'],
    ['revoked', healthy({ status: 'revoked' }), 'node-heartbeat'],
    ['old agent', healthy({ agentVersion: '0.0.1' }), 'agent-version'],
    ['wrong protocol', healthy({ protocolVersion: 99 }), 'agent-protocol'],
    [
      'no App Runtime',
      healthy({ capabilities: capabilities({ contracts: { ai: false, gameServers: false, appRuntime: false } }) }),
      'app-runtime-contract',
    ],
    [
      'old Node on the node',
      healthy({ capabilities: capabilities({ appRuntime: { ...capabilities().appRuntime!, nodeVersion: '18.0.0' } }) }),
      'app-runtime-node',
    ],
    [
      'at the deployment ceiling',
      healthy({ capabilities: capabilities({ appRuntime: { ...capabilities().appRuntime!, activeDeployments: 12, maxDeployments: 12 } }) }),
      'app-runtime-capacity',
    ],
    [
      'no memory',
      healthy({ capabilities: capabilities({ memory: { totalBytes: 1024 ** 3, freeBytes: 1024 } }) }),
      'node-memory',
    ],
    [
      'no disk',
      healthy({ capabilities: capabilities({ disk: { totalBytes: 1024 ** 3, freeBytes: 1024 } }) }),
      'node-disk',
    ],
  ];
  for (const [label, input, expected] of cases) {
    const report = evaluatePreflight(input);
    assert.equal(report.verdict, 'blocked', `${label} should block`);
    assert.ok(failedCheckCodes(report).includes(expected as never), `${label} -> ${expected}`);
  }
});

void test('a node that has not reported yet is a wait, not a refusal', () => {
  const report = evaluatePreflight(healthy({ capabilities: null, agentVersion: null, protocolVersion: null }));
  assert.equal(report.verdict, 'ready');
  assert.ok(report.checks.some((entry) => entry.status === 'unknown'));
  // But it still cannot deploy, because the blocking subset is separate.
  assert.ok(deploymentBlockers(healthy({ status: 'offline' })).includes('node-heartbeat'));
});

void test('remediation is fixed text and never echoes the node', () => {
  const hostile = capabilities({
    cpu: { cores: 1, model: '<script>alert(1)</script>' },
    appRuntime: { ...capabilities().appRuntime!, nodeVersion: '<img onerror=1>', available: true },
  });
  const report = evaluatePreflight(healthy({ capabilities: hostile }));
  const text = JSON.stringify(report);
  assert.doesNotMatch(text, /<script>|onerror|alert\(/);
  for (const entry of report.checks) {
    assert.ok(entry.remediation.length > 0);
    assert.ok(entry.title.length > 0);
  }
});

void test('resource checks are advisory but capability checks refuse deployment', () => {
  // Low disk explains a likely problem; it does not stop the queue, because
  // the node's own report is the only source and `planDeployment` re-checks
  // the reserve against the actual request.
  const lowDisk = healthy({ capabilities: capabilities({ disk: { totalBytes: 1024 ** 3, freeBytes: 1024 } }) });
  assert.equal(evaluatePreflight(lowDisk).verdict, 'blocked');
  assert.deepEqual(deploymentBlockers(lowDisk), []);

  // Compatibility is not advisory.
  assert.ok(deploymentBlockers(healthy({ protocolVersion: 7 })).includes('agent-protocol'));
  assert.ok(deploymentBlockers(healthy({ agentVersion: '0.0.1' })).includes('agent-version'));
});

// ---------------------------------------------------------------------------
// Server enforcement: preflight is not decoration.
// ---------------------------------------------------------------------------

void test('the deployment path re-evaluates readiness itself', () => {
  const deployments = code('lib/server/deployments.ts');
  assert.match(deployments, /deploymentBlockers\(\{/);
  assert.match(deployments, /agentVersion: row\.agentVersion/);
  assert.match(deployments, /protocolVersion: row\.protocolVersion/);
  // The columns it judges on must actually be selected.
  assert.match(deployments, /agentVersion, protocolVersion\s*\n\s*FROM compute_node/);

  // A client-supplied verdict must never appear.
  assert.doesNotMatch(deployments, /body\.preflight|preflightPassed|skipPreflight/);
  const route = code('app/api/smart-deploy/route.ts');
  assert.doesNotMatch(route, /preflight/i);
});

void test('the pairing status surface cannot leak the secret', () => {
  const onboarding = code('lib/server/node-onboarding.ts');
  const route = code('app/api/nodes/pairing/[id]/route.ts');
  for (const body of [onboarding, route]) {
    assert.doesNotMatch(body, /codeHash/);
    assert.doesNotMatch(body, /tokenCiphertext/);
    assert.doesNotMatch(body, /tokenHash/);
  }
  // The SELECTs name their columns, so a `SELECT *` cannot start returning the
  // hash after a future schema change.
  assert.doesNotMatch(onboarding, /SELECT \*/);
  assert.match(onboarding, /SELECT id, expiresAt, consumedAt, nodeId/);
});

void test('every onboarding read is scoped to the caller workspace', () => {
  const onboarding = code('lib/server/node-onboarding.ts');
  const statements = onboarding.match(/(?:SELECT|UPDATE)[\s\S]*?(?=`)/g) ?? [];
  assert.ok(statements.length >= 4);
  for (const statement of statements) {
    assert.match(
      statement,
      /workspaceId = \?/,
      `an onboarding statement is not workspace-scoped: ${statement.slice(0, 80)}`,
    );
  }
});

// ---------------------------------------------------------------------------
// Pairing lifecycle against a real database.
// ---------------------------------------------------------------------------

function pairingDatabase(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = OFF');
  for (const name of ['0001_auth.sql', '0002_workspace.sql', '0003_auth_rate_limit.sql',
    '0004_security.sql', '0005_storage.sql', '0006_compute_nodes.sql']) {
    for (const statement of splitStatements(stripSqlComments(source(`db/migrations/${name}`)))) {
      database.exec(statement);
    }
  }
  return database;
}

void test('a ticket pairs once and never again', () => {
  const database = pairingDatabase();
  const now = 1_000_000;
  database.prepare(
    `INSERT INTO node_pairing (id, workspaceId, codeHash, name, createdBy, nodeId, expiresAt, consumedAt, createdAt)
     VALUES ('pair_1','ws_1','hash','Node','owner',NULL,?,NULL,?)`,
  ).run(now + NODE_TIMING.pairingTtlMs, now);

  // The atomic consume the real pairNode performs.
  const consume = database.prepare(
    `UPDATE node_pairing SET consumedAt = ?, nodeId = ?
      WHERE id = ? AND consumedAt IS NULL AND expiresAt > ?`,
  );
  assert.equal(consume.run(now, 'node_a', 'pair_1', now).changes, 1, 'first pairing must succeed');
  assert.equal(consume.run(now, 'node_b', 'pair_1', now).changes, 0, 'replay must change nothing');

  const row = database.prepare('SELECT nodeId FROM node_pairing WHERE id = ?').get('pair_1') as { nodeId: string };
  assert.equal(row.nodeId, 'node_a', 'the replay must not steal the ticket');
});

void test('an expired ticket cannot pair', () => {
  const database = pairingDatabase();
  const now = 1_000_000;
  database.prepare(
    `INSERT INTO node_pairing (id, workspaceId, codeHash, name, createdBy, nodeId, expiresAt, consumedAt, createdAt)
     VALUES ('pair_old','ws_1','hash','Node','owner',NULL,?,NULL,?)`,
  ).run(now - 1, now - NODE_TIMING.pairingTtlMs);
  const changed = database.prepare(
    `UPDATE node_pairing SET consumedAt = ?, nodeId = ?
      WHERE id = ? AND consumedAt IS NULL AND expiresAt > ?`,
  ).run(now, 'node_a', 'pair_old', now).changes;
  assert.equal(changed, 0);
});

void test('cancellation makes a ticket unusable by the same rule that rejects expiry', () => {
  const database = pairingDatabase();
  const now = 1_000_000;
  database.prepare(
    `INSERT INTO node_pairing (id, workspaceId, codeHash, name, createdBy, nodeId, expiresAt, consumedAt, createdAt)
     VALUES ('pair_c','ws_1','hash','Node','owner',NULL,?,NULL,?)`,
  ).run(now + NODE_TIMING.pairingTtlMs, now);

  // Cancellation is expiry-at-the-epoch, exactly what the service writes.
  database.prepare(
    `UPDATE node_pairing SET expiresAt = 0 WHERE id = ? AND workspaceId = ? AND consumedAt IS NULL`,
  ).run('pair_c', 'ws_1');

  const changed = database.prepare(
    `UPDATE node_pairing SET consumedAt = ?, nodeId = ?
      WHERE id = ? AND consumedAt IS NULL AND expiresAt > ?`,
  ).run(now, 'node_a', 'pair_c', now).changes;
  assert.equal(changed, 0, 'a cancelled ticket must not pair');

  const row = database.prepare('SELECT expiresAt, consumedAt FROM node_pairing WHERE id = ?').get('pair_c') as
    { expiresAt: number; consumedAt: number | null };
  // The row survives, so the audit trail still has something to point at.
  assert.equal(row.expiresAt, 0);
  assert.equal(row.consumedAt, null);
});

void test('cancelling never reaches another workspace', () => {
  const database = pairingDatabase();
  const now = 1_000_000;
  database.prepare(
    `INSERT INTO node_pairing (id, workspaceId, codeHash, name, createdBy, nodeId, expiresAt, consumedAt, createdAt)
     VALUES ('pair_x','ws_victim','hash','Node','owner',NULL,?,NULL,?)`,
  ).run(now + NODE_TIMING.pairingTtlMs, now);

  const changed = database.prepare(
    `UPDATE node_pairing SET expiresAt = 0 WHERE id = ? AND workspaceId = ? AND consumedAt IS NULL`,
  ).run('pair_x', 'ws_attacker').changes;
  assert.equal(changed, 0, 'a foreign workspace must not be able to cancel');

  const row = database.prepare('SELECT expiresAt FROM node_pairing WHERE id = ?').get('pair_x') as { expiresAt: number };
  assert.ok(row.expiresAt > now, 'the victim ticket must be untouched');
});

void test('the ticket window was not widened for convenience', () => {
  assert.equal(NODE_TIMING.pairingTtlMs, 10 * MINUTE);
  assert.equal(NODE_TIMING.onlineMs, 60_000);
  assert.equal(NODE_TIMING.heartbeatMs, 25_000);
});

// ---------------------------------------------------------------------------
// Evidence.
// ---------------------------------------------------------------------------

void test('onboarding evidence carries codes, never secrets', () => {
  const cancel = EVIDENCE_ACTIONS.find((entry) => entry.action === 'node.pairing.cancel');
  const preflight = EVIDENCE_ACTIONS.find((entry) => entry.action === 'node.preflight.run');
  assert.ok(cancel && preflight);
  assert.equal(cancel.resourceType, 'node_pairing');
  assert.equal(preflight.resourceType, 'compute_node');
  assert.deepEqual([...cancel.metadataKeys], ['reason']);
  assert.deepEqual(
    [...preflight.metadataKeys].sort(),
    ['agentVersion', 'failedChecks', 'protocolVersion', 'verdict'],
  );

  for (const entry of [cancel, preflight]) {
    for (const forbidden of ['code', 'hash', 'token', 'secret', 'key', 'path', 'capabilit', 'env']) {
      assert.ok(
        !entry.metadataKeys.some((metadataKey) => metadataKey.toLowerCase().includes(forbidden)),
        `${entry.action} must not carry a "${forbidden}"-shaped key`,
      );
    }
  }

  // Anything undeclared is dropped, so a future caller cannot smuggle the code.
  assert.deepEqual(
    narrowEvidenceMetadata('node.pairing.cancel', {
      reason: 'operator_cancelled',
      code: 'ysdp_secretsecretsecretsecretsecr',
      codeHash: 'deadbeef',
    }),
    { reason: 'operator_cancelled' },
  );
});

void test('the catalog grew by exactly the two onboarding actions', () => {
  // 26 at 0.15.0, +0 in the 0.15.1 hotfix, +2 here.
  assert.equal(EVIDENCE_ACTIONS.length, 28);
  const added = EVIDENCE_ACTIONS
    .filter((entry) => entry.action.startsWith('node.pairing.') || entry.action === 'node.preflight.run')
    .map((entry) => entry.action)
    .sort();
  assert.deepEqual(added, ['node.pairing.cancel', 'node.preflight.run']);
});

// ---------------------------------------------------------------------------
// Schema and Zero Mode.
// ---------------------------------------------------------------------------

void test('Phase 16 adds no migration', () => {
  const db = code('lib/server/db.ts');
  assert.match(db, /\{ name: '0019_shield_posture', sql: shieldPostureSchema \}/);
  assert.doesNotMatch(db, /0020/);

  // Everything preflight reads already exists on compute_node.
  const schema = source('db/migrations/0006_compute_nodes.sql');
  for (const column of ['agentVersion', 'protocolVersion', 'platform', 'architecture', 'capabilities', 'lastHeartbeatAt']) {
    assert.match(schema, new RegExp(`\\b${column}\\b`), `compute_node must already have ${column}`);
  }
  // And cancellation needs no column of its own.
  assert.match(schema, /expiresAt INTEGER/);
  assert.match(schema, /consumedAt INTEGER/);
});

void test('Phase 16 adds no binding, no cron, and no paid dependency', () => {
  const wrangler = source('wrangler.jsonc');
  assert.equal((wrangler.match(/"binding": "DB"/g) ?? []).length, 1);
  assert.equal((wrangler.match(/"\* \* \* \* \*"/g) ?? []).length, 1);
  for (const forbidden of ['r2_buckets', 'durable_objects', 'queues', 'analytics_engine', 'vectorize', 'hyperdrive']) {
    assert.doesNotMatch(wrangler, new RegExp(forbidden));
  }

  // The artifact ships with the existing static assets. No release host, no
  // registry, no account.
  const build = code('scripts/build-agent.mjs');
  assert.match(build, /public/);
  assert.doesNotMatch(build, /npm publish|registry\.npmjs|gh release|actions\/upload/);

  // The agent bundle is not fetched from a third party at runtime.
  const release = code('lib/agent-release.ts');
  assert.doesNotMatch(release, /npmjs|unpkg|jsdelivr|github\.com/);
});

void test('the agent download is reachable, not swallowed by the app router', () => {
  // Found by Production acceptance, not by any local run. The dev server hands
  // `public/` straight back, so the middleware matcher is never consulted
  // locally -- but in the deployed Worker every path the matcher covers goes
  // to the app router first, which answers an unknown route with the 404 page.
  // The first 0.16.0 deploy served a 404 for an artifact the Worker was
  // holding. The matcher must exclude the release directory the same way it
  // already excludes the other static files.
  const middleware = source('middleware.ts');
  const matcher = middleware.match(/matcher: \[([^\]]+)\]/)?.[1] ?? '';
  assert.ok(matcher.includes('agent/'), 'middleware must not intercept the agent release path');

  // The negative lookahead has to keep the other exclusions too.
  for (const kept of ['_next/static', '_next/image', 'favicon.svg', 'og.png']) {
    assert.ok(matcher.includes(kept), `the matcher dropped ${kept}`);
  }

  // Behavioural, not textual: build the same regex the matcher declares and
  // check what it actually captures.
  const pattern = new RegExp('^' + matcher.replace(/^['"`]|['"`]$/g, '') + '$');
  for (const asset of [
    agentDownloadPath(), `${agentDownloadPath()}.sha256`, '/agent/manifest.json',
    '/favicon.svg', '/og.png',
  ]) {
    assert.ok(!pattern.test(asset), `${asset} must bypass the middleware`);
  }
  for (const page of ['/nodes', '/projects', '/api/nodes', '/']) {
    assert.ok(pattern.test(page), `${page} must still run through the middleware`);
  }
});

void test('the product never claims the release is signed', () => {
  // Signing words are allowed only inside a sentence that DENIES them. This is
  // the same shape as the Phase 15 cadence test: banning the vocabulary
  // outright would forbid the honest disclaimer, which is the one place the
  // words genuinely belong.
  const claimWords = /\b(?:code[- ]signed|signed (?:binary|release|artifact)|notarized|trusted publisher|tamper[- ]proof|authenticode)\b/i;
  const denial = /\b(?:not|never|no|without|cannot|neither|inventing|worse)\b/i;

  for (const path of ['lib/agent-release.ts', 'components/nodes-view.tsx', 'README.md']) {
    const body = source(path);
    for (const sentence of body.split(/(?<=[.!?])\s+|\n\n/)) {
      if (!claimWords.test(sentence)) continue;
      assert.match(
        sentence,
        denial,
        `${path} states a signing property as fact: ${sentence.trim().slice(0, 120)}`,
      );
    }
  }

  // And the limitation is written down rather than merely not overclaimed.
  const release = source('lib/agent-release.ts');
  assert.match(release, /must never be described as giving you/i);
  assert.match(release, /compromised control plane/i);
});

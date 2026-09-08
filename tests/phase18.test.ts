import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { validateAppRuntimeJobPayload, type AppRuntimeJobPayload } from '../lib/app-runtime.ts';
import { CURRENT_AGENT_VERSION, NODE_PROTOCOL_VERSION } from '../lib/nodes.ts';
import {
  RECOVERY_REASON_CODES,
  recoveryAgentCompatible,
  recoveryReasonMessage,
} from '../lib/runtime-recovery.ts';

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

const legacyPayload: Omit<AppRuntimeJobPayload, 'expectedDesiredRevision' | 'protectedArtifactIds'> = {
  operation: 'start',
  deploymentId: `dpl_${'1'.repeat(24)}`,
  projectId: `prj_${'2'.repeat(24)}`,
  actionId: `dact_${'3'.repeat(24)}`,
  artifactId: `art_${'4'.repeat(24)}`,
  targetArtifactId: null,
  source: null,
  contract: {
    version: 1, framework: 'Node.js', packageManager: 'npm', lockfile: 'package-lock.json',
    nodeMajor: 26, installPolicy: 'frozen-lockfile-ignore-scripts', buildPolicy: 'none',
    startPolicy: 'node-entry', entrypoint: 'server.js', envNames: [],
  },
  environment: 'Production', environmentCiphertext: null, port: 41_111,
  healthPath: '/health', memoryMb: 256, diskQuotaBytes: 128 * 1024 ** 2,
  retainArtifacts: 5,
};

void test('Phase 18 recovery remains compatible after Phase 19 keeps Protocol 1', () => {
  assert.equal(JSON.parse(source('package.json')).version, '0.20.0');
  assert.equal(CURRENT_AGENT_VERSION, '0.7.0');
  assert.equal(NODE_PROTOCOL_VERSION, 1);
  assert.equal(recoveryAgentCompatible('0.4.2'), false);
  assert.equal(recoveryAgentCompatible('0.5.0'), true);
});

void test('legacy 0.4.2 payload shape remains accepted and new recovery fields default safely', () => {
  const parsed = validateAppRuntimeJobPayload(legacyPayload);
  assert.equal(parsed.ok, true);
  if (parsed.ok) {
    assert.equal(parsed.payload.expectedDesiredRevision, null);
    assert.deepEqual(parsed.payload.protectedArtifactIds, []);
  }
  const deployments = source('lib/server/deployments.ts');
  assert.match(deployments, /recoveryAgentCompatible\(node\.row\.agentVersion \?\? ''\)/);
  assert.match(deployments, /expectedDesiredRevision:[\s\S]*protectedArtifactIds/);
});

void test('recover is a no-build operation with an exact existing artifact and revision', () => {
  const parsed = validateAppRuntimeJobPayload({
    ...legacyPayload,
    operation: 'recover',
    expectedDesiredRevision: 7,
    protectedArtifactIds: [legacyPayload.artifactId],
  });
  assert.equal(parsed.ok, true);
  const runtime = source('agent/app-runtime.ts');
  const buildBranch = runtime.indexOf("payload.operation === 'deploy' || payload.operation === 'redeploy'");
  const recoverySelection = runtime.indexOf("payload.operation === 'rollback' ? payload.targetArtifactId : payload.artifactId");
  assert.ok(buildBranch >= 0 && recoverySelection > buildBranch);
  assert.doesNotMatch(runtime.slice(buildBranch, recoverySelection), /operation === 'recover'/);
});

void test('reconciliation stays heartbeat-driven, node-scoped, capped at 12, and storm guarded', () => {
  const server = source('lib/server/nodes.ts');
  const agent = source('agent/cli.ts');
  assert.match(server, /d\.workspaceId = \? AND d\.nodeId = \?/);
  assert.match(server, /ORDER BY d\.updatedAt ASC LIMIT 12/);
  assert.match(server, /recoveryRevision/);
  assert.match(server, /recoveryGeneration/);
  assert.match(agent, /runtimeGeneration = randomToken\(18\)/);
  assert.match(agent, /NODE_TIMING\.heartbeatMs/);
  assert.doesNotMatch(agent, /setInterval\([^,]+,\s*1_?000/);
  assert.equal((source('wrangler.jsonc').match(/\* \* \* \* \*/g) ?? []).length, 1);
});

void test('Stop preempts a leased recovery and bumps desired revision before its replacement can win', () => {
  const server = source('lib/server/deployments.ts');
  assert.match(server, /input\.operation === 'stop' && detail\.state === 'recovering'/);
  assert.match(server, /desiredState = 'stopped'[\s\S]*desiredRevision = COALESCE\(desiredRevision, 0\) \+ 1/);
  assert.match(server, /Recovery superseded by intentional Stop/);
  const agent = source('agent/app-runtime.ts');
  assert.match(agent, /shouldSpawnCrashReplacement/);
  assert.match(agent, /scheduledRevision[\s\S]*currentRevision/);
});

void test('recovery diagnostics and UI use fixed codes without PID or filesystem paths', () => {
  assert.ok(RECOVERY_REASON_CODES.includes('port_in_use'));
  assert.match(recoveryReasonMessage('runtime_incompatible'), /Agent 0\.5\.0/);
  const view = source('components/section-dashboard.tsx') + source('components/deployment-actions.tsx');
  assert.match(view, /desiredState/);
  assert.match(view, /observedState/);
  assert.match(view, /recover/);
  assert.match(view, /recoveryReasonMessage/);
  assert.doesNotMatch(view, /\bpid\b|artifactDirectory|rootDirectory/);
});

void test('recovery evidence has one catalog action and trusted actor classification', () => {
  const catalog = source('lib/audit-actions.ts');
  assert.equal((catalog.match(/action: 'deployment\.recovery'/g) ?? []).length, 1);
  const control = source('lib/server/app-runtime-control.ts');
  assert.match(control, /automatic \? 'system' : 'user'/);
  assert.match(control, /\? 'denied'\s*:\s*'failed'/);
  for (const forbidden of ['token', 'environment', 'filesystem', 'pid', 'stdout', 'stderr']) {
    const entry = catalog.slice(catalog.indexOf("action: 'deployment.recovery'"), catalog.indexOf('},', catalog.indexOf("action: 'deployment.recovery'")));
    assert.doesNotMatch(entry, new RegExp(`['"]${forbidden}['"]`, 'i'));
  }
});

void test('failed App Runtime completions preserve bounded recovery diagnostics', () => {
  const nodes = source('lib/server/nodes.ts');
  assert.match(nodes, /job\.type === APP_RUNTIME_JOB_TYPE[\s\S]*sanitizeJobResult\(input\.result, 192 \* 1024\)/);
  assert.match(nodes, /App Runtime failures carry the same bounded, allowlisted diagnostic/);
});

void test('Phase 18 adds no paid Cloudflare resource and keeps Zero Mode at zero', () => {
  const wrangler = source('wrangler.jsonc');
  assert.doesNotMatch(wrangler, /\br2_buckets\b|\bqueues\b|\bdurable_objects\b/);
  assert.equal((wrangler.match(/database_name/g) ?? []).length, 1);
  assert.match(source('README.md'), /\$0\.00|zero-cost/i);
});

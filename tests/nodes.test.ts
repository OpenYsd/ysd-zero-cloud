import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  NODE_PROTOCOL_VERSION,
  NODE_TIMING,
  agentVersionSupported,
  constantTimeEqual,
  deriveNodeStatus,
  evaluateCompletion,
  parseCapabilities,
  parseMetrics,
  recoverExpiredLease,
  requestIsFresh,
  sanitizeJobResult,
  sha256,
  signAgentRequest,
  signJobClaim,
  stableJson,
  validNonce,
  validateJob,
  verifyAgentRequestSignature,
  verifyJobClaim,
  type SignedJobClaim,
} from '../lib/nodes.ts';

const TOKEN = `node_${'a'.repeat(24)}.a-strong-random-token`;
const NOW = Date.UTC(2026, 7, 29, 12, 0, 0);

void test('capabilities and metrics accept bounded hardware facts', () => {
  assert.deepEqual(
    parseCapabilities({
      cpu: { cores: 8, model: 'CPU' },
      memory: { totalBytes: 16 * 1024 ** 3 },
      gpu: { available: true, model: 'GPU' },
      docker: { available: true },
      contracts: { ai: true, gameServers: true },
    }),
    {
      cpu: { cores: 8, model: 'CPU' },
      memory: { totalBytes: 16 * 1024 ** 3 },
      gpu: { available: true, model: 'GPU' },
      docker: { available: true },
      contracts: { ai: true, gameServers: true },
    },
  );
  assert.equal(
    parseMetrics({
      cpuLoadPercent: 30,
      memoryUsedBytes: 5,
      memoryTotalBytes: 4,
      runningJobs: 0,
    }),
    null,
  );
});

void test('only diagnostic job payloads are executable', () => {
  assert.equal(validateJob('diagnostic.ping', { message: 'hello' }).ok, true);
  assert.equal(validateJob('diagnostic.snapshot', {}).ok, true);
  assert.deepEqual(validateJob('ai.inference', { prompt: 'x' }), {
    ok: false,
    status: 409,
    code: 'placeholder',
    error:
      'This is a Phase 3 API contract only. AI and Game Server execution are not enabled.',
  });
  for (const payload of [
    { shell: 'rm -rf /' },
    { command: 'whoami' },
    { script: 'process.exit()' },
    { __proto__: { polluted: true } },
  ]) {
    assert.equal(
      validateJob('diagnostic.ping', payload).ok,
      false,
      stableJson(payload),
    );
  }
});

void test('forged heartbeats fail their body-bound HMAC', async () => {
  const input = {
    method: 'POST',
    pathname: '/api/nodes/agent/heartbeat',
    timestamp: NOW,
    nonce: 'nonce_abcdefghijklmnopqrstuvwxyz',
    body: '{"metrics":{"cpuLoadPercent":10}}',
  };
  const signature = await signAgentRequest(TOKEN, input);
  assert.equal(
    await verifyAgentRequestSignature(TOKEN, { ...input, signature }),
    true,
  );
  assert.equal(
    await verifyAgentRequestSignature(TOKEN, {
      ...input,
      body: '{"metrics":{"cpuLoadPercent":99}}',
      signature,
    }),
    false,
  );
  assert.equal(
    await verifyAgentRequestSignature(`${TOKEN}x`, { ...input, signature }),
    false,
  );
});

void test('request timestamps and nonces enforce the replay window', () => {
  assert.equal(validNonce('nonce_abcdefghijklmnopqrstuvwxyz'), true);
  assert.equal(validNonce('short'), false);
  assert.equal(requestIsFresh(NOW, NOW), true);
  assert.equal(requestIsFresh(NOW - NODE_TIMING.requestSkewMs - 1, NOW), false);
});

void test('signed job claims bind tenant, node, payload, lease, and attempt', async () => {
  const claim: SignedJobClaim = {
    protocolVersion: NODE_PROTOCOL_VERSION,
    jobId: 'job_1',
    workspaceId: 'ws_one',
    nodeId: 'node_one',
    type: 'diagnostic.ping',
    payload: { message: 'hello' },
    payloadHash: await sha256(stableJson({ message: 'hello' })),
    leaseId: 'lease_one',
    leaseExpiresAt: NOW + 60_000,
    attempt: 1,
  };
  const signature = await signJobClaim(TOKEN, claim);
  assert.equal(await verifyJobClaim(TOKEN, claim, signature), true);
  assert.equal(
    await verifyJobClaim(TOKEN, { ...claim, workspaceId: 'ws_two' }, signature),
    false,
  );
  assert.equal(
    await verifyJobClaim(TOKEN, { ...claim, attempt: 2 }, signature),
    false,
  );
});

void test('stale and cross-node lease completions are refused', () => {
  const leased = {
    state: 'leased' as const,
    assignedNodeId: 'node_one',
    leaseId: 'lease_one',
    leaseExpiresAt: NOW + 10_000,
  };
  assert.deepEqual(evaluateCompletion(leased, 'node_one', 'lease_one', NOW), {
    allowed: true,
  });
  assert.equal(
    evaluateCompletion(leased, 'node_two', 'lease_one', NOW).allowed,
    false,
  );
  assert.deepEqual(
    evaluateCompletion(leased, 'node_one', 'lease_one', NOW + 10_000),
    {
      allowed: false,
      reason: 'expired',
      message: 'The job lease has expired.',
    },
  );
  assert.deepEqual(recoverExpiredLease(1, 3), {
    state: 'queued',
    retry: true,
  });
  assert.deepEqual(recoverExpiredLease(3, 3), {
    state: 'timed_out',
    retry: false,
  });
});

void test('offline, stale, and revoked node state is deterministic', () => {
  assert.equal(
    deriveNodeStatus({ revokedAt: null, lastHeartbeatAt: NOW, now: NOW }),
    'online',
  );
  assert.equal(
    deriveNodeStatus({
      revokedAt: null,
      lastHeartbeatAt: NOW - NODE_TIMING.onlineMs - 1,
      now: NOW,
    }),
    'stale',
  );
  assert.equal(
    deriveNodeStatus({
      revokedAt: null,
      lastHeartbeatAt: NOW - NODE_TIMING.staleMs - 1,
      now: NOW,
    }),
    'offline',
  );
  assert.equal(
    deriveNodeStatus({ revokedAt: NOW, lastHeartbeatAt: NOW, now: NOW }),
    'revoked',
  );
});

void test('credentials use fixed-time digest comparison and version gates', async () => {
  const digest = await sha256(TOKEN);
  assert.equal(constantTimeEqual(digest, await sha256(TOKEN)), true);
  assert.equal(constantTimeEqual(digest, await sha256(`${TOKEN}x`)), false);
  assert.equal(agentVersionSupported('0.1.0'), true);
  assert.equal(agentVersionSupported('0.0.9'), false);
  assert.equal(agentVersionSupported('not-a-version'), false);
});

void test('job results reject credential-like and oversized fields', () => {
  assert.deepEqual(sanitizeJobResult({ reply: 'pong' }), { reply: 'pong' });
  assert.equal(sanitizeJobResult({ token: 'leak' }), null);
  assert.equal(sanitizeJobResult({ output: 'x'.repeat(20_000) }), null);
});

void test('D1 schema makes idempotency and replay uniqueness workspace-safe', async () => {
  const migration = await readFile(
    new URL('../db/migrations/0006_compute_nodes.sql', import.meta.url),
    'utf8',
  );
  assert.match(migration, /PRIMARY KEY \(nodeId, nonce\)/);
  assert.match(
    migration,
    /UNIQUE INDEX IF NOT EXISTS node_job_idempotency_uidx\s+ON node_job \(workspaceId, idempotencyKey\)/,
  );
  for (const table of [
    'node_pairing',
    'compute_node',
    'node_request_nonce',
    'node_job',
    'node_metric',
    'node_job_event',
    'node_security_event',
  ]) {
    const tableBlock = migration.split(
      `CREATE TABLE IF NOT EXISTS ${table} (`,
    )[1];
    assert.match(tableBlock ?? '', /workspaceId TEXT NOT NULL/);
  }
});

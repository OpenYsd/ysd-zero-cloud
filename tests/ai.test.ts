import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  acquireAiModel,
  discoverAiCapabilities,
  executeAiInference,
  type LocalFetch,
} from '../agent/ai-runtime.ts';
import { executeSignedJob } from '../agent/runtime.ts';
import {
  AI_LIMITS,
  APPROVED_AI_MODELS,
  containsNetworkOrExecutionAbuse,
  parseAiCapabilities,
  validateAiJobPayload,
} from '../lib/ai.ts';
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
const TOKEN = `node_${'c'.repeat(24)}.ai-agent-secret`;
const MODEL = APPROVED_AI_MODELS[0];
const DIGEST = `sha256:${'a'.repeat(64)}`;

function inferencePayload() {
  return {
    modelId: MODEL.id,
    runtime: MODEL.runtime,
    runtimeModel: MODEL.runtimeModel,
    prompt: 'Give a short local-only answer.',
    systemPrompt: null,
    maxTokens: 128,
    temperature: 0.2,
    responseFormat: 'text' as const,
    timeoutMs: 30_000,
    provider: 'local-node' as const,
    zeroMode: true as const,
    expectedMemoryBytes: MODEL.expectedMemoryBytes,
    requiredVramBytes: MODEL.requiredVramBytes,
  };
}

function capabilities(options: { cached?: boolean; disk?: number } = {}): NodeCapabilities {
  return {
    cpu: { cores: 8, model: 'Test CPU' },
    memory: { totalBytes: 8 * GiB, freeBytes: 6 * GiB },
    gpu: { available: false, model: null, vramBytes: null },
    disk: { totalBytes: 20 * GiB, freeBytes: options.disk ?? 10 * GiB },
    docker: { available: false },
    ai: {
      runtimes: [
        {
          runtime: 'ollama',
          available: true,
          version: '0.12.0',
          transport: 'loopback-http',
        },
      ],
      cachedModels: options.cached
        ? [
            {
              runtime: 'ollama',
              runtimeModel: MODEL.runtimeModel,
              sizeBytes: MODEL.sizeBytes,
              checksum: DIGEST,
              modifiedAt: Date.now(),
            },
          ]
        : [],
      maxConcurrentJobs: 1,
    },
    gameServers: {
      minecraftJavaAvailable: false,
      javaVersion: null,
      activeServers: 0,
      maxConcurrentServers: 1,
    },
    contracts: { ai: true, gameServers: false },
  };
}

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status });
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  return input instanceof URL ? input.href : input.url;
}

void test('the AI contract accepts only reviewed local-node model fields', () => {
  const valid = validateAiJobPayload('ai.inference', inferencePayload());
  assert.equal(valid.ok, true);
  for (const mutation of [
    { provider: 'workers-ai' },
    { zeroMode: false },
    { command: 'whoami' },
    { runtimeModel: '../../secret.gguf' },
    { maxTokens: AI_LIMITS.maximumTokens + 1 },
  ]) {
    assert.equal(
      validateAiJobPayload('ai.inference', {
        ...inferencePayload(),
        ...mutation,
      }).ok,
      false,
      JSON.stringify(mutation),
    );
  }
  assert.equal(
    containsNetworkOrExecutionAbuse({
      prompt: 'fetch http://169.254.169.254/latest',
    }),
    true,
  );
  assert.equal(
    containsNetworkOrExecutionAbuse({
      prompt: 'local inference',
      provider: 'local-node',
    }),
    false,
  );
});

void test('capability parsing rejects forged runtime transports and duplicate runtimes', () => {
  const baseline = capabilities({ cached: true }).ai;
  assert.deepEqual(parseAiCapabilities(baseline), baseline);
  assert.equal(
    parseAiCapabilities({
      ...baseline,
      runtimes: [
        ...baseline.runtimes,
        { ...baseline.runtimes[0], version: 'forged' },
      ],
    }),
    null,
  );
  assert.equal(
    parseAiCapabilities({
      ...baseline,
      runtimes: [
        { ...baseline.runtimes[0], transport: 'public-websocket' },
      ],
    }),
    null,
  );
});

void test('signed Ollama inference uses only the fixed loopback endpoint', async () => {
  const payload = inferencePayload();
  const claim: SignedJobClaim = {
    protocolVersion: NODE_PROTOCOL_VERSION,
    jobId: 'job_ai_one',
    workspaceId: 'ws_one',
    nodeId: 'node_one',
    type: 'ai.inference',
    payload,
    payloadHash: await sha256(stableJson(payload)),
    leaseId: 'lease_ai_one',
    leaseExpiresAt: Date.now() + 60_000,
    attempt: 1,
  };
  const signature = await signJobClaim(TOKEN, claim);
  const urls: string[] = [];
  const fetcher: LocalFetch = async (input, init) => {
    const url = requestUrl(input);
    urls.push(url);
    assert.equal(url, 'http://127.0.0.1:11434/api/chat');
    assert.equal(init?.method, 'POST');
    return json({
      message: { content: 'Computed on the user-owned node.' },
      prompt_eval_count: 8,
      eval_count: 7,
    });
  };
  const result = await executeSignedJob({
    token: TOKEN,
    claim,
    signature,
    capabilities: capabilities({ cached: true }),
    fetcher,
  });
  assert.equal(result.status, 'succeeded');
  assert.deepEqual(urls, ['http://127.0.0.1:11434/api/chat']);

  const forged = await executeSignedJob({
    token: `${TOKEN}forged`,
    claim,
    signature,
    capabilities: capabilities({ cached: true }),
    fetcher: async () => {
      throw new Error('forged work reached the runtime');
    },
  });
  assert.equal(forged.status, 'failed');
});

void test('inference cancellation aborts local work and is never retried', async () => {
  const controller = new AbortController();
  controller.abort('operator-cancelled');
  const result = await executeAiInference({
    payload: inferencePayload(),
    capabilities: capabilities({ cached: true }),
    metrics: {
      cpuLoadPercent: 10,
      memoryUsedBytes: 2 * GiB,
      memoryTotalBytes: 8 * GiB,
      runningJobs: 1,
    },
    signal: controller.signal,
    fetcher: async (_input, init) => {
      if (init?.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
      return json({ message: { content: 'should not complete' } });
    },
  });
  assert.deepEqual(result, {
    status: 'cancelled',
    error: 'Inference was cancelled.',
    retryable: false,
  });
});

void test('model acquisition is allowlisted, disk guarded, and SHA-256 verified', async () => {
  const payload = {
    modelId: MODEL.id,
    runtime: 'ollama',
    runtimeModel: MODEL.runtimeModel,
    source: 'ollama-library',
    expectedSizeBytes: MODEL.sizeBytes,
    checksum: null,
  };
  const tooSmall = await acquireAiModel({
    payload,
    capabilities: capabilities({ disk: MODEL.sizeBytes }),
    fetcher: async () => {
      throw new Error('disk guard failed open');
    },
  });
  assert.equal(tooSmall.status, 'failed');

  const urls: string[] = [];
  const result = await acquireAiModel({
    payload,
    capabilities: capabilities(),
    fetcher: async (input) => {
      const url = requestUrl(input);
      urls.push(url);
      if (url.endsWith('/api/pull')) return json({ status: 'success' });
      if (url.endsWith('/api/tags')) {
        return json({
          models: [
            {
              name: MODEL.runtimeModel,
              size: MODEL.sizeBytes,
              digest: DIGEST,
              modified_at: new Date().toISOString(),
            },
          ],
        });
      }
      throw new Error(`unexpected endpoint: ${url}`);
    },
  });
  assert.equal(result.status, 'succeeded');
  assert.deepEqual(urls, [
    'http://127.0.0.1:11434/api/pull',
    'http://127.0.0.1:11434/api/tags',
  ]);

  assert.equal(
    (
      await acquireAiModel({
        payload: { ...payload, runtimeModel: '../malicious.gguf' },
        capabilities: capabilities(),
        fetcher: async () => {
          throw new Error('malicious path reached runtime');
        },
      })
    ).status,
    'failed',
  );
});

void test('runtime discovery probes only the two fixed loopback APIs', async () => {
  const urls: string[] = [];
  const discovered = await discoverAiCapabilities(async (input) => {
    const url = requestUrl(input);
    urls.push(url);
    if (url.endsWith('/api/version')) return json({ version: '0.12.0' });
    if (url.endsWith('/api/tags')) return json({ models: [] });
    if (url.endsWith('/health')) return json({ status: 'ok' });
    if (url.endsWith('/v1/models')) return json({ data: [] });
    return json({}, 404);
  });
  assert.equal(discovered.runtimes.length, 2);
  assert.ok(
    urls.every(
      (url) =>
        url.startsWith('http://127.0.0.1:11434/') ||
        url.startsWith('http://127.0.0.1:8080/'),
    ),
  );
});

void test('AI Shield reports unsigned, replayed, stale, and boundary abuse', () => {
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
    ai: {
      totalAiNodes: 2,
      eligibleOnlineNodes: 0,
      staleNodes: 1,
      offlineNodes: 1,
      outdatedNodes: 1,
      unsupportedRuntime: 0,
      invalidModelHash: 1,
      oversizedModels: 0,
      insufficientDisk: 0,
      unsignedJobs: 1,
      forgedClaims: 1,
      replayedJobs: 1,
      expiredLeases: 1,
      repeatedFailures: 0,
      suspiciousVolume: 0,
      resourceExhaustion: 0,
      unexpectedOutbound: 1,
      forbiddenProvider: 1,
      revokedActivity: 1,
      modelPathAbuse: 1,
      payloadAbuse: 1,
    },
    now: Date.now(),
  };
  const report = runShieldRules(snapshot);
  const codes = new Set(report.findings.map((finding) => finding.code));
  for (const code of [
    'ai-no-eligible-node',
    'ai-node-readiness',
    'ai-integrity-failure',
    'ai-execution-boundary-violation',
    'ai-revoked-node-activity',
    'ai-operational-anomaly',
  ]) {
    assert.equal(codes.has(code), true, code);
  }
});

void test('AI D1 schema is workspace isolated and does not add paid resources', async () => {
  const migration = await readFile(
    new URL('../db/migrations/0007_ai_compute.sql', import.meta.url),
    'utf8',
  );
  for (const table of ['ai_model', 'ai_model_cache', 'ai_inference']) {
    const block = migration.split(`CREATE TABLE IF NOT EXISTS ${table} (`)[1];
    assert.match(block ?? '', /workspaceId TEXT NOT NULL/);
  }
  assert.doesNotMatch(migration, /workers_ai|paid_provider|billing/i);
});

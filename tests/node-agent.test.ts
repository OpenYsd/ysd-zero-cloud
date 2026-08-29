import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { loadCredentials, saveCredentials } from '../agent/credentials.ts';
import { executeSignedJob } from '../agent/runtime.ts';
import {
  NODE_PROTOCOL_VERSION,
  sha256,
  signJobClaim,
  stableJson,
  type NodeCapabilities,
  type SignedJobClaim,
} from '../lib/nodes.ts';

const TOKEN = `node_${'b'.repeat(24)}.local-agent-secret`;
const TEST_CAPABILITIES: NodeCapabilities = {
  cpu: { cores: 2, model: 'test' },
  memory: { totalBytes: 4 * 1024 ** 3, freeBytes: 3 * 1024 ** 3 },
  gpu: { available: false, model: null, vramBytes: null },
  disk: { totalBytes: 10 * 1024 ** 3, freeBytes: 8 * 1024 ** 3 },
  docker: { available: false },
  ai: { runtimes: [], cachedModels: [], maxConcurrentJobs: 1 },
  contracts: { ai: false, gameServers: false },
};

void test('agent credential file is encrypted and rejects the wrong key', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ysd-node-agent-'));
  const file = path.join(directory, 'credentials.enc');
  const previous = process.env.YSD_NODE_AGENT_KEY;
  try {
    process.env.YSD_NODE_AGENT_KEY = 'correct-local-passphrase';
    await saveCredentials(file, {
      origin: 'https://example.workers.dev',
      nodeId: 'node_one',
      workspaceId: 'ws_one',
      token: TOKEN,
      createdAt: 1,
    });
    const disk = await readFile(file, 'utf8');
    assert.doesNotMatch(disk, /local-agent-secret/);
    assert.equal((await loadCredentials(file)).token, TOKEN);

    process.env.YSD_NODE_AGENT_KEY = 'incorrect-passphrase';
    await assert.rejects(loadCredentials(file));
  } finally {
    if (previous === undefined) delete process.env.YSD_NODE_AGENT_KEY;
    else process.env.YSD_NODE_AGENT_KEY = previous;
    await rm(directory, { recursive: true, force: true });
  }
});

void test('agent executes signed diagnostics without a shell surface', async () => {
  const payload = { message: 'hello' };
  const claim: SignedJobClaim = {
    protocolVersion: NODE_PROTOCOL_VERSION,
    jobId: 'job_one',
    workspaceId: 'ws_one',
    nodeId: 'node_one',
    type: 'diagnostic.ping',
    payload,
    payloadHash: await sha256(stableJson(payload)),
    leaseId: 'lease_one',
    leaseExpiresAt: Date.now() + 60_000,
    attempt: 1,
  };
  const signature = await signJobClaim(TOKEN, claim);
  const result = await executeSignedJob({
    token: TOKEN,
    claim,
    signature,
    capabilities: TEST_CAPABILITIES,
  });
  assert.equal(result.status, 'succeeded');
  if (result.status === 'succeeded') assert.equal(result.result.reply, 'pong');

  assert.deepEqual(
    await executeSignedJob({
      token: `${TOKEN}forged`,
      claim,
      signature,
      capabilities: TEST_CAPABILITIES,
    }),
    {
      status: 'failed',
      error: 'The control-plane job signature is invalid.',
      retryable: false,
    },
  );
});

void test('agent refuses an expired signed lease', async () => {
  const claim: SignedJobClaim = {
    protocolVersion: NODE_PROTOCOL_VERSION,
    jobId: 'job_old',
    workspaceId: 'ws_one',
    nodeId: 'node_one',
    type: 'diagnostic.snapshot',
    payload: {},
    payloadHash: await sha256('{}'),
    leaseId: 'lease_old',
    leaseExpiresAt: 100,
    attempt: 1,
  };
  const signature = await signJobClaim(TOKEN, claim);
  const result = await executeSignedJob({
    token: TOKEN,
    claim,
    signature,
    capabilities: TEST_CAPABILITIES,
    now: 101,
  });
  assert.deepEqual(result, {
    status: 'failed',
    error: 'The job claim is stale or incompatible.',
    retryable: false,
  });
});

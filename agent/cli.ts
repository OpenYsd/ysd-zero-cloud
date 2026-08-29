#!/usr/bin/env node

import os from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';

import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  NODE_TIMING,
  randomToken,
  signAgentRequest,
  type SignedJobClaim,
} from '../lib/nodes.ts';
import { loadCredentials, saveCredentials } from './credentials.ts';
import {
  collectCapabilities,
  collectMetrics,
  executeSignedJob,
} from './runtime.ts';

type Command = 'pair' | 'run';

type Arguments = {
  command: Command;
  origin: string;
  configPath: string;
};

function argument(name: string): string | null {
  const index = process.argv.indexOf(name);
  return index >= 0 ? (process.argv[index + 1] ?? null) : null;
}

function safeOrigin(value: string): string {
  const url = new URL(value);
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    throw new Error(
      'The control plane must use HTTPS (HTTP is allowed only on localhost).',
    );
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(
      'The control-plane URL cannot include credentials, a query, or a fragment.',
    );
  }
  return url.origin;
}

function parseArguments(): Arguments {
  const candidate = process.argv[2] ?? 'run';
  if (candidate !== 'pair' && candidate !== 'run') {
    throw new Error(
      'Usage: agent/cli.ts pair|run --url <https://control-plane> [--config <path>]',
    );
  }
  const origin = safeOrigin(
    argument('--url') ?? process.env.YSD_NODE_URL ?? '',
  );
  return {
    command: candidate,
    origin,
    configPath:
      argument('--config') ??
      process.env.YSD_NODE_CONFIG ??
      '.ysd-node-agent.credentials',
  };
}

async function jsonRequest<T>(url: string, init: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    signal: AbortSignal.timeout(30_000),
  });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) {
    throw new Error(body.error ?? `Control plane answered ${response.status}.`);
  }
  return body;
}

async function pair(arguments_: Arguments): Promise<void> {
  const code = process.env.YSD_NODE_PAIRING_CODE ?? '';
  if (!/^ysdp_[A-Za-z0-9_-]{32}$/.test(code)) {
    throw new Error(
      'Set YSD_NODE_PAIRING_CODE to the one-time code shown by the Nodes page.',
    );
  }
  const response = await jsonRequest<{
    nodeId: string;
    workspaceId: string;
    token: string;
  }>(`${arguments_.origin}/api/nodes/agent/pair`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      agentVersion: CURRENT_AGENT_VERSION,
      protocolVersion: NODE_PROTOCOL_VERSION,
      platform: os.platform(),
      architecture: os.arch(),
      capabilities: collectCapabilities(),
    }),
  });
  await saveCredentials(arguments_.configPath, {
    origin: arguments_.origin,
    nodeId: response.nodeId,
    workspaceId: response.workspaceId,
    token: response.token,
    createdAt: Date.now(),
  });
  console.log(
    `Paired node ${response.nodeId}. The credential is encrypted at ${arguments_.configPath}.`,
  );
  console.log(
    'Run the agent with the same YSD_NODE_AGENT_KEY and the run command.',
  );
}

async function signedPost<T>(input: {
  origin: string;
  token: string;
  pathname: string;
  body: Record<string, unknown>;
}): Promise<T> {
  const raw = JSON.stringify(input.body);
  const timestamp = Date.now();
  const nonce = randomToken(18);
  const signature = await signAgentRequest(input.token, {
    method: 'POST',
    pathname: input.pathname,
    timestamp,
    nonce,
    body: raw,
  });
  return jsonRequest<T>(`${input.origin}${input.pathname}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.token}`,
      'Content-Type': 'application/json',
      'X-YSD-Timestamp': String(timestamp),
      'X-YSD-Nonce': nonce,
      'X-YSD-Signature': signature,
    },
    body: raw,
  });
}

async function heartbeat(origin: string, token: string): Promise<void> {
  await signedPost({
    origin,
    token,
    pathname: '/api/nodes/agent/heartbeat',
    body: {
      agentVersion: CURRENT_AGENT_VERSION,
      capabilities: collectCapabilities(),
      metrics: collectMetrics(0),
    },
  });
}

async function poll(origin: string, token: string): Promise<boolean> {
  const response = await signedPost<{
    job: { claim: SignedJobClaim; signature: string } | null;
  }>({
    origin,
    token,
    pathname: '/api/nodes/agent/claim',
    body: {},
  });
  if (!response.job) return false;
  const completed = await executeSignedJob({
    token,
    claim: response.job.claim,
    signature: response.job.signature,
    capabilities: collectCapabilities(),
  });
  await signedPost({
    origin,
    token,
    pathname: `/api/nodes/agent/jobs/${response.job.claim.jobId}/complete`,
    body: {
      leaseId: response.job.claim.leaseId,
      claim: response.job.claim,
      claimSignature: response.job.signature,
      ...completed,
    },
  });
  console.log(
    `Completed ${response.job.claim.type} (${response.job.claim.jobId}).`,
  );
  return true;
}

async function run(arguments_: Arguments): Promise<never> {
  const credentials = await loadCredentials(arguments_.configPath);
  if (credentials.origin !== arguments_.origin) {
    throw new Error(
      'The encrypted credential belongs to a different control-plane origin.',
    );
  }
  console.log(
    `YSD Node Agent ${CURRENT_AGENT_VERSION} started in outbound-only mode.`,
  );
  let lastHeartbeat = 0;
  let backoff = 2_000;
  for (;;) {
    try {
      const now = Date.now();
      if (now - lastHeartbeat >= NODE_TIMING.heartbeatMs) {
        await heartbeat(credentials.origin, credentials.token);
        lastHeartbeat = Date.now();
      }
      const worked = await poll(credentials.origin, credentials.token);
      backoff = 2_000;
      if (!worked) await delay(5_000);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Unknown agent error.';
      console.error(`Control-plane connection failed: ${message}`);
      await delay(backoff);
      backoff = Math.min(30_000, backoff * 2);
    }
  }
}

const arguments_ = parseArguments();
if (arguments_.command === 'pair') await pair(arguments_);
else await run(arguments_);

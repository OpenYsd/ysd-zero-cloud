#!/usr/bin/env node

import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  NODE_TIMING,
  randomToken,
  signAgentRequest,
  type SignedJobClaim,
} from '../lib/nodes.ts';
import { defaultCredentialPath } from './agent-key.ts';
import { loadCredentials, saveCredentials } from './credentials.ts';
import {
  collectGameServerSnapshots,
  shutdownManagedGameServers,
} from './game-runtime.ts';
import {
  collectAppRuntimeSnapshots,
  shutdownManagedApps,
} from './app-runtime.ts';
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

const USAGE = [
  'YSD Node Agent',
  '',
  'Usage:',
  '  node ysd-node-agent-<version>.mjs pair --url <https://control-plane>',
  '  node ysd-node-agent-<version>.mjs run  --url <https://control-plane>',
  '',
  'Options:',
  '  --url <origin>     Control plane origin. HTTPS, or HTTP on localhost.',
  '  --config <path>    Credential file. Defaults to a per-user location.',
  '  --version          Print the agent and protocol version.',
  '  --help             Print this message.',
].join(String.fromCharCode(10));

function parseArguments(): Arguments {
  const candidate = process.argv[2] ?? 'run';
  if (candidate !== 'pair' && candidate !== 'run') {
    throw new Error(USAGE);
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
      defaultCredentialPath(),
  };
}

class ControlPlaneError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function jsonRequest<T>(url: string, init: RequestInit): Promise<T> {
  const timeout = AbortSignal.timeout(30_000);
  const response = await fetch(url, {
    ...init,
    signal: init.signal ? AbortSignal.any([init.signal, timeout]) : timeout,
  });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) {
    throw new ControlPlaneError(
      response.status,
      body.error ?? `Control plane answered ${response.status}.`,
    );
  }
  return body;
}

const PAIRING_CODE_PATTERN = /^ysdp_[A-Za-z0-9_-]{32}$/;

/**
 * Reads the one-time pairing code.
 *
 * An environment variable stays supported because automation and the
 * acceptance harness need it, but it is no longer the documented path. Typing
 * the code at a prompt keeps it out of shell history, out of the process list
 * where any other local user can read it, and out of the terminal scrollback
 * someone pastes into a screenshot. The code is never echoed back.
 */
async function readPairingCode(): Promise<string> {
  const supplied = process.env.YSD_NODE_PAIRING_CODE?.trim() ?? '';
  if (supplied) {
    if (!PAIRING_CODE_PATTERN.test(supplied)) {
      throw new Error('YSD_NODE_PAIRING_CODE is not a valid one-time pairing code.');
    }
    return supplied;
  }

  if (!process.stdin.isTTY) {
    throw new Error(
      'Run this in an interactive terminal so the pairing code can be typed, '
      + 'or set YSD_NODE_PAIRING_CODE for automation.',
    );
  }

  process.stdout.write('Paste the one-time pairing code from the Nodes page: ');
  const code = await new Promise<string>((resolve) => {
    let buffer = '';
    process.stdin.setEncoding('utf8');
    const onData = (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      process.stdin.off('data', onData);
      process.stdin.pause();
      resolve(buffer.slice(0, newline).trim());
    };
    process.stdin.on('data', onData);
    process.stdin.resume();
  });
  process.stdout.write('\n');

  if (!PAIRING_CODE_PATTERN.test(code)) {
    // The value is not echoed back: a mistyped code is still a secret.
    throw new Error('That is not a valid one-time pairing code.');
  }
  return code;
}

async function pair(arguments_: Arguments): Promise<void> {
  const code = await readPairingCode();
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
      capabilities: await collectCapabilities(),
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
  signal?: AbortSignal;
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
    signal: input.signal,
  });
}

async function heartbeat(
  origin: string,
  token: string,
  workspaceId: string,
  gameRootDirectory: string,
  appRootDirectory: string,
  runningJobs = 0,
): Promise<void> {
  await signedPost({
    origin,
    token,
    pathname: '/api/nodes/agent/heartbeat',
    body: {
      agentVersion: CURRENT_AGENT_VERSION,
      capabilities: await collectCapabilities(),
      metrics: collectMetrics(runningJobs),
      gameServers: await collectGameServerSnapshots(
        gameRootDirectory,
        workspaceId,
      ),
      appDeployments: collectAppRuntimeSnapshots(),
    },
  });
}

async function monitorClaim(input: {
  origin: string;
  token: string;
  claim: SignedJobClaim;
  execution: AbortController;
  signal: AbortSignal;
  workspaceId: string;
  gameRootDirectory: string;
  appRootDirectory: string;
}): Promise<void> {
  let lastHeartbeat = Date.now();
  while (!input.signal.aborted && !input.execution.signal.aborted) {
    try {
      const status = await signedPost<{
        state: string;
        cancelRequested: boolean;
      }>({
        origin: input.origin,
        token: input.token,
        pathname: `/api/nodes/agent/jobs/${input.claim.jobId}/status`,
        body: { leaseId: input.claim.leaseId },
        signal: input.signal,
      });
      if (status.cancelRequested || status.state !== 'leased') {
        input.execution.abort('control-plane-cancelled');
        return;
      }
      if (Date.now() - lastHeartbeat >= NODE_TIMING.heartbeatMs) {
        await heartbeat(
          input.origin,
          input.token,
          input.workspaceId,
          input.gameRootDirectory,
          input.appRootDirectory,
          1,
        );
        lastHeartbeat = Date.now();
      }
      await delay(1_500, undefined, { signal: input.signal });
    } catch (error) {
      if (input.signal.aborted) return;
      // Losing authenticated lease visibility is a fail-closed condition.
      input.execution.abort(error);
      return;
    }
  }
}

async function poll(
  origin: string,
  token: string,
  workspaceId: string,
  gameRootDirectory: string,
  appRootDirectory: string,
): Promise<boolean> {
  const response = await signedPost<{
    job: { claim: SignedJobClaim; signature: string } | null;
  }>({
    origin,
    token,
    pathname: '/api/nodes/agent/claim',
    body: {},
  });
  if (!response.job) return false;
  const capabilities = await collectCapabilities();
  const execution = new AbortController();
  const monitor = new AbortController();
  const monitorPromise = monitorClaim({
    origin,
    token,
    claim: response.job.claim,
    execution,
    signal: monitor.signal,
    workspaceId,
    gameRootDirectory,
    appRootDirectory,
  });
  let completed: Awaited<ReturnType<typeof executeSignedJob>>;
  try {
    completed = await executeSignedJob({
      token,
      claim: response.job.claim,
      signature: response.job.signature,
      capabilities,
      signal: execution.signal,
      gameRootDirectory,
      appRootDirectory,
    });
  } finally {
    monitor.abort('job-complete');
    await monitorPromise;
  }
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
  const gameRootDirectory = path.resolve(
    path.dirname(arguments_.configPath),
    '.ysd-game-servers',
  );
  const appRootDirectory = path.resolve(
    path.dirname(arguments_.configPath),
    '.ysd-app-runtime',
  );
  console.log(
    'Game Servers stay private on this machine unless you change local networking yourself.',
  );
  let lastHeartbeat = 0;
  let backoff = 2_000;
  for (;;) {
    try {
      const now = Date.now();
      if (now - lastHeartbeat >= NODE_TIMING.heartbeatMs) {
        await heartbeat(
          credentials.origin,
          credentials.token,
          credentials.workspaceId,
          gameRootDirectory,
          appRootDirectory,
        );
        lastHeartbeat = Date.now();
      }
      const worked = await poll(
        credentials.origin,
        credentials.token,
        credentials.workspaceId,
        gameRootDirectory,
        appRootDirectory,
      );
      backoff = 2_000;
      if (!worked) await delay(5_000);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Unknown agent error.';
      console.error(`Control-plane connection failed: ${message}`);
      if (
        error instanceof ControlPlaneError &&
        (error.status === 401 || error.status === 403)
      ) {
        await shutdownManagedGameServers();
        await shutdownManagedApps();
        throw new Error(
          'Node authorization was rejected; managed Game Servers were stopped locally.',
          { cause: error },
        );
      }
      await delay(backoff);
      backoff = Math.min(30_000, backoff * 2);
    }
  }
}

const flags = new Set(process.argv.slice(2));
if (flags.has('--version') || flags.has('-v')) {
  // Deliberately just these two lines. Printing the platform, paths, or
  // runtime details here would leak machine facts into whatever someone
  // pastes into a support thread.
  console.log('YSD Node Agent ' + CURRENT_AGENT_VERSION);
  console.log('Protocol ' + String(NODE_PROTOCOL_VERSION));
  process.exit(0);
}
if (flags.has('--help') || flags.has('-h') || flags.has('help')) {
  console.log(USAGE);
  process.exit(0);
}

const arguments_ = parseArguments();
if (arguments_.command === 'pair') await pair(arguments_);
else await run(arguments_);

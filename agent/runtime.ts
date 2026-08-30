import os from 'node:os';
import { statfs } from 'node:fs/promises';
import path from 'node:path';

import {
  acquireAiModel,
  discoverAiCapabilities,
  executeAiInference,
  type LocalFetch,
} from './ai-runtime.ts';
import {
  discoverGameServerCapabilities,
  executeGameServerJob,
} from './game-runtime.ts';

import {
  CURRENT_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  sha256,
  stableJson,
  verifyJobClaim,
  type NodeCapabilities,
  type NodeMetrics,
  type SignedJobClaim,
} from '../lib/nodes.ts';

/**
 * Local execution runtime.
 *
 * AI handlers use fixed loopback APIs. Game Server handlers use the fixed Java
 * executable with shell=false and reviewed arguments. No payload can select an
 * executable, command, script, path, or network destination.
 */

function nonNegativeEnvironmentBytes(name: string): number | null {
  const raw = process.env[name]?.trim();
  if (!raw) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export async function collectCapabilities(
  fetcher: LocalFetch = fetch,
): Promise<NodeCapabilities> {
  const processors = os.cpus();
  const gpuModel = process.env.YSD_NODE_GPU?.trim().slice(0, 128) || null;
  const gpuVramBytes = nonNegativeEnvironmentBytes('YSD_NODE_GPU_VRAM_BYTES');
  const docker = process.env.YSD_NODE_DOCKER?.trim().toLowerCase() === 'true';
  const [ai, gameServers] = await Promise.all([
    discoverAiCapabilities(fetcher),
    discoverGameServerCapabilities(),
  ]);
  let disk = { totalBytes: 0, freeBytes: 0 };
  try {
    const statistics = await statfs(process.cwd());
    disk = {
      totalBytes: Math.max(0, statistics.blocks * statistics.bsize),
      freeBytes: Math.max(0, statistics.bavail * statistics.bsize),
    };
  } catch {
    // A platform without statfs can still run diagnostics, but cannot acquire models.
  }
  return {
    cpu: {
      cores: Math.max(1, processors.length),
      model: processors[0]?.model?.trim().slice(0, 128) || 'Unknown CPU',
    },
    memory: { totalBytes: os.totalmem(), freeBytes: os.freemem() },
    gpu: {
      available: Boolean(gpuModel),
      model: gpuModel,
      vramBytes: gpuVramBytes,
    },
    disk,
    docker: { available: docker },
    ai,
    gameServers,
    contracts: {
      ai: ai.runtimes.some((runtime) => runtime.available),
      gameServers: gameServers.minecraftJavaAvailable,
    },
  };
}

export function collectMetrics(runningJobs = 0): NodeMetrics {
  const cores = Math.max(1, os.cpus().length);
  return {
    cpuLoadPercent: Math.max(
      0,
      Math.min(100, (os.loadavg()[0]! / cores) * 100),
    ),
    memoryUsedBytes: Math.max(0, os.totalmem() - os.freemem()),
    memoryTotalBytes: os.totalmem(),
    runningJobs,
  };
}

export type AgentJobResult =
  | { status: 'succeeded'; result: Record<string, unknown> }
  | { status: 'failed'; error: string; retryable: boolean }
  | { status: 'cancelled'; error: string; retryable: false };

export async function executeSignedJob(input: {
  token: string;
  claim: SignedJobClaim;
  signature: string;
  capabilities: NodeCapabilities;
  signal?: AbortSignal;
  fetcher?: LocalFetch;
  gameRootDirectory?: string;
  now?: number;
}): Promise<AgentJobResult> {
  const now = input.now ?? Date.now();
  if (!(await verifyJobClaim(input.token, input.claim, input.signature))) {
    return {
      status: 'failed',
      error: 'The control-plane job signature is invalid.',
      retryable: false,
    };
  }
  if (
    input.claim.protocolVersion !== NODE_PROTOCOL_VERSION ||
    input.claim.leaseExpiresAt <= now
  ) {
    return {
      status: 'failed',
      error: 'The job claim is stale or incompatible.',
      retryable: false,
    };
  }
  if (
    (await sha256(stableJson(input.claim.payload))) !== input.claim.payloadHash
  ) {
    return {
      status: 'failed',
      error: 'The job payload digest is invalid.',
      retryable: false,
    };
  }

  switch (input.claim.type) {
    case 'diagnostic.ping':
      return {
        status: 'succeeded',
        result: {
          reply: 'pong',
          message:
            typeof input.claim.payload.message === 'string'
              ? input.claim.payload.message
              : '',
          agentVersion: CURRENT_AGENT_VERSION,
          completedAt: now,
        },
      };
    case 'diagnostic.snapshot':
      return {
        status: 'succeeded',
        result: {
          capabilities: input.capabilities,
          metrics: collectMetrics(1),
          agentVersion: CURRENT_AGENT_VERSION,
          completedAt: now,
        },
      };
    case 'ai.inference':
      return executeAiInference({
        payload: input.claim.payload,
        capabilities: input.capabilities,
        metrics: collectMetrics(1),
        signal: input.signal,
        fetcher: input.fetcher,
      });
    case 'ai.model.acquire':
      return acquireAiModel({
        payload: input.claim.payload,
        capabilities: input.capabilities,
        signal: input.signal,
        fetcher: input.fetcher,
      });
    case 'game-server.lifecycle':
    case 'game-server.config':
    case 'game-server.player':
    case 'game-server.backup':
    case 'game-server.logs':
      return executeGameServerJob({
        type: input.claim.type,
        payload: input.claim.payload,
        workspaceId: input.claim.workspaceId,
        rootDirectory:
          input.gameRootDirectory ?? path.resolve('.ysd-game-servers'),
        capabilities: input.capabilities.gameServers,
        signal: input.signal,
        fetcher: input.fetcher,
      });
    default:
      return {
        status: 'failed',
        error: 'The job type is not in the local execution allowlist.',
        retryable: false,
      };
  }
}

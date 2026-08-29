import os from 'node:os';

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
 * There is intentionally no child_process import. Handlers call built-in Node
 * APIs only, so neither a job payload nor a later UI change can turn this
 * phase into remote shell access.
 */

export function collectCapabilities(): NodeCapabilities {
  const processors = os.cpus();
  const gpuModel = process.env.YSD_NODE_GPU?.trim().slice(0, 128) || null;
  const docker = process.env.YSD_NODE_DOCKER?.trim().toLowerCase() === 'true';
  return {
    cpu: {
      cores: Math.max(1, processors.length),
      model: processors[0]?.model?.trim().slice(0, 128) || 'Unknown CPU',
    },
    memory: { totalBytes: os.totalmem() },
    gpu: { available: Boolean(gpuModel), model: gpuModel },
    docker: { available: docker },
    // Capability contracts only. Phase 3 never dispatches these job types.
    contracts: { ai: Boolean(gpuModel), gameServers: docker },
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
  | { status: 'failed'; error: string };

export async function executeSignedJob(input: {
  token: string;
  claim: SignedJobClaim;
  signature: string;
  capabilities: NodeCapabilities;
  now?: number;
}): Promise<AgentJobResult> {
  const now = input.now ?? Date.now();
  if (!(await verifyJobClaim(input.token, input.claim, input.signature))) {
    return {
      status: 'failed',
      error: 'The control-plane job signature is invalid.',
    };
  }
  if (
    input.claim.protocolVersion !== NODE_PROTOCOL_VERSION ||
    input.claim.leaseExpiresAt <= now
  ) {
    return {
      status: 'failed',
      error: 'The job claim is stale or incompatible.',
    };
  }
  if (
    (await sha256(stableJson(input.claim.payload))) !== input.claim.payloadHash
  ) {
    return { status: 'failed', error: 'The job payload digest is invalid.' };
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
    default:
      return {
        status: 'failed',
        error: 'The job type is not in the local Phase 3 allowlist.',
      };
  }
}

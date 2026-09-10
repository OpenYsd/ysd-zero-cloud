import { env } from 'cloudflare:workers';

import { createId, decryptSecret, encryptSecret } from '@/lib/crypto';
import {
  AI_LIMITS,
  APPROVED_AI_MODELS,
  aiLeaseDuration,
  aiModelCached,
  aiRuntimeAvailable,
  estimateTokens,
  safeModelChecksum,
  validateAiJobPayload,
} from '@/lib/ai';
import type {
  ComputeNode,
  NodeJob,
  NodesState,
  NodeSecurityEvent,
} from '@/lib/domain';
import {
  GAME_SERVER_LIMITS,
  GAME_SERVER_STATUSES,
  gameServerLeaseDuration,
  parseGameServerSnapshots,
  redactGameLogLine,
  validateGameServerJobPayload,
  type GameServerStatus,
} from '@/lib/game-servers';
import {
  APP_RUNTIME_JOB_TYPE,
  APP_RUNTIME_LIMITS,
  appRuntimeLeaseDuration,
  parseAppRuntimeSnapshots,
  validateAppRuntimeJobPayload,
  type AppRuntimeJobPayload,
  type AppEnvironment,
  parsePrivatePortCandidates,
  privatePortInRange,
} from '@/lib/app-runtime';
import {
  planRuntimeReconciliation,
  recoveryAgentCompatible,
  type ReconciliationDeployment,
} from '@/lib/runtime-recovery';
import {
  CURRENT_AGENT_VERSION,
  sealNodeEnvironment,
  MINIMUM_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  NODE_TIMING,
  agentVersionSupported,
  constantTimeEqual,
  deriveNodeStatus,
  evaluateCompletion,
  isExecutableJobType,
  normalizeNodeName,
  parseCapabilities,
  parseMetrics,
  randomToken,
  requestIsFresh,
  sanitizeJobResult,
  sha256,
  signJobClaim,
  stableJson,
  validNonce,
  validateJob,
  verifyAgentRequestSignature,
  verifyJobClaim,
  type NodeCapabilities,
  type NodeJobState,
  type NodeMetrics,
  type SignedJobClaim,
} from '@/lib/nodes';
import { authSecret } from './auth';
import { recordEvidence } from './audit';
import { MAX_WORKFLOW_CHAIN_DEPTH } from '@/lib/workflows';
import { db, execute, query, queryOne } from './db';
import { clientAddress, enforceRateLimit } from './rate-limit';
import { writeLog } from './logs';
import { assertResourceCapacity } from './organization-limits';
import { emitWorkflowEvent, recordWorkflowSecurityEvent } from './workflow-events';
import {
  recordAppRuntimeJobOutcome,
  syncAppRuntimeSnapshots,
} from './app-runtime-control';

/**
 * D1-backed Compute Nodes control plane.
 *
 * An agent never accepts an inbound connection. It authenticates each polling
 * request with a bearer credential plus an HMAC over method, path, timestamp,
 * nonce, and body. D1's unique nonce key makes a valid request one-shot.
 */

const MAX_NODES_PER_WORKSPACE = 25;
const MAX_QUEUED_JOBS_PER_WORKSPACE = 250;
const DEFAULT_MAX_ATTEMPTS = 3;

type NodeRow = {
  id: string;
  workspaceId: string;
  pairingId: string;
  name: string;
  agentVersion: string;
  protocolVersion: number;
  platform: string;
  architecture: string;
  capabilities: string;
  tokenCiphertext: string;
  tokenHash: string;
  pairedAt: number;
  lastHeartbeatAt: number | null;
  revokedAt: number | null;
  revokedBy: string | null;
  assignmentsDisabledAt: number | null;
  assignmentsDisabledBy: string | null;
  createdAt: number;
  updatedAt: number;
};

type NodeWithMetricRow = NodeRow & {
  cpuLoadPercent: number | null;
  memoryUsedBytes: number | null;
  memoryTotalBytes: number | null;
  runningJobs: number | null;
};

type JobRow = {
  id: string;
  workspaceId: string;
  type: string;
  payload: string;
  payloadHash: string;
  state: NodeJobState;
  priority: number;
  idempotencyKey: string | null;
  targetNodeId: string | null;
  assignedNodeId: string | null;
  leaseId: string | null;
  leaseExpiresAt: number | null;
  attempts: number;
  maxAttempts: number;
  claimSignature: string | null;
  result: string | null;
  lastError: string | null;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
  workflowId: string | null;
  workflowExecutionId: string | null;
  workflowCorrelationId: string | null;
  workflowChainDepth: number | null;
};

export type WorkflowJobContext = {
  workflowId: string;
  executionId: string;
  correlationId: string;
  chainDepth: number;
};

type PairingRow = {
  id: string;
  workspaceId: string;
  name: string;
  expiresAt: number;
  consumedAt: number | null;
};

function changed(result: D1Result): boolean {
  return (result.meta.changes ?? 0) > 0;
}

function credentialKey(): string {
  return env.YSD_SECRETS_KEY?.trim() || authSecret();
}

function safePlatform(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const safe = value.replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 64);
  return safe || fallback;
}

function safeError(value: string): string {
  let safe = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code >= 32 && code !== 127) safe += character;
  }
  return safe.slice(0, 500);
}

function safeJsonRecord(value: string | null): Record<string, unknown> | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === 'object' &&
      parsed !== null &&
      !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function capabilitiesFromRow(value: string): NodeCapabilities {
  try {
    const parsed = parseCapabilities(JSON.parse(value) as unknown);
    if (parsed) return parsed;
  } catch {
    // A malformed historical row is rendered as an inert node, never trusted.
  }
  return {
    cpu: { cores: 1, model: 'Unknown CPU' },
    memory: { totalBytes: 1, freeBytes: 0 },
    gpu: { available: false, model: null, vramBytes: null },
    disk: { totalBytes: 0, freeBytes: 0 },
    docker: { available: false },
    ai: { runtimes: [], cachedModels: [], maxConcurrentJobs: 1 },
    gameServers: {
      minecraftJavaAvailable: false,
      javaVersion: null,
      activeServers: 0,
      maxConcurrentServers: 1,
    },
    appRuntime: {
      available: false,
      nodeVersion: '',
      nodeMajor: 0,
      permissionModel: false,
      networkGuard: false,
      packageManagers: [],
      activeDeployments: 0,
      maxDeployments: 1,
    },
    contracts: { ai: false, gameServers: false, appRuntime: false },
  };
}

function metricsFromRow(row: NodeWithMetricRow): NodeMetrics | null {
  if (
    row.cpuLoadPercent === null ||
    row.memoryUsedBytes === null ||
    row.memoryTotalBytes === null ||
    row.runningJobs === null
  ) {
    return null;
  }
  return {
    cpuLoadPercent: row.cpuLoadPercent,
    memoryUsedBytes: row.memoryUsedBytes,
    memoryTotalBytes: row.memoryTotalBytes,
    runningJobs: row.runningJobs,
  };
}

function toNode(row: NodeWithMetricRow, now: number): ComputeNode {
  return {
    id: row.id,
    name: row.name,
    status: deriveNodeStatus({
      revokedAt: row.revokedAt,
      lastHeartbeatAt: row.lastHeartbeatAt,
      now,
    }),
    agentVersion: row.agentVersion,
    protocolVersion: row.protocolVersion,
    platform: row.platform,
    architecture: row.architecture,
    capabilities: capabilitiesFromRow(row.capabilities),
    pairedAt: row.pairedAt,
    lastHeartbeatAt: row.lastHeartbeatAt,
    revokedAt: row.revokedAt,
    assignmentsDisabledAt: row.assignmentsDisabledAt,
    assignmentsDisabledBy: row.assignmentsDisabledBy,
    metrics: metricsFromRow(row),
  };
}

function toJob(row: JobRow): NodeJob {
  return {
    id: row.id,
    type: row.type as NodeJob['type'],
    state: row.state,
    targetNodeId: row.targetNodeId,
    assignedNodeId: row.assignedNodeId,
    attempts: row.attempts,
    maxAttempts: row.maxAttempts,
    leaseExpiresAt: row.leaseExpiresAt,
    result: safeJsonRecord(row.result),
    lastError: row.lastError,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    completedAt: row.completedAt,
  };
}

type AiModelRow = {
  id: string;
  catalogId: string;
  runtime: 'ollama' | 'llama.cpp';
  runtimeModel: string;
  checksum: string | null;
};

export async function ensureAiCatalog(
  workspaceId: string,
  now: number,
): Promise<void> {
  const database = await db();
  await database.batch(
    APPROVED_AI_MODELS.map((model) =>
      database
        .prepare(
          `INSERT OR IGNORE INTO ai_model
           (id, workspaceId, catalogId, displayName, runtime, family,
            runtimeModel, source, sizeBytes, expectedMemoryBytes,
            requiredVramBytes, checksum, enabled, state, lastVerifiedAt,
            lastUsedAt, createdAt, updatedAt)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'available',
                   NULL, NULL, ?, ?)`,
        )
        .bind(
          createId('aim'),
          workspaceId,
          model.id,
          model.displayName,
          model.runtime,
          model.family,
          model.runtimeModel,
          model.source,
          model.sizeBytes,
          model.expectedMemoryBytes,
          model.requiredVramBytes,
          model.checksum,
          now,
          now,
        ),
    ),
  );
}

async function syncAiNodeSnapshot(
  workspaceId: string,
  nodeId: string,
  capabilities: NodeCapabilities,
  now: number,
): Promise<void> {
  await ensureAiCatalog(workspaceId, now);
  const models = await query<AiModelRow>(
    `SELECT id, catalogId, runtime, runtimeModel, checksum
     FROM ai_model WHERE workspaceId = ? AND enabled = 1`,
    workspaceId,
  );
  const database = await db();
  await database.batch(
    models.map((model) => {
      const cached = capabilities.ai.cachedModels.find(
        (entry) =>
          entry.runtime === model.runtime &&
          (entry.runtimeModel === model.runtimeModel ||
            (model.runtime === 'llama.cpp' &&
              entry.runtimeModel === 'local-model')),
      );
      const runtimeReady = aiRuntimeAvailable(capabilities.ai, model.runtime);
      const checksumMismatch = Boolean(
        cached?.checksum &&
          model.checksum &&
          !constantTimeEqual(cached.checksum, model.checksum),
      );
      const state = checksumMismatch
        ? 'error'
        : cached
          ? 'ready'
          : runtimeReady
            ? 'available'
            : 'unavailable';
      return database
        .prepare(
          `INSERT INTO ai_model_cache
           (workspaceId, nodeId, modelId, state, sizeBytes, checksum, error,
            lastVerifiedAt, lastUsedAt, updatedAt)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
           ON CONFLICT(nodeId, modelId) DO UPDATE SET
             state = excluded.state,
             sizeBytes = excluded.sizeBytes,
             checksum = excluded.checksum,
             error = excluded.error,
             lastVerifiedAt = excluded.lastVerifiedAt,
             updatedAt = excluded.updatedAt`,
        )
        .bind(
          workspaceId,
          nodeId,
          model.id,
          state,
          cached?.sizeBytes ?? 0,
          cached?.checksum ?? null,
          checksumMismatch ? 'The reported model checksum does not match.' : null,
          now,
          now,
        );
    }),
  );
}

function jobEligibleForNode(
  job: JobRow,
  payload: Record<string, unknown>,
  capabilities: NodeCapabilities,
): boolean {
  if (job.type === APP_RUNTIME_JOB_TYPE) {
    const validated = validateAppRuntimeJobPayload(payload);
    if (!validated.ok || !capabilities.contracts.appRuntime || !capabilities.appRuntime?.available) return false;
    const app = validated.payload;
    return (
      capabilities.appRuntime.packageManagers.includes(app.contract?.packageManager ?? 'npm') &&
      capabilities.appRuntime.activeDeployments < capabilities.appRuntime.maxDeployments &&
      capabilities.memory.freeBytes >= app.memoryMb * 1024 ** 2 + APP_RUNTIME_LIMITS.memoryReserveBytes &&
      capabilities.disk.freeBytes >= app.diskQuotaBytes + APP_RUNTIME_LIMITS.diskReserveBytes
    );
  }
  if (job.type.startsWith('game-server.')) {
    const validated = validateGameServerJobPayload(job.type, payload);
    if (!validated.ok) return false;
    const operation = validated.payload.operation;
    if (
      job.type === 'game-server.lifecycle' &&
      (operation === 'create' || operation === 'start' || operation === 'restart')
    ) {
      if (
        !capabilities.gameServers.minecraftJavaAvailable ||
        capabilities.gameServers.activeServers >=
          capabilities.gameServers.maxConcurrentServers
      ) {
        return false;
      }
      if (operation === 'create') {
        const ramBytes = (validated.payload.ramMb as number) * 1024 ** 2;
        const diskBytes = validated.payload.diskQuotaBytes as number;
        return (
          capabilities.memory.freeBytes >=
            ramBytes + GAME_SERVER_LIMITS.memoryReserveBytes &&
          capabilities.disk.freeBytes >=
            diskBytes + GAME_SERVER_LIMITS.diskReserveBytes
        );
      }
    }
    return true;
  }
  if (job.type !== 'ai.inference' && job.type !== 'ai.model.acquire') {
    return true;
  }
  const validated = validateAiJobPayload(job.type, payload);
  if (!validated.ok) return false;
  const aiPayload = validated.payload;
  if (!aiRuntimeAvailable(capabilities.ai, aiPayload.runtime)) return false;
  if (job.type === 'ai.model.acquire') {
    if (!('expectedSizeBytes' in aiPayload)) return false;
    return (
      capabilities.disk.freeBytes >=
      aiPayload.expectedSizeBytes + AI_LIMITS.diskReserveBytes
    );
  }
  if (!('expectedMemoryBytes' in aiPayload)) return false;
  return (
    aiModelCached(
      capabilities.ai,
      aiPayload.runtime,
      aiPayload.runtimeModel,
    ) &&
    capabilities.memory.freeBytes >= aiPayload.expectedMemoryBytes &&
    (aiPayload.requiredVramBytes === 0 ||
      (capabilities.gpu.available &&
        (capabilities.gpu.vramBytes ?? 0) >= aiPayload.requiredVramBytes))
  );
}

export type PairingTicket = {
  id: string;
  name: string;
  code: string;
  expiresAt: number;
  protocolVersion: number;
  minimumAgentVersion: string;
};

export async function createPairing(input: {
  workspaceId: string;
  name: unknown;
  actor: string;
}): Promise<
  | { ok: true; pairing: PairingTicket }
  | { ok: false; status: number; error: string }
> {
  const name = normalizeNodeName(input.name);
  if (!name) {
    return {
      ok: false,
      status: 400,
      error: 'Use a node name between 2 and 64 characters.',
    };
  }
  const capacity = await assertResourceCapacity(input.workspaceId, 'nodes');
  if (!capacity.ok) return { ok: false, status: 409, error: capacity.error };
  const existing = await queryOne<{ total: number }>(
    'SELECT COUNT(*) AS total FROM compute_node WHERE workspaceId = ? AND revokedAt IS NULL',
    input.workspaceId,
  );
  if ((existing?.total ?? 0) >= MAX_NODES_PER_WORKSPACE) {
    return {
      ok: false,
      status: 409,
      error: `A workspace can keep at most ${MAX_NODES_PER_WORKSPACE} active nodes.`,
    };
  }

  const now = Date.now();
  const code = `ysdp_${randomToken(24)}`;
  const pairing: PairingTicket = {
    id: createId('pair'),
    name,
    code,
    expiresAt: now + NODE_TIMING.pairingTtlMs,
    protocolVersion: NODE_PROTOCOL_VERSION,
    minimumAgentVersion: MINIMUM_AGENT_VERSION,
  };
  await execute(
    `INSERT INTO node_pairing
     (id, workspaceId, codeHash, name, createdBy, nodeId, expiresAt, consumedAt, createdAt)
     VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?)`,
    pairing.id,
    input.workspaceId,
    await sha256(code),
    pairing.name,
    input.actor,
    pairing.expiresAt,
    now,
  );
  await writeLog({
    workspaceId: input.workspaceId,
    source: 'node',
    message: `Created a one-time pairing ticket for ${name}`,
    actor: input.actor,
    resource: pairing.id,
  });
  return { ok: true, pairing };
}

export type PairNodeInput = {
  code: unknown;
  agentVersion: unknown;
  protocolVersion: unknown;
  platform: unknown;
  architecture: unknown;
  capabilities: unknown;
};

export async function pairNode(input: PairNodeInput): Promise<
  | {
      ok: true;
      nodeId: string;
      workspaceId: string;
      token: string;
      heartbeatMs: number;
      leaseMs: number;
    }
  | { ok: false; status: number; error: string }
> {
  if (
    typeof input.code !== 'string' ||
    !/^ysdp_[A-Za-z0-9_-]{32}$/.test(input.code)
  ) {
    return { ok: false, status: 401, error: 'Pairing was refused.' };
  }
  if (
    typeof input.agentVersion !== 'string' ||
    !agentVersionSupported(input.agentVersion) ||
    input.protocolVersion !== NODE_PROTOCOL_VERSION
  ) {
    return {
      ok: false,
      status: 426,
      error: `Agent ${MINIMUM_AGENT_VERSION} or newer with protocol ${NODE_PROTOCOL_VERSION} is required.`,
    };
  }
  const capabilities = parseCapabilities(input.capabilities);
  if (!capabilities) {
    return {
      ok: false,
      status: 400,
      error: 'The capability declaration is invalid.',
    };
  }

  const now = Date.now();
  const pairing = await queryOne<PairingRow>(
    `SELECT id, workspaceId, name, expiresAt, consumedAt
     FROM node_pairing WHERE codeHash = ?`,
    await sha256(input.code),
  );
  if (!pairing || pairing.consumedAt !== null || pairing.expiresAt <= now) {
    return { ok: false, status: 401, error: 'Pairing was refused.' };
  }

  const nodeId = createId('node');
  const token = `${nodeId}.${randomToken(32)}`;
  const consumed = await execute(
    `UPDATE node_pairing SET consumedAt = ?, nodeId = ?
     WHERE id = ? AND consumedAt IS NULL AND expiresAt > ?`,
    now,
    nodeId,
    pairing.id,
    now,
  );
  if (!changed(consumed)) {
    return { ok: false, status: 409, error: 'Pairing was already consumed.' };
  }

  await execute(
    `INSERT INTO compute_node
     (id, workspaceId, pairingId, name, agentVersion, protocolVersion, platform,
      architecture, capabilities, tokenCiphertext, tokenHash, pairedAt,
      lastHeartbeatAt, revokedAt, revokedBy, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`,
    nodeId,
    pairing.workspaceId,
    pairing.id,
    pairing.name,
    input.agentVersion,
    NODE_PROTOCOL_VERSION,
    safePlatform(input.platform, 'unknown'),
    safePlatform(input.architecture, 'unknown'),
    stableJson(capabilities),
    await encryptSecret(token, credentialKey()),
    await sha256(token),
    now,
    now,
    now,
  );
  await syncAiNodeSnapshot(pairing.workspaceId, nodeId, capabilities, now);
  await writeLog({
    workspaceId: pairing.workspaceId,
    source: 'node',
    message: `Paired ${pairing.name} with outbound-only transport`,
    actor: `agent:${nodeId}`,
    resource: nodeId,
  });
  return {
    ok: true,
    nodeId,
    workspaceId: pairing.workspaceId,
    token,
    heartbeatMs: NODE_TIMING.heartbeatMs,
    leaseMs: NODE_TIMING.leaseMs,
  };
}

type AgentContext = {
  node: NodeRow;
  token: string;
};

export type AgentAuthentication =
  | { ok: true; context: AgentContext }
  | { ok: false; response: Response };

async function recordSecurityEvent(input: {
  node: Pick<NodeRow, 'id' | 'workspaceId'>;
  request: Request;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}): Promise<void> {
  try {
    const network = clientAddress(input.request);
    await execute(
      `INSERT INTO node_security_event
       (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      createId('nsec'),
      input.node.workspaceId,
      input.node.id,
      input.type,
      input.severity,
      input.detail.slice(0, 500),
      network ? (await sha256(network)).slice(0, 22) : null,
      Date.now(),
    );
  } catch {
    // Authentication must still fail closed if its audit row cannot be stored.
  }
}

function agentFailure(status = 401): AgentAuthentication {
  return {
    ok: false,
    response: Response.json(
      { error: 'Node authentication failed.' },
      { status },
    ),
  };
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get('authorization');
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token.length <= 256 ? token : null;
}

export async function authenticateAgentRequest(
  request: Request,
  rawBody: string,
): Promise<AgentAuthentication> {
  const token = bearerToken(request);
  const separator = token?.indexOf('.') ?? -1;
  const nodeId = separator > 0 ? token!.slice(0, separator) : '';
  if (!/^node_[a-f0-9]{24}$/.test(nodeId)) return agentFailure();

  const node = await queryOne<NodeRow>(
    `SELECT id, workspaceId, pairingId, name, agentVersion, protocolVersion,
            platform, architecture, capabilities, tokenCiphertext, tokenHash,
            pairedAt, lastHeartbeatAt, revokedAt, revokedBy, createdAt, updatedAt
     FROM compute_node WHERE id = ?`,
    nodeId,
  );
  if (!node) return agentFailure();
  const tokenHash = await sha256(token!);
  if (!constantTimeEqual(tokenHash, node.tokenHash)) {
    await recordSecurityEvent({
      node,
      request,
      type: 'invalid-token',
      severity: 'high',
      detail:
        'A bearer credential with the node identifier had an invalid secret.',
    });
    return agentFailure();
  }
  if (node.revokedAt !== null) {
    await recordSecurityEvent({
      node,
      request,
      type: 'revoked-token-used',
      severity: 'high',
      detail: 'A revoked node credential attempted to reach the control plane.',
    });
    return agentFailure();
  }

  let decrypted: string;
  try {
    decrypted = await decryptSecret(node.tokenCiphertext, credentialKey());
  } catch {
    return agentFailure(503);
  }
  if (!constantTimeEqual(decrypted, token!)) return agentFailure();

  const timestamp = Number(request.headers.get('x-ysd-timestamp'));
  const nonce = request.headers.get('x-ysd-nonce') ?? '';
  const signature = request.headers.get('x-ysd-signature') ?? '';
  if (!requestIsFresh(timestamp, Date.now()) || !validNonce(nonce)) {
    await recordSecurityEvent({
      node,
      request,
      type: 'stale-or-invalid-request',
      severity: 'medium',
      detail:
        'A signed request was outside the accepted clock window or used an invalid nonce.',
    });
    return agentFailure();
  }

  const verified = await verifyAgentRequestSignature(decrypted, {
    method: request.method,
    pathname: new URL(request.url).pathname,
    timestamp,
    nonce,
    body: rawBody,
    signature,
  });
  if (!verified) {
    await recordSecurityEvent({
      node,
      request,
      type: 'forged-request-signature',
      severity: 'critical',
      detail: 'The request HMAC did not match its body and node credential.',
    });
    return agentFailure();
  }

  const nonceResult = await execute(
    `INSERT OR IGNORE INTO node_request_nonce
     (workspaceId, nodeId, nonce, requestTimestamp, createdAt) VALUES (?, ?, ?, ?, ?)`,
    node.workspaceId,
    node.id,
    nonce,
    timestamp,
    Date.now(),
  );
  if (!changed(nonceResult)) {
    await recordSecurityEvent({
      node,
      request,
      type: 'replay-detected',
      severity: 'critical',
      detail: 'A previously accepted signed nonce was replayed.',
    });
    return agentFailure();
  }

  const limited = await enforceRateLimit('node:agent', node.id);
  if (limited.response) return { ok: false, response: limited.response };
  return { ok: true, context: { node, token: decrypted } };
}

async function pruneNodeHistory(nodeId: string, now: number): Promise<void> {
  const database = await db();
  await database.batch([
    database
      .prepare(
        'DELETE FROM node_request_nonce WHERE nodeId = ? AND createdAt < ?',
      )
      .bind(nodeId, now - NODE_TIMING.nonceRetentionMs),
    database
      .prepare('DELETE FROM node_metric WHERE nodeId = ? AND recordedAt < ?')
      .bind(nodeId, now - NODE_TIMING.metricRetentionMs),
  ]);
}

async function pruneGameServerLogs(
  workspaceId: string,
  nodeId: string,
  now: number,
): Promise<void> {
  const database = await db();
  await database.batch([
    database
      .prepare(
        `DELETE FROM game_server_log
         WHERE workspaceId = ? AND nodeId = ? AND createdAt < ?`,
      )
      .bind(workspaceId, nodeId, now - 7 * 24 * 60 * 60_000),
    database
      .prepare(
        `DELETE FROM game_server_log
         WHERE workspaceId = ? AND nodeId = ?
           AND id NOT IN (
             SELECT id FROM game_server_log
             WHERE workspaceId = ? AND nodeId = ?
             ORDER BY createdAt DESC LIMIT 2000
           )`,
      )
      .bind(workspaceId, nodeId, workspaceId, nodeId),
  ]);
}

async function syncGameServerSnapshots(input: {
  workspaceId: string;
  nodeId: string;
  value: unknown;
  now: number;
}): Promise<boolean> {
  const snapshots = parseGameServerSnapshots(input.value);
  if (!snapshots) return false;
  const rows = await query<{ id: string; status: string; crashLoop: number; crashCount: number }>(
    `SELECT id, status, crashLoop, crashCount FROM game_server
     WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL`,
    input.workspaceId,
    input.nodeId,
  );
  const known = new Map(rows.map((row) => [row.id, row]));
  const database = await db();
  const statements: D1PreparedStatement[] = [];
  const transitions: { type: 'game_server.started' | 'game_server.stopped' | 'game_server.crashed' | 'game_server.crash_loop'; serverId: string; status: string; crashCount: number; observedAt: number }[] = [];
  for (const snapshot of snapshots) {
    if (
      Math.abs(snapshot.observedAt - input.now) > NODE_TIMING.requestSkewMs
    ) {
      statements.push(
        database
          .prepare(
            `INSERT INTO node_security_event
             (id, workspaceId, nodeId, type, severity, detail,
              networkFingerprint, createdAt)
             VALUES (?, ?, ?, 'game-stale-server-snapshot', 'medium', ?, NULL, ?)`,
          )
          .bind(
            createId('nsec'),
            input.workspaceId,
            input.nodeId,
            `The node reported an out-of-window snapshot for ${snapshot.serverId}.`,
            input.now,
          ),
      );
      continue;
    }
    const previous = known.get(snapshot.serverId);
    if (!previous) {
      statements.push(
        database
          .prepare(
            `INSERT INTO node_security_event
             (id, workspaceId, nodeId, type, severity, detail,
              networkFingerprint, createdAt)
             VALUES (?, ?, ?, 'game-unknown-server-snapshot', 'medium', ?, NULL, ?)`,
          )
          .bind(
            createId('nsec'),
            input.workspaceId,
            input.nodeId,
            `The node reported unknown local server ${snapshot.serverId}.`,
            input.now,
          ),
      );
      continue;
    }
    const transition = snapshot.crashLoop && previous.crashLoop !== 1
      ? 'game_server.crash_loop' as const
      : snapshot.status === 'running' && previous.status !== 'running'
        ? 'game_server.started' as const
        : snapshot.status === 'stopped' && previous.status !== 'stopped'
          ? 'game_server.stopped' as const
          : (snapshot.status === 'error' || snapshot.crashCount > previous.crashCount)
              && previous.status !== 'error'
            ? 'game_server.crashed' as const
            : null;
    if (transition) transitions.push({
      type: transition, serverId: snapshot.serverId, status: snapshot.status,
      crashCount: snapshot.crashCount, observedAt: snapshot.observedAt,
    });
    statements.push(
      database
        .prepare(
          `UPDATE game_server
           SET status = ?, observedExposure = ?, playerCount = ?, playersJson = ?,
               cpuLoadPercent = ?, memoryUsedBytes = ?, uptimeSeconds = ?,
               binaryHash = ?, binaryVerified = ?, crashCount = ?, crashLoop = ?,
               lastError = CASE WHEN ? = 1
                 THEN 'Crash-loop protection stopped automatic restarts.'
                 WHEN ? IN ('running','stopped') THEN NULL ELSE lastError END,
               lastStatusAt = ?, updatedAt = ?
           WHERE workspaceId = ? AND nodeId = ? AND id = ? AND deletedAt IS NULL`,
        )
        .bind(
          snapshot.status,
          snapshot.exposure,
          snapshot.playerCount,
          stableJson(snapshot.players),
          snapshot.cpuLoadPercent,
          snapshot.memoryUsedBytes,
          snapshot.uptimeSeconds,
          snapshot.binaryHash,
          snapshot.binaryVerified ? 1 : 0,
          snapshot.crashCount,
          snapshot.crashLoop ? 1 : 0,
          snapshot.crashLoop ? 1 : 0,
          snapshot.status,
          snapshot.observedAt,
          input.now,
          input.workspaceId,
          input.nodeId,
          snapshot.serverId,
        ),
    );
    for (const message of snapshot.logTail.slice(-2)) {
      statements.push(
        database
          .prepare(
            `INSERT INTO game_server_log
             (id, workspaceId, serverId, nodeId, level, message, createdAt)
             SELECT ?, ?, ?, ?, ?, ?, ?
             WHERE NOT EXISTS (
               SELECT 1 FROM game_server_log
               WHERE workspaceId = ? AND serverId = ? AND message = ?
                 AND createdAt >= ?
             )`,
          )
          .bind(
            createId('glog'),
            input.workspaceId,
            snapshot.serverId,
            input.nodeId,
            /error|failed|crash/i.test(message) ? 'WARN' : 'INFO',
            message,
            input.now,
            input.workspaceId,
            snapshot.serverId,
            message,
            input.now - 10 * 60_000,
          ),
      );
    }
  }
  if (statements.length > 0) await database.batch(statements);
  await Promise.all(transitions.map((transition) => emitWorkflowEvent({
    workspaceId: input.workspaceId,
    type: transition.type,
    resourceType: 'game_server',
    resourceId: transition.serverId,
    payload: {
      status: transition.status, serverId: transition.serverId,
      nodeId: input.nodeId, crashCount: transition.crashCount,
    },
    dedupeKey: `${transition.type}:${transition.serverId}:snapshot:${transition.observedAt}`,
    createdAt: input.now,
  }).catch(() => undefined)));
  await pruneGameServerLogs(input.workspaceId, input.nodeId, input.now);
  return true;
}

type RecoveryDeploymentRow = ReconciliationDeployment & {
  projectId: string;
  nodeId: string;
  localPort: number;
  healthPath: string;
  environment: 'Production' | 'Preview' | 'Development';
};

async function reconcileAppRuntimes(input: {
  context: AgentContext;
  agentVersion: string;
  generation: string;
  managedDeploymentIds: string[];
  now: number;
}): Promise<void> {
  if (!recoveryAgentCompatible(input.agentVersion)) return;
  const rows = await query<RecoveryDeploymentRow>(
    `SELECT d.id AS deploymentId, d.projectId, d.nodeId, d.localPort, d.healthPath,
            d.environment, COALESCE(d.desiredState, 'running') AS desiredState,
            COALESCE(d.desiredRevision, 1) AS desiredRevision,
            d.currentArtifactId, d.recoveryStatus, d.recoveryRevision,
            d.recoveryGeneration,
            CASE WHEN d.state IN ('queued','building','starting','stopping','restarting',
                 'rolling_back','deleting','cancelling','recovering') THEN 1 ELSE 0 END AS busy
       FROM deployment d
      WHERE d.workspaceId = ? AND d.nodeId = ? AND d.deletedAt IS NULL
        AND d.projectId IS NOT NULL AND d.localPort IS NOT NULL
        AND COALESCE(d.desiredState, 'running') = 'running'
      ORDER BY d.updatedAt ASC LIMIT 12`,
    input.context.node.workspaceId,
    input.context.node.id,
  );
  const plans = planRuntimeReconciliation({
    agentVersion: input.agentVersion,
    managedDeploymentIds: input.managedDeploymentIds,
    deployments: rows.map((row) => ({ ...row, busy: Boolean(row.busy) })),
    runtimeGeneration: input.generation,
  });
  for (const plan of plans) {
    const deployment = rows.find((row) => row.deploymentId === plan.deploymentId);
    if (!deployment) continue;
    const artifact = await queryOne<{
      id: string; state: string; availabilityState: string | null;
      lastVerifiedOnNodeAt: number | null;
    }>(
      `SELECT id, state, availabilityState, lastVerifiedOnNodeAt FROM app_artifact
       WHERE workspaceId = ? AND projectId = ? AND deploymentId = ? AND nodeId = ?
         AND id = ? AND deletedAt IS NULL`,
      input.context.node.workspaceId, deployment.projectId, deployment.deploymentId,
      deployment.nodeId, plan.artifactId,
    );
    if (!artifact || artifact.state !== 'verified' ||
        artifact.availabilityState === 'missing' || artifact.availabilityState === 'corrupted') {
      await execute(
        `UPDATE deployment SET observedState = 'blocked', recoveryStatus = 'blocked',
                recoveryReasonCode = ?, recoveryRevision = ?, recoveryGeneration = ?,
                lastReconciledAt = ?, updatedAt = ?
          WHERE workspaceId = ? AND id = ? AND desiredState = 'running' AND desiredRevision = ?`,
        artifact?.availabilityState === 'corrupted' ? 'artifact_corrupted' :
          artifact?.availabilityState === 'missing' || !artifact ? 'artifact_missing' : 'artifact_unavailable',
        plan.expectedDesiredRevision, input.generation, input.now, input.now,
        input.context.node.workspaceId, deployment.deploymentId, plan.expectedDesiredRevision,
      );
      continue;
    }
    const history = await query<{ payload: string }>(
      `SELECT j.payload FROM node_job j
       JOIN app_deployment_action a ON a.jobId = j.id AND a.workspaceId = j.workspaceId
       WHERE a.workspaceId = ? AND a.deploymentId = ? AND a.nodeId = ?
         AND j.type = ? AND j.state = 'succeeded'
       ORDER BY j.completedAt DESC LIMIT 10`,
      input.context.node.workspaceId, deployment.deploymentId, deployment.nodeId,
      APP_RUNTIME_JOB_TYPE,
    );
    let prior: AppRuntimeJobPayload | null = null;
    for (const item of history) {
      try {
        const candidate = validateAppRuntimeJobPayload(JSON.parse(item.payload));
        if (candidate.ok &&
            (candidate.payload.artifactId === plan.artifactId || candidate.payload.targetArtifactId === plan.artifactId) &&
            candidate.payload.contract) {
          prior = candidate.payload;
          break;
        }
      } catch {
        // Invalid historical payloads are never replayed.
      }
    }
    if (!prior) {
      await execute(
        `UPDATE deployment SET observedState = 'blocked', recoveryStatus = 'blocked',
                recoveryReasonCode = 'artifact_unavailable', recoveryRevision = ?,
                recoveryGeneration = ?, lastReconciledAt = ?, updatedAt = ?
          WHERE workspaceId = ? AND id = ? AND desiredState = 'running' AND desiredRevision = ?`,
        plan.expectedDesiredRevision, input.generation, input.now, input.now,
        input.context.node.workspaceId, deployment.deploymentId, plan.expectedDesiredRevision,
      );
      continue;
    }
    const previous = await queryOne<{ id: string }>(
      `SELECT id FROM app_artifact WHERE workspaceId = ? AND projectId = ? AND deploymentId = ?
         AND nodeId = ? AND state = 'verified' AND deletedAt IS NULL AND id <> ?
         AND availabilityState NOT IN ('missing','corrupted')
       ORDER BY version DESC LIMIT 1`,
      input.context.node.workspaceId, deployment.projectId, deployment.deploymentId,
      deployment.nodeId, plan.artifactId,
    );
    const actionId = createId('dact');
    // An attempt is identified by the deployment, the intent revision it serves,
    // the Agent generation that observed it -- and when the node last confirmed
    // these bytes. Without that last part, a restore is invisible here: the
    // failed attempt from before the artifact came back already holds the key,
    // the enqueue is deduplicated, and the deployment sits available and
    // recoverable with nothing ever queued for it. Confirmation only moves this
    // forward when an artifact is actually present, and the availability gate
    // above has already refused a missing one, so this cannot become a retry
    // loop: a failed recovery marks the artifact missing and stops at the gate.
    const confirmedAt = artifact.lastVerifiedOnNodeAt ?? 0;
    const queued = await enqueueJob({
      workspaceId: input.context.node.workspaceId,
      actor: 'system:runtime-recovery',
      type: APP_RUNTIME_JOB_TYPE,
      payload: {
        operation: 'recover', deploymentId: deployment.deploymentId,
        projectId: deployment.projectId, actionId, artifactId: plan.artifactId,
        targetArtifactId: null, source: null, contract: prior.contract,
        environment: deployment.environment,
        environmentCiphertext: prior.environmentCiphertext,
        port: deployment.localPort, healthPath: deployment.healthPath,
        memoryMb: prior.memoryMb, diskQuotaBytes: prior.diskQuotaBytes,
        retainArtifacts: APP_RUNTIME_LIMITS.maximumArtifactsPerProject,
        expectedDesiredRevision: plan.expectedDesiredRevision,
        protectedArtifactIds: [plan.artifactId, ...(previous ? [previous.id] : [])],
      },
      targetNodeId: deployment.nodeId,
      idempotencyKey:
        `recover:${deployment.deploymentId}:${plan.expectedDesiredRevision}:${input.generation}:${confirmedAt}`,
    });
    if (!queued.ok || !queued.created) continue;
    const database = await db();
    await database.batch([
      database.prepare(
        `INSERT INTO app_deployment_action
         (id, workspaceId, deploymentId, projectId, nodeId, jobId, kind, state,
          idempotencyKey, requestedBy, error, createdAt, updatedAt, completedAt)
         VALUES (?, ?, ?, ?, ?, ?, 'recover', 'queued', ?, 'system:runtime-recovery', NULL, ?, ?, NULL)`,
      ).bind(actionId, input.context.node.workspaceId, deployment.deploymentId,
        deployment.projectId, deployment.nodeId, queued.job.id,
        `recover:${deployment.deploymentId}:${plan.expectedDesiredRevision}:${input.generation}:${confirmedAt}`,
        input.now, input.now),
      database.prepare(
        `UPDATE deployment SET state = 'recovering', observedState = 'recovering',
                recoveryStatus = 'pending', recoveryReasonCode = 'process_missing',
                recoveryRevision = ?, recoveryGeneration = ?, lastReconciledAt = ?,
                jobId = ?, updatedAt = ?
          WHERE workspaceId = ? AND id = ? AND desiredState = 'running'
            AND desiredRevision = ?`,
      ).bind(plan.expectedDesiredRevision, input.generation, input.now, queued.job.id,
        input.now, input.context.node.workspaceId, deployment.deploymentId,
        plan.expectedDesiredRevision),
    ]);
  }
}

export async function recordHeartbeat(input: {
  context: AgentContext;
  capabilities: unknown;
  metrics: unknown;
  agentVersion: unknown;
  gameServers?: unknown;
  appDeployments?: unknown;
  runtimeGeneration?: unknown;
}): Promise<
  | { ok: true; status: 'online'; serverTime: number }
  | { ok: false; status: number; error: string }
> {
  if (
    typeof input.agentVersion !== 'string' ||
    !agentVersionSupported(input.agentVersion)
  ) {
    return {
      ok: false,
      status: 426,
      error: `Agent ${MINIMUM_AGENT_VERSION} or newer is required.`,
    };
  }
  const capabilities = parseCapabilities(input.capabilities);
  const metrics = parseMetrics(input.metrics);
  const snapshots = parseGameServerSnapshots(input.gameServers ?? []);
  const appSnapshots = parseAppRuntimeSnapshots(input.appDeployments ?? []);
  const runtimeGeneration = typeof input.runtimeGeneration === 'string' &&
    /^[A-Za-z0-9_-]{16,64}$/.test(input.runtimeGeneration)
    ? input.runtimeGeneration
    : null;
  if (!capabilities || !metrics || !snapshots || !appSnapshots) {
    return {
      ok: false,
      status: 400,
      error: 'Heartbeat capabilities or metrics are invalid.',
    };
  }

  const now = Date.now();
  const updated = await execute(
    `UPDATE compute_node
     SET capabilities = ?, agentVersion = ?, lastHeartbeatAt = ?, updatedAt = ?
     WHERE id = ? AND workspaceId = ? AND revokedAt IS NULL`,
    stableJson(capabilities),
    input.agentVersion,
    now,
    now,
    input.context.node.id,
    input.context.node.workspaceId,
  );
  if (!changed(updated)) {
    return { ok: false, status: 401, error: 'The node is no longer active.' };
  }
  await execute(
    `INSERT INTO node_metric
     (id, workspaceId, nodeId, cpuLoadPercent, memoryUsedBytes,
      memoryTotalBytes, runningJobs, recordedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    createId('nmet'),
    input.context.node.workspaceId,
    input.context.node.id,
    metrics.cpuLoadPercent,
    metrics.memoryUsedBytes,
    metrics.memoryTotalBytes,
    metrics.runningJobs,
    now,
  );
  await syncAiNodeSnapshot(
    input.context.node.workspaceId,
    input.context.node.id,
    capabilities,
    now,
  );
  await syncGameServerSnapshots({
    workspaceId: input.context.node.workspaceId,
    nodeId: input.context.node.id,
    value: snapshots,
    now,
  });
  await syncAppRuntimeSnapshots({
    workspaceId: input.context.node.workspaceId,
    nodeId: input.context.node.id,
    snapshots: appSnapshots,
    cpuLoadPercent: metrics.cpuLoadPercent,
    memoryUsedBytes: metrics.memoryUsedBytes,
    now,
  });
  if (runtimeGeneration) {
    await reconcileAppRuntimes({
      context: input.context,
      agentVersion: input.agentVersion,
      generation: runtimeGeneration,
      managedDeploymentIds: appSnapshots.map((snapshot) => snapshot.deploymentId),
      now,
    });
  }
  await pruneNodeHistory(input.context.node.id, now);
  return { ok: true, status: 'online', serverTime: now };
}

/**
 * The environment a deployment is allowed to see, read from durable storage.
 *
 * It lives here rather than in `deployments.ts` because two callers now need
 * it: the ordinary job builders, and the Phase 22 import reservation. Copying
 * it would have been worse -- this decides which secrets a deployment may
 * read, and two copies of that rule is one too many.
 */
export async function scopedEnvironment(input: {
  workspaceId: string;
  projectId: string;
  deploymentId: string;
  environment: AppEnvironment;
  names: string[];
}): Promise<Record<string, string>> {
  if (input.names.length === 0) return {};
  const rows = await query<{ name: string; scope: string; ciphertext: string }>(
    `SELECT name, scope, ciphertext FROM secret
     WHERE workspaceId = ? AND environment IN (?, 'All')`,
    input.workspaceId,
    input.environment,
  );
  const allowed = new Set(input.names);
  const scopes = new Set(['Workspace', `Project:${input.projectId}`, `Deployment:${input.deploymentId}`]);
  const values: Record<string, string> = {};
  for (const row of rows) {
    if (!allowed.has(row.name) || !scopes.has(row.scope)) continue;
    values[row.name] = await decryptSecret(row.ciphertext, credentialKey());
  }
  return values;
}

async function requeueExpiredJobs(
  workspaceId: string,
  now: number,
): Promise<void> {
  const expiredAppJobs = await query<JobRow>(
    `SELECT * FROM node_job WHERE workspaceId = ? AND type = ?
     AND state IN ('leased','cancelling') AND leaseExpiresAt <= ?`,
    workspaceId,
    APP_RUNTIME_JOB_TYPE,
    now,
  );
  for (const job of expiredAppJobs) {
    await recordAppRuntimeJobOutcome({
      job,
      state: job.state === 'cancelling' ? 'cancelled' : 'timed_out',
      result: null,
      error: 'The App Runtime lease expired before completion.',
      now,
    });
    await execute(
      `INSERT INTO node_security_event
       (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
       VALUES (?, ?, ?, 'app-expired-lease', 'high', ?, NULL, ?)`,
      createId('nsec'), workspaceId, job.assignedNodeId,
      `App Runtime job ${job.id} expired and will not be replayed.`, now,
    );
  }
  const expiredGameJobs = await query<JobRow>(
    `SELECT * FROM node_job
     WHERE workspaceId = ? AND type LIKE 'game-server.%'
       AND state IN ('leased','cancelling') AND leaseExpiresAt <= ?`,
    workspaceId,
    now,
  );
  for (const job of expiredGameJobs) {
    const state: NodeJobState =
      job.state === 'cancelling'
        ? 'cancelled'
        : job.attempts < job.maxAttempts
          ? 'queued'
          : 'timed_out';
    await recordGameServerJobOutcome({
      job,
      state,
      result: null,
      error:
        state === 'cancelled'
          ? 'Cancellation confirmed at lease expiry.'
          : 'Lease expired before completion.',
      now,
    });
    await execute(
      `INSERT INTO node_security_event
       (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
       VALUES (?, ?, ?, 'game-expired-lease', 'medium', ?, NULL, ?)`,
      createId('nsec'),
      workspaceId,
      job.assignedNodeId,
      `A Game Server lifecycle lease expired. Job ${job.id}.`,
      now,
    );
  }
  const database = await db();
  await database.batch([
    database
      .prepare(
        `UPDATE node_job
         SET state = CASE WHEN attempts < maxAttempts THEN 'queued' ELSE 'timed_out' END,
             assignedNodeId = NULL,
             leaseId = NULL,
             leaseExpiresAt = NULL,
             claimSignature = NULL,
             lastError = 'Lease expired before completion.',
             completedAt = CASE WHEN attempts < maxAttempts THEN NULL ELSE ? END,
             updatedAt = ?
         WHERE workspaceId = ? AND state = 'leased' AND leaseExpiresAt <= ?`,
      )
      .bind(now, now, workspaceId, now),
    database
      .prepare(
        `UPDATE node_job
         SET state = 'cancelled', lastError = 'Cancellation confirmed at lease expiry.',
             completedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND state = 'cancelling' AND leaseExpiresAt <= ?`,
      )
      .bind(now, now, workspaceId, now),
  ]);
}

export async function claimNextJob(
  context: AgentContext,
): Promise<{ claim: SignedJobClaim; signature: string } | null> {
  const now = Date.now();
  await requeueExpiredJobs(context.node.workspaceId, now);
  const assignmentPolicy = await queryOne<{ allowed: number }>(
    `SELECT CASE WHEN revokedAt IS NULL AND assignmentsDisabledAt IS NULL THEN 1 ELSE 0 END AS allowed
       FROM compute_node WHERE workspaceId = ? AND id = ?`,
    context.node.workspaceId,
    context.node.id,
  );
  if (assignmentPolicy?.allowed !== 1) return null;
  const capabilities = capabilitiesFromRow(context.node.capabilities);

  const candidates = await query<JobRow>(
    `SELECT * FROM node_job
     WHERE workspaceId = ? AND state = 'queued'
       AND (targetNodeId IS NULL OR targetNodeId = ?)
     ORDER BY priority DESC, createdAt ASC
     LIMIT 8`,
    context.node.workspaceId,
    context.node.id,
  );

  for (const job of candidates) {
    if (!isExecutableJobType(job.type)) continue;
    const payload = safeJsonRecord(job.payload);
    if (!payload || (await sha256(stableJson(payload))) !== job.payloadHash) {
      await execute(
        `UPDATE node_job SET state = 'failed', lastError = ?, completedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND id = ? AND state = 'queued'`,
        'Payload integrity check failed.',
        now,
        now,
        context.node.workspaceId,
        job.id,
      );
      await recordJobSecurityEvent(
        context.node,
        job.id,
        'job-payload-integrity',
        'critical',
        'A queued job payload no longer matched its recorded digest.',
      );
      continue;
    }
    if (!jobEligibleForNode(job, payload, capabilities)) continue;

    const leaseId = createId('lease');
    const appPayload = job.type === APP_RUNTIME_JOB_TYPE
      ? validateAppRuntimeJobPayload(payload)
      : null;
    if (appPayload?.ok && appPayload.payload.operation === 'import') {
      // Import carries more authority than any other operation -- it installs
      // bytes for a deployment whose previous node is gone -- so every fact it
      // rests on is re-read here, at the moment the work is handed over, and
      // not trusted from the payload that was written when it was queued.
      const authorized = await queryOne<{ ok: number }>(
        `SELECT 1 AS ok
           FROM deployment d
           JOIN app_artifact source ON source.id = d.currentArtifactId
            AND source.workspaceId = d.workspaceId AND source.deletedAt IS NULL
           JOIN compute_node lost ON lost.id = source.nodeId
            AND lost.workspaceId = d.workspaceId
           JOIN app_artifact replacement ON replacement.id = ?
            AND replacement.workspaceId = d.workspaceId AND replacement.deploymentId = d.id
            AND replacement.deletedAt IS NULL
          WHERE d.workspaceId = ? AND d.id = ? AND d.nodeId = ? AND d.deletedAt IS NULL
            AND d.desiredRevision = ? AND d.currentArtifactId = ?
            AND source.nodeId <> d.nodeId
            AND source.state = 'verified' AND source.checksum IS NOT NULL
            AND lost.revokedAt IS NOT NULL
            AND replacement.nodeId = ? AND replacement.state = 'building'`,
        appPayload.payload.artifactId,
        context.node.workspaceId,
        appPayload.payload.deploymentId,
        context.node.id,
        appPayload.payload.expectedDesiredRevision,
        appPayload.payload.targetArtifactId,
        context.node.id,
      );
      if (!authorized) {
        const database = await db();
        await database.batch([
          database.prepare(
            `UPDATE node_job SET state = 'failed', lastError = 'stale_desired_revision',
                    completedAt = ?, updatedAt = ?
             WHERE workspaceId = ? AND id = ? AND state = 'queued'`,
          ).bind(now, now, context.node.workspaceId, job.id),
          database.prepare(
            `UPDATE app_deployment_action SET state = 'failed', error = 'stale_desired_revision',
                    completedAt = ?, updatedAt = ?
             WHERE workspaceId = ? AND jobId = ? AND state = 'queued'`,
          ).bind(now, now, context.node.workspaceId, job.id),
        ]);
        continue;
      }
    }
    if (appPayload?.ok && appPayload.payload.operation === 'recover') {
      const intent = await queryOne<{
        desiredState: string | null; desiredRevision: number | null;
        currentArtifactId: string | null; nodeId: string | null;
      }>(
        `SELECT desiredState, desiredRevision, currentArtifactId, nodeId
           FROM deployment WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL`,
        context.node.workspaceId, appPayload.payload.deploymentId,
      );
      const compatible = recoveryAgentCompatible(context.node.agentVersion);
      const current = compatible && intent?.desiredState === 'running' &&
        intent.desiredRevision === appPayload.payload.expectedDesiredRevision &&
        intent.currentArtifactId === appPayload.payload.artifactId &&
        intent.nodeId === context.node.id;
      if (!current) {
        const reason = compatible ? 'stale_desired_revision' : 'runtime_incompatible';
        const database = await db();
        await database.batch([
          database.prepare(
            `UPDATE node_job SET state = 'failed', lastError = ?, completedAt = ?, updatedAt = ?
             WHERE workspaceId = ? AND id = ? AND state = 'queued'`,
          ).bind(reason, now, now, context.node.workspaceId, job.id),
          database.prepare(
            `UPDATE app_deployment_action SET state = 'failed', error = ?, completedAt = ?, updatedAt = ?
             WHERE workspaceId = ? AND jobId = ? AND state = 'queued'`,
          ).bind(reason, now, now, context.node.workspaceId, job.id),
          database.prepare(
            `UPDATE deployment SET observedState = 'blocked', recoveryStatus = 'blocked',
                    recoveryReasonCode = ?, lastReconciledAt = ?, updatedAt = ?
             WHERE workspaceId = ? AND id = ? AND jobId = ?`,
          ).bind(reason, now, now, context.node.workspaceId, appPayload.payload.deploymentId, job.id),
        ]);
        continue;
      }
    }
    const leaseExpiresAt = now + (
      job.type.startsWith('game-server.')
        ? gameServerLeaseDuration(job.type, payload)
        : appPayload?.ok
          ? appRuntimeLeaseDuration(appPayload.payload.operation)
          : aiLeaseDuration(job.type, payload)
    );
    const claim: SignedJobClaim = {
      protocolVersion: NODE_PROTOCOL_VERSION,
      jobId: job.id,
      workspaceId: job.workspaceId,
      nodeId: context.node.id,
      type: job.type,
      payload,
      payloadHash: job.payloadHash,
      leaseId,
      leaseExpiresAt,
      attempt: job.attempts + 1,
    };
    const signature = await signJobClaim(context.token, claim);
    const result = await execute(
      `UPDATE node_job
       SET state = 'leased', assignedNodeId = ?, leaseId = ?, leaseExpiresAt = ?,
           attempts = attempts + 1, claimSignature = ?, updatedAt = ?
       WHERE workspaceId = ? AND id = ? AND state = 'queued'`,
      context.node.id,
      leaseId,
      claim.leaseExpiresAt,
      signature,
      now,
      context.node.workspaceId,
      job.id,
    );
    if (!changed(result)) continue;
    await writeJobEvent({
      workspaceId: context.node.workspaceId,
      nodeId: context.node.id,
      jobId: job.id,
      kind: 'claimed',
      message: `Attempt ${claim.attempt} leased until ${claim.leaseExpiresAt}.`,
    });
    return { claim, signature };
  }
  return null;
}

async function writeJobEvent(input: {
  workspaceId: string;
  nodeId: string | null;
  jobId: string | null;
  kind: string;
  message: string;
}): Promise<void> {
  await execute(
    `INSERT INTO node_job_event
     (id, workspaceId, nodeId, jobId, kind, message, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    createId('nje'),
    input.workspaceId,
    input.nodeId,
    input.jobId,
    input.kind,
    input.message.slice(0, 500),
    Date.now(),
  );
}

async function recordJobSecurityEvent(
  node: Pick<NodeRow, 'id' | 'workspaceId'>,
  jobId: string,
  type: string,
  severity: 'low' | 'medium' | 'high' | 'critical',
  detail: string,
): Promise<void> {
  await execute(
    `INSERT INTO node_security_event
     (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
    createId('nsec'),
    node.workspaceId,
    node.id,
    type,
    severity,
    `${detail} Job ${jobId}.`.slice(0, 500),
    Date.now(),
  );
}

/**
 * What a node needs to know before it may rehydrate a missing artifact.
 *
 * Read-only and deliberately narrow. A restore has to prove the bundle it was
 * handed belongs to *this* deployment on *this* node, and only the control
 * plane knows that; letting the Agent decide from the bundle alone would make
 * the bundle its own authorisation. So this returns the identifiers and the
 * checksum already recorded for the current artifact -- nothing else, and never
 * an environment value, a secret, or a path.
 *
 * It mutates nothing, creates no evidence, and is scoped to the authenticated
 * node: a deployment owned by another node is simply not found.
 */
export async function readArtifactRestorePreflight(
  context: AgentContext,
  deploymentId: string,
): Promise<
  | {
      ok: true;
      workspaceId: string;
      projectId: string;
      deploymentId: string;
      nodeId: string;
      currentArtifactId: string;
      checksum: string;
      desiredState: string;
    }
  | { ok: false; status: number; error: string }
> {
  if (!/^dpl_[a-f0-9]{24}$/.test(deploymentId)) {
    return { ok: false, status: 400, error: 'Restore preflight request is invalid.' };
  }
  const row = await queryOne<{
    workspaceId: string;
    projectId: string | null;
    nodeId: string | null;
    currentArtifactId: string | null;
    desiredState: string | null;
    checksum: string | null;
    artifactNodeId: string | null;
  }>(
    `SELECT d.workspaceId AS workspaceId, d.projectId AS projectId, d.nodeId AS nodeId,
            d.currentArtifactId AS currentArtifactId, d.desiredState AS desiredState,
            a.checksum AS checksum, a.nodeId AS artifactNodeId
       FROM deployment d
       LEFT JOIN app_artifact a ON a.id = d.currentArtifactId AND a.workspaceId = d.workspaceId
      WHERE d.workspaceId = ? AND d.id = ? AND d.nodeId = ? AND d.deletedAt IS NULL`,
    context.node.workspaceId,
    deploymentId,
    context.node.id,
  );
  if (!row || !row.projectId || !row.nodeId) {
    return { ok: false, status: 404, error: 'Deployment not found for this node.' };
  }
  if (!row.currentArtifactId || !row.checksum || row.artifactNodeId !== context.node.id) {
    return { ok: false, status: 409, error: 'This deployment has no current artifact on this node.' };
  }
  return {
    ok: true,
    workspaceId: row.workspaceId,
    projectId: row.projectId,
    deploymentId,
    nodeId: row.nodeId,
    currentArtifactId: row.currentArtifactId,
    checksum: row.checksum,
    desiredState: row.desiredState ?? 'running',
  };
}

/**
 * Records that a node has put a lost artifact back, byte for byte.
 *
 * Restoring a backup is local: bytes reappear on a disk the control plane
 * cannot see, and until it is told, D1 still says `missing`. Every recovery
 * route refuses an artifact believed gone, so without this the operator would
 * have to issue a Start -- which is not recovery, it is a person doing by hand
 * what Phase 18 exists to do. This is the smallest statement that closes that
 * gap: the node says "this exact artifact, this exact checksum, is here again".
 *
 * The trust boundary is the one already used for every other artifact
 * observation a node reports -- a signed request from the node that owns the
 * deployment. It is not proof in a cryptographic sense; the Agent verified the
 * rebuilt manifest and re-hashed the payload before calling, and the control
 * plane believes that report exactly as much as it believes a job result that
 * says an artifact verified. Stated plainly rather than dressed up.
 *
 * Nothing here can move an artifact between nodes, change what is current,
 * change desired state, or invent a row: identity is read from the database
 * and every supplied value has to agree with it.
 */
export async function confirmArtifactRestore(
  context: AgentContext,
  deploymentId: string,
  body: { artifactId?: unknown; checksum?: unknown },
): Promise<
  | { ok: true; artifactId: string; availability: 'present'; recoveryCleared: boolean }
  | { ok: false; status: number; error: string }
> {
  const artifactId = typeof body.artifactId === 'string' ? body.artifactId : '';
  const checksum = typeof body.checksum === 'string' ? body.checksum : '';
  if (
    !/^dpl_[a-f0-9]{24}$/.test(deploymentId) ||
    !/^art_[a-f0-9]{24}$/.test(artifactId) ||
    !/^sha256:[a-f0-9]{64}$/.test(checksum)
  ) {
    return { ok: false, status: 400, error: 'Restore confirmation is invalid.' };
  }
  const row = await queryOne<{
    projectId: string | null;
    nodeId: string | null;
    currentArtifactId: string | null;
    artifactNodeId: string | null;
    artifactChecksum: string | null;
    artifactState: string | null;
    availabilityState: string | null;
    recoveryStatus: string | null;
    recoveryReasonCode: string | null;
  }>(
    `SELECT d.projectId AS projectId, d.nodeId AS nodeId, d.currentArtifactId AS currentArtifactId,
            a.nodeId AS artifactNodeId, a.checksum AS artifactChecksum, a.state AS artifactState,
            a.availabilityState AS availabilityState,
            d.recoveryStatus AS recoveryStatus, d.recoveryReasonCode AS recoveryReasonCode
       FROM deployment d
       LEFT JOIN app_artifact a
         ON a.id = ? AND a.workspaceId = d.workspaceId AND a.projectId = d.projectId
        AND a.deploymentId = d.id AND a.deletedAt IS NULL
      WHERE d.workspaceId = ? AND d.id = ? AND d.nodeId = ? AND d.deletedAt IS NULL`,
    artifactId,
    context.node.workspaceId,
    deploymentId,
    context.node.id,
  );
  // One refusal for "not yours" and "not there", so probing cannot tell a
  // foreign deployment apart from an absent one.
  if (!row || !row.projectId || row.nodeId !== context.node.id) {
    return { ok: false, status: 404, error: 'Deployment not found for this node.' };
  }
  if (
    !row.artifactChecksum || row.artifactNodeId !== context.node.id ||
    row.artifactState !== 'verified' || row.currentArtifactId !== artifactId
  ) {
    return { ok: false, status: 409, error: 'That artifact is not the current verified artifact on this node.' };
  }
  if (!constantTimeEqual(checksum, row.artifactChecksum)) {
    return { ok: false, status: 409, error: 'The restored checksum does not match the recorded artifact.' };
  }

  const now = Date.now();
  // Only a condition this evidence actually refutes is cleared. A recovery
  // blocked on a port already in use is not answered by bytes reappearing, and
  // clearing it would be inventing a remediation that never happened.
  const availabilityCondition = new Set(['artifact_missing', 'artifact_corrupted', 'artifact_unavailable']);
  const blocked = row.recoveryStatus === 'blocked' || row.recoveryStatus === 'failed' ||
    row.recoveryStatus === 'pending';
  const clears = blocked && availabilityCondition.has(row.recoveryReasonCode ?? '');
  await execute(
    `UPDATE app_artifact
        SET availabilityState = 'present', lastVerifiedOnNodeAt = ?
      WHERE workspaceId = ? AND projectId = ? AND deploymentId = ? AND nodeId = ?
        AND id = ? AND checksum = ? AND state = 'verified' AND deletedAt IS NULL`,
    now, context.node.workspaceId, row.projectId, deploymentId, context.node.id,
    artifactId, row.artifactChecksum,
  );
  if (clears) {
    // Phase 18 refuses to retry a blocked recovery without remediation or a new
    // intent revision, and it is right to: restarting an Agent must never
    // become an automatic retry loop. A restore *is* the remediation, so the
    // condition is retired here rather than by asking a person to press Start.
    // The generation goes with it, or the same guard would still hold.
    await execute(
      `UPDATE deployment
          SET recoveryStatus = NULL, recoveryReasonCode = NULL, recoveryGeneration = NULL,
              updatedAt = ?
        WHERE workspaceId = ? AND id = ? AND nodeId = ? AND deletedAt IS NULL
          AND currentArtifactId = ?`,
      now, context.node.workspaceId, deploymentId, context.node.id, artifactId,
    );
  }
  const tenant = await queryOne<{ organizationId: string | null }>(
    'SELECT organizationId FROM workspace WHERE id = ?', context.node.workspaceId,
  );
  const workspace = { organizationId: tenant?.organizationId ?? '' };
  if (workspace.organizationId) {
    await recordEvidence({
      organizationId: workspace.organizationId,
      workspaceId: context.node.workspaceId,
      actorType: 'system',
      actorId: 'system:artifact-restore',
      action: 'deployment.artifact_restore',
      resourceId: deploymentId,
      outcome: 'success',
      metadata: {
        artifactId,
        nodeId: context.node.id,
        availability: 'present',
        clearedReasonCode: clears ? row.recoveryReasonCode ?? '' : '',
      },
    });
  }
  return { ok: true, artifactId, availability: 'present', recoveryCleared: clears };
}

/**
 * Agrees a private port a node can actually bind.
 *
 * The control plane assigns private ports from its own range, and until now it
 * assumed a port no deployment owned was a port the node could use. That is not
 * true on Windows: blocks are reserved for Hyper-V and WSL, and binding one
 * fails with `EACCES` while nothing is listening on it. A node assigned 41000
 * out of a reserved 40947-41146 range could not deploy anything, ever.
 *
 * So bindability is the node's to determine and assignment stays the control
 * plane's. The node offers a short list of ports it has just bound and released;
 * this picks the first that no other deployment on that node holds, and writes
 * it. Nothing about which artifact runs, what state it is in, or who owns it
 * moves.
 */
export async function negotiatePrivatePort(
  context: AgentContext,
  deploymentId: string,
  body: { expectedCurrentPort?: unknown; candidatePorts?: unknown },
): Promise<
  | { ok: true; localPort: number; changed: boolean }
  | { ok: false; status: number; error: string }
> {
  const candidates = parsePrivatePortCandidates(body.candidatePorts);
  if (!/^dpl_[a-f0-9]{24}$/.test(deploymentId) || !candidates
    || !privatePortInRange(body.expectedCurrentPort)) {
    return { ok: false, status: 400, error: 'Private port negotiation is invalid.' };
  }
  const expected = body.expectedCurrentPort;
  const row = await queryOne<{
    projectId: string | null;
    nodeId: string | null;
    localPort: number | null;
    state: string | null;
    observedState: string | null;
  }>(
    `SELECT projectId, nodeId, localPort, state, observedState FROM deployment
     WHERE workspaceId = ? AND id = ? AND nodeId = ? AND deletedAt IS NULL`,
    context.node.workspaceId, deploymentId, context.node.id,
  );
  if (!row || !row.projectId || row.nodeId !== context.node.id) {
    return { ok: false, status: 404, error: 'Deployment not found for this node.' };
  }
  // A port is negotiated on the way to running, not out from under something
  // already serving on it. A healthy deployment keeps the port it has -- Phase
  // 18 recovery and the artifact restore gate both depend on that staying put.
  if (row.observedState === 'healthy') {
    return { ok: false, status: 409, error: 'A healthy deployment keeps its private port.' };
  }
  if (row.localPort !== expected) {
    // Someone else moved it. Refuse rather than overwrite a newer assignment.
    return { ok: false, status: 409, error: 'The private port changed; refresh and retry.' };
  }
  const taken = new Set((await query<{ localPort: number }>(
    `SELECT localPort FROM deployment
     WHERE nodeId = ? AND localPort IS NOT NULL AND deletedAt IS NULL
       AND state <> 'blocked' AND id <> ?`,
    context.node.id, deploymentId,
  )).map((entry) => entry.localPort));

  if (candidates.includes(expected) && !taken.has(expected)) {
    // The node can bind what it already has and no sibling deployment on this
    // node holds it; nothing to negotiate.
    return { ok: true, localPort: expected, changed: false };
  }
  // A port this node can bind is not automatically a port this node is free to
  // keep. A deployment that arrived by ownership transfer brings its old port
  // as a preference, and a stopped sibling here may already own that number
  // without listening on it -- so the node's probe would happily offer it.
  // Retaining it would collide on `deployment_node_port_uidx` the moment this
  // row stopped being blocked. Fall through to ordinary candidate selection.

  for (const candidate of candidates) {
    if (taken.has(candidate)) continue;
    // Conditional on the port we read, so two deployments negotiating at once
    // cannot both take it: the loser's update matches nothing and it moves on.
    const claimed = await execute(
      `UPDATE deployment SET localPort = ?, localAddress = ?, updatedAt = ?
        WHERE workspaceId = ? AND id = ? AND nodeId = ? AND localPort = ?
          AND deletedAt IS NULL`,
      candidate, `http://127.0.0.1:${candidate}`, Date.now(),
      context.node.workspaceId, deploymentId, context.node.id, expected,
    );
    if ((claimed as { meta?: { changes?: number } }).meta?.changes === 1) {
      return { ok: true, localPort: candidate, changed: true };
    }
    return { ok: false, status: 409, error: 'The private port changed; refresh and retry.' };
  }
  return { ok: false, status: 409, error: 'No private port on this node is available.' };
}

export async function readAgentJobStatus(
  context: AgentContext,
  jobId: string,
  leaseId: unknown,
): Promise<
  | {
      ok: true;
      state: NodeJobState;
      cancelRequested: boolean;
      leaseExpiresAt: number | null;
    }
  | { ok: false; status: number; error: string }
> {
  if (
    !/^job_[a-f0-9]{24}$/.test(jobId) ||
    typeof leaseId !== 'string' ||
    !/^lease_[a-f0-9]{24}$/.test(leaseId)
  ) {
    return { ok: false, status: 400, error: 'Job status request is invalid.' };
  }
  const job = await queryOne<JobRow>(
    'SELECT * FROM node_job WHERE workspaceId = ? AND id = ?',
    context.node.workspaceId,
    jobId,
  );
  if (!job) return { ok: false, status: 404, error: 'Job not found.' };
  if (job.assignedNodeId !== context.node.id || job.leaseId !== leaseId) {
    await recordJobSecurityEvent(
      context.node,
      job.id,
      'ai-job-status-forgery',
      'critical',
      'A node requested cancellation state for a lease it does not own.',
    );
    return { ok: false, status: 403, error: 'The job lease is invalid.' };
  }
  return {
    ok: true,
    state: job.state,
    cancelRequested:
      job.state === 'cancelling' || job.state === 'cancelled',
    leaseExpiresAt: job.leaseExpiresAt,
  };
}

function boundedResultInteger(
  value: unknown,
  maximum = Number.MAX_SAFE_INTEGER,
): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= maximum
    ? value
    : null;
}

async function recordAiJobOutcome(input: {
  job: JobRow;
  state: NodeJobState;
  result: Record<string, unknown> | null;
  error: string | null;
  now: number;
}): Promise<void> {
  if (input.job.type === 'ai.inference') {
    const payload = safeJsonRecord(input.job.payload);
    const prompt = typeof payload?.prompt === 'string' ? payload.prompt : '';
    const systemPrompt =
      typeof payload?.systemPrompt === 'string' ? payload.systemPrompt : '';
    const inputTokens =
      boundedResultInteger(input.result?.inputTokens, 1_000_000) ??
      estimateTokens(`${systemPrompt}\n${prompt}`);
    const outputTokens =
      boundedResultInteger(input.result?.outputTokens, 1_000_000) ??
      (typeof input.result?.text === 'string'
        ? estimateTokens(input.result.text)
        : null);
    const latencyMs = boundedResultInteger(input.result?.latencyMs, 3_600_000);
    await execute(
      `UPDATE ai_inference
       SET inputTokensEstimate = ?, outputTokensEstimate = ?, latencyMs = ?,
           updatedAt = ? WHERE workspaceId = ? AND jobId = ?`,
      inputTokens,
      outputTokens,
      latencyMs,
      input.now,
      input.job.workspaceId,
      input.job.id,
    );
    if (input.state === 'succeeded' && payload?.modelId) {
      await execute(
        `UPDATE ai_model SET lastUsedAt = ?, lastVerifiedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND catalogId = ?`,
        input.now,
        input.now,
        input.now,
        input.job.workspaceId,
        payload.modelId,
      );
      if (input.job.assignedNodeId) {
        await execute(
          `UPDATE ai_model_cache SET lastUsedAt = ?, updatedAt = ?
           WHERE workspaceId = ? AND nodeId = ?
             AND modelId IN (
               SELECT id FROM ai_model WHERE workspaceId = ? AND catalogId = ?
             )`,
          input.now,
          input.now,
          input.job.workspaceId,
          input.job.assignedNodeId,
          input.job.workspaceId,
          payload.modelId,
        );
      }
    }
    if (input.state === 'succeeded' || input.state === 'failed' || input.state === 'timed_out') {
      const type = input.state === 'succeeded' ? 'ai.job.completed' : 'ai.job.failed';
      await emitWorkflowEvent({
        workspaceId: input.job.workspaceId,
        type,
        resourceType: 'ai_job',
        resourceId: input.job.id,
        payload: {
          status: input.state,
          jobId: input.job.id,
          nodeId: input.job.assignedNodeId,
          failureCount: input.state === 'succeeded' ? 0 : input.job.attempts,
        },
        dedupeKey: `${type}:${input.job.id}:${input.job.attempts}`,
        correlationId: input.job.workflowCorrelationId ?? undefined,
        causationId: input.job.workflowExecutionId,
        sourceWorkflowId: input.job.workflowId,
        chainDepth: input.job.workflowChainDepth ?? 0,
        createdAt: input.now,
      }).catch(() => undefined);
    }
    return;
  }

  if (input.job.type === 'ai.model.acquire' && input.job.assignedNodeId) {
    const payload = safeJsonRecord(input.job.payload);
    if (typeof payload?.modelId !== 'string') return;
    const model = await queryOne<{ id: string }>(
      'SELECT id FROM ai_model WHERE workspaceId = ? AND catalogId = ?',
      input.job.workspaceId,
      payload.modelId,
    );
    if (!model) return;
    const successful = input.state === 'succeeded';
    const reportedChecksum = safeModelChecksum(input.result?.checksum);
    if (successful && reportedChecksum) {
      await execute(
        `UPDATE ai_model SET checksum = COALESCE(checksum, ?),
           lastVerifiedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND id = ?`,
        reportedChecksum,
        input.now,
        input.now,
        input.job.workspaceId,
        model.id,
      );
    }
    await execute(
      `INSERT INTO ai_model_cache
       (workspaceId, nodeId, modelId, state, sizeBytes, checksum, error,
        lastVerifiedAt, lastUsedAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
       ON CONFLICT(nodeId, modelId) DO UPDATE SET
         state = excluded.state, sizeBytes = excluded.sizeBytes,
         checksum = excluded.checksum, error = excluded.error,
         lastVerifiedAt = excluded.lastVerifiedAt, updatedAt = excluded.updatedAt`,
      input.job.workspaceId,
      input.job.assignedNodeId,
      model.id,
      successful ? 'ready' : 'error',
      boundedResultInteger(input.result?.sizeBytes, AI_LIMITS.maximumModelBytes) ??
        0,
      reportedChecksum,
      successful ? null : (input.error ?? 'Model acquisition failed.'),
      successful ? input.now : null,
      input.now,
    );
  }
}

function safeGamePlayers(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > 500) return null;
  const players = value.filter(
    (player): player is string =>
      typeof player === 'string' && /^[A-Za-z0-9_]{1,16}$/.test(player),
  );
  return players.length === value.length ? players : null;
}

function safeGameStatus(value: unknown): GameServerStatus | null {
  return GAME_SERVER_STATUSES.includes(value as GameServerStatus)
    ? (value as GameServerStatus)
    : null;
}

async function recordGameServerJobOutcome(input: {
  job: JobRow;
  state: NodeJobState;
  result: Record<string, unknown> | null;
  error: string | null;
  now: number;
}): Promise<void> {
  if (!input.job.type.startsWith('game-server.')) return;
  const payload = safeJsonRecord(input.job.payload);
  const serverId =
    typeof payload?.serverId === 'string' ? payload.serverId : null;
  if (!serverId) return;

  await execute(
    `UPDATE game_server_action
     SET state = ?, error = ?, updatedAt = ?,
         completedAt = CASE WHEN ? IN ('queued','leased','cancelling')
           THEN NULL ELSE ? END
     WHERE workspaceId = ? AND jobId = ?`,
    input.state,
    input.error,
    input.now,
    input.state,
    input.now,
    input.job.workspaceId,
    input.job.id,
  );

  if (input.state === 'queued') return;
  if (input.state !== 'succeeded') {
    await execute(
      `UPDATE game_server
       SET status = CASE WHEN status IN ('running','stopped') THEN status ELSE 'error' END,
           lastError = ?, updatedAt = ?
       WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL`,
      input.error ?? `Game Server action ${input.state}.`,
      input.now,
      input.job.workspaceId,
      serverId,
    );
    if (input.job.type === 'game-server.backup' && payload?.operation === 'create') {
      await execute(
        `UPDATE game_server_backup SET state = 'failed', error = ?, updatedAt = ?
         WHERE workspaceId = ? AND id = ? AND serverId = ?`,
        input.error ?? 'Local backup creation failed.',
        input.now,
        input.job.workspaceId,
        payload.backupId,
        serverId,
      );
    }
    if (input.state === 'failed' || input.state === 'timed_out') {
      await emitWorkflowEvent({
        workspaceId: input.job.workspaceId,
        type: 'game_server.crashed',
        resourceType: 'game_server',
        resourceId: serverId,
        payload: {
          status: input.state,
          serverId,
          nodeId: input.job.assignedNodeId,
          crashCount: input.job.attempts,
        },
        dedupeKey: `game_server.crashed:${serverId}:${input.job.id}`,
        correlationId: input.job.workflowCorrelationId ?? undefined,
        causationId: input.job.workflowExecutionId,
        sourceWorkflowId: input.job.workflowId,
        chainDepth: input.job.workflowChainDepth ?? 0,
        createdAt: input.now,
      }).catch(() => undefined);
    }
    return;
  }

  const resultStatus = safeGameStatus(input.result?.status);
  const players = safeGamePlayers(input.result?.players);
  const playerCount = players?.length ?? null;
  const binaryHash =
    typeof input.result?.binaryHash === 'string' &&
    /^sha256:[a-f0-9]{64}$/.test(input.result.binaryHash)
      ? input.result.binaryHash
      : null;
  const exposure =
    input.result?.exposure === 'private' ||
    input.result?.exposure === 'unexpected'
      ? input.result.exposure
      : null;
  let desiredStatus: 'running' | 'stopped' | null = null;
  let persistedStatus = resultStatus;
  if (input.job.type === 'game-server.lifecycle') {
    if (payload?.operation === 'start' || payload?.operation === 'restart') {
      desiredStatus = 'running';
      persistedStatus ??= 'running';
    } else if (
      payload?.operation === 'create' ||
      payload?.operation === 'stop'
    ) {
      desiredStatus = 'stopped';
      persistedStatus ??= 'stopped';
    } else if (payload?.operation === 'delete') {
      await execute(
        `UPDATE game_server SET status = 'deleted', desiredStatus = 'stopped',
            deletedAt = ?, updatedAt = ?, lastError = NULL
         WHERE workspaceId = ? AND id = ?`,
        input.now,
        input.now,
        input.job.workspaceId,
        serverId,
      );
    }
  }

  if (payload?.operation !== 'delete') {
    await execute(
      `UPDATE game_server
       SET status = COALESCE(?, status),
           desiredStatus = COALESCE(?, desiredStatus),
           observedExposure = COALESCE(?, observedExposure),
           playerCount = COALESCE(?, playerCount),
           playersJson = COALESCE(?, playersJson),
           uptimeSeconds = COALESCE(?, uptimeSeconds),
           binaryHash = COALESCE(?, binaryHash),
           binaryVerified = CASE WHEN ? IS NULL THEN binaryVerified ELSE ? END,
           crashCount = COALESCE(?, crashCount),
           crashLoop = CASE WHEN ? IS NULL THEN crashLoop ELSE ? END,
           lastError = NULL, lastStatusAt = ?, updatedAt = ?
       WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL`,
      persistedStatus,
      desiredStatus,
      exposure,
      playerCount,
      players ? stableJson(players) : null,
      boundedResultInteger(input.result?.uptimeSeconds),
      binaryHash,
      typeof input.result?.binaryVerified === 'boolean'
        ? 1
        : null,
      input.result?.binaryVerified === true ? 1 : 0,
      boundedResultInteger(input.result?.crashCount, 1_000_000),
      typeof input.result?.crashLoop === 'boolean'
        ? 1
        : null,
      input.result?.crashLoop === true ? 1 : 0,
      input.now,
      input.now,
      input.job.workspaceId,
      serverId,
    );
  }

  if (input.job.type === 'game-server.config') {
    await execute(
      `UPDATE game_server
       SET port = ?, config = ?, onlineMode = ?, whitelistEnabled = ?,
           observedExposure = 'private', updatedAt = ?
       WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL`,
      payload?.port,
      stableJson(payload?.properties ?? {}),
      (payload?.properties as Record<string, unknown> | undefined)?.onlineMode ===
        true
        ? 1
        : 0,
      (payload?.properties as Record<string, unknown> | undefined)?.whitelist ===
        true
        ? 1
        : 0,
      input.now,
      input.job.workspaceId,
      serverId,
    );
  }

  if (input.job.type === 'game-server.backup') {
    const backupId =
      typeof payload?.backupId === 'string' ? payload.backupId : null;
    if (backupId && payload?.operation === 'create') {
      await execute(
        `UPDATE game_server_backup
         SET state = 'ready', sizeBytes = ?, checksum = ?, fileCount = ?,
             error = NULL, verifiedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND serverId = ? AND id = ?`,
        boundedResultInteger(input.result?.sizeBytes) ?? 0,
        typeof input.result?.checksum === 'string' &&
          /^sha256:[a-f0-9]{64}$/.test(input.result.checksum)
          ? input.result.checksum
          : null,
        boundedResultInteger(input.result?.fileCount, 100_000) ?? 0,
        input.now,
        input.now,
        input.job.workspaceId,
        serverId,
        backupId,
      );
    } else if (backupId && payload?.operation === 'restore') {
      await execute(
        `UPDATE game_server_backup SET restoredAt = ?, verifiedAt = ?,
            error = NULL, updatedAt = ?
         WHERE workspaceId = ? AND serverId = ? AND id = ? AND deletedAt IS NULL`,
        input.now,
        input.now,
        input.now,
        input.job.workspaceId,
        serverId,
        backupId,
      );
    } else if (backupId && payload?.operation === 'delete') {
      await execute(
        `UPDATE game_server_backup SET state = 'deleted', deletedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND serverId = ? AND id = ?`,
        input.now,
        input.now,
        input.job.workspaceId,
        serverId,
        backupId,
      );
    }
  }

  const logs = Array.isArray(input.result?.logs) ? input.result.logs : [];
  const safeLogs = logs
    .map(redactGameLogLine)
    .filter((line): line is string => Boolean(line))
    .slice(-GAME_SERVER_LIMITS.maximumLogLines);
  if (safeLogs.length > 0 && input.job.assignedNodeId) {
    const database = await db();
    await database.batch(
      safeLogs.map((message) =>
        database
          .prepare(
            `INSERT INTO game_server_log
             (id, workspaceId, serverId, nodeId, level, message, createdAt)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            createId('glog'),
            input.job.workspaceId,
            serverId,
            input.job.assignedNodeId,
            /error|failed|crash/i.test(message) ? 'WARN' : 'INFO',
            message,
            input.now,
          ),
      ),
    );
    await pruneGameServerLogs(
      input.job.workspaceId,
      input.job.assignedNodeId,
      input.now,
    );
  }
  const workflowEvent = input.result?.crashLoop === true
    ? 'game_server.crash_loop'
    : input.job.type === 'game-server.lifecycle' &&
        (payload?.operation === 'start' || payload?.operation === 'restart')
      ? 'game_server.started'
      : input.job.type === 'game-server.lifecycle' && payload?.operation === 'stop'
        ? 'game_server.stopped'
        : null;
  if (workflowEvent) {
    await emitWorkflowEvent({
      workspaceId: input.job.workspaceId,
      type: workflowEvent,
      resourceType: 'game_server',
      resourceId: serverId,
      payload: {
        status: persistedStatus ?? 'unknown',
        serverId,
        nodeId: input.job.assignedNodeId,
        crashCount: boundedResultInteger(input.result?.crashCount, 1_000_000) ?? 0,
      },
      dedupeKey: `${workflowEvent}:${serverId}:${input.job.id}`,
      correlationId: input.job.workflowCorrelationId ?? undefined,
      causationId: input.job.workflowExecutionId,
      sourceWorkflowId: input.job.workflowId,
      chainDepth: input.job.workflowChainDepth ?? 0,
      createdAt: input.now,
    }).catch(() => undefined);
  }
}

export type CompleteJobInput = {
  leaseId: unknown;
  claim: unknown;
  claimSignature: unknown;
  status: unknown;
  result: unknown;
  error: unknown;
  retryable: unknown;
};

export async function completeJob(
  context: AgentContext,
  jobId: string,
  input: CompleteJobInput,
): Promise<
  | { ok: true; state: NodeJobState; retry: boolean }
  | { ok: false; status: number; error: string }
> {
  if (
    typeof input.leaseId !== 'string' ||
    typeof input.claimSignature !== 'string' ||
    (input.status !== 'succeeded' &&
      input.status !== 'failed' &&
      input.status !== 'cancelled') ||
    typeof input.claim !== 'object' ||
    input.claim === null
  ) {
    return { ok: false, status: 400, error: 'Completion payload is invalid.' };
  }
  const job = await queryOne<JobRow>(
    'SELECT * FROM node_job WHERE workspaceId = ? AND id = ?',
    context.node.workspaceId,
    jobId,
  );
  if (!job) return { ok: false, status: 404, error: 'Job not found.' };

  const decision = evaluateCompletion(
    job,
    context.node.id,
    input.leaseId,
    Date.now(),
  );
  if (!decision.allowed) {
    await recordJobSecurityEvent(
      context.node,
      job.id,
      `invalid-completion-${decision.reason}`,
      decision.reason === 'node' ? 'critical' : 'high',
      decision.message,
    );
    return { ok: false, status: 409, error: decision.message };
  }

  const claim = input.claim as SignedJobClaim;
  const validClaim =
    claim.jobId === job.id &&
    claim.workspaceId === job.workspaceId &&
    claim.nodeId === context.node.id &&
    claim.leaseId === job.leaseId &&
    claim.leaseExpiresAt === job.leaseExpiresAt &&
    claim.attempt === job.attempts &&
    claim.type === job.type &&
    claim.payloadHash === job.payloadHash &&
    (await verifyJobClaim(context.token, claim, input.claimSignature)) &&
    constantTimeEqual(input.claimSignature, job.claimSignature ?? '');
  if (!validClaim) {
    await recordJobSecurityEvent(
      context.node,
      job.id,
      'unsigned-or-forged-job-completion',
      'critical',
      'The completion did not carry the exact signed lease claim.',
    );
    return {
      ok: false,
      status: 403,
      error: 'The signed job claim is invalid.',
    };
  }

  const now = Date.now();
  let nextState: NodeJobState;
  let retry = false;
  let result: Record<string, unknown> | null = null;
  let error: string | null = null;
  if (job.state === 'cancelling' || input.status === 'cancelled') {
    nextState = 'cancelled';
    error = 'The job was cancelled.';
  } else if (input.status === 'succeeded') {
    result = sanitizeJobResult(
      input.result,
      job.type.startsWith('ai.') || job.type.startsWith('game-server.') || job.type === APP_RUNTIME_JOB_TYPE
        ? job.type === APP_RUNTIME_JOB_TYPE ? 192 * 1024 : 64 * 1024
        : 16_384,
    );
    if (!result) {
      return {
        ok: false,
        status: 400,
        error:
          'The job result is invalid, too large, or contains a forbidden field.',
      };
    }
    nextState = 'succeeded';
  } else {
    // App Runtime failures carry the same bounded, allowlisted diagnostic
    // object as successful completions. Preserve it so recovery can report a
    // fixed phase/reason/availability state instead of collapsing every
    // failure to a generic reconciliation error. Other job types retain their
    // established failure contract.
    if (job.type === APP_RUNTIME_JOB_TYPE && input.result !== undefined && input.result !== null) {
      result = sanitizeJobResult(input.result, 192 * 1024);
      if (!result) {
        return {
          ok: false,
          status: 400,
          error: 'The job result is invalid, too large, or contains a forbidden field.',
        };
      }
    }
    error =
      typeof input.error === 'string'
        ? safeError(input.error)
        : 'The agent reported a job failure.';
    retry = input.retryable === true && job.attempts < job.maxAttempts;
    nextState = retry ? 'queued' : 'failed';
  }

  const update = await execute(
    `UPDATE node_job
     SET state = ?, result = ?, lastError = ?,
         assignedNodeId = CASE WHEN ? = 'queued' THEN NULL ELSE assignedNodeId END,
         leaseId = CASE WHEN ? = 'queued' THEN NULL ELSE leaseId END,
         leaseExpiresAt = CASE WHEN ? = 'queued' THEN NULL ELSE leaseExpiresAt END,
         claimSignature = CASE WHEN ? = 'queued' THEN NULL ELSE claimSignature END,
         completedAt = CASE WHEN ? = 'queued' THEN NULL ELSE ? END,
         updatedAt = ?
     WHERE workspaceId = ? AND id = ? AND leaseId = ?
       AND ((? = 'cancelled' AND state IN ('leased','cancelling'))
         OR (? <> 'cancelled' AND state = 'leased'))`,
    nextState,
    result ? stableJson(result) : null,
    error,
    nextState,
    nextState,
    nextState,
    nextState,
    nextState,
    now,
    now,
    context.node.workspaceId,
    job.id,
    input.leaseId,
    nextState,
    nextState,
  );
  if (!changed(update)) {
    const raced = await queryOne<Pick<JobRow, 'state'>>(
      'SELECT state FROM node_job WHERE workspaceId = ? AND id = ?',
      context.node.workspaceId,
      job.id,
    );
    if (raced?.state === 'cancelling') {
      const cancelled = await execute(
        `UPDATE node_job SET state = 'cancelled', lastError = ?, completedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND id = ? AND state = 'cancelling' AND leaseId = ?`,
        'Cancellation won the completion race.',
        now,
        now,
        context.node.workspaceId,
        job.id,
        input.leaseId,
      );
      if (changed(cancelled)) {
        nextState = 'cancelled';
        retry = false;
        result = null;
        error = 'Cancellation won the completion race.';
      } else {
        return {
          ok: false,
          status: 409,
          error: 'The lease changed before completion.',
        };
      }
    } else {
      return {
        ok: false,
        status: 409,
        error: 'The lease changed before completion.',
      };
    }
  }
  await recordAiJobOutcome({ job, state: nextState, result, error, now });
  await recordGameServerJobOutcome({
    job,
    state: nextState,
    result,
    error,
    now,
  });
  if (job.type === APP_RUNTIME_JOB_TYPE) {
    await recordAppRuntimeJobOutcome({ job, state: nextState, result, error, now });
  }
  await writeJobEvent({
    workspaceId: context.node.workspaceId,
    nodeId: context.node.id,
    jobId: job.id,
    kind: retry ? 'retry' : nextState,
    message: retry
      ? `Attempt ${job.attempts} failed and the job returned to the queue.`
      : `Job ${nextState}.`,
  });
  await writeLog({
    workspaceId: context.node.workspaceId,
    source: 'node',
    level:
      nextState === 'succeeded' || nextState === 'cancelled' ? 'INFO' : 'WARN',
    message: `Node job ${job.type} ${retry ? 'will retry' : nextState}`,
    actor: `agent:${context.node.id}`,
    resource: job.id,
  });
  return { ok: true, state: nextState, retry };
}

export async function enqueueJob(input: {
  workspaceId: string;
  actor: string;
  type: unknown;
  payload: unknown;
  targetNodeId: unknown;
  idempotencyKey: string | null;
  workflowContext?: WorkflowJobContext;
}): Promise<
  | { ok: true; job: NodeJob; created: boolean }
  | { ok: false; status: number; error: string }
> {
  const validated = validateJob(input.type, input.payload);
  if (!validated.ok) {
    return {
      ok: false,
      status: validated.status,
      error: validated.error,
    };
  }
  const targetNodeId =
    typeof input.targetNodeId === 'string' && input.targetNodeId
      ? input.targetNodeId
      : null;
  if (input.workflowContext) {
    const context = input.workflowContext;
    if (!Number.isSafeInteger(context.chainDepth) || context.chainDepth < 1 ||
        context.chainDepth > MAX_WORKFLOW_CHAIN_DEPTH) {
      return { ok: false, status: 400, error: 'Workflow job chain depth is invalid.' };
    }
    const trusted = await queryOne<{ id: string }>(
      `SELECT e.id FROM workflow_execution e JOIN workflow w ON w.id = e.workflowId
        WHERE e.workspaceId = ? AND e.id = ? AND e.workflowId = ?
          AND e.correlationId = ? AND w.deletedAt IS NULL`,
      input.workspaceId, context.executionId, context.workflowId, context.correlationId,
    );
    if (!trusted) {
      await recordWorkflowSecurityEvent({
        workspaceId: input.workspaceId, workflowId: context.workflowId,
        executionId: context.executionId, type: 'workflow-job-context-rejected',
        severity: 'critical', detail: 'A node job attempted to forge workflow causation metadata.',
      }).catch(() => undefined);
      return { ok: false, status: 400, error: 'Workflow job context is invalid.' };
    }
  }
  if (targetNodeId) {
    const node = await queryOne<{ id: string }>(
      `SELECT id FROM compute_node
       WHERE workspaceId = ? AND id = ? AND revokedAt IS NULL`,
      input.workspaceId,
      targetNodeId,
    );
    if (!node) {
      return { ok: false, status: 404, error: 'Target node not found.' };
    }
  }

  const idempotencyKey = input.idempotencyKey?.trim().slice(0, 128) || null;
  if (idempotencyKey) {
    const duplicate = await queryOne<JobRow>(
      'SELECT * FROM node_job WHERE workspaceId = ? AND idempotencyKey = ?',
      input.workspaceId,
      idempotencyKey,
    );
    if (duplicate) return { ok: true, job: toJob(duplicate), created: false };
  }
  const queued = await queryOne<{ total: number }>(
     `SELECT COUNT(*) AS total FROM node_job
      WHERE workspaceId = ? AND state IN ('queued', 'leased', 'cancelling')`,
    input.workspaceId,
  );
  if ((queued?.total ?? 0) >= MAX_QUEUED_JOBS_PER_WORKSPACE) {
    return {
      ok: false,
      status: 409,
      error: 'The workspace job queue has reached its Zero Mode ceiling.',
    };
  }

  const now = Date.now();
  const payload = stableJson(validated.payload);
  const id = createId('job');
  await execute(
    `INSERT OR IGNORE INTO node_job
     (id, workspaceId, type, payload, payloadHash, state, priority,
      idempotencyKey, targetNodeId, assignedNodeId, leaseId, leaseExpiresAt,
      attempts, maxAttempts, claimSignature, result, lastError, createdBy,
      createdAt, updatedAt, completedAt, workflowId, workflowExecutionId,
      workflowCorrelationId, workflowChainDepth)
     VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?, NULL, NULL, NULL, 0, ?, NULL,
             NULL, NULL, ?, ?, ?, NULL, ?, ?, ?, ?)`,
    id,
    input.workspaceId,
    validated.type,
    payload,
    await sha256(payload),
    idempotencyKey,
    targetNodeId,
    validated.type === APP_RUNTIME_JOB_TYPE ? 1 : DEFAULT_MAX_ATTEMPTS,
    input.actor,
    now,
    now,
    input.workflowContext?.workflowId ?? null,
    input.workflowContext?.executionId ?? null,
    input.workflowContext?.correlationId ?? null,
    input.workflowContext?.chainDepth ?? null,
  );
  const created = await queryOne<JobRow>(
    idempotencyKey
      ? 'SELECT * FROM node_job WHERE workspaceId = ? AND idempotencyKey = ?'
      : 'SELECT * FROM node_job WHERE workspaceId = ? AND id = ?',
    input.workspaceId,
    idempotencyKey ?? id,
  );
  if (!created) {
    return { ok: false, status: 500, error: 'The job could not be queued.' };
  }
  const isNew = created.id === id;
  if (isNew) {
    await writeJobEvent({
      workspaceId: input.workspaceId,
      nodeId: targetNodeId,
      jobId: id,
      kind: 'queued',
      message: `Allowlisted job ${validated.type} queued.`,
    });
    await writeLog({
      workspaceId: input.workspaceId,
      source: 'node',
      message: `Queued ${validated.type} for user-owned compute`,
      actor: input.actor,
      resource: id,
    });
  }
  return { ok: true, job: toJob(created), created: isNew };
}

export async function revokeNode(input: {
  workspaceId: string;
  nodeId: string;
  actor: string;
  workflowContext?: WorkflowJobContext;
}): Promise<boolean> {
  const node = await queryOne<Pick<NodeRow, 'id' | 'name'>>(
    'SELECT id, name FROM compute_node WHERE workspaceId = ? AND id = ?',
    input.workspaceId,
    input.nodeId,
  );
  if (!node) return false;

  const now = Date.now();
  const activeAi = await queryOne<{ total: number }>(
    `SELECT COUNT(*) AS total FROM node_job
     WHERE workspaceId = ? AND assignedNodeId = ?
       AND type LIKE 'ai.%' AND state IN ('leased','cancelling')`,
    input.workspaceId,
    input.nodeId,
  );
  const activeGameServers = await queryOne<{ total: number }>(
    `SELECT COUNT(*) AS total FROM game_server
     WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL
       AND status IN ('starting','running','stopping','restarting')`,
    input.workspaceId,
    input.nodeId,
  );
  const activeApps = await queryOne<{ total: number }>(
    `SELECT COUNT(*) AS total FROM deployment
     WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL
       AND state IN ('queued','building','starting','healthy','restarting','rolling_back')`,
    input.workspaceId,
    input.nodeId,
  );
  const database = await db();
  await database.batch([
    database
      .prepare(
        `UPDATE compute_node
         SET revokedAt = ?, revokedBy = ?, tokenCiphertext = '', updatedAt = ?
         WHERE workspaceId = ? AND id = ? AND revokedAt IS NULL`,
      )
      .bind(now, input.actor, now, input.workspaceId, input.nodeId),
    database
      .prepare(
         `UPDATE node_job
          SET state = CASE
               WHEN state = 'cancelling' THEN 'cancelled'
               WHEN type LIKE 'game-server.%' THEN 'failed'
               WHEN attempts < maxAttempts THEN 'queued'
               ELSE 'timed_out'
              END,
             assignedNodeId = NULL, leaseId = NULL, leaseExpiresAt = NULL,
             claimSignature = NULL, lastError = 'Assigned node was revoked.',
              completedAt = CASE
                WHEN state = 'cancelling' OR type LIKE 'game-server.%'
                  OR attempts >= maxAttempts THEN ?
                ELSE NULL
              END,
             updatedAt = ?
         WHERE workspaceId = ?
           AND (assignedNodeId = ?
             OR (type LIKE 'game-server.%' AND targetNodeId = ?))
           AND state IN ('queued','leased','cancelling')`,
      )
      .bind(now, now, input.workspaceId, input.nodeId, input.nodeId),
    database
      .prepare(
        `UPDATE game_server
         SET status = 'node_revoked',
             lastError = 'The assigned node was revoked. The local process may still be running, but no further control-plane commands are accepted.',
             updatedAt = ?
         WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL`,
      )
      .bind(now, input.workspaceId, input.nodeId),
    database
      .prepare(
        `UPDATE game_server_action
         SET state = 'failed', error = 'The assigned node was revoked.',
             completedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND nodeId = ?
           AND state IN ('queued','leased','cancelling')`,
      )
      .bind(now, now, input.workspaceId, input.nodeId),
    database
      .prepare(
        `UPDATE deployment
         SET state = 'node_revoked', desiredState = 'stopped',
             desiredRevision = COALESCE(desiredRevision, 0) + 1,
             observedState = 'blocked', recoveryStatus = 'blocked',
             recoveryReasonCode = 'node_revoked',
             lastError = 'The assigned node was revoked. The local App Runtime is stopped when the agent observes the rejected credential.',
             finishedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL
           AND state NOT IN ('blocked','deleted')`,
      )
      .bind(now, now, input.workspaceId, input.nodeId),
    database
      .prepare(
        `UPDATE app_deployment_action
         SET state = 'failed', error = 'The assigned node was revoked.',
             completedAt = ?, updatedAt = ?
         WHERE workspaceId = ? AND nodeId = ?
           AND state IN ('queued','leased','cancelling')`,
      )
      .bind(now, now, input.workspaceId, input.nodeId),
    database
      .prepare(
        `UPDATE public_exposure
         SET healthState = 'revoked',
             status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END,
             transport = 'none', transportState = 'revoked', tlsState = 'unavailable',
             lastError = 'The target node was revoked; routing is failed closed.', updatedAt = ?
         WHERE workspaceId = ? AND targetNodeId = ? AND deletedAt IS NULL`,
      )
      .bind(now, input.workspaceId, input.nodeId),
  ]);
  if ((activeAi?.total ?? 0) > 0) {
    await execute(
      `INSERT INTO node_security_event
       (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
       VALUES (?, ?, ?, 'revoked-node-ai-activity', 'high', ?, NULL, ?)`,
      createId('nsec'),
      input.workspaceId,
      input.nodeId,
      `Node was revoked during ${activeAi!.total} active AI job${activeAi!.total === 1 ? '' : 's'}.`,
      now,
    );
  }
  if ((activeGameServers?.total ?? 0) > 0) {
    await execute(
      `INSERT INTO node_security_event
       (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
       VALUES (?, ?, ?, 'revoked-node-game-activity', 'high', ?, NULL, ?)`,
      createId('nsec'),
      input.workspaceId,
      input.nodeId,
      `Node was revoked while ${activeGameServers!.total} Game Server${activeGameServers!.total === 1 ? ' was' : 's were'} active. Local processes are no longer remotely controlled.`,
      now,
    );
  }
  if ((activeApps?.total ?? 0) > 0) {
    await execute(
      `INSERT INTO node_security_event
       (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
       VALUES (?, ?, ?, 'revoked-node-app-activity', 'critical', ?, NULL, ?)`,
      createId('nsec'),
      input.workspaceId,
      input.nodeId,
      `Node was revoked during ${activeApps!.total} managed App Runtime deployment${activeApps!.total === 1 ? '' : 's'}.`,
      now,
    );
  }
  await writeLog({
    workspaceId: input.workspaceId,
    source: 'node',
    level: 'WARN',
    message: `Revoked and disconnected ${node.name}`,
    actor: input.actor,
    resource: input.nodeId,
  });
  await emitWorkflowEvent({
    workspaceId: input.workspaceId,
    type: 'node.revoked',
    resourceType: 'node',
    resourceId: input.nodeId,
    payload: { status: 'revoked', nodeId: input.nodeId },
    dedupeKey: `node.revoked:${input.nodeId}:${now}`,
    correlationId: input.workflowContext?.correlationId,
    causationId: input.workflowContext?.executionId ?? null,
    sourceWorkflowId: input.workflowContext?.workflowId ?? null,
    chainDepth: input.workflowContext?.chainDepth ?? 0,
  }).catch(() => undefined);
  return true;
}

export async function readNodesState(
  workspaceId: string,
  now = Date.now(),
): Promise<NodesState> {
  await requeueExpiredJobs(workspaceId, now);
  const [rows, jobRows, securityEvents] = await Promise.all([
    query<NodeWithMetricRow>(
      `SELECT n.*,
         m.cpuLoadPercent, m.memoryUsedBytes, m.memoryTotalBytes, m.runningJobs
       FROM compute_node n
       LEFT JOIN node_metric m ON m.id = (
         SELECT id FROM node_metric
         WHERE workspaceId = n.workspaceId AND nodeId = n.id
         ORDER BY recordedAt DESC LIMIT 1
       )
       WHERE n.workspaceId = ?
       ORDER BY n.createdAt DESC`,
      workspaceId,
    ),
    query<JobRow>(
      `SELECT * FROM node_job WHERE workspaceId = ?
       ORDER BY createdAt DESC LIMIT 100`,
      workspaceId,
    ),
    query<NodeSecurityEvent>(
      `SELECT id, nodeId, type, severity, detail, createdAt
       FROM node_security_event WHERE workspaceId = ?
       ORDER BY createdAt DESC LIMIT 20`,
      workspaceId,
    ),
  ]);
  const nodes = rows.map((row) => toNode(row, now));
  const jobs = jobRows.map(toJob);
  return {
    nodes,
    jobs,
    securityEvents,
    summary: {
      total: nodes.length,
      online: nodes.filter((node) => node.status === 'online').length,
      stale: nodes.filter((node) => node.status === 'stale').length,
      offline: nodes.filter((node) => node.status === 'offline').length,
      revoked: nodes.filter((node) => node.status === 'revoked').length,
      queuedJobs: jobs.filter((job) => job.state === 'queued').length,
      activeLeases: jobs.filter(
        (job) => job.state === 'leased' || job.state === 'cancelling',
      ).length,
    },
    protocolVersion: NODE_PROTOCOL_VERSION,
    currentAgentVersion: CURRENT_AGENT_VERSION,
    minimumAgentVersion: MINIMUM_AGENT_VERSION,
    outboundOnly: true,
    projectedMonthlyCost: 0,
  };
}

export type NodesShieldState = {
  total: number;
  stale: number;
  offline: number;
  revoked: number;
  outdated: number;
  unsignedJobs: number;
  staleLeases: number;
  anomalousEvents: number;
  revokedActivity: number;
};

export async function nodesForShield(
  workspaceId: string,
  now = Date.now(),
): Promise<NodesShieldState> {
  const rows = await query<
    Pick<NodeRow, 'agentVersion' | 'lastHeartbeatAt' | 'revokedAt'>
  >(
    `SELECT agentVersion, lastHeartbeatAt, revokedAt
     FROM compute_node WHERE workspaceId = ?`,
    workspaceId,
  );
  const states = rows.map((row) => ({
    ...row,
    status: deriveNodeStatus({ ...row, now }),
  }));
  const [unsigned, staleLeases, anomalous, revokedActivity] = await Promise.all(
    [
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_job
       WHERE workspaceId = ? AND state IN ('leased','cancelling','succeeded','failed')
         AND (claimSignature IS NULL OR claimSignature = '')`,
        workspaceId,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_job
       WHERE workspaceId = ? AND state IN ('leased','cancelling') AND leaseExpiresAt <= ?`,
        workspaceId,
        now,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_security_event
       WHERE workspaceId = ? AND severity IN ('high','critical') AND createdAt >= ?`,
        workspaceId,
        now - 24 * 60 * 60_000,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_security_event
       WHERE workspaceId = ? AND type = 'revoked-token-used' AND createdAt >= ?`,
        workspaceId,
        now - 24 * 60 * 60_000,
      ),
    ],
  );
  return {
    total: rows.length,
    stale: states.filter((node) => node.status === 'stale').length,
    offline: states.filter((node) => node.status === 'offline').length,
    revoked: states.filter((node) => node.status === 'revoked').length,
    outdated: rows.filter((node) => !agentVersionSupported(node.agentVersion))
      .length,
    unsignedJobs: unsigned?.total ?? 0,
    staleLeases: staleLeases?.total ?? 0,
    anomalousEvents: anomalous?.total ?? 0,
    revokedActivity: revokedActivity?.total ?? 0,
  };
}


// ---------------------------------------------------------------------------
// Phase 22: declared-loss replacement-node recovery.
//
// A Compute Node can be destroyed, stolen, or simply never come back. Until
// now that was terminal for everything on it: `revokeNode` kills the
// credential and stops the deployments, and nothing can move them, because
// `deployment.nodeId` is written once and every runtime query filters on it.
//
// These functions add the one path out, and they are deliberately three
// separate authorized steps rather than one convenient button: declaring the
// loss, moving ownership, and importing the bytes. Nothing here fetches source,
// installs packages, builds, or starts a runtime.
// ---------------------------------------------------------------------------

/**
 * Declares a Compute Node permanently lost.
 *
 * This is not `revokeNode` with a different name. Revoke is the answer to "I no
 * longer trust this node", and it is right for revoke to stop the work: it sets
 * every assigned deployment to desired `stopped`. Declared loss is the answer to
 * "this machine is gone", where the operator still wants the applications
 * running -- somewhere else. So the credential is killed exactly as revoke kills
 * it, and the intent is left standing.
 *
 * Irreversible by construction: there is no un-lose, and the ciphertext that
 * would be needed to accept the old credential again is blanked, not hidden.
 */
export async function declareNodeLost(input: {
  workspaceId: string;
  nodeId: string;
  actor: string;
}): Promise<
  | { ok: true; declared: boolean; deployments: number }
  | { ok: false; status: number; error: string }
> {
  const node = await queryOne<{ id: string; name: string; revokedAt: number | null }>(
    'SELECT id, name, revokedAt FROM compute_node WHERE workspaceId = ? AND id = ?',
    input.workspaceId,
    input.nodeId,
  );
  if (!node) return { ok: false, status: 404, error: 'Compute Node not found.' };

  const now = Date.now();
  // The credential write is the idempotency latch for the whole operation. A
  // second declaration matches no row, so revisions are not bumped again and a
  // deployment already transferred away is never dragged back into a blocked
  // state.
  const claimed = await execute(
    `UPDATE compute_node
        SET revokedAt = ?, revokedBy = ?, tokenCiphertext = '',
            assignmentsDisabledAt = COALESCE(assignmentsDisabledAt, ?),
            assignmentsDisabledBy = COALESCE(assignmentsDisabledBy, ?),
            updatedAt = ?
      WHERE workspaceId = ? AND id = ? AND revokedAt IS NULL`,
    now, input.actor, now, input.actor, now, input.workspaceId, input.nodeId,
  );
  if (!changed(claimed)) {
    return { ok: true, declared: false, deployments: 0 };
  }

  const owned = await queryOne<{ total: number }>(
    `SELECT COUNT(*) AS total FROM deployment
      WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL
        AND state NOT IN ('deleted')`,
    input.workspaceId, input.nodeId,
  );
  const database = await db();
  await database.batch([
    // Identical to revoke: in-flight work is unassigned and either requeued or
    // failed. A lost node must never be able to lease anything again.
    database
      .prepare(
        `UPDATE node_job
            SET state = CASE
                 WHEN state = 'cancelling' THEN 'cancelled'
                 WHEN type LIKE 'game-server.%' THEN 'failed'
                 WHEN attempts < maxAttempts THEN 'queued'
                 ELSE 'timed_out'
                END,
               assignedNodeId = NULL, leaseId = NULL, leaseExpiresAt = NULL,
               claimSignature = NULL, lastError = 'Assigned node was declared lost.',
               completedAt = CASE
                 WHEN state = 'cancelling' OR type LIKE 'game-server.%'
                   OR attempts >= maxAttempts THEN ?
                 ELSE NULL
                END,
               updatedAt = ?
          WHERE workspaceId = ?
            AND (assignedNodeId = ?
              OR (type LIKE 'game-server.%' AND targetNodeId = ?))
            AND state IN ('queued','leased','cancelling')`,
      )
      .bind(now, now, input.workspaceId, input.nodeId, input.nodeId),
    // The one clause that differs from revoke: `desiredState` is not written.
    // The operator's intent survives the machine.
    database
      .prepare(
        `UPDATE deployment
            SET state = 'blocked', observedState = 'blocked',
                recoveryStatus = 'blocked', recoveryReasonCode = 'node_lost',
                recoveryGeneration = NULL, recoveryRevision = NULL,
                desiredRevision = COALESCE(desiredRevision, 0) + 1,
                lastError = 'This Compute Node was declared permanently lost. Transfer this deployment to a replacement node.',
                updatedAt = ?
          WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL
            AND state NOT IN ('deleted')`,
      )
      .bind(now, input.workspaceId, input.nodeId),
    database
      .prepare(
        `UPDATE app_deployment_action
            SET state = 'failed', error = 'The assigned node was declared lost.',
                completedAt = ?, updatedAt = ?
          WHERE workspaceId = ? AND nodeId = ?
            AND state IN ('queued','leased','cancelling')`,
      )
      .bind(now, now, input.workspaceId, input.nodeId),
    database
      .prepare(
        `UPDATE game_server
            SET status = 'node_revoked',
                lastError = 'The assigned node was declared lost. The local process may still be running, but no further control-plane commands are accepted.',
                updatedAt = ?
          WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL`,
      )
      .bind(now, input.workspaceId, input.nodeId),
    database
      .prepare(
        `UPDATE public_exposure
            SET healthState = 'revoked',
                status = CASE WHEN mode = 'private' THEN 'disabled' ELSE 'unavailable_zero_mode' END,
                transport = 'none', transportState = 'revoked', tlsState = 'unavailable',
                lastError = 'The target node was declared lost; routing is failed closed.',
                updatedAt = ?
          WHERE workspaceId = ? AND targetNodeId = ? AND deletedAt IS NULL`,
      )
      .bind(now, input.workspaceId, input.nodeId),
  ]);

  const tenant = await queryOne<{ organizationId: string | null }>(
    'SELECT organizationId FROM workspace WHERE id = ?', input.workspaceId,
  );
  if (tenant?.organizationId) {
    await recordEvidence({
      organizationId: tenant.organizationId,
      workspaceId: input.workspaceId,
      actorType: 'user',
      actorId: input.actor,
      action: 'node.declare_lost',
      resourceId: input.nodeId,
      outcome: 'success',
      metadata: { nodeId: input.nodeId, deployments: owned?.total ?? 0, reasonCode: 'node_lost' },
    });
  }
  await writeLog({
    workspaceId: input.workspaceId,
    source: 'node',
    level: 'WARN',
    message: `Declared ${node.name} permanently lost`,
    actor: input.actor,
    resource: input.nodeId,
  });
  return { ok: true, declared: true, deployments: owned?.total ?? 0 };
}

/**
 * Moves one deployment from a lost node to a replacement node.
 *
 * The decisive write is a single conditional statement, and the transfer is
 * accepted only when that one statement reports exactly one changed row. That
 * matters more than it looks: it means correctness does not rest on any claim
 * about multi-statement atomicity. Two operators racing, a stale revision, a
 * deployment that moved a moment ago -- each of them matches nothing and loses
 * cleanly.
 *
 * What deliberately does not move: the source artifact row. It keeps its
 * `nodeId`, its checksum and its state forever, because it is the immutable
 * record that those bytes existed on the machine that is gone.
 */
export async function transferDeploymentOwnership(input: {
  workspaceId: string;
  deploymentId: string;
  sourceNodeId: string;
  replacementNodeId: string;
  expectedDesiredRevision: number;
  expectedArtifactId: string;
  actor: string;
}): Promise<
  | { ok: true; desiredRevision: number; desiredState: string; artifactId: string }
  | { ok: false; status: number; error: string }
> {
  if (
    !/^dpl_[a-f0-9]{24}$/.test(input.deploymentId) ||
    !/^node_[a-f0-9]{24}$/.test(input.sourceNodeId) ||
    !/^node_[a-f0-9]{24}$/.test(input.replacementNodeId) ||
    !/^art_[a-f0-9]{24}$/.test(input.expectedArtifactId) ||
    !Number.isSafeInteger(input.expectedDesiredRevision) ||
    input.expectedDesiredRevision < 1
  ) {
    return { ok: false, status: 400, error: 'Ownership transfer request is invalid.' };
  }
  if (input.sourceNodeId === input.replacementNodeId) {
    return { ok: false, status: 400, error: 'A deployment cannot be transferred to the node it already has.' };
  }

  const guard = await queryOne<{
    desiredState: string | null;
    desiredRevision: number | null;
    artifactState: string | null;
    artifactChecksum: string | null;
    artifactNodeId: string | null;
    sourceRevokedAt: number | null;
    replacementRevokedAt: number | null;
    replacementDisabledAt: number | null;
    replacementAgentVersion: string | null;
    replacementCapabilities: string | null;
  }>(
    `SELECT d.desiredState AS desiredState, d.desiredRevision AS desiredRevision,
            a.state AS artifactState, a.checksum AS artifactChecksum, a.nodeId AS artifactNodeId,
            lost.revokedAt AS sourceRevokedAt,
            fresh.revokedAt AS replacementRevokedAt,
            fresh.assignmentsDisabledAt AS replacementDisabledAt,
            fresh.agentVersion AS replacementAgentVersion,
            fresh.capabilities AS replacementCapabilities
       FROM deployment d
       JOIN compute_node lost ON lost.id = d.nodeId AND lost.workspaceId = d.workspaceId
       JOIN compute_node fresh ON fresh.id = ? AND fresh.workspaceId = d.workspaceId
       LEFT JOIN app_artifact a ON a.id = d.currentArtifactId AND a.workspaceId = d.workspaceId
        AND a.deletedAt IS NULL
      WHERE d.workspaceId = ? AND d.id = ? AND d.nodeId = ? AND d.deletedAt IS NULL
        AND d.currentArtifactId = ?`,
    input.replacementNodeId,
    input.workspaceId,
    input.deploymentId,
    input.sourceNodeId,
    input.expectedArtifactId,
  );
  if (!guard) {
    return { ok: false, status: 404, error: 'That deployment, source node, replacement node, or artifact does not match.' };
  }
  if (guard.sourceRevokedAt === null) {
    return {
      ok: false,
      status: 409,
      error: 'Declare the source Compute Node permanently lost before transferring its deployments.',
    };
  }
  if (guard.replacementRevokedAt !== null || guard.replacementDisabledAt !== null) {
    return { ok: false, status: 409, error: 'The replacement Compute Node is not accepting assignments.' };
  }
  if (
    guard.artifactState !== 'verified' || !guard.artifactChecksum ||
    guard.artifactNodeId !== input.sourceNodeId
  ) {
    return {
      ok: false,
      status: 409,
      error: 'The current artifact is not a verified artifact of the source node.',
    };
  }
  const capabilities = capabilitiesFromRow(guard.replacementCapabilities ?? '');
  if (capabilities.artifactBackup?.replacementImport !== true) {
    return {
      ok: false,
      status: 409,
      error: 'Upgrade the replacement Compute Node to an Agent that supports replacement import.',
    };
  }

  const now = Date.now();
  const nextRevision = input.expectedDesiredRevision + 1;
  // The whole transfer, in one statement. `localPort` is deliberately left
  // alone: the row becomes `blocked`, which the partial unique index on
  // (nodeId, localPort) excludes, so the old port travels as a preference and
  // is settled by ordinary negotiation before this deployment is eligible to
  // run again. `desiredState` and `currentArtifactId` are equally deliberately
  // absent -- intent is preserved, and the source artifact stays current until
  // real bytes exist here.
  const moved = await execute(
    `UPDATE deployment
        SET nodeId = ?, desiredRevision = ?, state = 'blocked', observedState = 'blocked',
            recoveryStatus = 'blocked', recoveryReasonCode = 'awaiting_import',
            recoveryGeneration = NULL, recoveryRevision = NULL, jobId = NULL,
            lastError = 'Waiting for an artifact backup import on the replacement Compute Node.',
            updatedAt = ?
      WHERE workspaceId = ? AND id = ? AND nodeId = ? AND desiredRevision = ?
        AND currentArtifactId = ? AND deletedAt IS NULL`,
    input.replacementNodeId, nextRevision, now,
    input.workspaceId, input.deploymentId, input.sourceNodeId,
    input.expectedDesiredRevision, input.expectedArtifactId,
  );
  if (!changed(moved)) {
    return { ok: false, status: 409, error: 'This deployment changed while the transfer was being prepared.' };
  }

  const tenant = await queryOne<{ organizationId: string | null }>(
    'SELECT organizationId FROM workspace WHERE id = ?', input.workspaceId,
  );
  if (tenant?.organizationId) {
    await recordEvidence({
      organizationId: tenant.organizationId,
      workspaceId: input.workspaceId,
      actorType: 'user',
      actorId: input.actor,
      action: 'deployment.ownership_transfer',
      resourceId: input.deploymentId,
      outcome: 'success',
      metadata: {
        sourceNodeId: input.sourceNodeId,
        nodeId: input.replacementNodeId,
        artifactId: input.expectedArtifactId,
        desiredRevision: nextRevision,
      },
    });
  }
  return {
    ok: true,
    desiredRevision: nextRevision,
    desiredState: guard.desiredState ?? 'running',
    artifactId: input.expectedArtifactId,
  };
}

/**
 * Authorizes one replacement node to import one backup, and reserves the row
 * the imported bytes will become.
 *
 * The node supplies which deployment it is asking about and nothing else that
 * matters. It does not choose the artifact id -- the control plane allocates
 * it. It does not choose the checksum -- that is read from the immutable source
 * row, so a node cannot import bytes of its own choosing by naming their hash.
 *
 * Reservation is idempotent through the existing action/job idempotency key, so
 * a node that retries after a crash gets the same provisional artifact back
 * instead of leaving a trail of abandoned rows.
 */
export async function readArtifactImportPreflight(
  context: AgentContext,
  deploymentId: string,
): Promise<
  | {
      ok: true;
      workspaceId: string;
      projectId: string;
      deploymentId: string;
      nodeId: string;
      sourceArtifactId: string;
      sourceNodeId: string;
      replacementArtifactId: string;
      checksum: string;
      desiredRevision: number;
      desiredState: string;
      localPort: number;
      contract: unknown;
      created: boolean;
    }
  | { ok: false; status: number; error: string }
> {
  if (!/^dpl_[a-f0-9]{24}$/.test(deploymentId)) {
    return { ok: false, status: 400, error: 'Import preflight request is invalid.' };
  }
  const row = await queryOne<{
    projectId: string | null;
    nodeId: string | null;
    state: string | null;
    desiredState: string | null;
    desiredRevision: number | null;
    recoveryReasonCode: string | null;
    localPort: number | null;
    healthPath: string | null;
    environment: string | null;
    sourceArtifactId: string | null;
    sourceNodeId: string | null;
    sourceState: string | null;
    sourceChecksum: string | null;
    sourceCommit: string | null;
    sourceManifest: string | null;
    sourceRevokedAt: number | null;
  }>(
    `SELECT d.projectId AS projectId, d.nodeId AS nodeId, d.state AS state,
            d.desiredState AS desiredState, d.desiredRevision AS desiredRevision,
            d.recoveryReasonCode AS recoveryReasonCode, d.localPort AS localPort,
            d.healthPath AS healthPath, d.environment AS environment,
            a.id AS sourceArtifactId, a.nodeId AS sourceNodeId, a.state AS sourceState,
            a.checksum AS sourceChecksum, a.commitSha AS sourceCommit, a.manifest AS sourceManifest,
            lost.revokedAt AS sourceRevokedAt
       FROM deployment d
       LEFT JOIN app_artifact a ON a.id = d.currentArtifactId AND a.workspaceId = d.workspaceId
        AND a.deletedAt IS NULL
       LEFT JOIN compute_node lost ON lost.id = a.nodeId AND lost.workspaceId = d.workspaceId
      WHERE d.workspaceId = ? AND d.id = ? AND d.nodeId = ? AND d.deletedAt IS NULL`,
    context.node.workspaceId, deploymentId, context.node.id,
  );
  // One refusal for "not yours" and "not there", matching the restore gate, so
  // probing cannot tell a foreign deployment apart from an absent one.
  if (!row || !row.projectId || row.nodeId !== context.node.id) {
    return { ok: false, status: 404, error: 'Deployment not found for this node.' };
  }
  if (row.desiredRevision === null) {
    return { ok: false, status: 409, error: 'This deployment is not awaiting a replacement import.' };
  }
  if (!row.sourceArtifactId || !row.sourceChecksum || row.sourceState !== 'verified' ||
      !row.sourceNodeId) {
    return { ok: false, status: 409, error: 'The source artifact is not a verified artifact.' };
  }
  if (row.sourceNodeId === context.node.id) {
    return { ok: false, status: 409, error: 'This artifact already belongs to this node; use restore.' };
  }
  if (row.sourceRevokedAt === null) {
    return { ok: false, status: 409, error: 'The source Compute Node is not revoked.' };
  }

  if (row.localPort === null) {
    return { ok: false, status: 409, error: 'This deployment has no private port to import onto.' };
  }

  // Keyed on the transfer revision, so one authorized import reserves exactly
  // one replacement artifact, one action and one job -- no matter how many
  // times the node asks, and no matter how many ask at once.
  const idempotencyKey = `import:${deploymentId}:${row.desiredRevision}`;
  const projectId = row.projectId;
  const sourceArtifactId = row.sourceArtifactId;
  const sourceNodeId = row.sourceNodeId;
  const sourceChecksum = row.sourceChecksum;
  const sourceCommit = row.sourceCommit ?? '';
  const desiredRevision = row.desiredRevision;
  // Provenance rides in the manifest the artifact row already carries. Nothing
  // in the runtime path reads it back, so it needs no column of its own -- it
  // exists so a person can answer "where did these bytes come from" years later.
  const provenanceManifest = (contract: unknown): string => stableJson({
    contract: (safeJsonRecord(row.sourceManifest) as { contract?: unknown } | null)?.contract ?? contract,
    source: {
      kind: 'backup-import',
      sourceArtifactId,
      sourceNodeId,
      checksum: sourceChecksum,
      transferRevision: desiredRevision,
    },
  });
  const settled = {
    workspaceId: context.node.workspaceId,
    projectId: row.projectId,
    deploymentId,
    nodeId: context.node.id,
    sourceArtifactId: row.sourceArtifactId,
    sourceNodeId: row.sourceNodeId,
    checksum: row.sourceChecksum,
    desiredRevision: row.desiredRevision,
    desiredState: row.desiredState ?? 'running',
  };

  // The job is the authority on whether this import was already reserved, and
  // it is reserved first, so it is the row that certainly exists if anything
  // does. A crash between reserving the job and writing the two rows that
  // describe it would otherwise leave this deployment permanently unable to
  // recover: the key is taken, so no new job can be made, and the artifact the
  // node is told to import has no row to become. So a retry repairs what is
  // missing from the payload that is already there, rather than starting over.
  const reserveArtifactId = createId('art');
  const reserveActionId = createId('dact');

  async function adoptExistingReservation(jobId: string, payload: string): Promise<
    | { ok: true; artifactId: string; contract: unknown }
    | { ok: false; status: number; error: string }
  > {
    let claim: AppRuntimeJobPayload | null = null;
    try {
      const parsed = validateAppRuntimeJobPayload(JSON.parse(payload));
      if (parsed.ok) claim = parsed.payload;
    } catch {
      // A payload that no longer parses is never replayed as authorization.
    }
    // The reservation has to still describe the import this deployment is
    // actually waiting for. Anything else is a conflict, not something to fix.
    if (
      !claim || claim.operation !== 'import' || !claim.artifactId ||
      claim.deploymentId !== deploymentId || claim.projectId !== projectId ||
      claim.targetArtifactId !== sourceArtifactId ||
      claim.expectedDesiredRevision !== desiredRevision
    ) {
      return { ok: false, status: 409, error: 'A conflicting import is already reserved for this deployment.' };
    }
    const artifactId = claim.artifactId;
    const artifact = await queryOne<{ nodeId: string; deploymentId: string; state: string }>(
      `SELECT nodeId, deploymentId, state FROM app_artifact
        WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL`,
      context.node.workspaceId, artifactId,
    );
    if (artifact && (artifact.nodeId !== context.node.id || artifact.deploymentId !== deploymentId)) {
      return { ok: false, status: 409, error: 'The reserved artifact belongs to another node or deployment.' };
    }
    const action = await queryOne<{ id: string }>(
      `SELECT id FROM app_deployment_action WHERE workspaceId = ? AND jobId = ?`,
      context.node.workspaceId, jobId,
    );
    const now = Date.now();
    const repairs = [];
    const database = await db();
    if (!artifact) {
      const version = await queryOne<{ version: number }>(
        `SELECT COALESCE(MAX(version), 0) + 1 AS version FROM app_artifact
          WHERE workspaceId = ? AND projectId = ? AND nodeId = ?`,
        context.node.workspaceId, projectId, context.node.id,
      );
      repairs.push(database.prepare(
        `INSERT INTO app_artifact
          (id, workspaceId, deploymentId, projectId, nodeId, commitSha, version,
           state, manifest, checksum, sizeBytes, createdAt, verifiedAt, activatedAt, deletedAt,
           availabilityState, lastVerifiedOnNodeAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'building', ?, NULL, 0, ?, NULL, NULL, NULL, 'unknown', NULL)`,
      ).bind(artifactId, context.node.workspaceId, deploymentId, projectId, context.node.id,
        sourceCommit, version?.version ?? 1, provenanceManifest(claim.contract), now));
    }
    if (!action) {
      repairs.push(database.prepare(
        `INSERT INTO app_deployment_action
          (id, workspaceId, deploymentId, projectId, nodeId, jobId, kind, state,
           idempotencyKey, requestedBy, error, createdAt, updatedAt, completedAt)
         VALUES (?, ?, ?, ?, ?, ?, 'import', 'queued', ?, 'system:artifact-import', NULL, ?, ?, NULL)`,
      ).bind(claim.actionId, context.node.workspaceId, deploymentId, projectId, context.node.id,
        jobId, idempotencyKey, now, now));
    }
    repairs.push(database.prepare(
      `UPDATE node_job
          SET state = 'leased', assignedNodeId = ?, leaseExpiresAt = ?, updatedAt = ?
        WHERE workspaceId = ? AND id = ? AND state = 'queued'`,
    ).bind(context.node.id, now + appRuntimeLeaseDuration('import'), now,
      context.node.workspaceId, jobId));
    await database.batch(repairs);
    return { ok: true, artifactId, contract: claim.contract };
  }

  const reserved = await queryOne<{ id: string; payload: string }>(
    `SELECT id, payload FROM node_job
      WHERE workspaceId = ? AND idempotencyKey = ? AND type = ?`,
    context.node.workspaceId, `app:${idempotencyKey}`, APP_RUNTIME_JOB_TYPE,
  );
  if (reserved) {
    const adopted = await adoptExistingReservation(reserved.id, reserved.payload);
    if (!adopted.ok) return adopted;
    return {
      ok: true, ...settled, replacementArtifactId: adopted.artifactId,
      localPort: row.localPort, contract: adopted.contract, created: false,
    };
  }

  // The runtime shape comes from the last job that succeeded on the *lost*
  // node, because that is the machine this deployment actually ran on. Nothing
  // here invents a resource policy: if that history is gone, the import stops
  // rather than guessing memory, disk, or an environment envelope.
  const history = await query<{ payload: string }>(
    `SELECT j.payload FROM node_job j
       JOIN app_deployment_action a ON a.jobId = j.id AND a.workspaceId = j.workspaceId
      WHERE a.workspaceId = ? AND a.deploymentId = ? AND a.nodeId = ?
        AND j.type = ? AND j.state = 'succeeded'
      ORDER BY j.completedAt DESC LIMIT 10`,
    context.node.workspaceId, deploymentId, row.sourceNodeId, APP_RUNTIME_JOB_TYPE,
  );
  let prior: AppRuntimeJobPayload | null = null;
  for (const item of history) {
    try {
      const candidate = validateAppRuntimeJobPayload(JSON.parse(item.payload));
      if (candidate.ok && candidate.payload.contract &&
          (candidate.payload.artifactId === row.sourceArtifactId ||
           candidate.payload.targetArtifactId === row.sourceArtifactId)) {
        prior = candidate.payload;
        break;
      }
    } catch {
      // Invalid historical payloads are never replayed.
    }
  }
  if (!prior || !prior.contract) {
    return {
      ok: false,
      status: 409,
      error: 'The runtime contract for this artifact is no longer on record, so it cannot be imported.',
    };
  }

  const now = Date.now();
  const replacementArtifactId = reserveArtifactId;
  const actionId = reserveActionId;
  // Queue first. If another request won the race, `created` is false and no
  // artifact row is written at all, so a lost race leaves nothing behind.
  const queued = await enqueueJob({
    workspaceId: context.node.workspaceId,
    actor: 'system:artifact-import',
    type: APP_RUNTIME_JOB_TYPE,
    payload: {
      operation: 'import', deploymentId, projectId: row.projectId, actionId,
      artifactId: replacementArtifactId, targetArtifactId: row.sourceArtifactId,
      source: null, contract: prior.contract,
      environment: row.environment ?? prior.environment,
      environmentCiphertext: await sealNodeEnvironment(context.token, await scopedEnvironment({
        workspaceId: context.node.workspaceId,
        projectId: row.projectId,
        deploymentId,
        environment: (row.environment ?? prior.environment) as AppEnvironment,
        names: prior.contract.envNames,
      })),
      port: row.localPort, healthPath: row.healthPath ?? prior.healthPath,
      memoryMb: prior.memoryMb, diskQuotaBytes: prior.diskQuotaBytes,
      retainArtifacts: APP_RUNTIME_LIMITS.maximumArtifactsPerProject,
      expectedDesiredRevision: row.desiredRevision,
      protectedArtifactIds: [],
    },
    targetNodeId: context.node.id,
    idempotencyKey: `app:${idempotencyKey}`,
  });
  if (!queued.ok) {
    return { ok: false, status: queued.status, error: queued.error };
  }
  if (!queued.created) {
    // Someone reserved it between the lookup above and here. Same repair path:
    // adopt their artifact, never allocate a second one.
    const raced = await queryOne<{ payload: string }>(
      `SELECT payload FROM node_job WHERE workspaceId = ? AND id = ?`,
      context.node.workspaceId, queued.job.id,
    );
    if (!raced) {
      return { ok: false, status: 409, error: 'Another import for this deployment is already reserved.' };
    }
    const adopted = await adoptExistingReservation(queued.job.id, raced.payload);
    if (!adopted.ok) return adopted;
    return {
      ok: true, ...settled, replacementArtifactId: adopted.artifactId,
      localPort: row.localPort, contract: adopted.contract, created: false,
    };
  }

  const next = await queryOne<{ version: number }>(
    `SELECT COALESCE(MAX(version), 0) + 1 AS version FROM app_artifact
      WHERE workspaceId = ? AND projectId = ? AND nodeId = ?`,
    context.node.workspaceId, row.projectId, context.node.id,
  );
  const manifest = provenanceManifest(prior.contract);
  const database = await db();
  await database.batch([
    database.prepare(
      `INSERT INTO app_artifact
        (id, workspaceId, deploymentId, projectId, nodeId, commitSha, version,
         state, manifest, checksum, sizeBytes, createdAt, verifiedAt, activatedAt, deletedAt,
         availabilityState, lastVerifiedOnNodeAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'building', ?, NULL, 0, ?, NULL, NULL, NULL, 'unknown', NULL)`,
    ).bind(replacementArtifactId, context.node.workspaceId, deploymentId, row.projectId,
      context.node.id, row.sourceCommit ?? '', next?.version ?? 1, manifest, now),
    database.prepare(
      `INSERT INTO app_deployment_action
        (id, workspaceId, deploymentId, projectId, nodeId, jobId, kind, state,
         idempotencyKey, requestedBy, error, createdAt, updatedAt, completedAt)
       VALUES (?, ?, ?, ?, ?, ?, 'import', 'queued', ?, 'system:artifact-import', NULL, ?, ?, NULL)`,
    ).bind(actionId, context.node.workspaceId, deploymentId, row.projectId, context.node.id,
      queued.job.id, idempotencyKey, now, now),
    // Held, not offered. No claim signature is written because this work is
    // never handed to an Agent poller -- the operator's CLI is doing it.
    database.prepare(
      `UPDATE node_job
          SET state = 'leased', assignedNodeId = ?, leaseExpiresAt = ?, updatedAt = ?
        WHERE workspaceId = ? AND id = ? AND state = 'queued'`,
    ).bind(context.node.id, now + appRuntimeLeaseDuration('import'), now,
      context.node.workspaceId, queued.job.id),
  ]);
  return {
    ok: true, ...settled, replacementArtifactId,
    localPort: row.localPort, contract: prior.contract, created: true,
  };
}

/**
 * Records that a replacement node has the imported bytes.
 *
 * Every fact is re-read here rather than believed from the request: which node
 * owns the deployment, which artifact is current, what the source checksum is,
 * and what revision the transfer settled on. The node's report is checked
 * against those, never the other way round.
 *
 * The deployment stays blocked afterwards. Bytes existing is not the same as a
 * port being agreed, and Phase 18 must not be handed a deployment whose port
 * could still move underneath it.
 */
export async function confirmArtifactImport(
  context: AgentContext,
  deploymentId: string,
  body: {
    artifactId?: unknown;
    sourceArtifactId?: unknown;
    checksum?: unknown;
    sizeBytes?: unknown;
    expectedDesiredRevision?: unknown;
  },
): Promise<
  | { ok: true; artifactId: string; state: 'verified'; replayed: boolean }
  | { ok: false; status: number; error: string }
> {
  const artifactId = typeof body.artifactId === 'string' ? body.artifactId : '';
  const sourceArtifactId = typeof body.sourceArtifactId === 'string' ? body.sourceArtifactId : '';
  const checksum = typeof body.checksum === 'string' ? body.checksum : '';
  const sizeBytes = typeof body.sizeBytes === 'number' && Number.isSafeInteger(body.sizeBytes) &&
    body.sizeBytes >= 0 ? body.sizeBytes : -1;
  const expectedDesiredRevision = typeof body.expectedDesiredRevision === 'number' &&
    Number.isSafeInteger(body.expectedDesiredRevision) && body.expectedDesiredRevision >= 1
    ? body.expectedDesiredRevision : -1;
  if (
    !/^dpl_[a-f0-9]{24}$/.test(deploymentId) ||
    !/^art_[a-f0-9]{24}$/.test(artifactId) ||
    !/^art_[a-f0-9]{24}$/.test(sourceArtifactId) ||
    !/^sha256:[a-f0-9]{64}$/.test(checksum) ||
    sizeBytes < 0 || expectedDesiredRevision < 0 || artifactId === sourceArtifactId
  ) {
    return { ok: false, status: 400, error: 'Import confirmation is invalid.' };
  }

  const row = await queryOne<{
    projectId: string | null;
    nodeId: string | null;
    currentArtifactId: string | null;
    desiredRevision: number | null;
    recoveryReasonCode: string | null;
    replacementState: string | null;
    replacementNodeId: string | null;
    replacementChecksum: string | null;
    replacementAvailability: string | null;
    sourceState: string | null;
    sourceChecksum: string | null;
    sourceNodeId: string | null;
    sourceRevokedAt: number | null;
  }>(
    `SELECT d.projectId AS projectId, d.nodeId AS nodeId,
            d.currentArtifactId AS currentArtifactId, d.desiredRevision AS desiredRevision,
            d.recoveryReasonCode AS recoveryReasonCode,
            replacement.state AS replacementState, replacement.nodeId AS replacementNodeId,
            replacement.checksum AS replacementChecksum,
            replacement.availabilityState AS replacementAvailability,
            source.state AS sourceState, source.checksum AS sourceChecksum,
            source.nodeId AS sourceNodeId, lost.revokedAt AS sourceRevokedAt
       FROM deployment d
       LEFT JOIN app_artifact replacement ON replacement.id = ? AND replacement.workspaceId = d.workspaceId
        AND replacement.deploymentId = d.id AND replacement.deletedAt IS NULL
       LEFT JOIN app_artifact source ON source.id = ? AND source.workspaceId = d.workspaceId
        AND source.deploymentId = d.id AND source.deletedAt IS NULL
       LEFT JOIN compute_node lost ON lost.id = source.nodeId AND lost.workspaceId = d.workspaceId
      WHERE d.workspaceId = ? AND d.id = ? AND d.nodeId = ? AND d.deletedAt IS NULL`,
    artifactId, sourceArtifactId, context.node.workspaceId, deploymentId, context.node.id,
  );
  if (!row || !row.projectId || row.nodeId !== context.node.id) {
    return { ok: false, status: 404, error: 'Deployment not found for this node.' };
  }
  if (row.desiredRevision !== expectedDesiredRevision) {
    return { ok: false, status: 409, error: 'This deployment moved on; the import is stale.' };
  }
  if (!row.sourceChecksum || row.sourceState !== 'verified' || row.sourceRevokedAt === null ||
      row.sourceNodeId === context.node.id) {
    return { ok: false, status: 409, error: 'The source artifact is not an artifact of a lost node.' };
  }
  if (row.replacementNodeId !== context.node.id) {
    return { ok: false, status: 409, error: 'That replacement artifact does not belong to this node.' };
  }
  // The authorized checksum is the source row's, never the request's.
  if (!constantTimeEqual(checksum, row.sourceChecksum)) {
    return { ok: false, status: 409, error: 'The imported checksum does not match the source artifact.' };
  }


  /**
   * Moves the public exposure onto the node that now holds the bytes.
   *
   * Both target columns move in one statement because they are one fact: the
   * 0011 trigger requires the exposure's node to be the deployment's node *and*
   * the artifact to live on that node, so a half-move -- N2 with A1, or N1 with
   * A2 -- is rejected, correctly. Doing it during the ownership transfer would
   * have been exactly that half-move, which is why it happens here instead,
   * after the artifact exists and while the deployment is still blocked.
   *
   * It does not re-open anything. `declareNodeLost` failed the exposure closed,
   * and nothing durable records what mode it was serving before the machine was
   * lost, so guessing would be inventing a routing decision the operator never
   * made. The exposure stays disabled until a person looks at the recovered
   * application and turns it back on.
   *
   * Safe to repeat: an exposure already pointing at this node and artifact
   * matches nothing and is left alone.
   */
  async function retargetRecoveredExposure(): Promise<boolean> {
    const stale = await query<{ id: string }>(
      `SELECT id FROM public_exposure
        WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL
          AND (targetNodeId IS NOT ? OR targetArtifactId IS NOT ?)`,
      context.node.workspaceId, deploymentId, context.node.id, artifactId,
    );
    if (stale.length === 0) return false;
    const moved = await execute(
      `UPDATE public_exposure
          SET targetNodeId = ?, targetArtifactId = ?, updatedAt = ?
        WHERE workspaceId = ? AND deploymentId = ? AND deletedAt IS NULL
          AND EXISTS (
            SELECT 1 FROM deployment d
             WHERE d.id = ? AND d.workspaceId = public_exposure.workspaceId
               AND d.nodeId = ? AND d.currentArtifactId = ? AND d.desiredRevision = ?
               AND d.deletedAt IS NULL)
          AND EXISTS (
            SELECT 1 FROM app_artifact a
             WHERE a.id = ? AND a.workspaceId = public_exposure.workspaceId
               AND a.deploymentId = public_exposure.deploymentId AND a.nodeId = ?
               AND a.state = 'verified' AND a.availabilityState = 'present'
               AND a.deletedAt IS NULL)`,
      context.node.id, artifactId, Date.now(),
      context.node.workspaceId, deploymentId,
      deploymentId, context.node.id, artifactId, expectedDesiredRevision,
      artifactId, context.node.id,
    );
    return changed(moved);
  }

  const now = Date.now();
  // A replay arrives with everything already true. Recognising it is not a
  // convenience: an agent that installed the bytes and then lost the response
  // has to be able to say so again without being told it is wrong.
  if (row.replacementState === 'verified' && row.currentArtifactId === artifactId) {
    if (!row.replacementChecksum || !constantTimeEqual(row.replacementChecksum, row.sourceChecksum)) {
      return { ok: false, status: 409, error: 'A different artifact is already recorded under that id.' };
    }
    if (row.replacementNodeId !== context.node.id) {
      return { ok: false, status: 409, error: 'That replacement artifact does not belong to this node.' };
    }
    // The durable record of the import itself, which no later runtime attempt
    // rewrites. Without it this path would let an artifact that never completed
    // an import claim to be a replay of one.
    const completed = await queryOne<{ ok: number }>(
      `SELECT 1 AS ok FROM app_deployment_action a
         JOIN node_job j ON j.id = a.jobId AND j.workspaceId = a.workspaceId
        WHERE a.workspaceId = ? AND a.deploymentId = ? AND a.nodeId = ? AND a.kind = 'import'
          AND a.state = 'succeeded' AND j.state = 'succeeded'`,
      context.node.workspaceId, deploymentId, context.node.id,
    );
    if (!completed) {
      return { ok: false, status: 409, error: 'No completed import is recorded for this deployment.' };
    }
    // Finish what a dead request may have left half done, then report the
    // replay honestly. Availability is read, never written, here.
    await retargetRecoveredExposure();
    return { ok: true, artifactId, state: 'verified', replayed: true };
  }
  if (row.replacementState !== 'building') {
    return { ok: false, status: 409, error: 'That replacement artifact is not awaiting import.' };
  }
  if (row.currentArtifactId !== sourceArtifactId) {
    return { ok: false, status: 409, error: 'This deployment is not awaiting this import.' };
  }

  const verified = await execute(
    `UPDATE app_artifact
        SET state = 'verified', checksum = ?, sizeBytes = ?, verifiedAt = ?,
            availabilityState = 'present', lastVerifiedOnNodeAt = ?
      WHERE workspaceId = ? AND id = ? AND deploymentId = ? AND nodeId = ?
        AND state = 'building' AND deletedAt IS NULL`,
    row.sourceChecksum, sizeBytes, now, now,
    context.node.workspaceId, artifactId, deploymentId, context.node.id,
  );
  if (!changed(verified)) {
    return { ok: false, status: 409, error: 'That replacement artifact is not awaiting import.' };
  }
  // Only now does the deployment point at the imported copy -- and it stays
  // blocked, because the port has not been agreed yet.
  const flipped = await execute(
    `UPDATE deployment
        SET currentArtifactId = ?, updatedAt = ?
      WHERE workspaceId = ? AND id = ? AND nodeId = ? AND deletedAt IS NULL
        AND desiredRevision = ? AND currentArtifactId = ?`,
    artifactId, now, context.node.workspaceId, deploymentId, context.node.id,
    expectedDesiredRevision, sourceArtifactId,
  );
  if (!changed(flipped)) {
    return { ok: false, status: 409, error: 'This deployment changed while the import was being recorded.' };
  }

  await retargetRecoveredExposure();

  // Only now, with the bytes verified and current, does the reservation become
  // a succeeded record. Marking it earlier would claim an import that had not
  // happened; leaving it held would strand recovery, because Phase 18 rebuilds
  // a deployment's runtime shape from the succeeded history on its own node.
  const database = await db();
  await database.batch([
    database.prepare(
      `UPDATE node_job
          SET state = 'succeeded', leaseExpiresAt = NULL, completedAt = ?, updatedAt = ?
        WHERE workspaceId = ? AND id = (
          SELECT jobId FROM app_deployment_action
           WHERE workspaceId = ? AND deploymentId = ? AND nodeId = ? AND kind = 'import'
           ORDER BY createdAt DESC LIMIT 1)
          AND state = 'leased'`,
    ).bind(now, now, context.node.workspaceId, context.node.workspaceId, deploymentId,
      context.node.id),
    database.prepare(
      `UPDATE app_deployment_action
          SET state = 'succeeded', completedAt = ?, updatedAt = ?
        WHERE workspaceId = ? AND deploymentId = ? AND nodeId = ? AND kind = 'import'
          AND state = 'queued'`,
    ).bind(now, now, context.node.workspaceId, deploymentId, context.node.id),
  ]);

  const tenant = await queryOne<{ organizationId: string | null }>(
    'SELECT organizationId FROM workspace WHERE id = ?', context.node.workspaceId,
  );
  if (tenant?.organizationId) {
    await recordEvidence({
      organizationId: tenant.organizationId,
      workspaceId: context.node.workspaceId,
      actorType: 'system',
      actorId: 'system:artifact-import',
      action: 'deployment.artifact_import',
      resourceId: deploymentId,
      outcome: 'success',
      metadata: {
        artifactId,
        sourceArtifactId,
        sourceNodeId: row.sourceNodeId ?? '',
        nodeId: context.node.id,
        desiredRevision: expectedDesiredRevision,
      },
    });
  }
  return { ok: true, artifactId, state: 'verified', replayed: false };
}

/**
 * Retires the `awaiting_import` block once, and only once, everything it stands
 * for is actually true.
 *
 * This starts nothing. It removes the reason Phase 18 was refusing to look at
 * this deployment, and leaves the rest to ordinary reconciliation -- which is
 * the whole point: the operator never issues a Start.
 */
export async function clearReplacementImportBlock(
  context: AgentContext,
  deploymentId: string,
): Promise<
  | { ok: true; cleared: boolean; desiredState: string; localPort: number }
  | { ok: false; status: number; error: string }
> {
  if (!/^dpl_[a-f0-9]{24}$/.test(deploymentId)) {
    return { ok: false, status: 400, error: 'Import completion request is invalid.' };
  }
  const row = await queryOne<{
    desiredState: string | null;
    localPort: number | null;
    recoveryStatus: string | null;
    recoveryReasonCode: string | null;
    artifactState: string | null;
    artifactNodeId: string | null;
    availabilityState: string | null;
  }>(
    `SELECT d.desiredState AS desiredState, d.localPort AS localPort,
            d.recoveryStatus AS recoveryStatus, d.recoveryReasonCode AS recoveryReasonCode,
            a.state AS artifactState, a.nodeId AS artifactNodeId,
            a.availabilityState AS availabilityState
       FROM deployment d
       LEFT JOIN app_artifact a ON a.id = d.currentArtifactId AND a.workspaceId = d.workspaceId
        AND a.deletedAt IS NULL
      WHERE d.workspaceId = ? AND d.id = ? AND d.nodeId = ? AND d.deletedAt IS NULL`,
    context.node.workspaceId, deploymentId, context.node.id,
  );
  if (!row) return { ok: false, status: 404, error: 'Deployment not found for this node.' };
  if (row.recoveryStatus === null) {
    return { ok: true, cleared: false, desiredState: row.desiredState ?? 'running', localPort: row.localPort ?? 0 };
  }
  if (row.artifactState !== 'verified' || row.artifactNodeId !== context.node.id ||
      row.availabilityState !== 'present' || row.localPort === null) {
    return { ok: false, status: 409, error: 'The imported artifact and private port are not settled yet.' };
  }
  const cleared = await execute(
    `UPDATE deployment
        SET state = 'stopped', observedState = 'stopped', recoveryStatus = NULL,
            recoveryReasonCode = NULL, recoveryGeneration = NULL, lastError = NULL,
            updatedAt = ?
      WHERE workspaceId = ? AND id = ? AND nodeId = ? AND deletedAt IS NULL
        AND recoveryStatus IS NOT NULL`,
    Date.now(), context.node.workspaceId, deploymentId, context.node.id,
  );
  return {
    ok: true,
    cleared: changed(cleared),
    desiredState: row.desiredState ?? 'running',
    localPort: row.localPort,
  };
}


/**
 * Everything the replacement-recovery screen needs, read once.
 *
 * "Lost" is not a status a node carries -- `revokedAt` is set by ordinary
 * revocation too, and conflating them would tell an operator their revoked node
 * is unrecoverable when it is merely revoked. The narrowest truthful evidence
 * already in the database is a deployment still reporting `node_lost`, so that
 * is what this reads, and nothing else claims it.
 */
export async function readReplacementRecoveryState(
  workspaceId: string,
  allowedProjectIds: readonly string[] | null,
): Promise<{
  lostNodeIds: string[];
  deployments: {
    id: string;
    name: string;
    nodeId: string | null;
    nodeName: string | null;
    desiredState: 'running' | 'stopped';
    recoveryReasonCode: string | null;
    observedState: string | null;
    health: string | null;
    desiredRevision: number;
    currentArtifactId: string | null;
    artifactChecksum: string | null;
    localPort: number | null;
  }[];
  candidates: {
    id: string;
    name: string;
    agentVersion: string;
    status: 'online' | 'stale' | 'offline' | 'revoked';
    assignmentsDisabled: boolean;
    replacementImport: boolean;
  }[];
}> {
  const rows = await query<{
    id: string;
    repository: string;
    nodeId: string | null;
    nodeName: string | null;
    desiredState: string | null;
    recoveryReasonCode: string | null;
    observedState: string | null;
    state: string | null;
    desiredRevision: number | null;
    currentArtifactId: string | null;
    artifactChecksum: string | null;
    localPort: number | null;
    projectId: string | null;
  }>(
    `SELECT d.id AS id, d.repository AS repository, d.nodeId AS nodeId, n.name AS nodeName,
            d.desiredState AS desiredState, d.recoveryReasonCode AS recoveryReasonCode,
            d.observedState AS observedState, d.state AS state,
            d.desiredRevision AS desiredRevision, d.currentArtifactId AS currentArtifactId,
            a.checksum AS artifactChecksum, d.localPort AS localPort, d.projectId AS projectId
       FROM deployment d
       LEFT JOIN compute_node n ON n.id = d.nodeId AND n.workspaceId = d.workspaceId
       LEFT JOIN app_artifact a ON a.id = d.currentArtifactId AND a.workspaceId = d.workspaceId
      WHERE d.workspaceId = ? AND d.deletedAt IS NULL
        AND d.recoveryReasonCode IN ('node_lost','awaiting_import')
      ORDER BY d.updatedAt DESC LIMIT 25`,
    workspaceId,
  );
  const visible = rows.filter((row) =>
    allowedProjectIds === null || (row.projectId !== null && allowedProjectIds.includes(row.projectId)));

  const nodes = await query<{
    id: string; name: string; agentVersion: string; capabilities: string;
    revokedAt: number | null; lastHeartbeatAt: number | null; assignmentsDisabledAt: number | null;
  }>(
    `SELECT id, name, agentVersion, capabilities, revokedAt, lastHeartbeatAt, assignmentsDisabledAt
       FROM compute_node WHERE workspaceId = ? ORDER BY createdAt DESC LIMIT 100`,
    workspaceId,
  );
  const now = Date.now();
  return {
    // Only a deployment that still says `node_lost` proves a declared loss.
    lostNodeIds: [...new Set(
      visible.filter((row) => row.recoveryReasonCode === 'node_lost' && row.nodeId)
        .map((row) => row.nodeId!),
    )],
    deployments: visible.map((row) => ({
      id: row.id,
      name: row.repository,
      nodeId: row.nodeId,
      nodeName: row.nodeName,
      desiredState: row.desiredState === 'stopped' ? 'stopped' as const : 'running' as const,
      recoveryReasonCode: row.recoveryReasonCode,
      observedState: row.observedState,
      health: row.state === 'healthy' ? 'healthy' : null,
      desiredRevision: row.desiredRevision ?? 1,
      currentArtifactId: row.currentArtifactId,
      artifactChecksum: row.artifactChecksum,
      localPort: row.localPort,
    })),
    candidates: nodes.map((node) => ({
      id: node.id,
      name: node.name,
      agentVersion: node.agentVersion,
      status: deriveNodeStatus({
        revokedAt: node.revokedAt, lastHeartbeatAt: node.lastHeartbeatAt, now,
      }),
      assignmentsDisabled: node.assignmentsDisabledAt !== null,
      replacementImport:
        capabilitiesFromRow(node.capabilities).artifactBackup?.replacementImport === true,
    })),
  };
}

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
} from '@/lib/app-runtime';
import {
  CURRENT_AGENT_VERSION,
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
import { db, execute, query, queryOne } from './db';
import { clientAddress, enforceRateLimit } from './rate-limit';
import { writeLog } from './logs';
import { assertResourceCapacity } from './organization-limits';
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
  const rows = await query<{ id: string }>(
    `SELECT id FROM game_server
     WHERE workspaceId = ? AND nodeId = ? AND deletedAt IS NULL`,
    input.workspaceId,
    input.nodeId,
  );
  const known = new Set(rows.map((row) => row.id));
  const database = await db();
  const statements: D1PreparedStatement[] = [];
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
    if (!known.has(snapshot.serverId)) {
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
  await pruneGameServerLogs(input.workspaceId, input.nodeId, input.now);
  return true;
}

export async function recordHeartbeat(input: {
  context: AgentContext;
  capabilities: unknown;
  metrics: unknown;
  agentVersion: unknown;
  gameServers?: unknown;
  appDeployments?: unknown;
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
  await pruneNodeHistory(input.context.node.id, now);
  return { ok: true, status: 'online', serverTime: now };
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
      createdAt, updatedAt, completedAt)
     VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?, NULL, NULL, NULL, 0, ?, NULL,
             NULL, NULL, ?, ?, ?, NULL)`,
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
         SET state = 'node_revoked',
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

import {
  AI_LIMITS,
  AI_MODEL_STATES,
  AI_RUNTIMES,
  aiModelCached,
  aiRuntimeAvailable,
  approvedAiModel,
  containsNetworkOrExecutionAbuse,
  estimateTokens,
  validateAiJobPayload,
  type AiModelState,
  type AiRuntime,
} from '@/lib/ai';
import { createId } from '@/lib/crypto';
import type {
  AiModel,
  AiModelCache,
  AiRun,
  AiState,
  ComputeNode,
  NodeJob,
} from '@/lib/domain';
import {
  agentVersionSupported,
} from '@/lib/nodes';
import { db, execute, query, queryOne } from './db';
import { writeLog } from './logs';
import {
  enqueueJob,
  ensureAiCatalog,
  readNodesState,
} from './nodes';
import { getWorkspace } from './workspace';

type ModelRow = {
  id: string;
  workspaceId: string;
  catalogId: string;
  displayName: string;
  runtime: AiRuntime;
  family: string;
  runtimeModel: string;
  source: 'ollama-library' | 'local-runtime';
  sizeBytes: number;
  expectedMemoryBytes: number;
  requiredVramBytes: number;
  checksum: string | null;
  enabled: number;
  state: AiModelState;
  lastVerifiedAt: number | null;
  lastUsedAt: number | null;
  createdAt: number;
  updatedAt: number;
};

type CacheRow = {
  workspaceId: string;
  nodeId: string;
  nodeName: string;
  modelId: string;
  state: AiModelState;
  sizeBytes: number;
  checksum: string | null;
  error: string | null;
  lastVerifiedAt: number | null;
  lastUsedAt: number | null;
  updatedAt: number;
};

type RunRow = {
  jobId: string;
  workspaceId: string;
  modelId: string;
  modelName: string;
  runtime: AiRuntime;
  requestedNodeId: string | null;
  selectedNodeId: string | null;
  selectedNodeName: string | null;
  promptCharacters: number;
  systemPromptCharacters: number;
  maxTokens: number;
  temperature: number;
  responseFormat: 'text' | 'json';
  inputTokensEstimate: number | null;
  outputTokensEstimate: number | null;
  latencyMs: number | null;
  cancelRequestedAt: number | null;
  state: NodeJob['state'];
  attempts: number;
  result: string | null;
  lastError: string | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = new Set(allowed);
  return Object.keys(value).every((key) => keys.has(key));
}

function safeResult(value: string | null): Record<string, unknown> | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function validModelState(value: string): value is AiModelState {
  return (AI_MODEL_STATES as readonly string[]).includes(value);
}

function derivedModelState(
  row: ModelRow,
  caches: AiModelCache[],
): AiModelState {
  if (!row.enabled) return 'disabled';
  if (caches.some((cache) => cache.state === 'ready')) return 'ready';
  if (caches.some((cache) => cache.state === 'downloading')) return 'downloading';
  if (caches.some((cache) => cache.state === 'available')) return 'available';
  if (caches.some((cache) => cache.state === 'error')) return 'error';
  return 'unavailable';
}

async function recordAiSecurityEvent(input: {
  workspaceId: string;
  nodeId?: string | null;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}): Promise<void> {
  await execute(
    `INSERT INTO node_security_event
     (id, workspaceId, nodeId, type, severity, detail, networkFingerprint, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
    createId('nsec'),
    input.workspaceId,
    input.nodeId ?? null,
    input.type,
    input.severity,
    input.detail.slice(0, 500),
    Date.now(),
  );
}

function toRun(row: RunRow): AiRun {
  return {
    jobId: row.jobId,
    modelId: row.modelId,
    modelName: row.modelName,
    runtime: row.runtime,
    state: row.state,
    requestedNodeId: row.requestedNodeId,
    selectedNodeId: row.selectedNodeId,
    selectedNodeName: row.selectedNodeName,
    promptCharacters: row.promptCharacters,
    systemPromptCharacters: row.systemPromptCharacters,
    maxTokens: row.maxTokens,
    responseFormat: row.responseFormat,
    inputTokensEstimate: row.inputTokensEstimate,
    outputTokensEstimate: row.outputTokensEstimate,
    latencyMs: row.latencyMs,
    attempts: row.attempts,
    result: safeResult(row.result),
    lastError: row.lastError,
    cancelRequestedAt: row.cancelRequestedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    completedAt: row.completedAt,
  };
}

export async function readAiState(
  workspaceId: string,
  now = Date.now(),
): Promise<AiState> {
  await ensureAiCatalog(workspaceId, now);
  const [nodesState, modelRows, cacheRows, runRows] = await Promise.all([
    readNodesState(workspaceId, now),
    query<ModelRow>(
      `SELECT * FROM ai_model WHERE workspaceId = ? ORDER BY createdAt ASC`,
      workspaceId,
    ),
    query<CacheRow>(
      `SELECT c.*, n.name AS nodeName
       FROM ai_model_cache c JOIN compute_node n ON n.id = c.nodeId
       WHERE c.workspaceId = ? ORDER BY c.updatedAt DESC`,
      workspaceId,
    ),
    query<RunRow>(
      `SELECT i.*, m.displayName AS modelName, m.runtime,
              n.name AS selectedNodeName, j.state, j.attempts, j.result,
              j.lastError, j.completedAt
       FROM ai_inference i
       JOIN ai_model m ON m.id = i.modelId AND m.workspaceId = i.workspaceId
       JOIN node_job j ON j.id = i.jobId AND j.workspaceId = i.workspaceId
       LEFT JOIN compute_node n ON n.id = i.selectedNodeId
       WHERE i.workspaceId = ? ORDER BY i.createdAt DESC LIMIT 100`,
      workspaceId,
    ),
  ]);
  const aiNodes = nodesState.nodes.filter(
    (node) =>
      node.capabilities.contracts.ai ||
      node.capabilities.ai.runtimes.some((runtime) => runtime.available),
  );
  const models: AiModel[] = modelRows.map((row) => {
    const catalog = approvedAiModel(row.catalogId);
    const caches: AiModelCache[] = cacheRows
      .filter((cache) => cache.modelId === row.id)
      .map((cache) => ({
        nodeId: cache.nodeId,
        nodeName: cache.nodeName,
        state: validModelState(cache.state) ? cache.state : 'error',
        sizeBytes: cache.sizeBytes,
        checksum: cache.checksum,
        error: cache.error,
        lastVerifiedAt: cache.lastVerifiedAt,
        lastUsedAt: cache.lastUsedAt,
      }));
    return {
      id: row.id,
      catalogId: row.catalogId,
      displayName: row.displayName,
      runtime: row.runtime,
      family: row.family,
      runtimeModel: row.runtimeModel,
      source: row.source,
      sizeBytes: row.sizeBytes,
      expectedMemoryBytes: row.expectedMemoryBytes,
      requiredVramBytes: row.requiredVramBytes,
      checksum: row.checksum,
      downloadable: catalog?.downloadable ?? false,
      enabled: Boolean(row.enabled),
      state: derivedModelState(row, caches),
      caches,
      lastVerifiedAt: row.lastVerifiedAt,
      lastUsedAt: row.lastUsedAt,
    };
  });
  const runs = runRows.map(toRun);
  const finishedLatencies = runs
    .map((run) => run.latencyMs)
    .filter((latency): latency is number => latency !== null);
  return {
    nodes: aiNodes,
    models,
    runs,
    summary: {
      aiCapableNodes: aiNodes.length,
      onlineNodes: aiNodes.filter((node) => node.status === 'online').length,
      readyModels: models.filter((model) => model.state === 'ready').length,
      queued: runs.filter((run) => run.state === 'queued').length,
      running: runs.filter(
        (run) => run.state === 'leased' || run.state === 'cancelling',
      ).length,
      completed: runs.filter((run) => run.state === 'succeeded').length,
      failed: runs.filter(
        (run) => run.state === 'failed' || run.state === 'timed_out',
      ).length,
      cancelled: runs.filter((run) => run.state === 'cancelled').length,
      averageLatencyMs:
        finishedLatencies.length === 0
          ? null
          : Math.round(
              finishedLatencies.reduce((total, value) => total + value, 0) /
                finishedLatencies.length,
            ),
    },
    supportedRuntimes: AI_RUNTIMES,
    localOnly: true,
    zeroModeEnforced: true,
    projectedMonthlyCost: 0,
  };
}

type EligibleNode = {
  node: ComputeNode;
  score: number;
};

async function selectInferenceNode(input: {
  workspaceId: string;
  model: ModelRow;
  requestedNodeId: string | null;
  now: number;
}): Promise<EligibleNode | null> {
  const state = await readAiState(input.workspaceId, input.now);
  const model = state.models.find((entry) => entry.id === input.model.id);
  if (!model) return null;
  const activeRows = await query<{ assignedNodeId: string; total: number }>(
    `SELECT assignedNodeId, COUNT(*) AS total FROM node_job
     WHERE workspaceId = ? AND type = 'ai.inference'
       AND state IN ('leased','cancelling') AND assignedNodeId IS NOT NULL
     GROUP BY assignedNodeId`,
    input.workspaceId,
  );
  const active = new Map(activeRows.map((row) => [row.assignedNodeId, row.total]));
  const candidates: EligibleNode[] = [];
  for (const node of state.nodes) {
    if (input.requestedNodeId && node.id !== input.requestedNodeId) continue;
    const cached = model.caches.some(
      (cache) => cache.nodeId === node.id && cache.state === 'ready',
    );
    if (
      node.status !== 'online' ||
      !agentVersionSupported(node.agentVersion) ||
      !aiRuntimeAvailable(node.capabilities.ai, model.runtime) ||
      !cached ||
      !aiModelCached(
        node.capabilities.ai,
        model.runtime,
        model.runtimeModel,
      ) ||
      node.capabilities.memory.freeBytes < model.expectedMemoryBytes ||
      (model.requiredVramBytes > 0 &&
        (!node.capabilities.gpu.available ||
          (node.capabilities.gpu.vramBytes ?? 0) < model.requiredVramBytes)) ||
      (node.metrics?.cpuLoadPercent ?? 0) >= 90 ||
      (active.get(node.id) ?? 0) >= node.capabilities.ai.maxConcurrentJobs
    ) {
      continue;
    }
    const cacheBonus = 10_000;
    const gpuBonus = node.capabilities.gpu.available ? 1_000 : 0;
    const memoryGiB = Math.floor(node.capabilities.memory.freeBytes / 1024 ** 3);
    const loadPenalty = Math.round(node.metrics?.cpuLoadPercent ?? 0);
    candidates.push({
      node,
      score: cacheBonus + gpuBonus + memoryGiB * 10 - loadPenalty,
    });
  }
  return candidates.sort((left, right) => right.score - left.score)[0] ?? null;
}

export async function queueAiInference(input: {
  workspaceId: string;
  actor: string;
  body: unknown;
  idempotencyKey: string | null;
}): Promise<
  | { ok: true; run: AiRun; created: boolean }
  | { ok: false; status: number; error: string }
> {
  if (!isRecord(input.body)) {
    return { ok: false, status: 400, error: 'Inference request must be an object.' };
  }
  const allowed = [
    'modelId',
    'targetNodeId',
    'prompt',
    'systemPrompt',
    'maxTokens',
    'temperature',
    'responseFormat',
    'timeoutMs',
    'provider',
    'zeroMode',
  ];
  if (!onlyKeys(input.body, allowed) || containsNetworkOrExecutionAbuse(input.body)) {
    await recordAiSecurityEvent({
      workspaceId: input.workspaceId,
      type: containsNetworkOrExecutionAbuse(input.body)
        ? 'ai-payload-abuse'
        : 'ai-malformed-payload',
      severity: 'high',
      detail: 'An inference request contained a forbidden network, path, execution, or unknown field.',
    });
    return { ok: false, status: 400, error: 'Inference payload contains forbidden fields or network targets.' };
  }
  if (
    (input.body.provider !== undefined && input.body.provider !== 'local-node') ||
    (input.body.zeroMode !== undefined && input.body.zeroMode !== true)
  ) {
    await recordAiSecurityEvent({
      workspaceId: input.workspaceId,
      type: 'ai-forbidden-provider',
      severity: 'critical',
      detail: 'A client attempted to bypass local-only Zero Mode AI execution.',
    });
    return { ok: false, status: 400, error: 'AI execution is local-node and Zero Mode only.' };
  }
  const workspace = await getWorkspace(input.workspaceId);
  if (!workspace?.zeroMode) {
    return {
      ok: false,
      status: 409,
      error: 'AI Compute requires Zero Mode to be enabled server-side.',
    };
  }
  const modelId = typeof input.body.modelId === 'string' ? input.body.modelId : '';
  const model = await queryOne<ModelRow>(
    'SELECT * FROM ai_model WHERE workspaceId = ? AND id = ? AND enabled = 1',
    input.workspaceId,
    modelId,
  );
  if (!model || !approvedAiModel(model.catalogId)) {
    return { ok: false, status: 404, error: 'Approved model not found.' };
  }
  const prompt = typeof input.body.prompt === 'string' ? input.body.prompt : '';
  const systemPrompt =
    input.body.systemPrompt === undefined || input.body.systemPrompt === ''
      ? null
      : input.body.systemPrompt;
  const maxTokens = input.body.maxTokens ?? 512;
  const temperature = input.body.temperature ?? 0.7;
  const responseFormat = input.body.responseFormat ?? 'text';
  const timeoutMs = input.body.timeoutMs ?? 120_000;
  const targetNodeId =
    typeof input.body.targetNodeId === 'string' && input.body.targetNodeId
      ? input.body.targetNodeId
      : null;
  const candidateContract = {
    modelId: model.catalogId,
    runtime: model.runtime,
    runtimeModel: model.runtimeModel,
    prompt,
    systemPrompt,
    maxTokens,
    temperature,
    responseFormat,
    timeoutMs,
    provider: 'local-node',
    zeroMode: true,
    expectedMemoryBytes: model.expectedMemoryBytes,
    requiredVramBytes: model.requiredVramBytes,
  };
  const validatedContract = validateAiJobPayload(
    'ai.inference',
    candidateContract,
  );
  if (!validatedContract.ok || !('prompt' in validatedContract.payload)) {
    await recordAiSecurityEvent({
      workspaceId: input.workspaceId,
      type: 'ai-malformed-payload',
      severity: 'high',
      detail: validatedContract.ok
        ? 'An inference contract could not be narrowed safely.'
        : validatedContract.error,
    });
    return {
      ok: false,
      status: 400,
      error: validatedContract.ok
        ? 'Inference payload is invalid.'
        : validatedContract.error,
    };
  }
  const contract = validatedContract.payload;
  const selected = await selectInferenceNode({
    workspaceId: input.workspaceId,
    model,
    requestedNodeId: targetNodeId,
    now: Date.now(),
  });
  if (!selected) {
    return {
      ok: false,
      status: 409,
      error:
        'No online local node has the runtime, cached model, free memory, and concurrency capacity required for this inference.',
    };
  }
  const idempotencyKey = input.idempotencyKey?.trim().slice(0, 100) || createId('idem');
  const queued = await enqueueJob({
    workspaceId: input.workspaceId,
    actor: input.actor,
    type: 'ai.inference',
    payload: contract,
    targetNodeId: selected.node.id,
    idempotencyKey: `ai:${idempotencyKey}`,
  });
  if (!queued.ok) return queued;
  const now = Date.now();
  if (queued.created) {
    await execute(
      `INSERT INTO ai_inference
       (jobId, workspaceId, modelId, requestedNodeId, selectedNodeId, provider,
        zeroMode, promptCharacters, systemPromptCharacters, maxTokens,
        temperature, responseFormat, inputTokensEstimate, outputTokensEstimate,
        latencyMs, cancelRequestedAt, cancelledBy, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, 'local-node', 1, ?, ?, ?, ?, ?, ?, NULL, NULL,
               NULL, NULL, ?, ?)`,
      queued.job.id,
      input.workspaceId,
      model.id,
      targetNodeId,
      selected.node.id,
      prompt.length,
      typeof systemPrompt === 'string' ? systemPrompt.length : 0,
      maxTokens,
      temperature,
      responseFormat,
      estimateTokens(`${typeof systemPrompt === 'string' ? systemPrompt : ''}\n${prompt}`),
      now,
      now,
    );
    await writeLog({
      workspaceId: input.workspaceId,
      source: 'ai',
      message: `Queued local ${model.displayName} inference on ${selected.node.name}`,
      actor: input.actor,
      resource: queued.job.id,
    });
  }
  const row = await queryOne<RunRow>(
    `SELECT i.*, m.displayName AS modelName, m.runtime,
            n.name AS selectedNodeName, j.state, j.attempts, j.result,
            j.lastError, j.completedAt
     FROM ai_inference i
     JOIN ai_model m ON m.id = i.modelId AND m.workspaceId = i.workspaceId
     JOIN node_job j ON j.id = i.jobId AND j.workspaceId = i.workspaceId
     LEFT JOIN compute_node n ON n.id = i.selectedNodeId
     WHERE i.workspaceId = ? AND i.jobId = ?`,
    input.workspaceId,
    queued.job.id,
  );
  if (!row) return { ok: false, status: 500, error: 'Inference metadata was not created.' };
  return { ok: true, run: toRun(row), created: queued.created };
}

export async function queueModelCache(input: {
  workspaceId: string;
  actor: string;
  modelId: string;
  nodeId: unknown;
  approved: unknown;
  idempotencyKey: string | null;
}): Promise<
  | { ok: true; job: NodeJob; created: boolean }
  | { ok: false; status: number; error: string }
> {
  if (input.approved !== true || typeof input.nodeId !== 'string') {
    return { ok: false, status: 400, error: 'Explicit model download approval and a node are required.' };
  }
  const model = await queryOne<ModelRow>(
    'SELECT * FROM ai_model WHERE workspaceId = ? AND id = ? AND enabled = 1',
    input.workspaceId,
    input.modelId,
  );
  const catalog = model ? approvedAiModel(model.catalogId) : null;
  if (!model || !catalog || !catalog.downloadable || catalog.runtime !== 'ollama') {
    return { ok: false, status: 409, error: 'This model cannot be downloaded by the reviewed agent.' };
  }
  if (model.sizeBytes > AI_LIMITS.maximumModelBytes) {
    await recordAiSecurityEvent({
      workspaceId: input.workspaceId,
      nodeId: input.nodeId,
      type: 'ai-oversized-model',
      severity: 'high',
      detail: 'A model exceeded the local Zero Mode size ceiling.',
    });
    return { ok: false, status: 409, error: 'Model exceeds the safe local size limit.' };
  }
  const state = await readAiState(input.workspaceId);
  const node = state.nodes.find((entry) => entry.id === input.nodeId);
  if (!node || node.status === 'revoked') {
    return { ok: false, status: 404, error: 'Target AI node not found.' };
  }
  if (
    node.status !== 'online' ||
    !aiRuntimeAvailable(node.capabilities.ai, 'ollama')
  ) {
    return { ok: false, status: 409, error: 'The node must be online with Ollama already installed.' };
  }
  if (
    node.capabilities.disk.freeBytes <
    model.sizeBytes + AI_LIMITS.diskReserveBytes
  ) {
    await recordAiSecurityEvent({
      workspaceId: input.workspaceId,
      nodeId: node.id,
      type: 'ai-insufficient-disk',
      severity: 'medium',
      detail: 'Model acquisition was refused because free disk was below the model plus reserve.',
    });
    return { ok: false, status: 409, error: 'The node does not have enough free disk plus the safety reserve.' };
  }
  const candidateContract = {
    modelId: model.catalogId,
    runtime: 'ollama',
    runtimeModel: model.runtimeModel,
    source: 'ollama-library',
    expectedSizeBytes: model.sizeBytes,
    checksum: model.checksum,
  };
  const validatedContract = validateAiJobPayload(
    'ai.model.acquire',
    candidateContract,
  );
  if (!validatedContract.ok || !('expectedSizeBytes' in validatedContract.payload)) {
    await recordAiSecurityEvent({
      workspaceId: input.workspaceId,
      nodeId: node.id,
      type: 'ai-model-path-abuse',
      severity: 'high',
      detail: validatedContract.ok
        ? 'A model acquisition contract could not be narrowed safely.'
        : validatedContract.error,
    });
    return {
      ok: false,
      status: 400,
      error: validatedContract.ok
        ? 'Model acquisition is invalid.'
        : validatedContract.error,
    };
  }
  const contract = validatedContract.payload;
  const key = input.idempotencyKey?.trim().slice(0, 80) || createId('idem');
  const queued = await enqueueJob({
    workspaceId: input.workspaceId,
    actor: input.actor,
    type: 'ai.model.acquire',
    payload: contract,
    targetNodeId: node.id,
    idempotencyKey: `ai-cache:${model.catalogId}:${node.id}:${key}`,
  });
  if (!queued.ok) return queued;
  if (queued.created) {
    const now = Date.now();
    await execute(
      `INSERT INTO ai_model_cache
       (workspaceId, nodeId, modelId, state, sizeBytes, checksum, error,
        lastVerifiedAt, lastUsedAt, updatedAt)
       VALUES (?, ?, ?, 'downloading', 0, NULL, NULL, NULL, NULL, ?)
       ON CONFLICT(nodeId, modelId) DO UPDATE SET
         state = 'downloading', error = NULL, updatedAt = excluded.updatedAt`,
      input.workspaceId,
      node.id,
      model.id,
      now,
    );
    await writeLog({
      workspaceId: input.workspaceId,
      source: 'ai',
      message: `Approved ${model.displayName} cache acquisition on ${node.name}`,
      actor: input.actor,
      resource: queued.job.id,
    });
  }
  return { ok: true, job: queued.job, created: queued.created };
}

export async function cancelAiInference(input: {
  workspaceId: string;
  jobId: string;
  actor: string;
}): Promise<
  | { ok: true; state: NodeJob['state']; duplicate: boolean }
  | { ok: false; status: number; error: string }
> {
  const run = await queryOne<{ state: NodeJob['state'] }>(
    `SELECT j.state FROM ai_inference i
     JOIN node_job j ON j.id = i.jobId AND j.workspaceId = i.workspaceId
     WHERE i.workspaceId = ? AND i.jobId = ?`,
    input.workspaceId,
    input.jobId,
  );
  if (!run) return { ok: false, status: 404, error: 'Inference job not found.' };
  if (run.state === 'cancelled' || run.state === 'cancelling') {
    return { ok: true, state: run.state, duplicate: true };
  }
  if (run.state !== 'queued' && run.state !== 'leased') {
    return { ok: false, status: 409, error: `A ${run.state} inference cannot be cancelled.` };
  }
  const now = Date.now();
  const nextState = run.state === 'queued' ? 'cancelled' : 'cancelling';
  const database = await db();
  const results = await database.batch([
    database
      .prepare(
        `UPDATE node_job SET state = ?, lastError = ?,
           completedAt = CASE WHEN ? = 'cancelled' THEN ? ELSE NULL END,
           updatedAt = ?
         WHERE workspaceId = ? AND id = ? AND state = ?`,
      )
      .bind(
        nextState,
        nextState === 'cancelled'
          ? 'Cancelled before claim.'
          : 'Cancellation requested.',
        nextState,
        now,
        now,
        input.workspaceId,
        input.jobId,
        run.state,
      ),
    database
      .prepare(
        `UPDATE ai_inference SET cancelRequestedAt = ?, cancelledBy = ?, updatedAt = ?
         WHERE workspaceId = ? AND jobId = ?`,
      )
      .bind(now, input.actor, now, input.workspaceId, input.jobId),
    database
      .prepare(
        `INSERT INTO node_job_event
         (id, workspaceId, nodeId, jobId, kind, message, createdAt)
         VALUES (?, ?, NULL, ?, 'cancel-requested', ?, ?)`,
      )
      .bind(
        createId('nje'),
        input.workspaceId,
        input.jobId,
        nextState === 'cancelled'
          ? 'Queued inference cancelled.'
          : 'Running inference cancellation requested.',
        now,
      ),
  ]);
  if ((results[0]!.meta.changes ?? 0) === 0) {
    return { ok: false, status: 409, error: 'The inference state changed before cancellation.' };
  }
  await writeLog({
    workspaceId: input.workspaceId,
    source: 'ai',
    level: 'WARN',
    message: `AI inference ${nextState}`,
    actor: input.actor,
    resource: input.jobId,
  });
  return { ok: true, state: nextState, duplicate: false };
}

export type AiShieldState = {
  totalAiNodes: number;
  eligibleOnlineNodes: number;
  staleNodes: number;
  offlineNodes: number;
  outdatedNodes: number;
  unsupportedRuntime: number;
  invalidModelHash: number;
  oversizedModels: number;
  insufficientDisk: number;
  unsignedJobs: number;
  forgedClaims: number;
  replayedJobs: number;
  expiredLeases: number;
  repeatedFailures: number;
  suspiciousVolume: number;
  resourceExhaustion: number;
  unexpectedOutbound: number;
  forbiddenProvider: number;
  revokedActivity: number;
  modelPathAbuse: number;
  payloadAbuse: number;
};

export async function aiForShield(
  workspaceId: string,
  now = Date.now(),
): Promise<AiShieldState> {
  const state = await readAiState(workspaceId, now);
  const aiNodes = state.nodes;
  const eventCount = async (types: readonly string[]) => {
    const placeholders = types.map(() => '?').join(',');
    return (
      await queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_security_event
         WHERE workspaceId = ? AND createdAt >= ? AND type IN (${placeholders})`,
        workspaceId,
        now - 24 * 60 * 60_000,
        ...types,
      )
    )?.total ?? 0;
  };
  const [unsigned, expired, failures, recent, invalidHash, oversized] =
    await Promise.all([
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_job WHERE workspaceId = ?
         AND type LIKE 'ai.%' AND state IN ('leased','cancelling','succeeded','failed')
         AND (claimSignature IS NULL OR claimSignature = '')`,
        workspaceId,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_job WHERE workspaceId = ?
         AND type LIKE 'ai.%' AND state IN ('leased','cancelling')
         AND leaseExpiresAt <= ?`,
        workspaceId,
        now,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_job WHERE workspaceId = ?
         AND type = 'ai.inference' AND state IN ('failed','timed_out')
         AND updatedAt >= ?`,
        workspaceId,
        now - 24 * 60 * 60_000,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_job WHERE workspaceId = ?
         AND type = 'ai.inference' AND createdAt >= ?`,
        workspaceId,
        now - 60 * 60_000,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM ai_model_cache WHERE workspaceId = ?
         AND error LIKE '%checksum%'`,
        workspaceId,
      ),
      queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM ai_model WHERE workspaceId = ? AND sizeBytes > ?`,
        workspaceId,
        AI_LIMITS.maximumModelBytes,
      ),
    ]);
  const insufficientDisk = aiNodes.filter((node) =>
    state.models.some(
      (model) =>
        model.downloadable &&
        aiRuntimeAvailable(node.capabilities.ai, model.runtime) &&
        node.capabilities.disk.freeBytes <
          model.sizeBytes + AI_LIMITS.diskReserveBytes,
    ),
  ).length;
  return {
    totalAiNodes: aiNodes.length,
    eligibleOnlineNodes: aiNodes.filter(
      (node) =>
        node.status === 'online' &&
        agentVersionSupported(node.agentVersion) &&
        node.capabilities.ai.runtimes.some((runtime) => runtime.available),
    ).length,
    staleNodes: aiNodes.filter((node) => node.status === 'stale').length,
    offlineNodes: aiNodes.filter((node) => node.status === 'offline').length,
    outdatedNodes: aiNodes.filter((node) => !agentVersionSupported(node.agentVersion)).length,
    unsupportedRuntime: await eventCount(['ai-unsupported-runtime']),
    invalidModelHash: invalidHash?.total ?? 0,
    oversizedModels: oversized?.total ?? 0,
    insufficientDisk,
    unsignedJobs: unsigned?.total ?? 0,
    forgedClaims: await eventCount([
      'unsigned-or-forged-job-completion',
      'ai-job-status-forgery',
    ]),
    replayedJobs: await eventCount(['replay-detected']),
    expiredLeases: expired?.total ?? 0,
    repeatedFailures: Math.max(0, (failures?.total ?? 0) - 2),
    suspiciousVolume:
      (recent?.total ?? 0) > AI_LIMITS.suspiciousJobsPerHour
        ? recent?.total ?? 0
        : 0,
    resourceExhaustion: await eventCount(['ai-resource-exhaustion']),
    unexpectedOutbound: await eventCount(['ai-unexpected-outbound']),
    forbiddenProvider: await eventCount(['ai-forbidden-provider']),
    revokedActivity: await eventCount([
      'revoked-node-ai-activity',
      'revoked-token-used',
    ]),
    modelPathAbuse: await eventCount(['ai-model-path-abuse']),
    payloadAbuse: await eventCount([
      'ai-payload-abuse',
      'ai-malformed-payload',
    ]),
  };
}

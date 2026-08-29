import {
  AI_LIMITS,
  aiModelCached,
  aiRuntimeAvailable,
  parseAiCapabilities,
  safeModelChecksum,
  safeRuntimeModel,
  validateAiJobPayload,
  type AiCapabilities,
  type AiCachedModelCapability,
  type AiInferencePayload,
  type AiModelAcquirePayload,
} from '../lib/ai.ts';
import type { NodeCapabilities, NodeMetrics } from '../lib/nodes.ts';

/** Fixed loopback APIs. No job field can replace either origin or pathname. */
const OLLAMA_ORIGIN = 'http://127.0.0.1:11434';
const LLAMA_CPP_ORIGIN = 'http://127.0.0.1:8080';
const DISCOVERY_TIMEOUT_MS = 1_500;
const MAX_DISCOVERY_BYTES = 256 * 1024;
const MAX_INFERENCE_BYTES = 64 * 1024;

export type LocalFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export type AiExecutionResult =
  | { status: 'succeeded'; result: Record<string, unknown> }
  | { status: 'failed'; error: string; retryable: boolean }
  | { status: 'cancelled'; error: string; retryable: false };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : null;
}

async function boundedJson(
  response: Response,
  maximumBytes: number,
): Promise<unknown> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maximumBytes) {
    throw new Error('Local runtime response exceeded the safety limit.');
  }
  if (!response.body) return {};
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      total += chunk.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel('response-too-large');
        throw new Error('Local runtime response exceeded the safety limit.');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(body) || '{}') as unknown;
}

async function localJson(
  fetcher: LocalFetch,
  url: string,
  init: RequestInit,
  maximumBytes: number,
): Promise<unknown> {
  const response = await fetcher(url, { ...init, redirect: 'error' });
  if (!response.ok) {
    throw new Error(`Local runtime answered ${response.status}.`);
  }
  return boundedJson(response, maximumBytes);
}

function ollamaModels(value: unknown): AiCachedModelCapability[] {
  if (!isRecord(value) || !Array.isArray(value.models)) return [];
  const models: AiCachedModelCapability[] = [];
  for (const candidate of value.models.slice(0, 64)) {
    if (!isRecord(candidate)) continue;
    const runtimeModel = safeRuntimeModel(candidate.name ?? candidate.model);
    const sizeBytes = boundedInteger(
      candidate.size,
      0,
      AI_LIMITS.maximumModelBytes,
    );
    const checksum = safeModelChecksum(candidate.digest);
    const modifiedAt =
      typeof candidate.modified_at === 'string'
        ? Date.parse(candidate.modified_at)
        : null;
    if (!runtimeModel || sizeBytes === null) continue;
    models.push({
      runtime: 'ollama',
      runtimeModel,
      sizeBytes,
      checksum,
      modifiedAt:
        modifiedAt !== null && Number.isFinite(modifiedAt) ? modifiedAt : null,
    });
  }
  return models;
}

async function discoverOllama(fetcher: LocalFetch): Promise<{
  available: boolean;
  version: string | null;
  models: AiCachedModelCapability[];
}> {
  try {
    const signal = AbortSignal.timeout(DISCOVERY_TIMEOUT_MS);
    const versionBody = await localJson(
      fetcher,
      `${OLLAMA_ORIGIN}/api/version`,
      { method: 'GET', signal },
      8 * 1024,
    );
    const version =
      isRecord(versionBody) && typeof versionBody.version === 'string'
        ? versionBody.version.slice(0, 64)
        : null;
    const tagsBody = await localJson(
      fetcher,
      `${OLLAMA_ORIGIN}/api/tags`,
      { method: 'GET', signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS) },
      MAX_DISCOVERY_BYTES,
    );
    return { available: true, version, models: ollamaModels(tagsBody) };
  } catch {
    return { available: false, version: null, models: [] };
  }
}

async function discoverLlamaCpp(fetcher: LocalFetch): Promise<{
  available: boolean;
  models: AiCachedModelCapability[];
}> {
  try {
    await localJson(
      fetcher,
      `${LLAMA_CPP_ORIGIN}/health`,
      { method: 'GET', signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS) },
      8 * 1024,
    );
    const list = await localJson(
      fetcher,
      `${LLAMA_CPP_ORIGIN}/v1/models`,
      { method: 'GET', signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS) },
      MAX_DISCOVERY_BYTES,
    );
    const hasModel =
      isRecord(list) && Array.isArray(list.data) && list.data.length > 0;
    return {
      available: true,
      models: hasModel
        ? [
            {
              runtime: 'llama.cpp',
              runtimeModel: 'local-model',
              sizeBytes: 0,
              checksum: null,
              modifiedAt: null,
            },
          ]
        : [],
    };
  } catch {
    return { available: false, models: [] };
  }
}

export async function discoverAiCapabilities(
  fetcher: LocalFetch = fetch,
): Promise<AiCapabilities> {
  const [ollama, llamaCpp] = await Promise.all([
    discoverOllama(fetcher),
    discoverLlamaCpp(fetcher),
  ]);
  const capabilities = {
    runtimes: [
      {
        runtime: 'ollama',
        available: ollama.available,
        version: ollama.version,
        transport: 'loopback-http',
      },
      {
        runtime: 'llama.cpp',
        available: llamaCpp.available,
        version: null,
        transport: 'loopback-http',
      },
    ],
    cachedModels: [...ollama.models, ...llamaCpp.models],
    maxConcurrentJobs: 1,
  } satisfies AiCapabilities;
  return parseAiCapabilities(capabilities) ?? {
    runtimes: [],
    cachedModels: [],
    maxConcurrentJobs: 1,
  };
}

function resourceGuard(
  payload: AiInferencePayload,
  capabilities: NodeCapabilities,
  metrics: NodeMetrics,
): string | null {
  if (!aiRuntimeAvailable(capabilities.ai, payload.runtime)) {
    return 'The requested allowlisted AI runtime is not available.';
  }
  if (!aiModelCached(capabilities.ai, payload.runtime, payload.runtimeModel)) {
    return 'The approved model is not cached on this node.';
  }
  const freeMemory = Math.max(
    0,
    metrics.memoryTotalBytes - metrics.memoryUsedBytes,
  );
  if (freeMemory < payload.expectedMemoryBytes) {
    return 'Free RAM is below the reviewed model requirement.';
  }
  if (
    payload.requiredVramBytes > 0 &&
    (!capabilities.gpu.available ||
      (capabilities.gpu.vramBytes ?? 0) < payload.requiredVramBytes)
  ) {
    return 'Available GPU VRAM is below the model requirement.';
  }
  if (metrics.cpuLoadPercent >= 90) {
    return 'Node load is above the safe inference threshold.';
  }
  // The current claim is included in runningJobs, so reject only excess work.
  if (metrics.runningJobs > capabilities.ai.maxConcurrentJobs) {
    return 'The node has reached its AI concurrency limit.';
  }
  return null;
}

function combinedSignal(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

function runtimeFailure(error: unknown, cancelled: boolean): AiExecutionResult {
  if (cancelled) {
    return { status: 'cancelled', error: 'Inference was cancelled.', retryable: false };
  }
  const message = error instanceof Error ? error.message : 'Local runtime failed.';
  return {
    status: 'failed',
    error: message.slice(0, 500),
    retryable: /timeout|fetch|connect|network|socket|terminated/i.test(message),
  };
}

export async function executeAiInference(input: {
  payload: unknown;
  capabilities: NodeCapabilities;
  metrics: NodeMetrics;
  signal?: AbortSignal;
  fetcher?: LocalFetch;
}): Promise<AiExecutionResult> {
  const validated = validateAiJobPayload('ai.inference', input.payload);
  if (!validated.ok || !('prompt' in validated.payload)) {
    return { status: 'failed', error: validated.ok ? 'Invalid inference payload.' : validated.error, retryable: false };
  }
  const payload = validated.payload;
  const resourceError = resourceGuard(payload, input.capabilities, input.metrics);
  if (resourceError) {
    return { status: 'failed', error: resourceError, retryable: false };
  }
  const fetcher = input.fetcher ?? fetch;
  const startedAt = Date.now();
  const signal = combinedSignal(input.signal, payload.timeoutMs);
  try {
    let body: unknown;
    if (payload.runtime === 'ollama') {
      body = await localJson(
        fetcher,
        `${OLLAMA_ORIGIN}/api/chat`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: payload.runtimeModel,
            messages: [
              ...(payload.systemPrompt
                ? [{ role: 'system', content: payload.systemPrompt }]
                : []),
              { role: 'user', content: payload.prompt },
            ],
            stream: false,
            ...(payload.responseFormat === 'json' ? { format: 'json' } : {}),
            options: {
              num_predict: payload.maxTokens,
              temperature: payload.temperature,
            },
          }),
          signal,
        },
        MAX_INFERENCE_BYTES,
      );
      const message = isRecord(body) && isRecord(body.message) ? body.message : null;
      const text = message && typeof message.content === 'string' ? message.content : '';
      if (!text || text.length > AI_LIMITS.resultCharacters) {
        throw new Error('Ollama returned an empty or oversized result.');
      }
      return {
        status: 'succeeded',
        result: {
          text,
          runtime: 'ollama',
          model: payload.runtimeModel,
          inputTokens: boundedInteger(
            isRecord(body) ? body.prompt_eval_count : null,
            0,
            1_000_000,
          ),
          outputTokens: boundedInteger(
            isRecord(body) ? body.eval_count : null,
            0,
            1_000_000,
          ),
          latencyMs: Date.now() - startedAt,
          responseFormat: payload.responseFormat,
        },
      };
    }

    body = await localJson(
      fetcher,
      `${LLAMA_CPP_ORIGIN}/v1/chat/completions`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'local-model',
          messages: [
            ...(payload.systemPrompt
              ? [{ role: 'system', content: payload.systemPrompt }]
              : []),
            { role: 'user', content: payload.prompt },
          ],
          max_tokens: payload.maxTokens,
          temperature: payload.temperature,
          ...(payload.responseFormat === 'json'
            ? { response_format: { type: 'json_object' } }
            : {}),
        }),
        signal,
      },
      MAX_INFERENCE_BYTES,
    );
    const choices = isRecord(body) && Array.isArray(body.choices) ? body.choices : [];
    const first = isRecord(choices[0]) ? choices[0] : null;
    const message = first && isRecord(first.message) ? first.message : null;
    const text = message && typeof message.content === 'string' ? message.content : '';
    if (!text || text.length > AI_LIMITS.resultCharacters) {
      throw new Error('llama.cpp returned an empty or oversized result.');
    }
    const usage = isRecord(body) && isRecord(body.usage) ? body.usage : null;
    return {
      status: 'succeeded',
      result: {
        text,
        runtime: 'llama.cpp',
        model: 'local-model',
        inputTokens: boundedInteger(usage?.prompt_tokens, 0, 1_000_000),
        outputTokens: boundedInteger(usage?.completion_tokens, 0, 1_000_000),
        latencyMs: Date.now() - startedAt,
        responseFormat: payload.responseFormat,
      },
    };
  } catch (error) {
    return runtimeFailure(error, Boolean(input.signal?.aborted));
  }
}

async function cleanupFailedOllamaModel(
  fetcher: LocalFetch,
  runtimeModel: string,
): Promise<void> {
  try {
    await localJson(
      fetcher,
      `${OLLAMA_ORIGIN}/api/delete`,
      {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: runtimeModel }),
        signal: AbortSignal.timeout(5_000),
      },
      8 * 1024,
    );
  } catch {
    // Ollama may already have removed the partial layer; never widen cleanup.
  }
}

export async function acquireAiModel(input: {
  payload: unknown;
  capabilities: NodeCapabilities;
  signal?: AbortSignal;
  fetcher?: LocalFetch;
}): Promise<AiExecutionResult> {
  const validated = validateAiJobPayload('ai.model.acquire', input.payload);
  if (!validated.ok || !('expectedSizeBytes' in validated.payload)) {
    return { status: 'failed', error: validated.ok ? 'Invalid model acquisition.' : validated.error, retryable: false };
  }
  const payload: AiModelAcquirePayload = validated.payload;
  if (!aiRuntimeAvailable(input.capabilities.ai, 'ollama')) {
    return { status: 'failed', error: 'Ollama is not installed and available.', retryable: false };
  }
  if (
    input.capabilities.disk.freeBytes <
    payload.expectedSizeBytes + AI_LIMITS.diskReserveBytes
  ) {
    return { status: 'failed', error: 'Free disk is below the model plus safety reserve.', retryable: false };
  }
  const alreadyCached = aiModelCached(
    input.capabilities.ai,
    'ollama',
    payload.runtimeModel,
  );
  if (alreadyCached) {
    const existing = input.capabilities.ai.cachedModels.find(
      (model) =>
        model.runtime === 'ollama' && model.runtimeModel === payload.runtimeModel,
    );
    return {
      status: 'succeeded',
      result: {
        cached: true,
        modelId: payload.modelId,
        runtimeModel: payload.runtimeModel,
        sizeBytes: existing?.sizeBytes ?? payload.expectedSizeBytes,
        checksum: existing?.checksum ?? null,
        reused: true,
      },
    };
  }
  const fetcher = input.fetcher ?? fetch;
  try {
    await localJson(
      fetcher,
      `${OLLAMA_ORIGIN}/api/pull`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: payload.runtimeModel, stream: false }),
        signal: combinedSignal(input.signal, AI_LIMITS.acquisitionTimeoutMs),
      },
      MAX_DISCOVERY_BYTES,
    );
    const tags = await localJson(
      fetcher,
      `${OLLAMA_ORIGIN}/api/tags`,
      { method: 'GET', signal: AbortSignal.timeout(5_000) },
      MAX_DISCOVERY_BYTES,
    );
    const cached = ollamaModels(tags).find(
      (model) => model.runtimeModel === payload.runtimeModel,
    );
    if (!cached) throw new Error('Ollama did not report the model after acquisition.');
    if (!cached.checksum) {
      throw new Error('Ollama did not provide a valid SHA-256 model digest.');
    }
    if (payload.checksum && cached.checksum !== payload.checksum) {
      await cleanupFailedOllamaModel(fetcher, payload.runtimeModel);
      return { status: 'failed', error: 'Downloaded model checksum did not match.', retryable: false };
    }
    return {
      status: 'succeeded',
      result: {
        cached: true,
        modelId: payload.modelId,
        runtimeModel: payload.runtimeModel,
        sizeBytes: cached.sizeBytes,
        checksum: cached.checksum,
        reused: false,
      },
    };
  } catch (error) {
    await cleanupFailedOllamaModel(fetcher, payload.runtimeModel);
    return runtimeFailure(error, Boolean(input.signal?.aborted));
  }
}

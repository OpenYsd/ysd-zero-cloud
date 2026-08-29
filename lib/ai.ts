/**
 * Phase 4 AI Compute contracts.
 *
 * Cloudflare is only the workspace-scoped control plane. These contracts can
 * dispatch work exclusively to a paired, user-owned node and never name a
 * paid provider, arbitrary executable, path, URL, or network destination.
 */

export const AI_RUNTIMES = ['ollama', 'llama.cpp'] as const;
export type AiRuntime = (typeof AI_RUNTIMES)[number];

export const AI_MODEL_STATES = [
  'unavailable',
  'available',
  'downloading',
  'ready',
  'error',
  'disabled',
] as const;
export type AiModelState = (typeof AI_MODEL_STATES)[number];

export const AI_LIMITS = {
  promptCharacters: 16_384,
  systemPromptCharacters: 4_096,
  maximumTokens: 4_096,
  maximumTimeoutMs: 180_000,
  minimumTimeoutMs: 5_000,
  maximumModelBytes: 4 * 1024 * 1024 * 1024,
  diskReserveBytes: 512 * 1024 * 1024,
  maximumConcurrentJobs: 2,
  resultCharacters: 32_768,
  acquisitionTimeoutMs: 20 * 60_000,
  suspiciousJobsPerHour: 50,
} as const;

export type AiRuntimeCapability = {
  runtime: AiRuntime;
  available: boolean;
  version: string | null;
  transport: 'loopback-http';
};

export type AiCachedModelCapability = {
  runtime: AiRuntime;
  runtimeModel: string;
  sizeBytes: number;
  checksum: string | null;
  modifiedAt: number | null;
};

export type AiCapabilities = {
  runtimes: AiRuntimeCapability[];
  cachedModels: AiCachedModelCapability[];
  maxConcurrentJobs: number;
};

export type ApprovedAiModel = {
  id: string;
  displayName: string;
  runtime: AiRuntime;
  family: string;
  runtimeModel: string;
  source: 'ollama-library' | 'local-runtime';
  sizeBytes: number;
  expectedMemoryBytes: number;
  requiredVramBytes: number;
  checksum: string | null;
  downloadable: boolean;
};

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

/**
 * Reviewed initial catalog. Model acquisition can reference only these exact
 * records; the client cannot substitute a URL, filesystem path, or binary.
 */
export const APPROVED_AI_MODELS = [
  {
    id: 'ollama-qwen2.5-0.5b',
    displayName: 'Qwen 2.5 0.5B',
    runtime: 'ollama',
    family: 'qwen2.5',
    runtimeModel: 'qwen2.5:0.5b',
    source: 'ollama-library',
    sizeBytes: 400 * MiB,
    expectedMemoryBytes: 2 * GiB,
    requiredVramBytes: 0,
    checksum: null,
    downloadable: true,
  },
  {
    id: 'ollama-gemma3-1b',
    displayName: 'Gemma 3 1B',
    runtime: 'ollama',
    family: 'gemma3',
    runtimeModel: 'gemma3:1b',
    source: 'ollama-library',
    sizeBytes: 850 * MiB,
    expectedMemoryBytes: 3 * GiB,
    requiredVramBytes: 0,
    checksum: null,
    downloadable: true,
  },
  {
    id: 'ollama-llama3.2-1b',
    displayName: 'Llama 3.2 1B',
    runtime: 'ollama',
    family: 'llama3.2',
    runtimeModel: 'llama3.2:1b',
    source: 'ollama-library',
    sizeBytes: 1_350 * MiB,
    expectedMemoryBytes: 3 * GiB,
    requiredVramBytes: 0,
    checksum: null,
    downloadable: true,
  },
  {
    id: 'llamacpp-local-model',
    displayName: 'llama.cpp Local Server Model',
    runtime: 'llama.cpp',
    family: 'local-gguf',
    runtimeModel: 'local-model',
    source: 'local-runtime',
    sizeBytes: 0,
    expectedMemoryBytes: 2 * GiB,
    requiredVramBytes: 0,
    checksum: null,
    downloadable: false,
  },
] as const satisfies readonly ApprovedAiModel[];

export type AiInferencePayload = {
  modelId: string;
  runtime: AiRuntime;
  runtimeModel: string;
  prompt: string;
  systemPrompt: string | null;
  maxTokens: number;
  temperature: number;
  responseFormat: 'text' | 'json';
  timeoutMs: number;
  provider: 'local-node';
  zeroMode: true;
  expectedMemoryBytes: number;
  requiredVramBytes: number;
};

export type AiModelAcquirePayload = {
  modelId: string;
  runtime: 'ollama';
  runtimeModel: string;
  source: 'ollama-library';
  expectedSizeBytes: number;
  checksum: string | null;
};

export type AiJobPayload = AiInferencePayload | AiModelAcquirePayload;

export type AiPayloadValidation =
  | { ok: true; payload: AiJobPayload }
  | { ok: false; code: string; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
): boolean {
  const expected = new Set(required);
  return (
    Object.keys(value).length === expected.size &&
    Object.keys(value).every((key) => expected.has(key))
  );
}

function finiteInteger(
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

function finiteNumber(
  value: unknown,
  minimum: number,
  maximum: number,
): number | null {
  return typeof value === 'number' &&
    Number.isFinite(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : null;
}

export function approvedAiModel(id: string): ApprovedAiModel | null {
  return (
    APPROVED_AI_MODELS.find((model) => model.id === id) ?? null
  ) as ApprovedAiModel | null;
}

export function safeRuntimeModel(value: unknown): string | null {
  if (typeof value !== 'string' || value.length < 1 || value.length > 128) {
    return null;
  }
  if (
    value.includes('..') ||
    value.includes('\\') ||
    value.startsWith('/') ||
    value.includes('://') ||
    value.toLowerCase().startsWith('file:')
  ) {
    return null;
  }
  return /^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?$/.test(value)
    ? value
    : null;
}

export function safeModelChecksum(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value !== 'string' || value.length > 160) return null;
  return /^(?:sha256:)?[a-fA-F0-9]{64}$/.test(value) ? value.toLowerCase() : null;
}

export function parseAiCapabilities(value: unknown): AiCapabilities | null {
  if (!isRecord(value)) return null;
  if (
    !Array.isArray(value.runtimes) ||
    !Array.isArray(value.cachedModels)
  ) {
    return null;
  }
  const maxConcurrentJobs = finiteInteger(
    value.maxConcurrentJobs,
    1,
    AI_LIMITS.maximumConcurrentJobs,
  );
  if (maxConcurrentJobs === null || value.runtimes.length > AI_RUNTIMES.length) {
    return null;
  }

  const runtimes: AiRuntimeCapability[] = [];
  for (const candidate of value.runtimes) {
    if (!isRecord(candidate)) return null;
    if (
      !AI_RUNTIMES.includes(candidate.runtime as AiRuntime) ||
      typeof candidate.available !== 'boolean' ||
      candidate.transport !== 'loopback-http' ||
      (candidate.version !== null &&
        (typeof candidate.version !== 'string' || candidate.version.length > 64))
    ) {
      return null;
    }
    if (runtimes.some((entry) => entry.runtime === candidate.runtime)) return null;
    runtimes.push({
      runtime: candidate.runtime as AiRuntime,
      available: candidate.available,
      version: candidate.version,
      transport: 'loopback-http',
    });
  }

  if (value.cachedModels.length > 64) return null;
  const cachedModels: AiCachedModelCapability[] = [];
  for (const candidate of value.cachedModels) {
    if (!isRecord(candidate)) return null;
    const runtimeModel = safeRuntimeModel(candidate.runtimeModel);
    const sizeBytes = finiteInteger(
      candidate.sizeBytes,
      0,
      AI_LIMITS.maximumModelBytes,
    );
    const modifiedAt =
      candidate.modifiedAt === null
        ? null
        : finiteInteger(candidate.modifiedAt, 0, Number.MAX_SAFE_INTEGER);
    if (
      !AI_RUNTIMES.includes(candidate.runtime as AiRuntime) ||
      !runtimeModel ||
      sizeBytes === null ||
      (modifiedAt === null && candidate.modifiedAt !== null) ||
      (candidate.checksum !== null && safeModelChecksum(candidate.checksum) === null)
    ) {
      return null;
    }
    cachedModels.push({
      runtime: candidate.runtime as AiRuntime,
      runtimeModel,
      sizeBytes,
      checksum: safeModelChecksum(candidate.checksum),
      modifiedAt,
    });
  }
  return { runtimes, cachedModels, maxConcurrentJobs };
}

export function validateAiJobPayload(
  type: 'ai.inference' | 'ai.model.acquire',
  value: unknown,
): AiPayloadValidation {
  if (!isRecord(value)) {
    return { ok: false, code: 'payload', error: 'AI payload must be an object.' };
  }
  if (type === 'ai.inference') {
    const keys = [
      'modelId',
      'runtime',
      'runtimeModel',
      'prompt',
      'systemPrompt',
      'maxTokens',
      'temperature',
      'responseFormat',
      'timeoutMs',
      'provider',
      'zeroMode',
      'expectedMemoryBytes',
      'requiredVramBytes',
    ];
    if (!exactKeys(value, keys)) {
      return {
        ok: false,
        code: 'payload-abuse',
        error: 'Inference payload contains missing or forbidden fields.',
      };
    }
    const model =
      typeof value.modelId === 'string' ? approvedAiModel(value.modelId) : null;
    const maxTokens = finiteInteger(value.maxTokens, 1, AI_LIMITS.maximumTokens);
    const temperature = finiteNumber(value.temperature, 0, 2);
    const timeoutMs = finiteInteger(
      value.timeoutMs,
      AI_LIMITS.minimumTimeoutMs,
      AI_LIMITS.maximumTimeoutMs,
    );
    if (
      !model ||
      value.runtime !== model.runtime ||
      value.runtimeModel !== model.runtimeModel ||
      typeof value.prompt !== 'string' ||
      value.prompt.length < 1 ||
      value.prompt.length > AI_LIMITS.promptCharacters ||
      (value.systemPrompt !== null &&
        (typeof value.systemPrompt !== 'string' ||
          value.systemPrompt.length > AI_LIMITS.systemPromptCharacters)) ||
      maxTokens === null ||
      temperature === null ||
      (value.responseFormat !== 'text' && value.responseFormat !== 'json') ||
      timeoutMs === null ||
      value.provider !== 'local-node' ||
      value.zeroMode !== true ||
      value.expectedMemoryBytes !== model.expectedMemoryBytes ||
      value.requiredVramBytes !== model.requiredVramBytes
    ) {
      return {
        ok: false,
        code:
          value.provider !== 'local-node' || value.zeroMode !== true
            ? 'forbidden-provider'
            : 'payload',
        error: 'Inference request violates the reviewed local-node contract.',
      };
    }
    return {
      ok: true,
      payload: {
        modelId: model.id,
        runtime: model.runtime,
        runtimeModel: model.runtimeModel,
        prompt: value.prompt,
        systemPrompt: value.systemPrompt,
        maxTokens,
        temperature,
        responseFormat: value.responseFormat,
        timeoutMs,
        provider: 'local-node',
        zeroMode: true,
        expectedMemoryBytes: model.expectedMemoryBytes,
        requiredVramBytes: model.requiredVramBytes,
      },
    };
  }

  const keys = [
    'modelId',
    'runtime',
    'runtimeModel',
    'source',
    'expectedSizeBytes',
    'checksum',
  ];
  if (!exactKeys(value, keys)) {
    return {
      ok: false,
      code: 'model-path-abuse',
      error: 'Model acquisition contains missing or forbidden fields.',
    };
  }
  const model =
    typeof value.modelId === 'string' ? approvedAiModel(value.modelId) : null;
  const checksum = safeModelChecksum(value.checksum);
  if (
    !model ||
    !model.downloadable ||
    model.runtime !== 'ollama' ||
    model.source !== 'ollama-library' ||
    value.runtime !== model.runtime ||
    value.runtimeModel !== model.runtimeModel ||
    value.source !== model.source ||
    value.expectedSizeBytes !== model.sizeBytes ||
    (value.checksum !== null && checksum === null) ||
    (model.checksum !== null && checksum !== model.checksum) ||
    model.sizeBytes > AI_LIMITS.maximumModelBytes
  ) {
    return {
      ok: false,
      code: 'model-source',
      error: 'Model acquisition is not in the reviewed catalog.',
    };
  }
  return {
    ok: true,
    payload: {
      modelId: model.id,
      runtime: 'ollama',
      runtimeModel: model.runtimeModel,
      source: 'ollama-library',
      expectedSizeBytes: model.sizeBytes,
      checksum,
    },
  };
}

export function aiRuntimeAvailable(
  capabilities: AiCapabilities,
  runtime: AiRuntime,
): boolean {
  return capabilities.runtimes.some(
    (entry) => entry.runtime === runtime && entry.available,
  );
}

export function aiModelCached(
  capabilities: AiCapabilities,
  runtime: AiRuntime,
  runtimeModel: string,
): boolean {
  return capabilities.cachedModels.some(
    (entry) =>
      entry.runtime === runtime &&
      (entry.runtimeModel === runtimeModel ||
        (runtime === 'llama.cpp' && entry.runtimeModel === 'local-model')),
  );
}

export function estimateTokens(text: string): number {
  return text.length === 0 ? 0 : Math.max(1, Math.ceil(text.length / 4));
}

export function aiLeaseDuration(type: string, payload: Record<string, unknown>): number {
  if (type === 'ai.inference') {
    const timeout =
      typeof payload.timeoutMs === 'number' ? payload.timeoutMs : AI_LIMITS.maximumTimeoutMs;
    return Math.min(AI_LIMITS.maximumTimeoutMs, Math.max(AI_LIMITS.minimumTimeoutMs, timeout)) + 30_000;
  }
  if (type === 'ai.model.acquire') return AI_LIMITS.acquisitionTimeoutMs + 30_000;
  return 60_000;
}

export function containsNetworkOrExecutionAbuse(value: unknown): boolean {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    return true;
  }
  return (
    /(?:https?:\/\/|file:\/\/|169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1|\.\.\/|\.\.\\)/i.test(
      serialized,
    ) ||
    /"(?:command|shell|script|executable|path|url|webhook)"\s*:/i.test(
      serialized,
    )
  );
}

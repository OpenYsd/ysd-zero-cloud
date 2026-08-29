/**
 * Compute Nodes protocol and security policy.
 *
 * This module is runtime-neutral: both the Cloudflare control plane and the
 * outbound-only Node Agent use the exact same validators and signatures.
 * Nothing here can execute a shell command. Phase 3 deliberately exposes only
 * two diagnostic handlers; AI and game-server contracts remain placeholders.
 */

export const NODE_PROTOCOL_VERSION = 1;
export const CURRENT_AGENT_VERSION = '0.1.0';
export const MINIMUM_AGENT_VERSION = '0.1.0';

export const NODE_TIMING = {
  heartbeatMs: 25_000,
  onlineMs: 60_000,
  staleMs: 3 * 60_000,
  requestSkewMs: 60_000,
  pairingTtlMs: 10 * 60_000,
  leaseMs: 60_000,
  nonceRetentionMs: 24 * 60 * 60_000,
  metricRetentionMs: 7 * 24 * 60 * 60_000,
} as const;

export const EXECUTABLE_NODE_JOB_TYPES = [
  'diagnostic.ping',
  'diagnostic.snapshot',
] as const;

export const PLACEHOLDER_NODE_JOB_TYPES = [
  'ai.inference',
  'game-server.lifecycle',
] as const;

export const NODE_JOB_TYPES = [
  ...EXECUTABLE_NODE_JOB_TYPES,
  ...PLACEHOLDER_NODE_JOB_TYPES,
] as const;

export type ExecutableNodeJobType = (typeof EXECUTABLE_NODE_JOB_TYPES)[number];
export type PlaceholderNodeJobType =
  (typeof PLACEHOLDER_NODE_JOB_TYPES)[number];
export type NodeJobType = (typeof NODE_JOB_TYPES)[number];

export type NodeCapabilities = {
  cpu: { cores: number; model: string };
  memory: { totalBytes: number };
  gpu: { available: boolean; model: string | null };
  docker: { available: boolean };
  contracts: { ai: boolean; gameServers: boolean };
};

export type NodeMetrics = {
  cpuLoadPercent: number;
  memoryUsedBytes: number;
  memoryTotalBytes: number;
  runningJobs: number;
};

export type NodeStatus = 'online' | 'stale' | 'offline' | 'revoked';
export type NodeJobState =
  | 'queued'
  | 'leased'
  | 'succeeded'
  | 'failed'
  | 'timed_out'
  | 'cancelled';

export type SignedJobClaim = {
  protocolVersion: typeof NODE_PROTOCOL_VERSION;
  jobId: string;
  workspaceId: string;
  nodeId: string;
  type: ExecutableNodeJobType;
  payload: Record<string, unknown>;
  payloadHash: string;
  leaseId: string;
  leaseExpiresAt: number;
  attempt: number;
};

export type CompletionCandidate = {
  state: NodeJobState;
  assignedNodeId: string | null;
  leaseId: string | null;
  leaseExpiresAt: number | null;
};

export type CompletionDecision =
  | { allowed: true }
  | {
      allowed: false;
      reason: 'state' | 'node' | 'lease' | 'expired';
      message: string;
    };

export type ExpiredLeaseDecision = {
  state: 'queued' | 'timed_out';
  retry: boolean;
};

export type JobValidation =
  | {
      ok: true;
      type: ExecutableNodeJobType;
      payload: Record<string, unknown>;
    }
  | {
      ok: false;
      status: 400 | 409;
      code: 'type' | 'placeholder' | 'payload';
      error: string;
    };

const encoder = new TextEncoder();

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function cleanText(value: unknown, maximum: number): string {
  if (typeof value !== 'string') return '';
  let safe = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code >= 32 && code !== 127) safe += character;
  }
  return safe.trim().slice(0, maximum);
}

function finiteInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  const integer = Math.floor(value);
  return integer >= minimum && integer <= maximum ? integer : null;
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

export function normalizeNodeName(value: unknown): string | null {
  const name = cleanText(value, 64).replace(/\s+/g, ' ');
  return name.length >= 2 ? name : null;
}

export function parseCapabilities(value: unknown): NodeCapabilities | null {
  if (!isRecord(value)) return null;
  const cpu = isRecord(value.cpu) ? value.cpu : null;
  const memory = isRecord(value.memory) ? value.memory : null;
  const gpu = isRecord(value.gpu) ? value.gpu : null;
  const docker = isRecord(value.docker) ? value.docker : null;
  const contracts = isRecord(value.contracts) ? value.contracts : null;
  if (!cpu || !memory || !gpu || !docker || !contracts) return null;

  const cores = finiteInteger(cpu.cores, 1, 4096);
  const totalBytes = finiteInteger(
    memory.totalBytes,
    1,
    Number.MAX_SAFE_INTEGER,
  );
  if (cores === null || totalBytes === null) return null;
  if (
    typeof gpu.available !== 'boolean' ||
    typeof docker.available !== 'boolean' ||
    typeof contracts.ai !== 'boolean' ||
    typeof contracts.gameServers !== 'boolean'
  ) {
    return null;
  }

  const gpuModel = gpu.available ? cleanText(gpu.model, 128) : '';
  return {
    cpu: { cores, model: cleanText(cpu.model, 128) || 'Unknown CPU' },
    memory: { totalBytes },
    gpu: { available: gpu.available, model: gpuModel || null },
    docker: { available: docker.available },
    // These advertise only that the local machine could support a later
    // contract. The Phase 3 control plane still refuses both job types.
    contracts: {
      ai: contracts.ai,
      gameServers: contracts.gameServers,
    },
  };
}

export function parseMetrics(value: unknown): NodeMetrics | null {
  if (!isRecord(value)) return null;
  const cpuLoadPercent = finiteNumber(value.cpuLoadPercent, 0, 100);
  const memoryUsedBytes = finiteInteger(
    value.memoryUsedBytes,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const memoryTotalBytes = finiteInteger(
    value.memoryTotalBytes,
    1,
    Number.MAX_SAFE_INTEGER,
  );
  const runningJobs = finiteInteger(value.runningJobs, 0, 32);
  if (
    cpuLoadPercent === null ||
    memoryUsedBytes === null ||
    memoryTotalBytes === null ||
    runningJobs === null ||
    memoryUsedBytes > memoryTotalBytes
  ) {
    return null;
  }
  return {
    cpuLoadPercent,
    memoryUsedBytes,
    memoryTotalBytes,
    runningJobs,
  };
}

export function isExecutableJobType(
  value: string,
): value is ExecutableNodeJobType {
  return (EXECUTABLE_NODE_JOB_TYPES as readonly string[]).includes(value);
}

export function isPlaceholderJobType(
  value: string,
): value is PlaceholderNodeJobType {
  return (PLACEHOLDER_NODE_JOB_TYPES as readonly string[]).includes(value);
}

function onlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const permitted = new Set(allowed);
  return Object.keys(value).every((key) => permitted.has(key));
}

/** Strict allowlist for payloads that can ever reach an agent handler. */
export function validateJob(
  typeValue: unknown,
  payloadValue: unknown,
): JobValidation {
  if (typeof typeValue !== 'string') {
    return {
      ok: false,
      status: 400,
      code: 'type',
      error: 'Choose a supported job type.',
    };
  }
  if (isPlaceholderJobType(typeValue)) {
    return {
      ok: false,
      status: 409,
      code: 'placeholder',
      error:
        'This is a Phase 3 API contract only. AI and Game Server execution are not enabled.',
    };
  }
  if (!isExecutableJobType(typeValue)) {
    return {
      ok: false,
      status: 400,
      code: 'type',
      error: 'The job type is not allowlisted.',
    };
  }
  if (!isRecord(payloadValue)) {
    return {
      ok: false,
      status: 400,
      code: 'payload',
      error: 'The job payload must be a JSON object.',
    };
  }

  let payload: Record<string, unknown>;
  if (typeValue === 'diagnostic.ping') {
    if (!onlyKeys(payloadValue, ['message'])) {
      return {
        ok: false,
        status: 400,
        code: 'payload',
        error: 'Ping accepts only an optional message.',
      };
    }
    const message = payloadValue.message;
    if (message !== undefined && typeof message !== 'string') {
      return {
        ok: false,
        status: 400,
        code: 'payload',
        error: 'Ping message must be text.',
      };
    }
    payload = message === undefined ? {} : { message: cleanText(message, 256) };
  } else {
    if (!onlyKeys(payloadValue, [])) {
      return {
        ok: false,
        status: 400,
        code: 'payload',
        error: 'Snapshot does not accept parameters.',
      };
    }
    payload = {};
  }

  if (stableJson(payload).length > 4096) {
    return {
      ok: false,
      status: 400,
      code: 'payload',
      error: 'The job payload is too large.',
    };
  }
  return { ok: true, type: typeValue, payload };
}

/** Deterministic JSON used only for signed protocol claims and hashes. */
export function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const entries = Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`);
  return `{${entries.join(',')}}`;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const padded = `${value.replace(/-/g, '+').replace(/_/g, '/')}${'='.repeat(
    (4 - (value.length % 4)) % 4,
  )}`;
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export function randomToken(bytes = 32): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return toBase64Url(new Uint8Array(digest));
}

/** Length-hiding comparison for stored token digests and other fixed strings. */
export function constantTimeEqual(left: string, right: string): boolean {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  const length = Math.max(a.length, b.length);
  let difference = a.length ^ b.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

async function hmacKey(
  value: string,
  usage: 'sign' | 'verify',
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(value),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    [usage],
  );
}

export async function signText(secret: string, value: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    'HMAC',
    await hmacKey(secret, 'sign'),
    encoder.encode(value),
  );
  return toBase64Url(new Uint8Array(signature));
}

export async function verifyTextSignature(
  secret: string,
  value: string,
  signature: string,
): Promise<boolean> {
  const bytes = fromBase64Url(signature);
  if (!bytes) return false;
  return crypto.subtle.verify(
    'HMAC',
    await hmacKey(secret, 'verify'),
    bytes as BufferSource,
    encoder.encode(value),
  );
}

export function agentRequestMessage(input: {
  method: string;
  pathname: string;
  timestamp: number;
  nonce: string;
  bodyHash: string;
}): string {
  return [
    'ysd-node-request-v1',
    input.method.toUpperCase(),
    input.pathname,
    String(input.timestamp),
    input.nonce,
    input.bodyHash,
  ].join('\n');
}

export async function signAgentRequest(
  secret: string,
  input: {
    method: string;
    pathname: string;
    timestamp: number;
    nonce: string;
    body: string;
  },
): Promise<string> {
  return signText(
    secret,
    agentRequestMessage({ ...input, bodyHash: await sha256(input.body) }),
  );
}

export async function verifyAgentRequestSignature(
  secret: string,
  input: {
    method: string;
    pathname: string;
    timestamp: number;
    nonce: string;
    body: string;
    signature: string;
  },
): Promise<boolean> {
  return verifyTextSignature(
    secret,
    agentRequestMessage({ ...input, bodyHash: await sha256(input.body) }),
    input.signature,
  );
}

export function requestIsFresh(
  timestamp: number,
  now: number,
  skewMs = NODE_TIMING.requestSkewMs,
): boolean {
  return Number.isSafeInteger(timestamp) && Math.abs(now - timestamp) <= skewMs;
}

export function validNonce(nonce: string): boolean {
  return /^[A-Za-z0-9_-]{22,64}$/.test(nonce);
}

export async function signJobClaim(
  secret: string,
  claim: SignedJobClaim,
): Promise<string> {
  return signText(secret, `ysd-node-job-v1\n${stableJson(claim)}`);
}

export async function verifyJobClaim(
  secret: string,
  claim: SignedJobClaim,
  signature: string,
): Promise<boolean> {
  return verifyTextSignature(
    secret,
    `ysd-node-job-v1\n${stableJson(claim)}`,
    signature,
  );
}

export function deriveNodeStatus(input: {
  revokedAt: number | null;
  lastHeartbeatAt: number | null;
  now: number;
}): NodeStatus {
  if (input.revokedAt !== null) return 'revoked';
  if (input.lastHeartbeatAt === null) return 'offline';
  const age = input.now - input.lastHeartbeatAt;
  if (age <= NODE_TIMING.onlineMs) return 'online';
  if (age <= NODE_TIMING.staleMs) return 'stale';
  return 'offline';
}

export function compareVersions(left: string, right: string): number {
  const parse = (version: string) =>
    version
      .replace(/^v/i, '')
      .split('-', 1)[0]!
      .split('.')
      .slice(0, 3)
      .map((part) => Number.parseInt(part, 10));
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index += 1) {
    const difference = (a[index] || 0) - (b[index] || 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

export function agentVersionSupported(version: string): boolean {
  return (
    /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version) &&
    compareVersions(version, MINIMUM_AGENT_VERSION) >= 0
  );
}

export function evaluateCompletion(
  job: CompletionCandidate,
  nodeId: string,
  leaseId: string,
  now: number,
): CompletionDecision {
  if (job.state !== 'leased') {
    return {
      allowed: false,
      reason: 'state',
      message: 'The job is not currently leased.',
    };
  }
  if (job.assignedNodeId !== nodeId) {
    return {
      allowed: false,
      reason: 'node',
      message: 'The lease belongs to another node.',
    };
  }
  if (!job.leaseId || job.leaseId !== leaseId) {
    return {
      allowed: false,
      reason: 'lease',
      message: 'The lease identifier is invalid.',
    };
  }
  if (!job.leaseExpiresAt || job.leaseExpiresAt <= now) {
    return {
      allowed: false,
      reason: 'expired',
      message: 'The job lease has expired.',
    };
  }
  return { allowed: true };
}

export function recoverExpiredLease(
  attempts: number,
  maxAttempts: number,
): ExpiredLeaseDecision {
  const retry = attempts < maxAttempts;
  return { state: retry ? 'queued' : 'timed_out', retry };
}

export function sanitizeJobResult(
  value: unknown,
): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  const serialized = stableJson(value);
  if (serialized.length > 16_384) return null;
  if (
    /"(?:command|shell|script|token|secret|password)"\s*:/i.test(serialized)
  ) {
    return null;
  }
  return JSON.parse(serialized) as Record<string, unknown>;
}

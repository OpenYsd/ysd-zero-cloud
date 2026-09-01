import type { WorkflowScalar } from './workflows';

/** Public, versioned contract for Phase 10 inbound events. */
export const WEBHOOK_MAX_BODY_BYTES = 32 * 1024;
export const WEBHOOK_TIMESTAMP_WINDOW_SECONDS = 5 * 60;
export const WEBHOOK_SOURCE_LIMIT_PER_WORKSPACE = 25;

export const WEBHOOK_SOURCE_ID = /^whsrc_[a-f0-9]{24}$/;
export const WEBHOOK_EVENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
export const WEBHOOK_NONCE = /^[A-Za-z0-9_-]{16,128}$/;
export const WEBHOOK_EVENT_TYPE = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,7}$/;

export const WEBHOOK_DATA_KEYS = [
  'status',
  'severity',
  'category',
  'action',
  'environment',
  'ref',
  'label',
  'count',
  'value',
  'success',
] as const;

export type WebhookDataKey = (typeof WEBHOOK_DATA_KEYS)[number];
export type SafeWebhookData = Partial<Record<WebhookDataKey, WorkflowScalar>>;

export type ParsedWebhookPayload = {
  eventType: string;
  subject: string | null;
  data: SafeWebhookData;
};

export type WebhookHeaders = {
  timestamp: number;
  eventId: string;
  nonce: string;
  signature: string;
};

export type WebhookRejectionCode =
  | 'content-type'
  | 'body-size'
  | 'malformed-json'
  | 'invalid-headers'
  | 'expired-timestamp'
  | 'invalid-signature'
  | 'unsafe-payload'
  | 'source-disabled'
  | 'source-archived'
  | 'source-not-found'
  | 'rate-limited'
  | 'replayed-event'
  | 'duplicate-event'
  | 'gateway-error';

const ROOT_KEYS = new Set(['event', 'subject', 'data']);
const DATA_KEYS = new Set<string>(WEBHOOK_DATA_KEYS);
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const UNSAFE_TEXT = /(?:https?:\/\/|file:\/\/|localhost|127\.0\.0\.1|::1|169\.254\.169\.254|\$\{|\{\{|<%|\r|\n|\beval\s*\(|\b(?:bash|powershell|cmd\.exe|sh\s+-c)\b|\b(?:token|password|secret|provider|billing|zero.?mode)\b)/i;
const SAFE_TEXT = /^[\p{L}\p{N}][\p{L}\p{N} ._:@+/-]{0,159}$/u;

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function safeString(value: unknown, maximum = 160): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || !SAFE_TEXT.test(normalized) ||
      UNSAFE_TEXT.test(normalized) || normalized.startsWith('/') || normalized.startsWith('\\') ||
      normalized.includes('..')) return null;
  return normalized;
}

function safeScalar(key: string, value: unknown): WorkflowScalar | undefined {
  if (key === 'count') {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000
      ? value
      : undefined;
  }
  if (key === 'value') {
    if (typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= 1_000_000_000) return value;
    if (typeof value === 'boolean') return value;
    return safeString(value) ?? undefined;
  }
  if (key === 'success') return typeof value === 'boolean' ? value : undefined;
  if (key === 'severity') {
    return typeof value === 'string' && SEVERITIES.has(value) ? value : undefined;
  }
  return safeString(value) ?? undefined;
}

export function webhookBodySizeAllowed(contentLength: string | null): boolean {
  if (contentLength === null || !/^\d+$/.test(contentLength)) return false;
  const length = Number(contentLength);
  return Number.isSafeInteger(length) && length >= 0 && length <= WEBHOOK_MAX_BODY_BYTES;
}

export function parseWebhookPayload(
  value: unknown,
): { ok: true; payload: ParsedWebhookPayload } | { ok: false; code: 'unsafe-payload' } {
  if (!record(value) || !Object.keys(value).every((key) => ROOT_KEYS.has(key)) ||
      typeof value.event !== 'string' || !WEBHOOK_EVENT_TYPE.test(value.event) ||
      value.event.length > 80) {
    return { ok: false, code: 'unsafe-payload' };
  }
  const subject = value.subject === undefined ? null : safeString(value.subject);
  if (value.subject !== undefined && subject === null) return { ok: false, code: 'unsafe-payload' };
  if (value.data !== undefined && !record(value.data)) return { ok: false, code: 'unsafe-payload' };
  const entries = Object.entries((value.data ?? {}) as Record<string, unknown>);
  if (entries.length > WEBHOOK_DATA_KEYS.length || entries.some(([key]) => !DATA_KEYS.has(key))) {
    return { ok: false, code: 'unsafe-payload' };
  }
  const data: SafeWebhookData = {};
  for (const [key, item] of entries) {
    const parsed = safeScalar(key, item);
    if (parsed === undefined) return { ok: false, code: 'unsafe-payload' };
    data[key as WebhookDataKey] = parsed;
  }
  return { ok: true, payload: { eventType: value.event, subject, data } };
}

export function parseWebhookHeaders(
  headers: Headers,
): { ok: true; headers: WebhookHeaders } | { ok: false; code: 'invalid-headers' } {
  const timestampText = headers.get('x-ysd-timestamp')?.trim() ?? '';
  const eventId = headers.get('x-ysd-event-id')?.trim() ?? '';
  const nonce = headers.get('x-ysd-nonce')?.trim() ?? '';
  const signature = headers.get('x-ysd-signature')?.trim().toLowerCase() ?? '';
  if (!/^\d{10}$/.test(timestampText) || !WEBHOOK_EVENT_ID.test(eventId) ||
      !WEBHOOK_NONCE.test(nonce) || !/^v1=[a-f0-9]{64}$/.test(signature)) {
    return { ok: false, code: 'invalid-headers' };
  }
  return {
    ok: true,
    headers: { timestamp: Number(timestampText), eventId, nonce, signature },
  };
}

export function webhookTimestampAccepted(timestampSeconds: number, nowMs = Date.now()): boolean {
  if (!Number.isSafeInteger(timestampSeconds)) return false;
  return Math.abs(Math.floor(nowMs / 1000) - timestampSeconds) <= WEBHOOK_TIMESTAMP_WINDOW_SECONDS;
}

export function webhookSigningPayload(
  timestamp: number,
  eventId: string,
  nonce: string,
  rawBody: string,
): string {
  return `${timestamp}.${eventId}.${nonce}.${rawBody}`;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function bytesFromHex(value: string): Uint8Array | null {
  if (!/^[a-f0-9]{64}$/.test(value)) return null;
  return new Uint8Array(value.match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16)));
}

async function hmacKey(secret: string, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    usages,
  );
}

/** Helper for first-party documentation and deterministic tests. */
export async function createWebhookSignature(secret: string, message: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    'HMAC',
    await hmacKey(secret, ['sign']),
    new TextEncoder().encode(message),
  );
  return `v1=${hex(new Uint8Array(signature))}`;
}

/** WebCrypto verification avoids data-dependent string comparison. */
export async function verifyWebhookSignature(
  secret: string,
  message: string,
  versionedSignature: string,
): Promise<boolean> {
  const provided = bytesFromHex(versionedSignature.replace(/^v1=/, ''));
  if (!provided) return false;
  return crypto.subtle.verify(
    'HMAC',
    await hmacKey(secret, ['verify']),
    provided as BufferSource,
    new TextEncoder().encode(message),
  );
}

export function webhookSourceAccepts(status: string, archivedAt: number | null): boolean {
  return status === 'enabled' && archivedAt === null;
}

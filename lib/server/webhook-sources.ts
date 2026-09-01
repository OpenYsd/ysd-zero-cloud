import { env } from 'cloudflare:workers';

import {
  createId,
  createOpaqueToken,
  decryptSecret,
  encryptSecret,
  fingerprint,
  sha256Hex,
} from '@/lib/crypto';
import type { Actor } from '@/lib/roles';
import { can, canAccessProject } from '@/lib/roles';
import {
  parseWebhookHeaders,
  parseWebhookPayload,
  verifyWebhookSignature,
  WEBHOOK_MAX_BODY_BYTES,
  WEBHOOK_SOURCE_ID,
  WEBHOOK_SOURCE_LIMIT_PER_WORKSPACE,
  webhookBodySizeAllowed,
  webhookSigningPayload,
  webhookSourceAccepts,
  webhookTimestampAccepted,
  type ParsedWebhookPayload,
  type WebhookRejectionCode,
} from '@/lib/webhook-gateway';
import { authSecret } from './auth';
import { recordAudit, requestAuditContext } from './audit';
import { count, execute, query, queryOne } from './db';
import { enforceRateLimit } from './rate-limit';
import { emitWorkflowEvent, recordWorkflowSecurityEvent } from './workflow-events';

type WebhookSourceRow = {
  id: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  name: string;
  description: string;
  status: 'enabled' | 'disabled' | 'archived';
  secretCiphertext: string;
  secretFingerprint: string;
  secretVersion: number;
  receivedCount: number;
  acceptedCount: number;
  rejectedCount: number;
  deduplicatedCount: number;
  workflowExecutionsCreated: number;
  lastReceivedAt: number | null;
  lastAcceptedAt: number | null;
  lastRejectedAt: number | null;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  rotatedAt: number | null;
  archivedAt: number | null;
};

type WebhookDeliveryRow = {
  id: string;
  sourceId: string;
  projectId: string | null;
  externalEventId: string | null;
  eventType: string | null;
  subject: string | null;
  status: 'accepted' | 'rejected' | 'deduplicated';
  reasonCode: string | null;
  workflowEventId: string | null;
  correlationId: string | null;
  workflowExecutionsCreated: number;
  receivedAt: number;
};

export type WebhookSourceView = Omit<
  WebhookSourceRow,
  'organizationId' | 'workspaceId' | 'secretCiphertext' | 'secretFingerprint' | 'createdBy'
> & {
  webhookPath: string;
};

export type WebhookDeliveryView = WebhookDeliveryRow;

export type WebhookGatewayState = {
  sources: WebhookSourceView[];
  recentEvents: WebhookDeliveryView[];
  summary: {
    received: number;
    accepted: number;
    rejected: number;
    deduplicated: number;
    workflowExecutionsCreated: number;
  };
};

type ManagementResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; securityCode?: string };

const SOURCE_NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._-]{1,79}$/u;

function masterKey(): string {
  return env.YSD_SECRETS_KEY?.trim() || authSecret();
}

function safeDescription(value: unknown): string | null {
  if (value === undefined) return '';
  if (typeof value !== 'string') return null;
  const text = value.trim();
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 32 || code === 127) return null;
  }
  if (text.length > 240) return null;
  return text;
}

function toView(row: WebhookSourceRow): WebhookSourceView {
  const {
    organizationId: _organizationId,
    workspaceId: _workspaceId,
    secretCiphertext: _secretCiphertext,
    secretFingerprint: _secretFingerprint,
    createdBy: _createdBy,
    ...safe
  } = row;
  return { ...safe, webhookPath: `/api/webhooks/inbound/${row.id}` };
}

async function projectBelongsToWorkspace(
  workspaceId: string,
  projectId: string | null,
): Promise<boolean> {
  if (projectId === null) return true;
  return Boolean(await queryOne<{ id: string }>(
    'SELECT id FROM project WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL',
    workspaceId, projectId,
  ));
}

export async function listWebhookGatewayState(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
}): Promise<WebhookGatewayState> {
  const rows = await query<WebhookSourceRow>(
    `SELECT * FROM webhook_source
      WHERE organizationId = ? AND workspaceId = ? AND archivedAt IS NULL
      ORDER BY updatedAt DESC LIMIT 100`,
    input.organizationId, input.workspaceId,
  );
  const visible = rows.filter((row) => canAccessProject(input.actor, row.projectId));
  const ids = new Set(visible.map((row) => row.id));
  const deliveries = ids.size === 0
    ? []
    : (await query<WebhookDeliveryRow>(
        `SELECT id, sourceId, projectId, externalEventId, eventType, subject, status,
                reasonCode, workflowEventId, correlationId, workflowExecutionsCreated, receivedAt
           FROM webhook_delivery
          WHERE organizationId = ? AND workspaceId = ?
          ORDER BY receivedAt DESC LIMIT 100`,
        input.organizationId, input.workspaceId,
      )).filter((row) => ids.has(row.sourceId)).slice(0, 30);
  return {
    sources: visible.map(toView),
    recentEvents: deliveries,
    summary: visible.reduce(
      (summary, row) => ({
        received: summary.received + row.receivedCount,
        accepted: summary.accepted + row.acceptedCount,
        rejected: summary.rejected + row.rejectedCount,
        deduplicated: summary.deduplicated + row.deduplicatedCount,
        workflowExecutionsCreated:
          summary.workflowExecutionsCreated + row.workflowExecutionsCreated,
      }),
      { received: 0, accepted: 0, rejected: 0, deduplicated: 0, workflowExecutionsCreated: 0 },
    ),
  };
}

export async function createWebhookSource(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  name: unknown;
  description: unknown;
  projectId: unknown;
}): Promise<ManagementResult<{ source: WebhookSourceView; secret: string }>> {
  if (!can(input.actor, 'webhook.manage')) {
    return { ok: false, status: 403, error: 'Only owners and admins can manage webhook sources.' };
  }
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  const description = safeDescription(input.description);
  const projectId = input.projectId === null || input.projectId === undefined || input.projectId === ''
    ? null
    : typeof input.projectId === 'string' ? input.projectId : '__invalid__';
  if (!SOURCE_NAME.test(name) || description === null) {
    return { ok: false, status: 400, error: 'Source name or description is invalid.' };
  }
  if (!canAccessProject(input.actor, projectId) ||
      !(await projectBelongsToWorkspace(input.workspaceId, projectId))) {
    return {
      ok: false, status: 403, error: 'The source project is outside this workspace.',
      securityCode: 'webhook-cross-workspace-source',
    };
  }
  if (await count(
    'SELECT COUNT(*) AS total FROM webhook_source WHERE workspaceId = ? AND archivedAt IS NULL',
    input.workspaceId,
  ) >= WEBHOOK_SOURCE_LIMIT_PER_WORKSPACE) {
    return { ok: false, status: 409, error: 'This workspace has reached its Zero Mode source limit.' };
  }
  const duplicate = await queryOne<{ id: string }>(
    'SELECT id FROM webhook_source WHERE workspaceId = ? AND name = ? AND archivedAt IS NULL',
    input.workspaceId, name,
  );
  if (duplicate) return { ok: false, status: 409, error: 'A source with this name already exists.' };
  const secret = createOpaqueToken('ysd_whsec');
  const [secretCiphertext, secretFingerprint] = await Promise.all([
    encryptSecret(secret, masterKey()),
    fingerprint(secret),
  ]);
  const now = Date.now();
  const id = createId('whsrc');
  await execute(
    `INSERT INTO webhook_source
      (id, organizationId, workspaceId, projectId, name, description, status,
       secretCiphertext, secretFingerprint, secretVersion, createdBy, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, 'enabled', ?, ?, 1, ?, ?, ?)`,
    id, input.organizationId, input.workspaceId, projectId, name, description,
    secretCiphertext, secretFingerprint, input.actor.userId, now, now,
  );
  const row = await queryOne<WebhookSourceRow>(
    'SELECT * FROM webhook_source WHERE organizationId = ? AND workspaceId = ? AND id = ?',
    input.organizationId, input.workspaceId, id,
  );
  if (!row) return { ok: false, status: 500, error: 'Webhook source could not be created.' };
  return { ok: true, value: { source: toView(row), secret } };
}

async function managedSource(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  sourceId: string;
}): Promise<ManagementResult<WebhookSourceRow>> {
  if (!can(input.actor, 'webhook.manage')) {
    return { ok: false, status: 403, error: 'Only owners and admins can manage webhook sources.' };
  }
  if (!WEBHOOK_SOURCE_ID.test(input.sourceId)) {
    return { ok: false, status: 404, error: 'Webhook source not found.' };
  }
  const source = await queryOne<WebhookSourceRow>(
    'SELECT * FROM webhook_source WHERE organizationId = ? AND workspaceId = ? AND id = ?',
    input.organizationId, input.workspaceId, input.sourceId,
  );
  if (!source || !canAccessProject(input.actor, source.projectId)) {
    return { ok: false, status: 404, error: 'Webhook source not found.' };
  }
  return { ok: true, value: source };
}

export async function updateWebhookSource(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  sourceId: string;
  operation: unknown;
  name?: unknown;
  description?: unknown;
}): Promise<ManagementResult<{ source: WebhookSourceView; secret?: string }>> {
  const found = await managedSource(input);
  if (!found.ok) return found;
  const source = found.value;
  if (source.archivedAt !== null || source.status === 'archived') {
    return { ok: false, status: 409, error: 'Archived webhook sources cannot be changed.' };
  }
  const operation = input.operation;
  const now = Date.now();
  let secret: string | undefined;
  if (operation === 'rotate') {
    secret = createOpaqueToken('ysd_whsec');
    const [ciphertext, nextFingerprint] = await Promise.all([
      encryptSecret(secret, masterKey()),
      fingerprint(secret),
    ]);
    await execute(
      `UPDATE webhook_source SET secretCiphertext = ?, secretFingerprint = ?,
              secretVersion = secretVersion + 1, rotatedAt = ?, updatedAt = ?
        WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
      ciphertext, nextFingerprint, now, now,
      input.organizationId, input.workspaceId, source.id,
    );
  } else if (operation === 'enable' || operation === 'disable') {
    await execute(
      `UPDATE webhook_source SET status = ?, updatedAt = ?
        WHERE organizationId = ? AND workspaceId = ? AND id = ? AND archivedAt IS NULL`,
      operation === 'enable' ? 'enabled' : 'disabled', now,
      input.organizationId, input.workspaceId, source.id,
    );
  } else if (operation === 'update') {
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    const description = safeDescription(input.description);
    if (!SOURCE_NAME.test(name) || description === null) {
      return { ok: false, status: 400, error: 'Source name or description is invalid.' };
    }
    const duplicate = await queryOne<{ id: string }>(
      `SELECT id FROM webhook_source
        WHERE workspaceId = ? AND name = ? AND id <> ? AND archivedAt IS NULL`,
      input.workspaceId, name, source.id,
    );
    if (duplicate) return { ok: false, status: 409, error: 'A source with this name already exists.' };
    await execute(
      `UPDATE webhook_source SET name = ?, description = ?, updatedAt = ?
        WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
      name, description, now, input.organizationId, input.workspaceId, source.id,
    );
  } else {
    return { ok: false, status: 400, error: 'Unknown webhook source operation.' };
  }
  const row = await queryOne<WebhookSourceRow>(
    'SELECT * FROM webhook_source WHERE organizationId = ? AND workspaceId = ? AND id = ?',
    input.organizationId, input.workspaceId, source.id,
  );
  if (!row) return { ok: false, status: 500, error: 'Webhook source could not be updated.' };
  return { ok: true, value: { source: toView(row), ...(secret ? { secret } : {}) } };
}

export async function archiveWebhookSource(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  sourceId: string;
}): Promise<ManagementResult<{ sourceId: string }>> {
  const found = await managedSource(input);
  if (!found.ok) return found;
  if (found.value.archivedAt !== null) return { ok: true, value: { sourceId: found.value.id } };
  const invalidated = createOpaqueToken('ysd_archived');
  const [ciphertext, nextFingerprint] = await Promise.all([
    encryptSecret(invalidated, masterKey()),
    fingerprint(invalidated),
  ]);
  const now = Date.now();
  await execute(
    `UPDATE webhook_source SET status = 'archived', archivedAt = ?, updatedAt = ?,
            secretCiphertext = ?, secretFingerprint = ?, secretVersion = secretVersion + 1
      WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
    now, now, ciphertext, nextFingerprint,
    input.organizationId, input.workspaceId, found.value.id,
  );
  return { ok: true, value: { sourceId: found.value.id } };
}

function rejectionStatus(code: WebhookRejectionCode): number {
  if (code === 'source-not-found') return 404;
  if (code === 'source-disabled' || code === 'source-archived') return 410;
  if (code === 'rate-limited') return 429;
  if (code === 'body-size') return 413;
  if (code === 'duplicate-event' || code === 'replayed-event') return 409;
  if (code === 'gateway-error') return 503;
  return 400;
}

async function recordDelivery(input: {
  source: WebhookSourceRow;
  status: 'accepted' | 'rejected' | 'deduplicated';
  reasonCode?: WebhookRejectionCode;
  eventId?: string;
  parsed?: ParsedWebhookPayload;
  workflowEventId?: string;
  correlationId?: string;
  receivedAt: number;
}): Promise<void> {
  await execute(
    `INSERT INTO webhook_delivery
      (id, organizationId, workspaceId, sourceId, projectId, externalEventId,
       eventType, subject, status, reasonCode, workflowEventId, correlationId,
       workflowExecutionsCreated, receivedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    createId('whdel'), input.source.organizationId, input.source.workspaceId,
    input.source.id, input.source.projectId, input.eventId?.slice(0, 128) ?? null,
    input.parsed?.eventType ?? null, input.parsed?.subject ?? null, input.status,
    input.reasonCode ?? null, input.workflowEventId ?? null,
    input.correlationId ?? null, input.receivedAt,
  );
  const counter = input.status === 'accepted'
    ? 'acceptedCount'
    : input.status === 'deduplicated' ? 'deduplicatedCount' : 'rejectedCount';
  const last = input.status === 'accepted' ? 'lastAcceptedAt' : 'lastRejectedAt';
  await execute(
    `UPDATE webhook_source SET ${counter} = ${counter} + 1, ${last} = ?, updatedAt = ? WHERE id = ?`,
    input.receivedAt, input.receivedAt, input.source.id,
  );
}

async function rejectWebhook(input: {
  request: Request;
  source: WebhookSourceRow;
  code: WebhookRejectionCode;
  eventId?: string;
  parsed?: ParsedWebhookPayload;
  receivedAt: number;
  headers?: HeadersInit;
}): Promise<Response> {
  await recordDelivery({
    source: input.source,
    status: input.code === 'duplicate-event' || input.code === 'replayed-event' ? 'deduplicated' : 'rejected',
    reasonCode: input.code,
    eventId: input.eventId,
    parsed: input.parsed,
    receivedAt: input.receivedAt,
  }).catch(() => undefined);
  await Promise.all([
    recordWorkflowSecurityEvent({
      workspaceId: input.source.workspaceId,
      type: `webhook-${input.code}`,
      severity: input.code === 'duplicate-event' || input.code === 'replayed-event' ? 'medium' : 'high',
      detail: `An inbound webhook was rejected by the ${input.code} guard. No payload was retained.`,
    }).catch(() => undefined),
    recordAudit({
      organizationId: input.source.organizationId,
      workspaceId: input.source.workspaceId,
      actorType: 'system',
      actorId: `webhook:${input.source.id}`,
      action: input.code === 'duplicate-event' || input.code === 'replayed-event'
        ? 'webhook.delivery.deduplicated'
        : 'webhook.delivery.rejected',
      resourceType: 'webhook_source',
      resourceId: input.source.id,
      outcome: 'denied',
      ...requestAuditContext(input.request),
      metadata: { reasonCode: input.code },
    }).catch(() => undefined),
  ]);
  const responseHeaders = new Headers(input.headers);
  responseHeaders.set('cache-control', 'no-store');
  return Response.json(
    { error: 'Webhook rejected.', code: input.code },
    { status: rejectionStatus(input.code), headers: responseHeaders },
  );
}

/** Public ingress. Authentication is the versioned HMAC contract, not a user session. */
export async function ingestWebhook(request: Request, sourceId: string): Promise<Response> {
  if (!WEBHOOK_SOURCE_ID.test(sourceId)) {
    console.warn('[ysd] webhook rejected', { reasonCode: 'source-not-found' });
    return Response.json({ error: 'Webhook source is unavailable.' }, { status: 404, headers: { 'cache-control': 'no-store' } });
  }
  const source = await queryOne<WebhookSourceRow>('SELECT * FROM webhook_source WHERE id = ?', sourceId);
  if (!source) {
    console.warn('[ysd] webhook rejected', { reasonCode: 'source-not-found' });
    return Response.json({ error: 'Webhook source is unavailable.' }, { status: 404, headers: { 'cache-control': 'no-store' } });
  }
  const receivedAt = Date.now();
  await execute(
    `UPDATE webhook_source SET receivedCount = receivedCount + 1,
            lastReceivedAt = ?, updatedAt = ? WHERE id = ?`,
    receivedAt, receivedAt, source.id,
  );
  if (!webhookSourceAccepts(source.status, source.archivedAt)) {
    return rejectWebhook({
      request, source,
      code: source.archivedAt !== null ? 'source-archived' : 'source-disabled',
      receivedAt,
    });
  }
  const sourceLimit = await enforceRateLimit('webhook:source', source.id, 'Webhook source rate limit reached.');
  if (sourceLimit.response) {
    return rejectWebhook({ request, source, code: 'rate-limited', receivedAt, headers: sourceLimit.headers });
  }
  const workspaceLimit = await enforceRateLimit(
    'webhook:workspace', source.workspaceId, 'Workspace webhook rate limit reached.',
  );
  if (workspaceLimit.response) {
    return rejectWebhook({ request, source, code: 'rate-limited', receivedAt, headers: workspaceLimit.headers });
  }
  const contentType = request.headers.get('content-type') ?? '';
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return rejectWebhook({ request, source, code: 'content-type', receivedAt });
  }
  const lengthText = request.headers.get('content-length');
  if (!webhookBodySizeAllowed(lengthText)) {
    return rejectWebhook({ request, source, code: 'body-size', receivedAt });
  }
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > WEBHOOK_MAX_BODY_BYTES) {
    return rejectWebhook({ request, source, code: 'body-size', receivedAt });
  }
  const parsedHeaders = parseWebhookHeaders(request.headers);
  if (!parsedHeaders.ok) {
    return rejectWebhook({ request, source, code: parsedHeaders.code, receivedAt });
  }
  if (!webhookTimestampAccepted(parsedHeaders.headers.timestamp, receivedAt)) {
    return rejectWebhook({
      request, source, code: 'expired-timestamp',
      eventId: parsedHeaders.headers.eventId, receivedAt,
    });
  }
  let secret: string;
  try {
    secret = await decryptSecret(source.secretCiphertext, masterKey());
  } catch {
    return rejectWebhook({
      request, source, code: 'gateway-error',
      eventId: parsedHeaders.headers.eventId, receivedAt,
    });
  }
  const signatureOk = await verifyWebhookSignature(
    secret,
    webhookSigningPayload(
      parsedHeaders.headers.timestamp,
      parsedHeaders.headers.eventId,
      parsedHeaders.headers.nonce,
      raw,
    ),
    parsedHeaders.headers.signature,
  );
  if (!signatureOk) {
    return rejectWebhook({
      request, source, code: 'invalid-signature',
      eventId: parsedHeaders.headers.eventId, receivedAt,
    });
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return rejectWebhook({
      request, source, code: 'malformed-json',
      eventId: parsedHeaders.headers.eventId, receivedAt,
    });
  }
  const parsed = parseWebhookPayload(json);
  if (!parsed.ok) {
    return rejectWebhook({
      request, source, code: parsed.code,
      eventId: parsedHeaders.headers.eventId, receivedAt,
    });
  }
  const nonceHash = await sha256Hex(parsedHeaders.headers.nonce);
  const guard = await execute(
    `INSERT OR IGNORE INTO webhook_replay_guard
      (organizationId, workspaceId, sourceId, externalEventId, nonceHash, receivedAt)
     VALUES (?, ?, ?, ?, ?, ?)`,
    source.organizationId, source.workspaceId, source.id,
    parsedHeaders.headers.eventId, nonceHash, receivedAt,
  );
  if ((guard.meta.changes ?? 0) === 0) {
    const duplicateId = await queryOne<{ externalEventId: string }>(
      'SELECT externalEventId FROM webhook_replay_guard WHERE sourceId = ? AND externalEventId = ?',
      source.id, parsedHeaders.headers.eventId,
    );
    return rejectWebhook({
      request, source, code: duplicateId ? 'duplicate-event' : 'replayed-event',
      eventId: parsedHeaders.headers.eventId,
      parsed: parsed.payload, receivedAt,
    });
  }
  const correlationId = createId('whcorr');
  const emitted = await emitWorkflowEvent({
    workspaceId: source.workspaceId,
    type: 'external.event',
    resourceType: 'webhook_source',
    resourceId: source.id,
    projectId: source.projectId,
    payload: {
      sourceId: source.id,
      externalEventType: parsed.payload.eventType,
      externalEventId: parsedHeaders.headers.eventId,
      subject: parsed.payload.subject,
      ...parsed.payload.data,
    },
    dedupeKey: `external:${source.id}:${parsedHeaders.headers.eventId}`,
    correlationId,
    createdAt: receivedAt,
  });
  if (!emitted.ok) {
    await execute(
      'DELETE FROM webhook_replay_guard WHERE sourceId = ? AND externalEventId = ? AND nonceHash = ?',
      source.id, parsedHeaders.headers.eventId, nonceHash,
    ).catch(() => undefined);
    return rejectWebhook({
      request, source, code: 'gateway-error', eventId: parsedHeaders.headers.eventId,
      parsed: parsed.payload, receivedAt,
    });
  }
  if (emitted.duplicate) {
    return rejectWebhook({
      request, source, code: 'duplicate-event', eventId: parsedHeaders.headers.eventId,
      parsed: parsed.payload, receivedAt,
    });
  }
  await recordDelivery({
    source, status: 'accepted', eventId: parsedHeaders.headers.eventId,
    parsed: parsed.payload, workflowEventId: emitted.event.id,
    correlationId: emitted.event.correlationId, receivedAt,
  });
  await recordAudit({
    organizationId: source.organizationId,
    workspaceId: source.workspaceId,
    actorType: 'system',
    actorId: `webhook:${source.id}`,
    action: 'webhook.delivery.accepted',
    resourceType: 'webhook_source',
    resourceId: source.id,
    outcome: 'success',
    ...requestAuditContext(request),
    metadata: {
      eventType: parsed.payload.eventType,
      correlationId: emitted.event.correlationId,
      secretVersion: source.secretVersion,
    },
  }).catch(() => undefined);
  const responseHeaders = new Headers(sourceLimit.headers);
  responseHeaders.set('cache-control', 'no-store');
  return Response.json(
    {
      accepted: true,
      eventId: parsedHeaders.headers.eventId,
      correlationId: emitted.event.correlationId,
      duplicate: false,
    },
    { status: 202, headers: responseHeaders },
  );
}

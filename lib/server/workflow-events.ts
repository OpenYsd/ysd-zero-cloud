import { createId } from '@/lib/crypto';
import {
  MAX_WORKFLOW_CHAIN_DEPTH,
  WORKFLOW_TRIGGER_TYPES,
  redactWorkflowValue,
  type TrustedWorkflowEvent,
  type WorkflowScalar,
  type WorkflowTriggerType,
} from '@/lib/workflows';
import { execute, queryOne } from './db';

const TYPES = new Set<string>(WORKFLOW_TRIGGER_TYPES);
const PAYLOAD_KEYS = new Set([
  'status', 'previousStatus', 'severity', 'previousSeverity', 'role',
  'previousRole', 'projectId', 'nodeId', 'deploymentId', 'serverId',
  'jobId', 'findingId', 'crashCount', 'failureCount', 'environment',
]);
const RESOURCE_ID = /^[a-z][a-z0-9_-]{2,159}$/i;

type EventRow = Omit<TrustedWorkflowEvent, 'payload'> & { payload: string };

export type EmitWorkflowEventInput = {
  workspaceId: string;
  type: WorkflowTriggerType;
  resourceType: string;
  resourceId: string | null;
  projectId?: string | null;
  payload?: Record<string, WorkflowScalar>;
  dedupeKey: string;
  source?: 'system' | 'schedule';
  correlationId?: string;
  causationId?: string | null;
  sourceWorkflowId?: string | null;
  chainDepth?: number;
  createdAt?: number;
};

function safePayload(value: Record<string, WorkflowScalar> | undefined): Record<string, WorkflowScalar> | null {
  if (!value) return {};
  const entries = Object.entries(value);
  if (entries.length > 20) return null;
  const clean: Record<string, WorkflowScalar> = {};
  for (const [key, item] of entries) {
    if (!PAYLOAD_KEYS.has(key) ||
        !(item === null || typeof item === 'boolean' ||
          (typeof item === 'number' && Number.isFinite(item)) ||
          (typeof item === 'string' && item.length <= 160))) return null;
    clean[key] = item;
  }
  return clean;
}

function toEvent(row: EventRow): TrustedWorkflowEvent {
  let payload: Record<string, WorkflowScalar> = {};
  try {
    payload = JSON.parse(row.payload) as Record<string, WorkflowScalar>;
  } catch {
    payload = {};
  }
  return { ...row, payload };
}

async function workspaceOrganization(workspaceId: string): Promise<string | null> {
  return (await queryOne<{ organizationId: string }>(
    `SELECT organizationId FROM workspace
      WHERE id = ? AND organizationId IS NOT NULL AND archivedAt IS NULL`,
    workspaceId,
  ))?.organizationId ?? null;
}

async function resourceProject(input: {
  workspaceId: string;
  type: WorkflowTriggerType;
  resourceId: string | null;
}): Promise<{ exists: boolean; projectId: string | null }> {
  if (input.type === 'schedule') {
    const row = await queryOne<{ projectId: string | null }>(
      'SELECT projectId FROM workflow WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL',
      input.workspaceId, input.resourceId,
    );
    return row ? { exists: true, projectId: row.projectId } : { exists: false, projectId: null };
  }
  if (input.type === 'manual') return { exists: false, projectId: null };
  if (!input.resourceId || !RESOURCE_ID.test(input.resourceId)) return { exists: false, projectId: null };
  const prefix = input.type.split('.')[0];
  if (prefix === 'deployment') {
    const row = await queryOne<{ projectId: string | null }>(
      'SELECT projectId FROM deployment WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL',
      input.workspaceId, input.resourceId,
    );
    return row ? { exists: true, projectId: row.projectId } : { exists: false, projectId: null };
  }
  if (prefix === 'node') {
    const row = await queryOne<{ id: string }>(
      'SELECT id FROM compute_node WHERE workspaceId = ? AND id = ?',
      input.workspaceId, input.resourceId,
    );
    return { exists: Boolean(row), projectId: null };
  }
  if (prefix === 'shield') {
    const row = await queryOne<{ id: string }>(
      'SELECT id FROM shield_finding WHERE workspaceId = ? AND id = ?',
      input.workspaceId, input.resourceId,
    );
    return { exists: Boolean(row), projectId: null };
  }
  if (prefix === 'game_server') {
    const row = await queryOne<{ id: string }>(
      'SELECT id FROM game_server WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL',
      input.workspaceId, input.resourceId,
    );
    return { exists: Boolean(row), projectId: null };
  }
  if (prefix === 'ai') {
    const row = await queryOne<{ id: string }>(
      'SELECT jobId AS id FROM ai_inference WHERE workspaceId = ? AND jobId = ?',
      input.workspaceId, input.resourceId,
    );
    return { exists: Boolean(row), projectId: null };
  }
  if (prefix === 'organization') {
    const row = await queryOne<{ organizationId: string }>(
      `SELECT organizationId FROM organization_member WHERE organizationId = (
         SELECT organizationId FROM workspace WHERE id = ?
       ) AND userId = ?
       UNION ALL
       SELECT organizationId FROM organization_invitation WHERE organizationId = (
         SELECT organizationId FROM workspace WHERE id = ?
       ) AND id = ? LIMIT 1`,
      input.workspaceId, input.resourceId, input.workspaceId, input.resourceId,
    );
    return { exists: Boolean(row), projectId: null };
  }
  return { exists: false, projectId: null };
}

export async function recordWorkflowSecurityEvent(input: {
  workspaceId: string;
  workflowId?: string | null;
  executionId?: string | null;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}): Promise<void> {
  const organizationId = await workspaceOrganization(input.workspaceId);
  if (!organizationId) return;
  await execute(
    `INSERT INTO workflow_security_event
      (id, organizationId, workspaceId, workflowId, executionId, type, severity, detail, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    createId('wfsec'), organizationId, input.workspaceId,
    input.workflowId ?? null, input.executionId ?? null,
    input.type.slice(0, 100), input.severity,
    input.detail.slice(0, 500), Date.now(),
  );
}

/**
 * Writes one server-derived event. There is intentionally no public raw-event
 * endpoint; manual runs are tied to one authorized workflow by the engine.
 */
export async function emitWorkflowEvent(
  input: EmitWorkflowEventInput,
): Promise<{ ok: true; event: TrustedWorkflowEvent; duplicate: boolean } | { ok: false; error: string }> {
  if (!TYPES.has(input.type) || input.type === 'manual') {
    return { ok: false, error: 'The event type is not accepted from this source.' };
  }
  const organizationId = await workspaceOrganization(input.workspaceId);
  if (!organizationId) return { ok: false, error: 'Workspace not found.' };
  const payload = safePayload(input.payload);
  if (!payload) {
    await recordWorkflowSecurityEvent({
      workspaceId: input.workspaceId, workflowId: input.sourceWorkflowId,
      type: 'workflow-event-payload-rejected', severity: 'high',
      detail: 'An internal event attempted to include an unknown, oversized, or sensitive payload field.',
    });
    return { ok: false, error: 'Event payload fields are invalid.' };
  }
  const chainDepth = input.chainDepth ?? 0;
  if (!Number.isSafeInteger(chainDepth) || chainDepth < 0 || chainDepth > MAX_WORKFLOW_CHAIN_DEPTH) {
    await recordWorkflowSecurityEvent({
      workspaceId: input.workspaceId, workflowId: input.sourceWorkflowId,
      type: 'workflow-chain-depth', severity: 'high',
      detail: 'An event chain exceeded the maximum automation depth.',
    });
    return { ok: false, error: 'Event chain depth exceeded.' };
  }
  const resource = await resourceProject({
    workspaceId: input.workspaceId, type: input.type, resourceId: input.resourceId,
  });
  if (!resource.exists) {
    await recordWorkflowSecurityEvent({
      workspaceId: input.workspaceId, workflowId: input.sourceWorkflowId,
      type: 'workflow-forged-event', severity: 'critical',
      detail: 'An event referenced a resource outside its trusted workspace schema.',
    });
    return { ok: false, error: 'Event resource was not found in this workspace.' };
  }
  if (input.projectId && resource.projectId && input.projectId !== resource.projectId) {
    await recordWorkflowSecurityEvent({
      workspaceId: input.workspaceId, workflowId: input.sourceWorkflowId,
      type: 'workflow-cross-project-event', severity: 'critical',
      detail: 'An event attempted to override the resource project identity.',
    });
    return { ok: false, error: 'Event project does not match its resource.' };
  }
  const dedupeKey = input.dedupeKey.trim().slice(0, 180);
  if (!dedupeKey || dedupeKey.length < 8) return { ok: false, error: 'A stable server dedupe key is required.' };
  const existing = await queryOne<EventRow>(
    'SELECT * FROM workflow_event WHERE organizationId = ? AND dedupeKey = ?',
    organizationId, dedupeKey,
  );
  if (existing) return { ok: true, event: toEvent(existing), duplicate: true };
  const now = input.createdAt ?? Date.now();
  const id = createId('wfevt');
  const correlationId = (input.correlationId?.trim().slice(0, 160) || id);
  await execute(
    `INSERT OR IGNORE INTO workflow_event
      (id, organizationId, workspaceId, projectId, type, resourceType, resourceId,
       payload, source, trusted, dedupeKey, correlationId, causationId,
       sourceWorkflowId, chainDepth, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
    id, organizationId, input.workspaceId, resource.projectId ?? input.projectId ?? null,
    input.type, input.resourceType.slice(0, 80), input.resourceId,
    JSON.stringify(redactWorkflowValue(payload)), input.source ?? 'system', dedupeKey,
    correlationId, input.causationId?.slice(0, 160) ?? null,
    input.sourceWorkflowId ?? null, chainDepth, now,
  );
  const row = await queryOne<EventRow>(
    'SELECT * FROM workflow_event WHERE organizationId = ? AND dedupeKey = ?',
    organizationId, dedupeKey,
  );
  return row
    ? { ok: true, event: toEvent(row), duplicate: row.id !== id }
    : { ok: false, error: 'Event could not be recorded.' };
}

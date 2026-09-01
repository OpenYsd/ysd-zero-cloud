import { createId, sha256Hex } from '@/lib/crypto';
import type { Incident, IncidentState, IncidentTimelineEvent } from '@/lib/domain';
import {
  INCIDENT_LIMITS,
  canManageIncident,
  canResolveIncident,
  safeIncidentText,
  type IncidentEventType,
  type IncidentFilters,
  type IncidentMutation,
  type IncidentSeverity,
  type IncidentStatus,
} from '@/lib/incidents';
import { canAccessProject, type Actor } from '@/lib/roles';
import type { WorkflowScalar } from '@/lib/workflows';
import { execute, query, queryOne } from './db';
import { recordAudit } from './audit';
import { emitWorkflowEvent } from './workflow-events';

type IncidentRow = Omit<Incident, 'timeline'> & {
  organizationId: string;
  workspaceId: string;
  dedupeKey: string;
};
type TimelineRow = Omit<IncidentTimelineEvent, 'metadata'> & { metadata: string };

type MutationResult =
  | { ok: true; incident: Incident }
  | { ok: false; status: number; error: string; securityCode?: string };

export type CreateIncidentInput = {
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  workflowId?: string | null;
  executionId?: string | null;
  resourceType: string;
  resourceId: string | null;
  title: string;
  detail: string;
  severity: IncidentSeverity;
  createdBy: string;
  correlationId: string;
  causationId?: string | null;
  sourceWorkflowId?: string | null;
  chainDepth?: number;
};

function parseMetadata(value: string): Record<string, string | number | boolean | null> {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(parsed).filter(([, item]) =>
      item === null || typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean',
    )) as Record<string, string | number | boolean | null>;
  } catch {
    return {};
  }
}

function timeline(row: TimelineRow): IncidentTimelineEvent {
  return { ...row, metadata: parseMetadata(row.metadata) };
}

function projectClause(actor: Actor, alias = 'i'): { sql: string; params: string[] } {
  if (actor.projectIds === null || actor.projectIds === undefined) return { sql: '', params: [] };
  if (actor.projectIds.length === 0) return { sql: ` AND ${alias}.projectId IS NULL AND 0`, params: [] };
  return {
    sql: ` AND ${alias}.projectId IN (${actor.projectIds.map(() => '?').join(',')})`,
    params: [...actor.projectIds],
  };
}

async function loadIncident(
  workspaceId: string,
  incidentId: string,
  actor: Actor,
): Promise<Incident | null> {
  const scope = projectClause(actor);
  const row = await queryOne<IncidentRow>(
    `SELECT i.id, i.projectId, i.workflowId, i.executionId, i.resourceType, i.resourceId,
            i.title, i.detail, i.severity, i.status, i.correlationId, i.dedupeKey,
            i.occurrenceCount, i.lastSeenAt, i.assignedTo, u.name AS assigneeName,
            i.acknowledgedAt, i.acknowledgedBy, i.resolvedAt, i.resolvedBy,
            i.resolution, i.revision, i.createdBy, i.createdAt, i.updatedAt
       FROM workflow_incident i LEFT JOIN "user" u ON u.id = i.assignedTo
      WHERE i.workspaceId = ? AND i.id = ?${scope.sql}`,
    workspaceId, incidentId, ...scope.params,
  );
  if (!row) return null;
  const events = await query<TimelineRow>(
    `SELECT id, incidentId, projectId, type, actorType, actorId, correlationId,
            fromStatus, toStatus, message, metadata, createdAt
       FROM incident_event WHERE workspaceId = ? AND incidentId = ?
      ORDER BY createdAt DESC, id DESC LIMIT ?`,
    workspaceId, incidentId, INCIDENT_LIMITS.timeline,
  );
  const { dedupeKey: _dedupeKey, ...incident } = row;
  return { ...incident, timeline: events.map(timeline) };
}

function filterClause(filters: IncidentFilters): { sql: string; params: unknown[] } {
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (filters.status !== 'all') { clauses.push('i.status = ?'); params.push(filters.status); }
  if (filters.severity !== 'all') { clauses.push('i.severity = ?'); params.push(filters.severity); }
  if (filters.assignee === 'unassigned') clauses.push('i.assignedTo IS NULL');
  else if (filters.assignee !== 'all') { clauses.push('i.assignedTo = ?'); params.push(filters.assignee); }
  if (filters.projectId !== 'all') { clauses.push('i.projectId = ?'); params.push(filters.projectId); }
  if (filters.resourceType !== 'all') { clauses.push('i.resourceType = ?'); params.push(filters.resourceType); }
  if (filters.search) {
    clauses.push(`(i.title LIKE ? ESCAPE '\\' OR i.resourceType LIKE ? ESCAPE '\\' OR COALESCE(i.resourceId, '') LIKE ? ESCAPE '\\' OR i.correlationId LIKE ? ESCAPE '\\')`);
    const escaped = filters.search.replace(/[\\%_]/g, '\\$&');
    params.push(`%${escaped}%`, `%${escaped}%`, `%${escaped}%`, `%${escaped}%`);
  }
  return { sql: clauses.length ? ` AND ${clauses.join(' AND ')}` : '', params };
}

export async function listIncidentState(input: {
  workspaceId: string;
  actor: Actor;
  filters: IncidentFilters;
}): Promise<IncidentState> {
  const scope = projectClause(input.actor);
  const filter = filterClause(input.filters);
  const rows = await query<IncidentRow>(
    `SELECT i.id, i.projectId, i.workflowId, i.executionId, i.resourceType, i.resourceId,
            i.title, i.detail, i.severity, i.status, i.correlationId, i.dedupeKey,
            i.occurrenceCount, i.lastSeenAt, i.assignedTo, u.name AS assigneeName,
            i.acknowledgedAt, i.acknowledgedBy, i.resolvedAt, i.resolvedBy,
            i.resolution, i.revision, i.createdBy, i.createdAt, i.updatedAt
       FROM workflow_incident i LEFT JOIN "user" u ON u.id = i.assignedTo
      WHERE i.workspaceId = ?${scope.sql}${filter.sql}
      ORDER BY CASE i.status WHEN 'open' THEN 1 WHEN 'acknowledged' THEN 2 ELSE 3 END,
               CASE i.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
               i.lastSeenAt DESC LIMIT ?`,
    input.workspaceId, ...scope.params, ...filter.params, INCIDENT_LIMITS.list,
  );
  const ids = rows.map((row) => row.id);
  const events = ids.length
    ? await query<TimelineRow>(
        `SELECT id, incidentId, projectId, type, actorType, actorId, correlationId,
                fromStatus, toStatus, message, metadata, createdAt
           FROM incident_event WHERE workspaceId = ?
            AND incidentId IN (${ids.map(() => '?').join(',')})
          ORDER BY createdAt DESC, id DESC`,
        input.workspaceId, ...ids,
      )
    : [];
  const byIncident = new Map<string, IncidentTimelineEvent[]>();
  for (const event of events) {
    const bucket = byIncident.get(event.incidentId) ?? [];
    if (bucket.length < INCIDENT_LIMITS.timeline) bucket.push(timeline(event));
    byIncident.set(event.incidentId, bucket);
  }
  const summary = await queryOne<{
    open: number; acknowledged: number; resolved: number; critical: number;
    unassigned: number; occurrences: number; mttaMs: number | null; mttrMs: number | null;
  }>(
    `SELECT
       SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open,
       SUM(CASE WHEN status = 'acknowledged' THEN 1 ELSE 0 END) AS acknowledged,
       SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved,
       SUM(CASE WHEN severity = 'critical' AND status <> 'resolved' THEN 1 ELSE 0 END) AS critical,
       SUM(CASE WHEN assignedTo IS NULL AND status <> 'resolved' THEN 1 ELSE 0 END) AS unassigned,
       COALESCE(SUM(occurrenceCount), 0) AS occurrences,
       CAST(AVG(CASE WHEN acknowledgedAt IS NOT NULL THEN acknowledgedAt - createdAt END) AS INTEGER) AS mttaMs,
       CAST(AVG(CASE WHEN resolvedAt IS NOT NULL THEN resolvedAt - createdAt END) AS INTEGER) AS mttrMs
     FROM workflow_incident i WHERE workspaceId = ?${scope.sql}`,
    input.workspaceId, ...scope.params,
  );
  return {
    incidents: rows.map(({ dedupeKey: _dedupeKey, ...row }) => ({
      ...row,
      timeline: byIncident.get(row.id) ?? [],
    })),
    summary: {
      open: summary?.open ?? 0,
      acknowledged: summary?.acknowledged ?? 0,
      resolved: summary?.resolved ?? 0,
      critical: summary?.critical ?? 0,
      unassigned: summary?.unassigned ?? 0,
      occurrences: summary?.occurrences ?? 0,
      mttaMs: summary?.mttaMs ?? null,
      mttrMs: summary?.mttrMs ?? null,
    },
    filters: input.filters,
    hardLimits: {
      list: INCIDENT_LIMITS.list,
      timeline: INCIDENT_LIMITS.timeline,
      activePerWorkspace: INCIDENT_LIMITS.activePerWorkspace,
    },
    zeroModeEnforced: true,
    projectedMonthlyCost: 0,
  };
}

async function appendEvent(input: {
  incident: IncidentRow;
  type: IncidentEventType;
  actorType: 'user' | 'system' | 'workflow';
  actorId: string;
  fromStatus?: IncidentStatus | null;
  toStatus?: IncidentStatus | null;
  message?: string | null;
  metadata?: Record<string, string | number | boolean | null>;
  idempotencyKey: string;
  now: number;
}): Promise<string> {
  const existing = await queryOne<{ total: number }>(
    'SELECT COUNT(*) AS total FROM incident_event WHERE workspaceId = ? AND incidentId = ?',
    input.incident.workspaceId, input.incident.id,
  );
  if ((existing?.total ?? 0) >= INCIDENT_LIMITS.timelineEventsPerIncident) {
    throw new Error('Incident timeline safety limit reached.');
  }
  const id = createId('incevt');
  await execute(
    `INSERT OR IGNORE INTO incident_event
      (id, organizationId, workspaceId, projectId, incidentId, type, actorType,
       actorId, correlationId, fromStatus, toStatus, message, metadata,
       idempotencyKey, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id, input.incident.organizationId, input.incident.workspaceId,
    input.incident.projectId, input.incident.id, input.type, input.actorType,
    input.actorId.slice(0, 160), input.incident.correlationId,
    input.fromStatus ?? null, input.toStatus ?? null, input.message ?? null,
    JSON.stringify(input.metadata ?? {}), input.idempotencyKey.slice(0, 180), input.now,
  );
  return id;
}

async function notify(input: {
  incident: IncidentRow;
  userId: string | null;
  title: string;
  message: string;
  severity: IncidentSeverity;
  dedupeKey: string;
  now: number;
}): Promise<void> {
  await execute(
    `INSERT OR IGNORE INTO internal_notification
      (id, organizationId, workspaceId, projectId, userId, workflowId, executionId,
       title, message, severity, resourceType, resourceId, href, dedupeKey, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'incident', ?, ?, ?, ?)`,
    createId('note'), input.incident.organizationId, input.incident.workspaceId,
    input.incident.projectId, input.userId, input.incident.workflowId,
    input.incident.executionId, input.title, input.message, input.severity,
    input.incident.id, `/incidents?id=${encodeURIComponent(input.incident.id)}`,
    input.dedupeKey, input.now,
  );
}

async function emitLifecycleEvent(input: {
  incident: IncidentRow;
  type: 'incident.opened' | 'incident.acknowledged' | 'incident.severity_changed' | 'incident.resolved' | 'incident.reopened';
  previousStatus?: IncidentStatus;
  previousSeverity?: IncidentSeverity;
  causationId: string;
  sourceWorkflowId?: string | null;
  chainDepth?: number;
  now: number;
}): Promise<void> {
  const payload: Record<string, WorkflowScalar> = {
    status: input.incident.status,
    severity: input.incident.severity,
    incidentId: input.incident.id,
    projectId: input.incident.projectId,
  };
  if (input.previousStatus) payload.previousStatus = input.previousStatus;
  if (input.previousSeverity) payload.previousSeverity = input.previousSeverity;
  await emitWorkflowEvent({
    workspaceId: input.incident.workspaceId,
    type: input.type,
    resourceType: 'incident',
    resourceId: input.incident.id,
    projectId: input.incident.projectId,
    payload,
    dedupeKey: `${input.type}:${input.incident.id}:${input.incident.revision}`,
    correlationId: input.incident.correlationId,
    causationId: input.causationId,
    sourceWorkflowId: input.sourceWorkflowId ?? null,
    chainDepth: input.chainDepth ?? 0,
    createdAt: input.now,
  });
}

export async function createOrAggregateIncident(input: CreateIncidentInput): Promise<{
  ok: true; incidentId: string; aggregated: boolean
} | { ok: false; error: string }> {
  const title = safeIncidentText(input.title, 240);
  const detail = safeIncidentText(input.detail, 1_000);
  if (!title || !detail || !input.correlationId.trim()) return { ok: false, error: 'Incident content is unsafe.' };
  const dedupeKey = await sha256Hex([
    input.workspaceId, input.projectId ?? '-', input.resourceType,
    input.resourceId ?? '-', title.toLowerCase(),
  ].join('|'));
  const now = Date.now();
  const existing = await queryOne<IncidentRow>(
    `SELECT * FROM workflow_incident
      WHERE workspaceId = ? AND dedupeKey = ? AND status <> 'resolved' LIMIT 1`,
    input.workspaceId, dedupeKey,
  );
  if (existing) {
    const severityRank: Record<IncidentSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
    const nextSeverity = severityRank[input.severity] > severityRank[existing.severity]
      ? input.severity
      : existing.severity;
    const changed = await execute(
      `UPDATE workflow_incident
          SET occurrenceCount = MIN(?, occurrenceCount + 1), lastSeenAt = ?,
              severity = ?, updatedAt = ?, revision = revision + 1
        WHERE id = ? AND workspaceId = ? AND status <> 'resolved'`,
      INCIDENT_LIMITS.occurrences, now, nextSeverity, now, existing.id, input.workspaceId,
    );
    if ((changed.meta.changes ?? 0) !== 1) return createOrAggregateIncident(input);
    const updated = await queryOne<IncidentRow>('SELECT * FROM workflow_incident WHERE id = ?', existing.id);
    if (!updated) return { ok: false, error: 'Incident aggregation failed.' };
    await appendEvent({
      incident: updated, type: 'incident.occurrence', actorType: 'workflow',
      actorId: input.createdBy, idempotencyKey: `occurrence:${input.executionId ?? input.causationId ?? now}`,
      metadata: { occurrenceCount: updated.occurrenceCount }, now,
    });
    if (updated.severity !== existing.severity) {
      const eventId = await appendEvent({
        incident: updated, type: 'incident.severity_changed', actorType: 'workflow',
        actorId: input.createdBy, idempotencyKey: `severity:${input.executionId ?? input.causationId ?? now}`,
        metadata: { previousSeverity: existing.severity, severity: updated.severity }, now,
      });
      await emitLifecycleEvent({
        incident: updated, type: 'incident.severity_changed', previousSeverity: existing.severity,
        causationId: eventId, sourceWorkflowId: input.sourceWorkflowId,
        chainDepth: input.chainDepth, now,
      });
    }
    await recordAudit({
      organizationId: updated.organizationId, workspaceId: updated.workspaceId,
      actorType: 'system', actorId: input.createdBy,
      action: 'incident.occurrence', resourceType: 'incident', resourceId: updated.id,
      outcome: 'success', metadata: { occurrenceCount: updated.occurrenceCount, correlationId: updated.correlationId },
    }).catch(() => undefined);
    return { ok: true, incidentId: updated.id, aggregated: true };
  }
  const active = await queryOne<{ total: number }>(
    `SELECT COUNT(*) AS total FROM workflow_incident
      WHERE workspaceId = ? AND status <> 'resolved'`,
    input.workspaceId,
  );
  if ((active?.total ?? 0) >= INCIDENT_LIMITS.activePerWorkspace) {
    return { ok: false, error: 'The workspace active-incident safety limit was reached.' };
  }
  const id = createId('incident');
  await execute(
    `INSERT OR IGNORE INTO workflow_incident
      (id, organizationId, workspaceId, projectId, workflowId, executionId,
       resourceType, resourceId, title, detail, severity, status, createdBy,
       createdAt, updatedAt, correlationId, dedupeKey, occurrenceCount, lastSeenAt, revision)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, 1, ?, 1)`,
    id, input.organizationId, input.workspaceId, input.projectId,
    input.workflowId ?? null, input.executionId ?? null, input.resourceType.slice(0, 80),
    input.resourceId?.slice(0, 160) ?? null, title, detail, input.severity,
    input.createdBy.slice(0, 160), now, now, input.correlationId.slice(0, 160),
    dedupeKey, now,
  );
  const created = await queryOne<IncidentRow>(
    `SELECT * FROM workflow_incident
      WHERE workspaceId = ? AND dedupeKey = ? AND status <> 'resolved' LIMIT 1`,
    input.workspaceId, dedupeKey,
  );
  if (!created) return { ok: false, error: 'Incident could not be created.' };
  if (created.id !== id) {
    return createOrAggregateIncident(input);
  }
  const eventId = await appendEvent({
    incident: created, type: 'incident.created', actorType: 'workflow', actorId: input.createdBy,
    fromStatus: null, toStatus: 'open', idempotencyKey: `created:${id}`, now,
  });
  await emitLifecycleEvent({
    incident: created, type: 'incident.opened', causationId: input.causationId ?? eventId,
    sourceWorkflowId: input.sourceWorkflowId, chainDepth: input.chainDepth, now,
  });
  if (created.severity === 'critical') {
    const owner = await queryOne<{ ownerUserId: string }>('SELECT ownerUserId FROM organization WHERE id = ?', created.organizationId);
    await notify({
      incident: created, userId: owner?.ownerUserId ?? null,
      title: 'Critical incident opened', message: created.title, severity: 'critical',
      dedupeKey: `incident-critical:${id}:1`, now,
    });
  }
  await recordAudit({
    organizationId: created.organizationId, workspaceId: created.workspaceId,
    actorType: 'system', actorId: input.createdBy,
    action: 'incident.create', resourceType: 'incident', resourceId: created.id,
    outcome: 'success', metadata: { severity: created.severity, correlationId: created.correlationId },
  }).catch(() => undefined);
  return { ok: true, incidentId: id, aggregated: false };
}

export async function mutateIncident(input: {
  organizationId: string;
  workspaceId: string;
  incidentId: string;
  actor: Actor;
  mutation: IncidentMutation;
}): Promise<MutationResult> {
  const incident = await queryOne<IncidentRow>(
    `SELECT * FROM workflow_incident
      WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
    input.organizationId, input.workspaceId, input.incidentId,
  );
  if (!incident || !canAccessProject(input.actor, incident.projectId)) {
    return { ok: false, status: 404, error: 'Incident not found.', securityCode: 'incident-cross-tenant-attempt' };
  }
  if (!canManageIncident(input.actor, incident.projectId)) {
    return { ok: false, status: 403, error: 'You cannot manage this incident.', securityCode: 'incident-permission-denied' };
  }
  if (input.mutation.operation === 'resolve' && !canResolveIncident(input.actor, incident.projectId, incident.severity)) {
    return { ok: false, status: 403, error: 'Only an owner or admin can resolve a critical incident.', securityCode: 'incident-critical-resolve-denied' };
  }
  if (incident.revision !== input.mutation.expectedRevision) {
    return { ok: false, status: 409, error: 'The incident changed. Refresh before trying again.' };
  }
  const now = Date.now();
  let eventType: IncidentEventType;
  const fromStatus: IncidentStatus | null = incident.status;
  let toStatus: IncidentStatus | null = incident.status;
  let message: string | null = null;
  let metadata: Record<string, string | number | boolean | null> = {};
  let sql: string;
  let params: unknown[];
  switch (input.mutation.operation) {
    case 'assign': {
      const member = await queryOne<{ id: string }>(
        `SELECT id FROM organization_member
          WHERE organizationId = ? AND userId = ? AND status = 'active' AND suspendedAt IS NULL`,
        input.organizationId, input.mutation.assigneeId,
      );
      if (!member) return { ok: false, status: 400, error: 'Choose an active organization member.', securityCode: 'incident-assignee-denied' };
      eventType = 'incident.assigned';
      metadata = { assigneeId: input.mutation.assigneeId };
      sql = 'UPDATE workflow_incident SET assignedTo = ?, revision = revision + 1, updatedAt = ? WHERE id = ? AND workspaceId = ? AND revision = ?';
      params = [input.mutation.assigneeId, now, incident.id, input.workspaceId, incident.revision];
      break;
    }
    case 'unassign':
      eventType = 'incident.unassigned';
      metadata = { previousAssigneeId: incident.assignedTo };
      sql = 'UPDATE workflow_incident SET assignedTo = NULL, revision = revision + 1, updatedAt = ? WHERE id = ? AND workspaceId = ? AND revision = ?';
      params = [now, incident.id, input.workspaceId, incident.revision];
      break;
    case 'acknowledge':
      if (incident.status !== 'open') return { ok: false, status: 409, error: 'Only an open incident can be acknowledged.' };
      eventType = 'incident.acknowledged'; toStatus = 'acknowledged';
      sql = `UPDATE workflow_incident SET status = 'acknowledged', acknowledgedAt = ?, acknowledgedBy = ?,
               revision = revision + 1, updatedAt = ? WHERE id = ? AND workspaceId = ? AND revision = ? AND status = 'open'`;
      params = [now, input.actor.userId, now, incident.id, input.workspaceId, incident.revision];
      break;
    case 'severity':
      eventType = 'incident.severity_changed';
      metadata = { previousSeverity: incident.severity, severity: input.mutation.severity };
      sql = 'UPDATE workflow_incident SET severity = ?, revision = revision + 1, updatedAt = ? WHERE id = ? AND workspaceId = ? AND revision = ?';
      params = [input.mutation.severity, now, incident.id, input.workspaceId, incident.revision];
      break;
    case 'note':
      eventType = 'incident.note_added'; message = input.mutation.note;
      sql = 'UPDATE workflow_incident SET revision = revision + 1, updatedAt = ? WHERE id = ? AND workspaceId = ? AND revision = ?';
      params = [now, incident.id, input.workspaceId, incident.revision];
      break;
    case 'resolve':
      if (incident.status === 'resolved') return { ok: false, status: 409, error: 'The incident is already resolved.' };
      eventType = 'incident.resolved'; toStatus = 'resolved'; message = input.mutation.resolution;
      sql = `UPDATE workflow_incident SET status = 'resolved', resolvedAt = ?, resolvedBy = ?, resolution = ?,
               revision = revision + 1, updatedAt = ? WHERE id = ? AND workspaceId = ? AND revision = ? AND status <> 'resolved'`;
      params = [now, input.actor.userId, input.mutation.resolution, now, incident.id, input.workspaceId, incident.revision];
      break;
    case 'reopen':
      if (incident.status !== 'resolved') return { ok: false, status: 409, error: 'Only a resolved incident can be reopened.' };
      if (await queryOne(
        `SELECT id FROM workflow_incident
          WHERE workspaceId = ? AND dedupeKey = ? AND status <> 'resolved' AND id <> ? LIMIT 1`,
        incident.workspaceId, incident.dedupeKey, incident.id,
      )) {
        return { ok: false, status: 409, error: 'An active incident already represents this root cause.' };
      }
      eventType = 'incident.reopened'; toStatus = 'open';
      sql = `UPDATE workflow_incident SET status = 'open', resolvedAt = NULL, resolvedBy = NULL, resolution = NULL,
               lastSeenAt = ?, revision = revision + 1, updatedAt = ?
             WHERE id = ? AND workspaceId = ? AND revision = ? AND status = 'resolved'`;
      params = [now, now, incident.id, input.workspaceId, incident.revision];
      break;
  }
  let changed: D1Result;
  try {
    changed = await execute(sql, ...params);
  } catch (error) {
    if (input.mutation.operation === 'reopen' && /UNIQUE constraint/i.test(String(error))) {
      return { ok: false, status: 409, error: 'An active incident already represents this root cause.' };
    }
    throw error;
  }
  if ((changed.meta.changes ?? 0) !== 1) return { ok: false, status: 409, error: 'The incident changed. Refresh before trying again.' };
  const updated = await queryOne<IncidentRow>('SELECT * FROM workflow_incident WHERE id = ?', incident.id);
  if (!updated) return { ok: false, status: 500, error: 'Incident state could not be read.' };
  const eventId = await appendEvent({
    incident: updated, type: eventType, actorType: 'user', actorId: input.actor.userId,
    fromStatus, toStatus, message, metadata,
    idempotencyKey: `${eventType}:${updated.id}:${updated.revision}`, now,
  });
  if (eventType === 'incident.assigned' && updated.assignedTo) {
    await notify({
      incident: updated, userId: updated.assignedTo, title: 'Incident assigned to you',
      message: updated.title, severity: updated.severity,
      dedupeKey: `incident-assigned:${eventId}`, now,
    });
  }
  if (eventType === 'incident.reopened') {
    const owner = await queryOne<{ ownerUserId: string }>('SELECT ownerUserId FROM organization WHERE id = ?', updated.organizationId);
    await notify({
      incident: updated, userId: owner?.ownerUserId ?? null, title: 'Incident reopened',
      message: updated.title, severity: updated.severity,
      dedupeKey: `incident-reopened:${eventId}`, now,
    });
  }
  if (eventType === 'incident.severity_changed' && updated.severity === 'critical') {
    const owner = await queryOne<{ ownerUserId: string }>('SELECT ownerUserId FROM organization WHERE id = ?', updated.organizationId);
    await notify({
      incident: updated, userId: owner?.ownerUserId ?? null, title: 'Incident escalated to critical',
      message: updated.title, severity: 'critical',
      dedupeKey: `incident-critical:${eventId}`, now,
    });
  }
  const workflowType = eventType === 'incident.acknowledged' || eventType === 'incident.severity_changed' ||
    eventType === 'incident.resolved' || eventType === 'incident.reopened'
    ? eventType
    : null;
  if (workflowType) {
    await emitLifecycleEvent({
      incident: updated, type: workflowType,
      previousStatus: incident.status, previousSeverity: incident.severity,
      causationId: eventId, now,
    });
  }
  const loaded = await loadIncident(input.workspaceId, incident.id, input.actor);
  return loaded
    ? { ok: true, incident: loaded }
    : { ok: false, status: 500, error: 'Incident state could not be read.' };
}

export async function incidentsForShield(workspaceId: string, now = Date.now()): Promise<{
  staleCritical: number;
  unassignedCritical: number;
  storms: number;
  orphanReferences: number;
  crossTenantAnomalies: number;
  suspiciousDeniedMutations: number;
}> {
  const [counts, orphan, crossTenant, denied] = await Promise.all([
    queryOne<{ staleCritical: number; unassignedCritical: number; storms: number }>(
      `SELECT
         SUM(CASE WHEN severity = 'critical' AND status <> 'resolved' AND lastSeenAt < ? THEN 1 ELSE 0 END) staleCritical,
         SUM(CASE WHEN severity = 'critical' AND status <> 'resolved' AND assignedTo IS NULL THEN 1 ELSE 0 END) unassignedCritical,
         SUM(CASE WHEN status <> 'resolved' AND occurrenceCount >= 10 THEN 1 ELSE 0 END) storms
       FROM workflow_incident WHERE workspaceId = ?`,
      now - 24 * 60 * 60 * 1000, workspaceId,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) total FROM workflow_incident i
        WHERE i.workspaceId = ? AND (
          (i.projectId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM project p WHERE p.id = i.projectId AND p.workspaceId = i.workspaceId))
          OR (i.workflowId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM workflow w WHERE w.id = i.workflowId AND w.workspaceId = i.workspaceId))
          OR (i.executionId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM workflow_execution e WHERE e.id = i.executionId AND e.workspaceId = i.workspaceId))
          OR (i.resourceType = 'deployment' AND i.resourceId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM deployment d WHERE d.id = i.resourceId AND d.workspaceId = i.workspaceId))
          OR (i.resourceType = 'node' AND i.resourceId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM compute_node n WHERE n.id = i.resourceId AND n.workspaceId = i.workspaceId))
          OR (i.resourceType = 'shield_finding' AND i.resourceId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM shield_finding f WHERE f.id = i.resourceId AND f.workspaceId = i.workspaceId))
          OR (i.resourceType = 'game_server' AND i.resourceId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM game_server g WHERE g.id = i.resourceId AND g.workspaceId = i.workspaceId))
          OR (i.resourceType = 'ai_job' AND i.resourceId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ai_inference a WHERE a.jobId = i.resourceId AND a.workspaceId = i.workspaceId))
          OR (i.resourceType = 'webhook_source' AND i.resourceId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM webhook_source s WHERE s.id = i.resourceId AND s.workspaceId = i.workspaceId))
        )`,
      workspaceId,
    ),
    queryOne<{ total: number }>(
      `SELECT (
        (SELECT COUNT(*) FROM workflow_incident i
          LEFT JOIN workspace w ON w.id = i.workspaceId
          LEFT JOIN project p ON p.id = i.projectId
          LEFT JOIN organization_member m ON m.organizationId = i.organizationId AND m.userId = i.assignedTo
         WHERE i.workspaceId = ? AND (w.organizationId IS NULL OR w.organizationId <> i.organizationId
           OR (i.projectId IS NOT NULL AND (p.workspaceId IS NULL OR p.workspaceId <> i.workspaceId))
           OR (i.assignedTo IS NOT NULL AND (m.id IS NULL OR m.status <> 'active' OR m.suspendedAt IS NOT NULL))))
        + (SELECT COUNT(*) FROM incident_event e JOIN workflow_incident i ON i.id = e.incidentId
           WHERE e.workspaceId = ? AND (e.organizationId <> i.organizationId OR e.workspaceId <> i.workspaceId
             OR COALESCE(e.projectId, '') <> COALESCE(i.projectId, '')))
       ) total`,
      workspaceId, workspaceId,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) total FROM audit_event
        WHERE workspaceId = ? AND action LIKE 'incident.%denied' AND createdAt >= ?`,
      workspaceId, now - 60 * 60 * 1000,
    ),
  ]);
  return {
    staleCritical: counts?.staleCritical ?? 0,
    unassignedCritical: counts?.unassignedCritical ?? 0,
    storms: counts?.storms ?? 0,
    orphanReferences: orphan?.total ?? 0,
    crossTenantAnomalies: crossTenant?.total ?? 0,
    suspiciousDeniedMutations: denied?.total ?? 0,
  };
}

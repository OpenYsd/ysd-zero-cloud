import { createId, sha256Hex } from '@/lib/crypto';
import { can, canAccessProject, type Actor, type Role } from '@/lib/roles';
import {
  MAX_WORKFLOW_CHAIN_DEPTH,
  WORKFLOW_TEMPLATES,
  executionTerminalState,
  redactWorkflowValue,
  retryDelayMs,
  shouldRunSchedule,
  validateWorkflowDefinition,
  workflowConditionsMatch,
  type TrustedWorkflowEvent,
  type WorkflowAction,
  type WorkflowDefinition,
  type WorkflowExecutionState,
  type WorkflowScalar,
  type WorkflowTriggerType,
} from '@/lib/workflows';
import { cancelAiInference } from './ai';
import { recordAudit } from './audit';
import { createDeploymentAction } from './deployments';
import { execute, query, queryOne } from './db';
import { queueGameServerRequest } from './game-servers';
import { readNodesState, revokeNode } from './nodes';
import {
  listWebhookGatewayState,
  type WebhookGatewayState,
} from './webhook-sources';
import {
  emitWorkflowEvent,
  recordWorkflowSecurityEvent,
} from './workflow-events';

type WorkflowRow = {
  id: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  name: string;
  description: string;
  status: 'draft' | 'active' | 'paused';
  activeVersionId: string | null;
  latestVersion: number;
  ownerUserId: string;
  failureStreak: number;
  lastTriggeredAt: number | null;
  lastSucceededAt: number | null;
  lastFailedAt: number | null;
  lastScheduledAt: number | null;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  deletedAt: number | null;
};

type VersionRow = {
  id: string;
  workflowId: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  version: number;
  kind: 'draft' | 'published' | 'rollback';
  triggerType: WorkflowTriggerType;
  definition: string;
  definitionHash: string;
  sourceVersionId: string | null;
  createdBy: string;
  createdAt: number;
  publishedAt: number | null;
};

type EventRow = {
  id: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  type: WorkflowTriggerType;
  resourceType: string;
  resourceId: string | null;
  payload: string;
  source: 'system' | 'manual' | 'schedule';
  dedupeKey: string;
  correlationId: string;
  causationId: string | null;
  sourceWorkflowId: string | null;
  chainDepth: number;
  createdAt: number;
  processedAt: number | null;
  rejectedAt: number | null;
  rejectionReason: string | null;
};

type ExecutionRow = {
  id: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  workflowId: string;
  versionId: string;
  eventId: string;
  state: WorkflowExecutionState;
  idempotencyKey: string;
  correlationId: string;
  causationId: string | null;
  chainDepth: number;
  actionIndex: number;
  attempts: number;
  maxAttempts: number;
  nextAttemptAt: number | null;
  timeoutAt: number;
  leaseToken: string | null;
  leaseExpiresAt: number | null;
  cancelRequestedAt: number | null;
  cancelRequestedBy: string | null;
  lastError: string | null;
  startedAt: number | null;
  finishedAt: number | null;
  deadLetterAt: number | null;
  manualRetryOf: string | null;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
};

type ActionRow = {
  id: string;
  executionId: string;
  actionIndex: number;
  attempt: number;
  actionType: string;
  state: 'running' | 'succeeded' | 'failed' | 'skipped';
  resourceType: string | null;
  resourceId: string | null;
  error: string | null;
  startedAt: number;
  finishedAt: number | null;
};

export type WorkflowVariableView = {
  id: string;
  name: string;
  kind: 'text' | 'number' | 'boolean' | 'secret';
  value: string | null;
  secretId: string | null;
  secretName: string | null;
  secretEnvironment: string | null;
  secretScope: string | null;
  createdAt: number;
  updatedAt: number;
};

export type WorkflowVersionView = Omit<VersionRow, 'definition'> & {
  definition: WorkflowDefinition;
};

export type WorkflowExecutionView = Omit<ExecutionRow, 'leaseToken'> & {
  actions: ActionRow[];
  event: {
    type: WorkflowTriggerType;
    resourceType: string;
    resourceId: string | null;
    correlationId: string;
    sourceId: string | null;
    externalEventType: string | null;
    externalEventId: string | null;
    subject: string | null;
  } | null;
};

export type WorkflowView = Omit<WorkflowRow, 'deletedAt'> & {
  activeVersion: WorkflowVersionView | null;
  versions: WorkflowVersionView[];
  executions: WorkflowExecutionView[];
  variables: WorkflowVariableView[];
};

export type InternalNotification = {
  id: string;
  projectId: string | null;
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  resourceType: string;
  resourceId: string | null;
  href: string | null;
  readAt: number | null;
  createdAt: number;
};

export type WorkflowsState = {
  workflows: WorkflowView[];
  notifications: InternalNotification[];
  webhookGateway: WebhookGatewayState;
  templates: typeof WORKFLOW_TEMPLATES;
  summary: {
    total: number;
    active: number;
    paused: number;
    failedExecutions: number;
    unreadNotifications: number;
  };
  schedule: {
    available: true;
    mode: 'single-free-cron-trigger';
    tickMinutes: 1;
  };
  zeroModeEnforced: true;
  projectedMonthlyCost: 0;
};

const NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._:/()-]{1,79}$/u;
const VARIABLE_NAME = /^[A-Z][A-Z0-9_]{1,63}$/;
const UNSAFE_VARIABLE_TEXT = /(?:https?:\/\/|\$\(|`|{{|}}|<script|\beval\b|\bexec\b|\bshell\b|\bcommand\b)/i;
const TERMINAL = new Set<WorkflowExecutionState>([
  'succeeded', 'failed', 'cancelled', 'timed_out', 'skipped',
]);
const ADMIN_ACTIONS = new Set([
  'node.disable_assignments', 'node.revoke', 'game_server.stop',
  'game_server.restart', 'ai.job.cancel', 'shield.acknowledge',
]);
const EVENT_EMITTING_ACTIONS = new Set<WorkflowAction['type']>([
  'deployment.redeploy', 'deployment.rollback_to_previous_healthy',
  'node.revoke', 'game_server.stop', 'game_server.restart',
]);
const LEASE_MS = 25_000;
const MAX_EVENTS_PER_TICK = 16;
const MAX_EXECUTIONS_PER_TICK = 8;

function parsedDefinition(value: string): WorkflowDefinition | null {
  try {
    return JSON.parse(value) as WorkflowDefinition;
  } catch {
    return null;
  }
}

function parsedPayload(value: string): Record<string, WorkflowScalar> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, WorkflowScalar>
      : {};
  } catch {
    return {};
  }
}

function toTrustedEvent(row: EventRow): TrustedWorkflowEvent {
  return {
    id: row.id,
    type: row.type,
    organizationId: row.organizationId,
    workspaceId: row.workspaceId,
    projectId: row.projectId,
    resourceId: row.resourceId,
    payload: parsedPayload(row.payload),
    correlationId: row.correlationId,
    causationId: row.causationId,
    sourceWorkflowId: row.sourceWorkflowId,
    chainDepth: row.chainDepth,
    createdAt: row.createdAt,
  };
}

function toVersion(row: VersionRow): WorkflowVersionView | null {
  const definition = parsedDefinition(row.definition);
  return definition ? { ...row, definition } : null;
}

async function organizationForWorkspace(workspaceId: string): Promise<{
  organizationId: string;
  zeroMode: boolean;
} | null> {
  const row = await queryOne<{ organizationId: string; zeroMode: number }>(
    `SELECT organizationId, zeroMode FROM workspace
      WHERE id = ? AND organizationId IS NOT NULL AND archivedAt IS NULL`,
    workspaceId,
  );
  return row ? { organizationId: row.organizationId, zeroMode: row.zeroMode === 1 } : null;
}

async function ownerRole(workflow: WorkflowRow): Promise<Role | null> {
  return (await queryOne<{ role: Role }>(
    `SELECT role FROM organization_member
      WHERE organizationId = ? AND userId = ? AND status = 'active' AND suspendedAt IS NULL`,
    workflow.organizationId, workflow.ownerUserId,
  ))?.role ?? null;
}

function mayEdit(actor: Actor, workflow: WorkflowRow): boolean {
  if (!can(actor, 'workflow.create')) return false;
  if (!canAccessProject(actor, workflow.projectId)) return false;
  if (actor.role === 'developer') {
    return workflow.projectId !== null && workflow.ownerUserId === actor.userId;
  }
  return can(actor, 'workflow.manage');
}

async function workflowById(
  organizationId: string,
  workspaceId: string,
  workflowId: string,
): Promise<WorkflowRow | null> {
  return queryOne<WorkflowRow>(
    `SELECT * FROM workflow
      WHERE organizationId = ? AND workspaceId = ? AND id = ? AND deletedAt IS NULL`,
    organizationId, workspaceId, workflowId,
  );
}

async function reserveVersion(workflowId: string): Promise<number> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await queryOne<{ latestVersion: number }>(
      'SELECT latestVersion FROM workflow WHERE id = ? AND deletedAt IS NULL',
      workflowId,
    );
    if (!current) throw new Error('Workflow not found.');
    const changed = await execute(
      `UPDATE workflow SET latestVersion = latestVersion + 1, updatedAt = ?
        WHERE id = ? AND latestVersion = ? AND deletedAt IS NULL`,
      Date.now(), workflowId, current.latestVersion,
    );
    if ((changed.meta.changes ?? 0) === 1) return current.latestVersion + 1;
  }
  throw new Error('Workflow version could not be reserved.');
}

async function insertVersion(input: {
  workflow: WorkflowRow;
  definition: WorkflowDefinition;
  kind: VersionRow['kind'];
  actorId: string;
  sourceVersionId?: string | null;
}): Promise<VersionRow> {
  const version = await reserveVersion(input.workflow.id);
  const definition = JSON.stringify(input.definition);
  const id = createId('wfver');
  const now = Date.now();
  await execute(
    `INSERT INTO workflow_version
      (id, workflowId, organizationId, workspaceId, projectId, version, kind,
       triggerType, definition, definitionHash, sourceVersionId, createdBy,
       createdAt, publishedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id, input.workflow.id, input.workflow.organizationId, input.workflow.workspaceId,
    input.workflow.projectId, version, input.kind, input.definition.trigger.type,
    definition, await sha256Hex(definition), input.sourceVersionId ?? null,
    input.actorId, now, input.kind === 'draft' ? null : now,
  );
  return (await queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', id))!;
}

async function validateForWorkflow(input: {
  workflow: Pick<WorkflowRow, 'organizationId' | 'workspaceId' | 'projectId'>;
  definition: unknown;
  role: Role;
  zeroMode: boolean;
  requireEnabledSource?: boolean;
}): Promise<{ ok: true; definition: WorkflowDefinition } | { ok: false; error: string; securityCode?: string }> {
  const validation = validateWorkflowDefinition(input.definition, {
    role: input.role,
    projectId: input.workflow.projectId,
    zeroMode: input.zeroMode,
  });
  if (!validation.ok) return validation;
  if (validation.definition.trigger.type === 'external.event') {
    const source = await queryOne<{ status: string; archivedAt: number | null }>(
      `SELECT status, archivedAt FROM webhook_source
        WHERE id = ? AND organizationId = ? AND workspaceId = ?
          AND COALESCE(projectId, '') = COALESCE(?, '')`,
      validation.definition.trigger.sourceId,
      input.workflow.organizationId,
      input.workflow.workspaceId,
      input.workflow.projectId,
    );
    if (!source || source.archivedAt !== null) {
      return {
        ok: false,
        error: 'External Event source is outside this workflow scope or archived.',
        securityCode: 'workflow-webhook-source-reference-rejected',
      };
    }
    if (input.requireEnabledSource && source.status !== 'enabled') {
      return {
        ok: false,
        error: 'Enable the External Event source before publishing or running this workflow.',
        securityCode: 'workflow-webhook-source-disabled',
      };
    }
  }
  return { ok: true, definition: validation.definition };
}

export async function listWorkflowsState(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  userId: string;
}): Promise<WorkflowsState> {
  const projectFilter = input.actor.projectIds !== null && input.actor.projectIds !== undefined;
  const projectIds = input.actor.projectIds ?? [];
  const workflows = projectFilter && projectIds.length === 0
    ? []
    : await query<WorkflowRow>(
      `SELECT * FROM workflow WHERE organizationId = ? AND workspaceId = ? AND deletedAt IS NULL${
        projectFilter ? ` AND projectId IN (${projectIds.map(() => '?').join(', ')})` : ''
      } ORDER BY updatedAt DESC LIMIT 100`,
      input.organizationId, input.workspaceId, ...projectIds,
    );
  const views: WorkflowView[] = [];
  for (const workflow of workflows) {
    const [versions, executions, variables] = await Promise.all([
      query<VersionRow>(
        'SELECT * FROM workflow_version WHERE workflowId = ? ORDER BY version DESC LIMIT 30',
        workflow.id,
      ),
      query<ExecutionRow>(
        `SELECT * FROM workflow_execution
          WHERE organizationId = ? AND workspaceId = ? AND workflowId = ?
          ORDER BY createdAt DESC LIMIT 50`,
        input.organizationId, input.workspaceId, workflow.id,
      ),
      query<WorkflowVariableView>(
        `SELECT v.id, v.name, v.kind,
                CASE WHEN v.kind = 'secret' THEN NULL ELSE v.value END AS value,
                v.secretId, s.name AS secretName, s.environment AS secretEnvironment,
                s.scope AS secretScope, v.createdAt, v.updatedAt
           FROM workflow_variable v LEFT JOIN secret s ON s.id = v.secretId
          WHERE v.organizationId = ? AND v.workspaceId = ? AND v.workflowId = ?
          ORDER BY v.name ASC`,
        input.organizationId, input.workspaceId, workflow.id,
      ),
    ]);
    const versionViews = versions.map(toVersion).filter((value): value is WorkflowVersionView => value !== null);
    const executionViews: WorkflowExecutionView[] = [];
    for (const execution of executions) {
      const [actions, eventRow] = await Promise.all([query<ActionRow>(
        `SELECT id, executionId, actionIndex, attempt, actionType, state,
                resourceType, resourceId, error, startedAt, finishedAt
           FROM workflow_action_execution WHERE executionId = ?
          ORDER BY actionIndex ASC, attempt ASC`,
        execution.id,
      ), queryOne<EventRow>(
        `SELECT * FROM workflow_event
          WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
        input.organizationId, input.workspaceId, execution.eventId,
      )]);
      const { leaseToken: _leaseToken, ...safeExecution } = execution;
      const eventPayload = eventRow ? parsedPayload(eventRow.payload) : {};
      executionViews.push({
        ...safeExecution,
        actions,
        event: eventRow ? {
          type: eventRow.type,
          resourceType: eventRow.resourceType,
          resourceId: eventRow.resourceId,
          correlationId: eventRow.correlationId,
          sourceId: typeof eventPayload.sourceId === 'string' ? eventPayload.sourceId : null,
          externalEventType: typeof eventPayload.externalEventType === 'string' ? eventPayload.externalEventType : null,
          externalEventId: typeof eventPayload.externalEventId === 'string' ? eventPayload.externalEventId : null,
          subject: typeof eventPayload.subject === 'string' ? eventPayload.subject : null,
        } : null,
      });
    }
    const { deletedAt: _deletedAt, ...safeWorkflow } = workflow;
    views.push({
      ...safeWorkflow,
      activeVersion: versionViews.find((version) => version.id === workflow.activeVersionId) ?? null,
      versions: versionViews,
      executions: executionViews,
      variables,
    });
  }
  const notifications = await query<InternalNotification>(
    `SELECT id, projectId, title, message, severity, resourceType, resourceId, href, readAt, createdAt
       FROM internal_notification
      WHERE organizationId = ? AND workspaceId = ? AND (userId IS NULL OR userId = ?)
      ORDER BY createdAt DESC LIMIT 100`,
    input.organizationId, input.workspaceId, input.userId,
  );
  const failedExecutions = views.reduce(
    (total, workflow) => total + workflow.executions.filter((item) => item.state === 'failed' || item.state === 'timed_out').length,
    0,
  );
  const webhookGateway = await listWebhookGatewayState({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    actor: input.actor,
  });
  return {
    workflows: views,
    notifications,
    webhookGateway,
    templates: WORKFLOW_TEMPLATES,
    summary: {
      total: views.length,
      active: views.filter((item) => item.status === 'active').length,
      paused: views.filter((item) => item.status === 'paused').length,
      failedExecutions,
      unreadNotifications: notifications.filter((item) => item.readAt === null).length,
    },
    schedule: { available: true, mode: 'single-free-cron-trigger', tickMinutes: 1 },
    zeroModeEnforced: true,
    projectedMonthlyCost: 0,
  };
}

export async function createWorkflow(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  name: unknown;
  description?: unknown;
  projectId?: unknown;
  definition: unknown;
}): Promise<{ ok: true; workflowId: string; versionId: string } | { ok: false; status: number; error: string; securityCode?: string }> {
  if (!can(input.actor, 'workflow.create')) return { ok: false, status: 403, error: 'Your role cannot create workflows.' };
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  const description = typeof input.description === 'string' ? input.description.trim().slice(0, 300) : '';
  const projectId = typeof input.projectId === 'string' && input.projectId ? input.projectId : null;
  if (!NAME.test(name)) return { ok: false, status: 400, error: 'Use a workflow name between 2 and 80 characters.' };
  if (input.actor.role === 'developer' && !projectId) return { ok: false, status: 403, error: 'Developers may create only project-scoped workflows.' };
  if (!canAccessProject(input.actor, projectId)) return { ok: false, status: 404, error: 'Project not found.' };
  if (projectId) {
    const project = await queryOne<{ id: string }>(
      'SELECT id FROM project WHERE workspaceId = ? AND id = ?',
      input.workspaceId, projectId,
    );
    if (!project) return { ok: false, status: 404, error: 'Project not found.' };
  }
  const workspace = await organizationForWorkspace(input.workspaceId);
  if (!workspace || workspace.organizationId !== input.organizationId) return { ok: false, status: 404, error: 'Workspace not found.' };
  const validated = await validateForWorkflow({
    workflow: { organizationId: input.organizationId, workspaceId: input.workspaceId, projectId },
    definition: input.definition,
    role: input.actor.role, zeroMode: workspace.zeroMode,
  });
  if (!validated.ok) return { ok: false, status: 400, error: validated.error, securityCode: validated.securityCode };
  const duplicate = await queryOne<{ id: string }>(
    'SELECT id FROM workflow WHERE workspaceId = ? AND name = ? AND deletedAt IS NULL',
    input.workspaceId, name,
  );
  if (duplicate) return { ok: false, status: 409, error: 'A workflow with that name already exists.' };
  const now = Date.now();
  const id = createId('wf');
  await execute(
    `INSERT INTO workflow
      (id, organizationId, workspaceId, projectId, name, description, status,
       activeVersionId, latestVersion, ownerUserId, failureStreak, createdBy,
       createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, 'draft', NULL, 0, ?, 0, ?, ?, ?)`,
    id, input.organizationId, input.workspaceId, projectId, name, description,
    input.actor.userId, input.actor.userId, now, now,
  );
  const workflow = (await workflowById(input.organizationId, input.workspaceId, id))!;
  const version = await insertVersion({ workflow, definition: validated.definition, kind: 'draft', actorId: input.actor.userId });
  return { ok: true, workflowId: id, versionId: version.id };
}

export async function createWorkflowFromTemplate(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  templateId: unknown;
  name?: unknown;
  projectId?: unknown;
}): ReturnType<typeof createWorkflow> {
  const template = typeof input.templateId === 'string'
    ? WORKFLOW_TEMPLATES.find((item) => item.id === input.templateId)
    : undefined;
  if (!template) return Promise.resolve({ ok: false, status: 400, error: 'Choose a built-in workflow template.' });
  const projectId = typeof input.projectId === 'string' && input.projectId ? input.projectId : null;
  if (template.projectScoped && !projectId) return Promise.resolve({ ok: false, status: 400, error: 'This template requires a project.' });
  return createWorkflow({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    actor: input.actor,
    name: typeof input.name === 'string' && input.name.trim() ? input.name : template.name,
    description: template.description,
    projectId,
    definition: template.definition,
  });
}

export async function updateWorkflowDraft(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  actor: Actor;
  name?: unknown;
  description?: unknown;
  definition: unknown;
}): Promise<{ ok: true; versionId: string } | { ok: false; status: number; error: string; securityCode?: string }> {
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (!mayEdit(input.actor, workflow)) return { ok: false, status: 403, error: 'Your role cannot edit this workflow.' };
  const workspace = await organizationForWorkspace(input.workspaceId);
  const validated = await validateForWorkflow({
    workflow, definition: input.definition, role: input.actor.role,
    zeroMode: workspace?.zeroMode ?? false,
  });
  if (!validated.ok) return { ok: false, status: 400, error: validated.error, securityCode: validated.securityCode };
  const name = input.name === undefined ? workflow.name : typeof input.name === 'string' ? input.name.trim() : '';
  const description = input.description === undefined
    ? workflow.description
    : typeof input.description === 'string' ? input.description.trim().slice(0, 300) : '';
  if (!NAME.test(name)) return { ok: false, status: 400, error: 'Workflow name is invalid.' };
  const duplicate = await queryOne<{ id: string }>(
    `SELECT id FROM workflow WHERE workspaceId = ? AND name = ? AND id <> ? AND deletedAt IS NULL`,
    input.workspaceId, name, workflow.id,
  );
  if (duplicate) return { ok: false, status: 409, error: 'A workflow with that name already exists.' };
  await execute(
    'UPDATE workflow SET name = ?, description = ?, updatedAt = ? WHERE id = ?',
    name, description, Date.now(), workflow.id,
  );
  const version = await insertVersion({ workflow: { ...workflow, name, description }, definition: validated.definition, kind: 'draft', actorId: input.actor.userId });
  return { ok: true, versionId: version.id };
}

export async function publishWorkflow(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  versionId: string;
  actor: Actor;
}): Promise<{ ok: true; versionId: string } | { ok: false; status: number; error: string; securityCode?: string }> {
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (!mayEdit(input.actor, workflow)) return { ok: false, status: 403, error: 'Your role cannot publish this workflow.' };
  const source = await queryOne<VersionRow>(
    'SELECT * FROM workflow_version WHERE workflowId = ? AND id = ?',
    workflow.id, input.versionId,
  );
  const definition = source ? parsedDefinition(source.definition) : null;
  if (!source || !definition) return { ok: false, status: 404, error: 'Workflow version not found.' };
  const workspace = await organizationForWorkspace(input.workspaceId);
  const validated = await validateForWorkflow({
    workflow, definition, role: input.actor.role, zeroMode: workspace?.zeroMode ?? false,
    requireEnabledSource: true,
  });
  if (!validated.ok) return { ok: false, status: 400, error: validated.error, securityCode: validated.securityCode };
  const published = await insertVersion({
    workflow, definition: validated.definition, kind: 'published',
    actorId: input.actor.userId, sourceVersionId: source.id,
  });
  await execute(
    `UPDATE workflow SET status = 'active', activeVersionId = ?, failureStreak = 0, updatedAt = ?
      WHERE id = ? AND deletedAt IS NULL`,
    published.id, Date.now(), workflow.id,
  );
  return { ok: true, versionId: published.id };
}

export async function rollbackWorkflowVersion(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  targetVersionId: string;
  actor: Actor;
}): Promise<{ ok: true; versionId: string } | { ok: false; status: number; error: string }> {
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (!mayEdit(input.actor, workflow)) return { ok: false, status: 403, error: 'Your role cannot roll back this workflow.' };
  const source = await queryOne<VersionRow>(
    `SELECT * FROM workflow_version WHERE workflowId = ? AND id = ? AND kind IN ('published','rollback')`,
    workflow.id, input.targetVersionId,
  );
  const definition = source ? parsedDefinition(source.definition) : null;
  if (!source || !definition) return { ok: false, status: 404, error: 'Published version not found.' };
  const workspace = await organizationForWorkspace(input.workspaceId);
  const validated = await validateForWorkflow({
    workflow, definition, role: input.actor.role, zeroMode: workspace?.zeroMode ?? false,
    requireEnabledSource: true,
  });
  if (!validated.ok) return { ok: false, status: 400, error: validated.error };
  const rollback = await insertVersion({
    workflow, definition: validated.definition, kind: 'rollback',
    actorId: input.actor.userId, sourceVersionId: source.id,
  });
  await execute(
    `UPDATE workflow SET status = 'active', activeVersionId = ?, failureStreak = 0, updatedAt = ? WHERE id = ?`,
    rollback.id, Date.now(), workflow.id,
  );
  return { ok: true, versionId: rollback.id };
}

export async function setWorkflowStatus(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  actor: Actor;
  status: 'active' | 'paused';
}): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (!mayEdit(input.actor, workflow)) return { ok: false, status: 403, error: 'Your role cannot change this workflow.' };
  if (input.status === 'active' && !workflow.activeVersionId) return { ok: false, status: 409, error: 'Publish a version before resuming this workflow.' };
  await execute('UPDATE workflow SET status = ?, updatedAt = ? WHERE id = ?', input.status, Date.now(), workflow.id);
  return { ok: true };
}

export async function deleteWorkflow(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  actor: Actor;
}): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (!mayEdit(input.actor, workflow)) return { ok: false, status: 403, error: 'Your role cannot delete this workflow.' };
  const now = Date.now();
  await execute(`UPDATE workflow SET status = 'paused', deletedAt = ?, updatedAt = ? WHERE id = ?`, now, now, workflow.id);
  await execute(
    `UPDATE workflow_execution SET cancelRequestedAt = ?, cancelRequestedBy = ?, updatedAt = ?
      WHERE workflowId = ? AND state IN ('queued','waiting','running')`,
    now, input.actor.userId, now, workflow.id,
  );
  const pending = await query<ExecutionRow>(
    `SELECT * FROM workflow_execution WHERE workflowId = ? AND state IN ('queued','waiting')`,
    workflow.id,
  );
  for (const execution of pending) {
    await finishExecution(execution, 'cancelled', 'Workflow deleted.', now);
  }
  return { ok: true };
}

export async function setWorkflowVariable(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  actor: Actor;
  name: unknown;
  kind: unknown;
  value?: unknown;
  secretId?: unknown;
}): Promise<{ ok: true } | { ok: false; status: number; error: string; securityCode?: string }> {
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (!mayEdit(input.actor, workflow)) return { ok: false, status: 403, error: 'Your role cannot edit this workflow.' };
  const name = typeof input.name === 'string' ? input.name.trim().toUpperCase() : '';
  if (!VARIABLE_NAME.test(name)) return { ok: false, status: 400, error: 'Use an uppercase variable name of 2-64 characters.' };
  if (!['text', 'number', 'boolean', 'secret'].includes(String(input.kind))) {
    return { ok: false, status: 400, error: 'Choose a supported variable type.' };
  }
  const kind = input.kind as WorkflowVariableView['kind'];
  let value: string | null = null;
  let secretId: string | null = null;
  if (kind === 'secret') {
    if (!can(input.actor, 'secret.metadata.read') || typeof input.secretId !== 'string') {
      return { ok: false, status: 403, error: 'Secret metadata access is required.' };
    }
    const secret = await queryOne<{ id: string; scope: string }>(
      'SELECT id, scope FROM secret WHERE workspaceId = ? AND id = ?',
      input.workspaceId, input.secretId,
    );
    const allowedScopes = workflow.projectId
      ? new Set(['Workspace', `Project:${workflow.projectId}`])
      : new Set(['Workspace']);
    if (!secret || !allowedScopes.has(secret.scope)) {
      return { ok: false, status: 404, error: 'Secret reference is outside this workflow scope.', securityCode: 'workflow-secret-scope-rejected' };
    }
    secretId = secret.id;
  } else {
    if (kind === 'boolean') {
      if (input.value !== true && input.value !== false && input.value !== 'true' && input.value !== 'false') {
        return { ok: false, status: 400, error: 'Boolean variables accept only true or false.' };
      }
      value = String(input.value);
    } else if (kind === 'number') {
      const number = typeof input.value === 'number' ? input.value : Number(input.value);
      if (!Number.isFinite(number) || Math.abs(number) > 1_000_000_000) {
        return { ok: false, status: 400, error: 'Number variable is outside the safe range.' };
      }
      value = String(number);
    } else {
      value = typeof input.value === 'string' ? input.value.trim() : '';
      if (!value || value.length > 500 || UNSAFE_VARIABLE_TEXT.test(value)) {
        return { ok: false, status: 400, error: 'Text variables are plain bounded values; templates, commands, scripts, and URLs are forbidden.', securityCode: 'workflow-template-injection-rejected' };
      }
    }
  }
  const now = Date.now();
  await execute(
    `INSERT INTO workflow_variable
      (id, workflowId, organizationId, workspaceId, projectId, name, kind,
       value, secretId, createdBy, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(workflowId, name) DO UPDATE SET
       kind = excluded.kind, value = excluded.value, secretId = excluded.secretId,
       updatedAt = excluded.updatedAt`,
    createId('wfvar'), workflow.id, workflow.organizationId, workflow.workspaceId,
    workflow.projectId, name, kind, value, secretId, input.actor.userId, now, now,
  );
  return { ok: true };
}

export async function deleteWorkflowVariable(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  actor: Actor;
  name: unknown;
}): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (!mayEdit(input.actor, workflow)) return { ok: false, status: 403, error: 'Your role cannot edit this workflow.' };
  const name = typeof input.name === 'string' ? input.name.trim().toUpperCase() : '';
  if (!VARIABLE_NAME.test(name)) return { ok: false, status: 400, error: 'Variable not found.' };
  const result = await execute(
    'DELETE FROM workflow_variable WHERE organizationId = ? AND workspaceId = ? AND workflowId = ? AND name = ?',
    input.organizationId, input.workspaceId, workflow.id, name,
  );
  return (result.meta.changes ?? 0) > 0
    ? { ok: true }
    : { ok: false, status: 404, error: 'Variable not found.' };
}

async function createExecution(input: {
  workflow: WorkflowRow;
  version: VersionRow;
  event: EventRow;
  state: WorkflowExecutionState;
  definition: WorkflowDefinition;
  createdBy: string;
  manualRetryOf?: string | null;
}): Promise<ExecutionRow | null> {
  const now = Date.now();
  const id = createId('wfexec');
  const idempotencyKey = `${input.workflow.id}:${input.version.id}:${input.event.id}`.slice(0, 180);
  await execute(
    `INSERT OR IGNORE INTO workflow_execution
      (id, organizationId, workspaceId, projectId, workflowId, versionId, eventId,
       state, idempotencyKey, correlationId, causationId, chainDepth, actionIndex,
       attempts, maxAttempts, nextAttemptAt, timeoutAt, leaseToken, leaseExpiresAt,
       manualRetryOf, createdBy, createdAt, updatedAt, finishedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?)`,
    id, input.workflow.organizationId, input.workflow.workspaceId, input.workflow.projectId,
    input.workflow.id, input.version.id, input.event.id, input.state, idempotencyKey,
    input.event.correlationId, input.event.id, input.event.chainDepth,
    input.definition.retry.maxAttempts, input.state === 'queued' ? now : null,
    now + input.definition.timeoutSeconds * 1_000,
    input.manualRetryOf ?? null, input.createdBy, now, now,
    input.state === 'skipped' ? now : null,
  );
  return queryOne<ExecutionRow>(
    'SELECT * FROM workflow_execution WHERE workflowId = ? AND versionId = ? AND eventId = ?',
    input.workflow.id, input.version.id, input.event.id,
  );
}

async function dispatchEvent(row: EventRow): Promise<number> {
  const event = toTrustedEvent(row);
  const workflows = await query<WorkflowRow>(
    `SELECT * FROM workflow
      WHERE organizationId = ? AND workspaceId = ? AND status = 'active'
        AND activeVersionId IS NOT NULL AND deletedAt IS NULL
        AND (projectId IS NULL OR projectId = ?)`,
    row.organizationId, row.workspaceId, row.projectId,
  );
  let created = 0;
  for (const workflow of workflows) {
    const version = await queryOne<VersionRow>(
      'SELECT * FROM workflow_version WHERE id = ? AND workflowId = ?',
      workflow.activeVersionId, workflow.id,
    );
    const definition = version ? parsedDefinition(version.definition) : null;
    if (!version || !definition || definition.trigger.type !== row.type) continue;
    if (definition.trigger.type === 'external.event' && definition.trigger.sourceId !== row.resourceId) continue;
    if (row.sourceWorkflowId === workflow.id) {
      await recordWorkflowSecurityEvent({
        workspaceId: workflow.workspaceId, workflowId: workflow.id,
        type: 'workflow-self-trigger-blocked', severity: 'medium',
        detail: 'A workflow-generated event was refused by its self-trigger guard.',
      });
      continue;
    }
    const role = await ownerRole(workflow);
    const workspace = await organizationForWorkspace(workflow.workspaceId);
    if (!role || !workspace) {
      await recordWorkflowSecurityEvent({
        workspaceId: workflow.workspaceId, workflowId: workflow.id,
        type: 'workflow-orphan-owner', severity: 'high',
        detail: 'An active workflow no longer has an active organization owner.',
      });
      continue;
    }
    const validation = await validateForWorkflow({
      workflow, definition, role, zeroMode: workspace.zeroMode,
      requireEnabledSource: true,
    });
    if (!validation.ok) {
      await recordWorkflowSecurityEvent({
        workspaceId: workflow.workspaceId, workflowId: workflow.id,
        type: validation.securityCode ?? 'workflow-runtime-validation', severity: 'critical',
        detail: validation.error,
      });
      continue;
    }
    const matches = workflowConditionsMatch(validation.definition, event);
    const execution = await createExecution({
      workflow, version, event: row, state: matches ? 'queued' : 'skipped',
      definition: validation.definition, createdBy: 'system',
    });
    if (execution && execution.createdAt === execution.updatedAt) created += 1;
    if (matches) {
      await execute(
        'UPDATE workflow SET lastTriggeredAt = ?, updatedAt = ? WHERE id = ?',
        Date.now(), Date.now(), workflow.id,
      );
    }
  }
  await execute('UPDATE workflow_event SET processedAt = ? WHERE id = ? AND processedAt IS NULL', Date.now(), row.id);
  if (row.type === 'external.event') {
    await execute(
      `UPDATE webhook_delivery SET workflowExecutionsCreated = ?
        WHERE workflowEventId = ? AND status = 'accepted'`,
      created, row.id,
    );
    if (created > 0 && row.resourceId) {
      await execute(
        `UPDATE webhook_source
            SET workflowExecutionsCreated = workflowExecutionsCreated + ?, updatedAt = ?
          WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
        created, Date.now(), row.organizationId, row.workspaceId, row.resourceId,
      );
    }
  }
  return created;
}

async function dispatchPendingEvents(): Promise<number> {
  const events = await query<EventRow>(
    `SELECT * FROM workflow_event
      WHERE processedAt IS NULL AND rejectedAt IS NULL
      ORDER BY createdAt ASC LIMIT ?`,
    MAX_EVENTS_PER_TICK,
  );
  let created = 0;
  for (const event of events) created += await dispatchEvent(event);
  return created;
}

async function createScheduleEvents(now: number): Promise<number> {
  const workflows = await query<WorkflowRow>(
    `SELECT * FROM workflow WHERE status = 'active' AND activeVersionId IS NOT NULL
      AND deletedAt IS NULL ORDER BY updatedAt ASC LIMIT 200`,
  );
  let created = 0;
  for (const workflow of workflows) {
    const version = await queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', workflow.activeVersionId);
    const definition = version ? parsedDefinition(version.definition) : null;
    if (!definition || definition.trigger.type !== 'schedule' ||
        !shouldRunSchedule(definition.trigger, now, workflow.lastScheduledAt)) continue;
    const minute = Math.floor(now / 60_000);
    const result = await emitWorkflowEvent({
      workspaceId: workflow.workspaceId,
      type: 'schedule',
      resourceType: 'workflow',
      resourceId: workflow.id,
      projectId: workflow.projectId,
      payload: {},
      source: 'schedule',
      dedupeKey: `schedule:${workflow.id}:${minute}`,
      createdAt: now,
    });
    if (result.ok) {
      await execute('UPDATE workflow SET lastScheduledAt = ?, updatedAt = ? WHERE id = ?', now, now, workflow.id);
      if (!result.duplicate) created += 1;
    }
  }
  return created;
}

async function createNodeTransitionEvents(now: number): Promise<number> {
  const workspaces = await query<{ id: string; organizationId: string }>(
    `SELECT id, organizationId FROM workspace
      WHERE organizationId IS NOT NULL AND archivedAt IS NULL`,
  );
  let created = 0;
  for (const workspace of workspaces) {
    const state = await readNodesState(workspace.id, now);
    for (const node of state.nodes) {
      const previous = await queryOne<{ state: string }>(
        `SELECT state FROM workflow_resource_state
          WHERE workspaceId = ? AND resourceType = 'node' AND resourceId = ?`,
        workspace.id, node.id,
      );
      await execute(
        `INSERT INTO workflow_resource_state
          (organizationId, workspaceId, resourceType, resourceId, state, updatedAt)
         VALUES (?, ?, 'node', ?, ?, ?)
         ON CONFLICT(workspaceId, resourceType, resourceId)
         DO UPDATE SET state = excluded.state, updatedAt = excluded.updatedAt`,
        workspace.organizationId, workspace.id, node.id, node.status, now,
      );
      if (!previous || previous.state === node.status || !['online', 'stale', 'offline'].includes(node.status)) continue;
      const type = `node.${node.status}` as WorkflowTriggerType;
      const emitted = await emitWorkflowEvent({
        workspaceId: workspace.id, type, resourceType: 'node', resourceId: node.id,
        payload: { status: node.status, previousStatus: previous.state, nodeId: node.id },
        dedupeKey: `${type}:${node.id}:${node.lastHeartbeatAt ?? node.pairedAt}`,
        createdAt: now,
      });
      if (emitted.ok && !emitted.duplicate) created += 1;
    }
  }
  return created;
}

async function recoverExpiredLeases(now: number): Promise<void> {
  const expired = await query<ExecutionRow>(
    `SELECT * FROM workflow_execution
      WHERE state = 'running' AND leaseExpiresAt IS NOT NULL AND leaseExpiresAt <= ? LIMIT 50`,
    now,
  );
  for (const execution of expired) {
    const version = await queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', execution.versionId);
    const definition = version ? parsedDefinition(version.definition) : null;
    if (!definition) {
      await failExecution(execution, 'Workflow definition is unreadable.', now, true);
      continue;
    }
    const terminal = executionTerminalState({
      now, timeoutAt: execution.timeoutAt,
      cancelRequested: execution.cancelRequestedAt !== null,
      actionFailed: true, attempt: execution.attempts, maxAttempts: execution.maxAttempts,
    });
    if (terminal === 'retry') {
      await execute(
        `UPDATE workflow_execution SET state = 'waiting', nextAttemptAt = ?, leaseToken = NULL,
          leaseExpiresAt = NULL, lastError = 'Execution lease expired.', updatedAt = ? WHERE id = ?`,
        now + retryDelayMs(definition, execution.attempts), now, execution.id,
      );
    } else {
      await finishExecution(execution, terminal === 'continue' ? 'failed' : terminal, 'Execution lease expired.', now);
    }
  }
  const expiredPending = await query<ExecutionRow>(
    `SELECT * FROM workflow_execution
      WHERE state IN ('queued','waiting') AND timeoutAt <= ? LIMIT 50`,
    now,
  );
  for (const execution of expiredPending) {
    await finishExecution(execution, 'timed_out', 'Execution timeout elapsed.', now);
  }
}

async function claimExecution(now: number): Promise<ExecutionRow | null> {
  const candidates = await query<ExecutionRow>(
    `SELECT * FROM workflow_execution
      WHERE state IN ('queued','waiting') AND (nextAttemptAt IS NULL OR nextAttemptAt <= ?)
        AND timeoutAt > ? ORDER BY createdAt ASC LIMIT 24`,
    now, now,
  );
  for (const candidate of candidates) {
    const version = await queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', candidate.versionId);
    const definition = version ? parsedDefinition(version.definition) : null;
    if (!definition) {
      await failExecution(candidate, 'Workflow definition is unreadable.', now, true);
      continue;
    }
    const leaseToken = createId('wflease');
    const changed = await execute(
      `UPDATE workflow_execution
        SET state = 'running', attempts = attempts + 1, leaseToken = ?, leaseExpiresAt = ?,
            startedAt = COALESCE(startedAt, ?), nextAttemptAt = NULL, updatedAt = ?
       WHERE id = ? AND state IN ('queued','waiting') AND timeoutAt > ?
         AND (SELECT COUNT(*) FROM workflow_execution active
               WHERE active.workflowId = workflow_execution.workflowId
                 AND active.state = 'running' AND active.leaseExpiresAt > ?) < ?
         AND (SELECT COUNT(*) FROM workflow_execution active
               WHERE active.workspaceId = workflow_execution.workspaceId
                 AND active.state = 'running' AND active.leaseExpiresAt > ?) < ?`,
      leaseToken, now + LEASE_MS, now, now, candidate.id, now,
      now, definition.concurrency.workflow, now, definition.concurrency.workspace,
    );
    if ((changed.meta.changes ?? 0) === 1) {
      return queryOne<ExecutionRow>('SELECT * FROM workflow_execution WHERE id = ? AND leaseToken = ?', candidate.id, leaseToken);
    }
  }
  return null;
}

async function assertActionResource(execution: ExecutionRow, event: EventRow, action: WorkflowAction): Promise<boolean> {
  if (action.type === 'workflow.pause' || action.type === 'notification.create' ||
      action.type === 'audit.note' || action.type === 'shield.create_incident') return true;
  if (!event.resourceId) return false;
  const prefix = action.type.split('.')[0];
  if (prefix === 'game_server') {
    return Boolean(await queryOne('SELECT id FROM game_server WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL', execution.workspaceId, event.resourceId));
  }
  if (prefix === 'deployment') {
    return Boolean(await queryOne('SELECT id FROM deployment WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL', execution.workspaceId, event.resourceId));
  }
  if (prefix === 'node') {
    return Boolean(await queryOne('SELECT id FROM compute_node WHERE workspaceId = ? AND id = ?', execution.workspaceId, event.resourceId));
  }
  if (prefix === 'ai') {
    return Boolean(await queryOne('SELECT jobId FROM ai_inference WHERE workspaceId = ? AND jobId = ?', execution.workspaceId, event.resourceId));
  }
  if (prefix === 'shield') {
    return Boolean(await queryOne('SELECT id FROM shield_finding WHERE workspaceId = ? AND id = ?', execution.workspaceId, event.resourceId));
  }
  return false;
}

type ActionOutcome =
  | { ok: true; resourceType: string; resourceId: string | null }
  | { ok: false; error: string };

async function executeAction(input: {
  execution: ExecutionRow;
  workflow: WorkflowRow;
  event: EventRow;
  action: WorkflowAction;
  actionIndex: number;
  attempt: number;
}): Promise<ActionOutcome> {
  const resourceId = input.event.resourceId;
  if (!(await assertActionResource(input.execution, input.event, input.action))) {
    return { ok: false, error: 'The event resource does not match this action in the workflow workspace.' };
  }
  if (EVENT_EMITTING_ACTIONS.has(input.action.type) &&
      input.execution.chainDepth >= MAX_WORKFLOW_CHAIN_DEPTH) {
    await recordWorkflowSecurityEvent({
      workspaceId: input.execution.workspaceId, workflowId: input.workflow.id,
      executionId: input.execution.id, type: 'workflow-chain-depth', severity: 'high',
      detail: 'A workflow action was stopped at the maximum causation depth.',
    }).catch(() => undefined);
    return { ok: false, error: 'Maximum workflow event chain depth reached.' };
  }
  const role = await ownerRole(input.workflow);
  if (!role) {
    await recordAudit({
      organizationId: input.execution.organizationId, workspaceId: input.execution.workspaceId,
      actorType: 'system', actorId: `workflow:${input.workflow.id}`,
      action: 'workflow.action.permission_denied', resourceType: 'workflow_action',
      resourceId: input.action.type, outcome: 'denied',
      metadata: { reason: 'inactive-owner', correlationId: input.execution.correlationId },
    }).catch(() => undefined);
    return { ok: false, error: 'The workflow owner is no longer active.' };
  }
  if (ADMIN_ACTIONS.has(input.action.type) && role !== 'owner' && role !== 'admin') {
    await Promise.all([
      recordAudit({
        organizationId: input.execution.organizationId, workspaceId: input.execution.workspaceId,
        actorType: 'system', actorId: `workflow:${input.workflow.id}`,
        action: 'workflow.action.permission_denied', resourceType: 'workflow_action',
        resourceId: input.action.type, outcome: 'denied',
        metadata: { reason: 'privileged-action', role, correlationId: input.execution.correlationId },
      }).catch(() => undefined),
      recordWorkflowSecurityEvent({
        workspaceId: input.execution.workspaceId, workflowId: input.workflow.id,
        executionId: input.execution.id, type: 'workflow-privileged-action-denied',
        severity: 'high', detail: 'A workflow owner no longer held the role required by its privileged action.',
      }).catch(() => undefined),
    ]);
    return { ok: false, error: 'The workflow owner no longer has permission for this privileged action.' };
  }
  const actor = `workflow:${input.workflow.id}`;
  const key = `wf:${input.execution.id}:${input.actionIndex}`;
  switch (input.action.type) {
    case 'deployment.redeploy':
    case 'deployment.stop': {
      const result = await createDeploymentAction({
        workspaceId: input.execution.workspaceId,
        deploymentId: resourceId!, actor,
        operation: input.action.type === 'deployment.redeploy' ? 'redeploy' : 'stop',
        idempotencyKey: key,
        allowedProjectIds: input.execution.projectId ? [input.execution.projectId] : null,
        workflowContext: {
          workflowId: input.workflow.id, executionId: input.execution.id,
          correlationId: input.execution.correlationId,
          chainDepth: input.execution.chainDepth + 1,
        },
      });
      return result.ok
        ? { ok: true, resourceType: 'deployment', resourceId }
        : { ok: false, error: result.error };
    }
    case 'deployment.rollback_to_previous_healthy': {
      const deployment = await queryOne<{ currentArtifactId: string | null; projectId: string; nodeId: string }>(
        `SELECT currentArtifactId, projectId, nodeId FROM deployment
          WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL`,
        input.execution.workspaceId, resourceId,
      );
      if (!deployment) return { ok: false, error: 'Deployment not found.' };
      const artifact = await queryOne<{ id: string }>(
        `SELECT id FROM app_artifact
          WHERE workspaceId = ? AND projectId = ? AND nodeId = ? AND deploymentId = ?
            AND state = 'verified' AND deletedAt IS NULL AND id <> COALESCE(?, '')
          ORDER BY COALESCE(activatedAt, verifiedAt, createdAt) DESC LIMIT 1`,
        input.execution.workspaceId, deployment.projectId, deployment.nodeId,
        resourceId, deployment.currentArtifactId,
      );
      if (!artifact) return { ok: false, error: 'No previous verified artifact is available.' };
      const result = await createDeploymentAction({
        workspaceId: input.execution.workspaceId, deploymentId: resourceId!, actor,
        operation: 'rollback', targetArtifactId: artifact.id,
        idempotencyKey: key,
        allowedProjectIds: input.execution.projectId ? [input.execution.projectId] : null,
        workflowContext: {
          workflowId: input.workflow.id, executionId: input.execution.id,
          correlationId: input.execution.correlationId,
          chainDepth: input.execution.chainDepth + 1,
        },
      });
      return result.ok
        ? { ok: true, resourceType: 'deployment', resourceId }
        : { ok: false, error: result.error };
    }
    case 'node.disable_assignments': {
      const now = Date.now();
      const changed = await execute(
        `UPDATE compute_node SET assignmentsDisabledAt = COALESCE(assignmentsDisabledAt, ?),
          assignmentsDisabledBy = COALESCE(assignmentsDisabledBy, ?), updatedAt = ?
         WHERE workspaceId = ? AND id = ? AND revokedAt IS NULL`,
        now, actor, now, input.execution.workspaceId, resourceId,
      );
      return (changed.meta.changes ?? 0) > 0
        ? { ok: true, resourceType: 'node', resourceId }
        : { ok: false, error: 'Node was not found or is revoked.' };
    }
    case 'node.revoke': {
      const revoked = await revokeNode({
        workspaceId: input.execution.workspaceId,
        nodeId: resourceId!,
        actor,
        workflowContext: {
          workflowId: input.workflow.id,
          executionId: input.execution.id,
          correlationId: input.execution.correlationId,
          chainDepth: input.execution.chainDepth + 1,
        },
      });
      if (!revoked) return { ok: false, error: 'Node not found.' };
      return { ok: true, resourceType: 'node', resourceId };
    }
    case 'game_server.stop':
    case 'game_server.restart': {
      const action = input.action.type === 'game_server.stop' ? 'stop' : 'restart';
      const result = await queueGameServerRequest({
        workspaceId: input.execution.workspaceId, actor, serverId: resourceId,
        body: { action, provider: 'local-node', zeroMode: true },
        idempotencyKey: key,
        workflowContext: {
          workflowId: input.workflow.id, executionId: input.execution.id,
          correlationId: input.execution.correlationId,
          chainDepth: input.execution.chainDepth + 1,
        },
      });
      return result.ok
        ? { ok: true, resourceType: 'game_server', resourceId }
        : { ok: false, error: result.error };
    }
    case 'ai.job.cancel': {
      const result = await cancelAiInference({ workspaceId: input.execution.workspaceId, jobId: resourceId!, actor });
      return result.ok
        ? { ok: true, resourceType: 'ai_job', resourceId }
        : { ok: false, error: result.error };
    }
    case 'shield.acknowledge': {
      const now = Date.now();
      const changed = await execute(
        `UPDATE shield_finding SET acknowledgedAt = COALESCE(acknowledgedAt, ?),
          acknowledgedBy = COALESCE(acknowledgedBy, ?)
         WHERE workspaceId = ? AND id = ? AND status = 'open'`,
        now, actor, input.execution.workspaceId, resourceId,
      );
      return (changed.meta.changes ?? 0) > 0
        ? { ok: true, resourceType: 'shield_finding', resourceId }
        : { ok: false, error: 'Open Shield finding not found.' };
    }
    case 'shield.create_incident': {
      const id = createId('incident');
      const now = Date.now();
      await execute(
        `INSERT INTO workflow_incident
          (id, organizationId, workspaceId, projectId, workflowId, executionId,
           resourceType, resourceId, title, detail, severity, status, createdBy,
           createdAt, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
        id, input.execution.organizationId, input.execution.workspaceId,
        input.execution.projectId, input.workflow.id, input.execution.id,
        input.event.resourceType, resourceId, input.action.title,
        input.action.message, input.action.severity ?? 'medium', actor, now, now,
      );
      return { ok: true, resourceType: 'incident', resourceId: id };
    }
    case 'notification.create': {
      const id = createId('note');
      const now = Date.now();
      const owner = await queryOne<{ ownerUserId: string }>('SELECT ownerUserId FROM organization WHERE id = ?', input.execution.organizationId);
      await execute(
        `INSERT OR IGNORE INTO internal_notification
          (id, organizationId, workspaceId, projectId, userId, workflowId,
           executionId, title, message, severity, resourceType, resourceId,
           href, dedupeKey, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        id, input.execution.organizationId, input.execution.workspaceId,
        input.execution.projectId, owner?.ownerUserId ?? null,
        input.workflow.id, input.execution.id, input.action.title,
        input.action.message, input.action.severity ?? 'medium',
        input.event.resourceType, resourceId,
        resourceId ? `/workflows?correlation=${encodeURIComponent(input.execution.correlationId)}` : '/workflows',
        key, now,
      );
      return { ok: true, resourceType: 'notification', resourceId: id };
    }
    case 'audit.note': {
      await recordAudit({
        organizationId: input.execution.organizationId,
        workspaceId: input.execution.workspaceId,
        actorType: 'system', actorId: actor,
        action: 'workflow.audit.note', resourceType: input.event.resourceType,
        resourceId, outcome: 'success', metadata: { note: input.action.message ?? 'Workflow note' },
      });
      return { ok: true, resourceType: 'audit_event', resourceId: null };
    }
    case 'workflow.pause': {
      await execute(`UPDATE workflow SET status = 'paused', updatedAt = ? WHERE id = ?`, Date.now(), input.workflow.id);
      return { ok: true, resourceType: 'workflow', resourceId: input.workflow.id };
    }
  }
}

async function finishExecution(
  execution: ExecutionRow,
  state: WorkflowExecutionState,
  error: string | null,
  now: number,
): Promise<void> {
  const terminal = TERMINAL.has(state);
  await execute(
    `UPDATE workflow_execution SET state = ?, lastError = ?,
      finishedAt = CASE WHEN ? THEN ? ELSE finishedAt END,
      deadLetterAt = CASE WHEN ? IN ('failed','timed_out') THEN ? ELSE deadLetterAt END,
      leaseToken = NULL, leaseExpiresAt = NULL, updatedAt = ? WHERE id = ?`,
    state, error?.slice(0, 500) ?? null, terminal ? 1 : 0, now, state, now, now, execution.id,
  );
  if (!terminal) return;
  const success = state === 'succeeded' || state === 'skipped';
  const failed = state === 'failed' || state === 'timed_out';
  await execute(
    `UPDATE workflow SET failureStreak = CASE WHEN ? THEN 0 WHEN ? THEN failureStreak + 1 ELSE failureStreak END,
      lastSucceededAt = CASE WHEN ? THEN ? ELSE lastSucceededAt END,
      lastFailedAt = CASE WHEN ? THEN ? ELSE lastFailedAt END,
      updatedAt = ? WHERE id = ?`,
    success ? 1 : 0, failed ? 1 : 0,
    success ? 1 : 0, now,
    failed ? 1 : 0, now,
    now, execution.workflowId,
  );
  await recordAudit({
    organizationId: execution.organizationId, workspaceId: execution.workspaceId,
    actorType: 'system', actorId: `workflow:${execution.workflowId}`,
    action: 'workflow.execution.end', resourceType: 'workflow_execution',
    resourceId: execution.id, outcome: success ? 'success' : state === 'cancelled' ? 'denied' : 'failed',
    metadata: { state, attempts: execution.attempts, correlationId: execution.correlationId },
  }).catch(() => undefined);
}

async function failExecution(execution: ExecutionRow, error: string, now: number, deadLetter: boolean): Promise<void> {
  await finishExecution(execution, 'failed', error, now);
  if (!deadLetter) await execute('UPDATE workflow_execution SET deadLetterAt = NULL WHERE id = ?', execution.id);
}

async function runClaimedExecution(execution: ExecutionRow): Promise<void> {
  const now = Date.now();
  const [workflow, version, event] = await Promise.all([
    queryOne<WorkflowRow>('SELECT * FROM workflow WHERE id = ? AND deletedAt IS NULL', execution.workflowId),
    queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', execution.versionId),
    queryOne<EventRow>('SELECT * FROM workflow_event WHERE id = ?', execution.eventId),
  ]);
  const definition = version ? parsedDefinition(version.definition) : null;
  if (!workflow || !version || !event || !definition) {
    await failExecution(execution, 'Workflow execution references are incomplete.', now, true);
    return;
  }
  const terminal = executionTerminalState({
    now, timeoutAt: execution.timeoutAt,
    cancelRequested: execution.cancelRequestedAt !== null,
    actionFailed: false, attempt: execution.attempts, maxAttempts: execution.maxAttempts,
  });
  if (terminal !== 'continue') {
    await finishExecution(
      execution,
      terminal === 'retry' ? 'failed' : terminal,
      terminal === 'cancelled' ? 'Cancellation requested.' : 'Execution timeout elapsed.',
      now,
    );
    return;
  }
  await recordAudit({
    organizationId: execution.organizationId, workspaceId: execution.workspaceId,
    actorType: 'system', actorId: `workflow:${workflow.id}`,
    action: 'workflow.execution.start', resourceType: 'workflow_execution',
    resourceId: execution.id, outcome: 'success',
    metadata: { version: version.version, attempt: execution.attempts, correlationId: execution.correlationId },
  }).catch(() => undefined);
  for (let index = execution.actionIndex; index < definition.actions.length; index += 1) {
    const refreshed = await queryOne<ExecutionRow>('SELECT * FROM workflow_execution WHERE id = ?', execution.id);
    if (!refreshed || refreshed.cancelRequestedAt !== null || Date.now() >= refreshed.timeoutAt) {
      await finishExecution(execution, refreshed?.cancelRequestedAt ? 'cancelled' : 'timed_out', refreshed?.cancelRequestedAt ? 'Cancellation requested.' : 'Execution timeout elapsed.', Date.now());
      return;
    }
    const action = definition.actions[index]!;
    const priorSuccess = await queryOne<{ id: string }>(
      `SELECT id FROM workflow_action_execution
        WHERE executionId = ? AND actionIndex = ? AND state = 'succeeded' LIMIT 1`,
      execution.id, index,
    );
    if (priorSuccess) {
      await execute('UPDATE workflow_execution SET actionIndex = ?, updatedAt = ? WHERE id = ?', index + 1, Date.now(), execution.id);
      continue;
    }
    const actionId = createId('wfact');
    const actionKey = `wf:${execution.id}:${index}:${execution.attempts}`;
    await execute(
      `INSERT INTO workflow_action_execution
        (id, organizationId, workspaceId, workflowId, executionId, actionIndex,
         attempt, actionType, state, idempotencyKey, startedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)`,
      actionId, execution.organizationId, execution.workspaceId, workflow.id,
      execution.id, index, execution.attempts, action.type, actionKey, Date.now(),
    );
    const outcome = await executeAction({ execution, workflow, event, action, actionIndex: index, attempt: execution.attempts });
    const finished = Date.now();
    await execute(
      `UPDATE workflow_action_execution SET state = ?, resourceType = ?, resourceId = ?,
        error = ?, finishedAt = ? WHERE id = ?`,
      outcome.ok ? 'succeeded' : 'failed',
      outcome.ok ? outcome.resourceType : null,
      outcome.ok ? outcome.resourceId : null,
      outcome.ok ? null : outcome.error.slice(0, 500), finished, actionId,
    );
    await recordAudit({
      organizationId: execution.organizationId, workspaceId: execution.workspaceId,
      actorType: 'system', actorId: `workflow:${workflow.id}`,
      action: 'workflow.action.outcome', resourceType: 'workflow_action',
      resourceId: actionId, outcome: outcome.ok ? 'success' : 'failed',
      metadata: { actionType: action.type, attempt: execution.attempts, correlationId: execution.correlationId },
    }).catch(() => undefined);
    if (!outcome.ok) {
      const decision = executionTerminalState({
        now: finished, timeoutAt: execution.timeoutAt,
        cancelRequested: false, actionFailed: true,
        attempt: execution.attempts, maxAttempts: execution.maxAttempts,
      });
      if (decision === 'retry') {
        await execute(
          `UPDATE workflow_execution SET state = 'waiting', nextAttemptAt = ?,
            lastError = ?, leaseToken = NULL, leaseExpiresAt = NULL, updatedAt = ? WHERE id = ?`,
          finished + retryDelayMs(definition, execution.attempts), outcome.error.slice(0, 500), finished, execution.id,
        );
        await recordAudit({
          organizationId: execution.organizationId, workspaceId: execution.workspaceId,
          actorType: 'system', actorId: `workflow:${workflow.id}`,
          action: 'workflow.execution.retry', resourceType: 'workflow_execution',
          resourceId: execution.id, outcome: 'failed',
          metadata: { attempt: execution.attempts, nextAttemptAt: finished + retryDelayMs(definition, execution.attempts) },
        }).catch(() => undefined);
      } else {
        await finishExecution(execution, decision === 'continue' ? 'failed' : decision, outcome.error, finished);
      }
      return;
    }
    await execute(
      `UPDATE workflow_execution SET actionIndex = ?, leaseExpiresAt = ?, updatedAt = ? WHERE id = ?`,
      index + 1, Date.now() + LEASE_MS, Date.now(), execution.id,
    );
  }
  await finishExecution(execution, 'succeeded', null, Date.now());
}

async function processExecutions(): Promise<number> {
  let processed = 0;
  for (; processed < MAX_EXECUTIONS_PER_TICK; processed += 1) {
    const execution = await claimExecution(Date.now());
    if (!execution) break;
    await runClaimedExecution(execution);
  }
  return processed;
}

export async function triggerWorkflowManual(input: {
  organizationId: string;
  workspaceId: string;
  workflowId: string;
  actor: Actor;
}): Promise<{ ok: true; executionId: string } | { ok: false; status: number; error: string }> {
  if (!can(input.actor, 'workflow.execute')) return { ok: false, status: 403, error: 'Your role cannot run workflows.' };
  const workflow = await workflowById(input.organizationId, input.workspaceId, input.workflowId);
  if (!workflow || !canAccessProject(input.actor, workflow.projectId)) return { ok: false, status: 404, error: 'Workflow not found.' };
  if (workflow.status !== 'active' || !workflow.activeVersionId) return { ok: false, status: 409, error: 'Only an active published workflow can run.' };
  const version = await queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', workflow.activeVersionId);
  const definition = version ? parsedDefinition(version.definition) : null;
  if (!version || !definition || definition.trigger.type !== 'manual') return { ok: false, status: 409, error: 'This workflow does not use the manual trigger.' };
  const now = Date.now();
  const event: EventRow = {
    id: createId('wfevt'), organizationId: workflow.organizationId,
    workspaceId: workflow.workspaceId, projectId: workflow.projectId,
    type: 'manual', resourceType: 'workflow', resourceId: workflow.id,
    payload: '{}', source: 'manual',
    dedupeKey: `manual:${workflow.id}:${createId('run')}`,
    correlationId: createId('corr'), causationId: null, sourceWorkflowId: null,
    chainDepth: 0, createdAt: now, processedAt: now,
    rejectedAt: null, rejectionReason: null,
  };
  await execute(
    `INSERT INTO workflow_event
      (id, organizationId, workspaceId, projectId, type, resourceType, resourceId,
       payload, source, trusted, dedupeKey, correlationId, causationId,
       sourceWorkflowId, chainDepth, createdAt, processedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'manual', 1, ?, ?, NULL, NULL, 0, ?, ?)`,
    event.id, event.organizationId, event.workspaceId, event.projectId,
    event.type, event.resourceType, event.resourceId, event.payload,
    event.dedupeKey, event.correlationId, now, now,
  );
  const execution = await createExecution({ workflow, version, event, state: 'queued', definition, createdBy: input.actor.userId });
  if (!execution) return { ok: false, status: 500, error: 'Manual execution could not be recorded.' };
  await processExecutions();
  return { ok: true, executionId: execution.id };
}

export async function cancelWorkflowExecution(input: {
  organizationId: string;
  workspaceId: string;
  executionId: string;
  actor: Actor;
}): Promise<{ ok: true; state: WorkflowExecutionState } | { ok: false; status: number; error: string }> {
  if (!can(input.actor, 'workflow.execute')) return { ok: false, status: 403, error: 'Your role cannot cancel executions.' };
  const execution = await queryOne<ExecutionRow>(
    `SELECT * FROM workflow_execution WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
    input.organizationId, input.workspaceId, input.executionId,
  );
  if (!execution || !canAccessProject(input.actor, execution.projectId)) return { ok: false, status: 404, error: 'Execution not found.' };
  if (TERMINAL.has(execution.state)) return { ok: true, state: execution.state };
  const now = Date.now();
  await execute(
    `UPDATE workflow_execution SET cancelRequestedAt = ?, cancelRequestedBy = ?,
      updatedAt = ? WHERE id = ? AND state NOT IN ('succeeded','failed','cancelled','timed_out','skipped')`,
    now, input.actor.userId, now, execution.id,
  );
  const refreshed = await queryOne<ExecutionRow>('SELECT * FROM workflow_execution WHERE id = ?', execution.id);
  if (refreshed && (refreshed.state === 'queued' || refreshed.state === 'waiting')) {
    await finishExecution(refreshed, 'cancelled', 'Cancellation requested.', now);
    return { ok: true, state: 'cancelled' };
  }
  return { ok: true, state: refreshed?.state ?? execution.state };
}

export async function retryWorkflowExecution(input: {
  organizationId: string;
  workspaceId: string;
  executionId: string;
  actor: Actor;
}): Promise<{ ok: true; executionId: string } | { ok: false; status: number; error: string }> {
  if (!can(input.actor, 'workflow.retry')) return { ok: false, status: 403, error: 'Only owners and admins can retry failed executions.' };
  const original = await queryOne<ExecutionRow>(
    `SELECT * FROM workflow_execution WHERE organizationId = ? AND workspaceId = ? AND id = ?`,
    input.organizationId, input.workspaceId, input.executionId,
  );
  if (!original || !['failed', 'timed_out', 'cancelled'].includes(original.state)) return { ok: false, status: 409, error: 'Only a final failed, timed-out, or cancelled execution can be retried.' };
  const [workflow, version, oldEvent] = await Promise.all([
    queryOne<WorkflowRow>('SELECT * FROM workflow WHERE id = ? AND deletedAt IS NULL', original.workflowId),
    queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', original.versionId),
    queryOne<EventRow>('SELECT * FROM workflow_event WHERE id = ?', original.eventId),
  ]);
  const definition = version ? parsedDefinition(version.definition) : null;
  if (!workflow || !version || !oldEvent || !definition) return { ok: false, status: 409, error: 'The original immutable version is unavailable.' };
  const now = Date.now();
  const event: EventRow = {
    ...oldEvent,
    id: createId('wfevt'), source: 'manual',
    dedupeKey: `retry:${original.id}:${createId('run')}`,
    causationId: original.id,
    chainDepth: Math.min(MAX_WORKFLOW_CHAIN_DEPTH, original.chainDepth + 1),
    createdAt: now, processedAt: now, rejectedAt: null, rejectionReason: null,
  };
  await execute(
    `INSERT INTO workflow_event
      (id, organizationId, workspaceId, projectId, type, resourceType, resourceId,
       payload, source, trusted, dedupeKey, correlationId, causationId,
       sourceWorkflowId, chainDepth, createdAt, processedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'manual', 1, ?, ?, ?, NULL, ?, ?, ?)`,
    event.id, event.organizationId, event.workspaceId, event.projectId, event.type,
    event.resourceType, event.resourceId, event.payload, event.dedupeKey,
    event.correlationId, original.id, event.chainDepth, now, now,
  );
  const retried = await createExecution({
    workflow, version, event, state: 'queued', definition,
    createdBy: input.actor.userId, manualRetryOf: original.id,
  });
  if (!retried) return { ok: false, status: 500, error: 'Retry could not be recorded.' };
  await recordAudit({
    organizationId: original.organizationId, workspaceId: original.workspaceId,
    actorType: 'user', actorId: input.actor.userId,
    action: 'workflow.execution.manual_retry', resourceType: 'workflow_execution',
    resourceId: retried.id, outcome: 'success', metadata: { originalExecutionId: original.id },
  });
  await processExecutions();
  return { ok: true, executionId: retried.id };
}

export async function markNotificationRead(input: {
  organizationId: string;
  workspaceId: string;
  notificationId: string;
  userId: string;
}): Promise<boolean> {
  const result = await execute(
    `UPDATE internal_notification SET readAt = COALESCE(readAt, ?)
      WHERE organizationId = ? AND workspaceId = ? AND id = ?
        AND (userId IS NULL OR userId = ?)`,
    Date.now(), input.organizationId, input.workspaceId, input.notificationId, input.userId,
  );
  return (result.meta.changes ?? 0) > 0;
}

export async function runWorkflowEngineTick(now = Date.now()): Promise<{
  schedules: number;
  nodeEvents: number;
  executionsCreated: number;
  executionsProcessed: number;
}> {
  await recoverExpiredLeases(now);
  const [schedules, nodeEvents] = await Promise.all([
    createScheduleEvents(now),
    createNodeTransitionEvents(now),
  ]);
  const executionsCreated = await dispatchPendingEvents();
  const executionsProcessed = await processExecutions();
  return { schedules, nodeEvents, executionsCreated, executionsProcessed };
}

export type WorkflowsShieldState = {
  privilegedLowOwner: number;
  excessiveRetry: number;
  potentialCycles: number;
  noTimeout: number;
  highConcurrency: number;
  stale: number;
  repeatedFailures: number;
  suspiciousVolume: number;
  orphanReferences: number;
  crossOrgAttempts: number;
  secretExposure: number;
  zeroModeBypass: number;
};

export async function workflowsForShield(
  organizationId: string,
  workspaceId: string,
  now = Date.now(),
): Promise<WorkflowsShieldState> {
  const workflows = await query<WorkflowRow>(
    `SELECT * FROM workflow WHERE organizationId = ? AND workspaceId = ? AND deletedAt IS NULL`,
    organizationId, workspaceId,
  );
  let excessiveRetry = 0;
  let potentialCycles = 0;
  let noTimeout = 0;
  let highConcurrency = 0;
  let privilegedLowOwner = 0;
  for (const workflow of workflows) {
    if (!workflow.activeVersionId) continue;
    const version = await queryOne<VersionRow>('SELECT * FROM workflow_version WHERE id = ?', workflow.activeVersionId);
    const definition = version ? parsedDefinition(version.definition) : null;
    if (!definition) continue;
    if (definition.retry.maxAttempts > 5) excessiveRetry += 1;
    if (definition.timeoutSeconds < 5 || definition.timeoutSeconds > 300) noTimeout += 1;
    if (definition.concurrency.workflow > 4 || definition.concurrency.workspace > 8) highConcurrency += 1;
    const validation = validateWorkflowDefinition(definition, {
      role: (await ownerRole(workflow)) ?? 'viewer',
      projectId: workflow.projectId,
      zeroMode: true,
    });
    if (!validation.ok && validation.securityCode === 'workflow-cycle-rejected') potentialCycles += 1;
    const role = await ownerRole(workflow);
    if (definition.actions.some((action) => ADMIN_ACTIONS.has(action.type)) && role !== 'owner' && role !== 'admin') privilegedLowOwner += 1;
  }
  const [repeatedFailures, suspiciousVolume, orphanReferences, crossOrgAttempts, secretExposure, zeroModeBypass] = await Promise.all([
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM workflow WHERE organizationId = ? AND workspaceId = ?
        AND deletedAt IS NULL AND failureStreak >= 3`, organizationId, workspaceId,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM workflow_event WHERE organizationId = ? AND workspaceId = ? AND createdAt >= ?`,
      organizationId, workspaceId, now - 60 * 60_000,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM workflow w
        LEFT JOIN workflow_version v ON v.id = w.activeVersionId AND v.workflowId = w.id
       WHERE w.organizationId = ? AND w.workspaceId = ? AND w.deletedAt IS NULL
         AND w.activeVersionId IS NOT NULL AND v.id IS NULL`, organizationId, workspaceId,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM workflow_security_event
        WHERE organizationId = ? AND workspaceId = ? AND createdAt >= ?
          AND type IN ('workflow-cross-project-event','workflow-forged-event')`,
      organizationId, workspaceId, now - 24 * 60 * 60_000,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM workflow_security_event
        WHERE organizationId = ? AND workspaceId = ? AND createdAt >= ?
          AND type IN ('workflow-event-payload-rejected','workflow-secret-exposure')`,
      organizationId, workspaceId, now - 24 * 60 * 60_000,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM workflow_security_event
        WHERE organizationId = ? AND workspaceId = ? AND createdAt >= ?
          AND type = 'workflow-zero-mode-bypass'`,
      organizationId, workspaceId, now - 24 * 60 * 60_000,
    ),
  ]);
  return {
    privilegedLowOwner, excessiveRetry, potentialCycles, noTimeout, highConcurrency,
    stale: workflows.filter((item) => item.updatedAt < now - 90 * 24 * 60 * 60_000).length,
    repeatedFailures: repeatedFailures?.total ?? 0,
    suspiciousVolume: Math.max(0, (suspiciousVolume?.total ?? 0) - 500),
    orphanReferences: orphanReferences?.total ?? 0,
    crossOrgAttempts: crossOrgAttempts?.total ?? 0,
    secretExposure: secretExposure?.total ?? 0,
    zeroModeBypass: zeroModeBypass?.total ?? 0,
  };
}

/** Used by tests and diagnostics without exposing definitions or secret values. */
export async function workflowQueueCounts(workspaceId: string): Promise<Record<WorkflowExecutionState, number>> {
  const rows = await query<{ state: WorkflowExecutionState; total: number }>(
    `SELECT state, COUNT(*) AS total FROM workflow_execution WHERE workspaceId = ? GROUP BY state`,
    workspaceId,
  );
  const result = Object.fromEntries([
    'queued','running','waiting','succeeded','failed','cancelled','timed_out','skipped',
  ].map((state) => [state, 0])) as Record<WorkflowExecutionState, number>;
  for (const row of rows) result[row.state] = row.total;
  return redactWorkflowValue(result) as Record<WorkflowExecutionState, number>;
}

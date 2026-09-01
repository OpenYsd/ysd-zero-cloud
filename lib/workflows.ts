import type { Role } from './roles.ts';

/**
 * Pure contracts for the Phase 9 workflow engine.
 *
 * No user expression is executable. A definition is a bounded JSON document
 * made from allowlisted triggers, paths, operators, and actions. Server code
 * validates the same document again before publishing and before execution.
 */

export const WORKFLOW_TRIGGER_TYPES = [
  'deployment.created',
  'deployment.deployed',
  'deployment.failed',
  'deployment.rolled_back',
  'node.online',
  'node.offline',
  'node.stale',
  'node.revoked',
  'shield.finding.opened',
  'shield.finding.resolved',
  'shield.finding.severity_changed',
  'game_server.started',
  'game_server.stopped',
  'game_server.crashed',
  'game_server.crash_loop',
  'ai.job.completed',
  'ai.job.failed',
  'organization.member.invited',
  'organization.member.removed',
  'organization.member.role_changed',
  'incident.opened',
  'incident.acknowledged',
  'incident.severity_changed',
  'incident.resolved',
  'incident.reopened',
  'external.event',
  'schedule',
  'manual',
] as const;

export type WorkflowTriggerType = (typeof WORKFLOW_TRIGGER_TYPES)[number];

export const WORKFLOW_ACTION_TYPES = [
  'deployment.redeploy',
  'deployment.rollback_to_previous_healthy',
  'deployment.stop',
  'node.disable_assignments',
  'node.revoke',
  'game_server.stop',
  'game_server.restart',
  'ai.job.cancel',
  'shield.acknowledge',
  'shield.create_incident',
  'audit.note',
  'notification.create',
  'workflow.pause',
] as const;

export type WorkflowActionType = (typeof WORKFLOW_ACTION_TYPES)[number];

export const WORKFLOW_STATES = [
  'queued',
  'running',
  'waiting',
  'succeeded',
  'failed',
  'cancelled',
  'timed_out',
  'skipped',
] as const;

export type WorkflowExecutionState = (typeof WORKFLOW_STATES)[number];

export const CONDITION_OPERATORS = [
  'equals',
  'not_equals',
  'in',
  'contains',
  'greater_than',
  'greater_or_equal',
  'less_than',
  'less_or_equal',
] as const;

export type ConditionOperator = (typeof CONDITION_OPERATORS)[number];

/** Only these paths can be read from a trusted event. */
export const WORKFLOW_EVENT_PATHS = [
  'event.type',
  'event.projectId',
  'event.resourceId',
  'event.payload.status',
  'event.payload.previousStatus',
  'event.payload.severity',
  'event.payload.previousSeverity',
  'event.payload.role',
  'event.payload.previousRole',
  'event.payload.projectId',
  'event.payload.nodeId',
  'event.payload.deploymentId',
  'event.payload.serverId',
  'event.payload.jobId',
  'event.payload.findingId',
  'event.payload.incidentId',
  'event.payload.crashCount',
  'event.payload.failureCount',
  'event.payload.environment',
  'event.payload.sourceId',
  'event.payload.externalEventType',
  'event.payload.externalEventId',
  'event.payload.subject',
  'event.payload.category',
  'event.payload.action',
  'event.payload.ref',
  'event.payload.label',
  'event.payload.count',
  'event.payload.value',
  'event.payload.success',
] as const;

export type WorkflowEventPath = (typeof WORKFLOW_EVENT_PATHS)[number];
export const WORKFLOW_EXTERNAL_EVENT_PATHS = [
  'event.type',
  'event.resourceId',
  'event.payload.status',
  'event.payload.severity',
  'event.payload.environment',
  'event.payload.sourceId',
  'event.payload.externalEventType',
  'event.payload.externalEventId',
  'event.payload.subject',
  'event.payload.category',
  'event.payload.action',
  'event.payload.ref',
  'event.payload.label',
  'event.payload.count',
  'event.payload.value',
  'event.payload.success',
] as const satisfies readonly WorkflowEventPath[];
export type WorkflowScalar = string | number | boolean | null;

export type WorkflowCondition = {
  path: WorkflowEventPath;
  operator: ConditionOperator;
  value: WorkflowScalar | WorkflowScalar[];
};

export type WorkflowAction = {
  type: WorkflowActionType;
  target: 'event.resource' | 'self';
  title?: string;
  message?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  confirmationPolicy?: 'owner-admin';
};

export type WorkflowTrigger =
  | { type: Exclude<WorkflowTriggerType, 'schedule' | 'external.event'> }
  | { type: 'external.event'; sourceId: string }
  | {
      type: 'schedule';
      intervalMinutes?: number;
      cron?: string;
    };

export type WorkflowDefinition = {
  trigger: WorkflowTrigger;
  conditions: WorkflowCondition[];
  actions: WorkflowAction[];
  retry: {
    maxAttempts: number;
    initialDelaySeconds: number;
    maximumDelaySeconds: number;
  };
  timeoutSeconds: number;
  concurrency: {
    workflow: number;
    workspace: number;
  };
};

export type TrustedWorkflowEvent = {
  id: string;
  type: WorkflowTriggerType;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  resourceId: string | null;
  payload: Record<string, WorkflowScalar>;
  correlationId: string;
  causationId: string | null;
  sourceWorkflowId: string | null;
  chainDepth: number;
  createdAt: number;
};

export type WorkflowValidationResult =
  | { ok: true; definition: WorkflowDefinition; warnings: string[] }
  | { ok: false; error: string; securityCode?: string };

const TRIGGERS = new Set<string>(WORKFLOW_TRIGGER_TYPES);
const ACTIONS = new Set<string>(WORKFLOW_ACTION_TYPES);
const OPERATORS = new Set<string>(CONDITION_OPERATORS);
const PATHS = new Set<string>(WORKFLOW_EVENT_PATHS);
const EXTERNAL_PATHS = new Set<string>(WORKFLOW_EXTERNAL_EVENT_PATHS);
const EXTERNAL_ONLY_PATHS = new Set<string>([
  'event.payload.sourceId', 'event.payload.externalEventType', 'event.payload.externalEventId',
  'event.payload.subject', 'event.payload.category', 'event.payload.action', 'event.payload.ref',
  'event.payload.label', 'event.payload.count', 'event.payload.value', 'event.payload.success',
]);
const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const MAX_TEXT = 240;
export const MAX_WORKFLOW_CHAIN_DEPTH = 5;

const FORBIDDEN_KEY = /(?:^|_)(?:url|uri|endpoint|host|hostname|ip|command|cmd|shell|script|eval|code|provider|billing|price|cost|zero.?mode|token|password|secret|prompt|result|payload)(?:$|_)/i;
const FORBIDDEN_VALUE = /(?:https?:\/\/|file:\/\/|169\.254\.169\.254|localhost|127\.0\.0\.1|::1|\beval\s*\(|\b(?:bash|powershell|cmd\.exe|sh\s+-c)\b)/i;

const ACTION_KEYS = new Set([
  'type',
  'target',
  'title',
  'message',
  'severity',
  'confirmationPolicy',
]);
const CONDITION_KEYS = new Set(['path', 'operator', 'value']);
const ROOT_KEYS = new Set(['trigger', 'conditions', 'actions', 'retry', 'timeoutSeconds', 'concurrency']);
const TRIGGER_KEYS = new Set(['type', 'intervalMinutes', 'cron', 'sourceId']);
const RETRY_KEYS = new Set(['maxAttempts', 'initialDelaySeconds', 'maximumDelaySeconds']);
const CONCURRENCY_KEYS = new Set(['workflow', 'workspace']);

const ADMIN_ACTIONS = new Set<WorkflowActionType>([
  'node.disable_assignments',
  'node.revoke',
  'game_server.stop',
  'game_server.restart',
  'ai.job.cancel',
  'shield.acknowledge',
]);

const ACTION_EMITTED_EVENTS: Readonly<Partial<Record<WorkflowActionType, readonly WorkflowTriggerType[]>>> = {
  'deployment.redeploy': ['deployment.created', 'deployment.deployed'],
  'deployment.rollback_to_previous_healthy': ['deployment.rolled_back'],
  'node.revoke': ['node.revoked'],
  'game_server.stop': ['game_server.stopped'],
  'game_server.restart': ['game_server.started'],
  'shield.create_incident': ['incident.opened'],
};

const ACTION_TRIGGER_PREFIX: Readonly<Partial<Record<WorkflowActionType, string>>> = {
  'deployment.redeploy': 'deployment.',
  'deployment.rollback_to_previous_healthy': 'deployment.',
  'deployment.stop': 'deployment.',
  'node.disable_assignments': 'node.',
  'node.revoke': 'node.',
  'game_server.stop': 'game_server.',
  'game_server.restart': 'game_server.',
  'ai.job.cancel': 'ai.',
  'shield.acknowledge': 'shield.',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function safeText(value: unknown, maximum = MAX_TEXT): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || FORBIDDEN_VALUE.test(normalized)) return null;
  return normalized;
}

function containsForbiddenInput(value: unknown, depth = 0): boolean {
  if (depth > 8) return true;
  if (typeof value === 'string') return FORBIDDEN_VALUE.test(value);
  if (Array.isArray(value)) return value.some((item) => containsForbiddenInput(item, depth + 1));
  if (!isRecord(value)) return false;
  return Object.entries(value).some(
    ([key, item]) => FORBIDDEN_KEY.test(key) || containsForbiddenInput(item, depth + 1),
  );
}

function integer(value: unknown, minimum: number, maximum: number): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
    ? value
    : null;
}

function scalar(value: unknown): value is WorkflowScalar {
  return value === null || typeof value === 'string' || typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value));
}

/** Supports only UTC hourly/daily cron shapes; arbitrary cron syntax is refused. */
export function validSafeCron(value: string): boolean {
  if (value.length > 32) return false;
  const parts = value.trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [minute, hour, day, month, weekday] = parts;
  const number = (item: string, min: number, max: number) => {
    if (!/^\d{1,2}$/.test(item)) return false;
    const parsed = Number(item);
    return parsed >= min && parsed <= max;
  };
  if (day !== '*' || month !== '*' || weekday !== '*') return false;
  return number(minute!, 0, 59) && (hour === '*' || number(hour!, 0, 23));
}

function parseTrigger(value: unknown): WorkflowTrigger | null {
  if (!isRecord(value) || !exactKeys(value, TRIGGER_KEYS) || typeof value.type !== 'string' || !TRIGGERS.has(value.type)) {
    return null;
  }
  if (value.type === 'external.event') {
    if ('intervalMinutes' in value || 'cron' in value ||
        typeof value.sourceId !== 'string' || !/^whsrc_[a-f0-9]{24}$/.test(value.sourceId)) return null;
    return { type: 'external.event', sourceId: value.sourceId };
  }
  if (value.type !== 'schedule') {
    if ('intervalMinutes' in value || 'cron' in value || 'sourceId' in value) return null;
    return { type: value.type as Exclude<WorkflowTriggerType, 'schedule' | 'external.event'> };
  }
  if ('sourceId' in value) return null;
  const intervalMinutes = value.intervalMinutes === undefined
    ? undefined
    : integer(value.intervalMinutes, 5, 1_440) ?? null;
  const cron = value.cron === undefined
    ? undefined
    : typeof value.cron === 'string' && validSafeCron(value.cron) ? value.cron.trim() : null;
  if ((intervalMinutes === undefined) === (cron === undefined) || intervalMinutes === null || cron === null) return null;
  return intervalMinutes === undefined
    ? { type: 'schedule', cron }
    : { type: 'schedule', intervalMinutes };
}

function parseCondition(value: unknown): WorkflowCondition | null {
  if (!isRecord(value) || !exactKeys(value, CONDITION_KEYS)) return null;
  if (typeof value.path !== 'string' || !PATHS.has(value.path) ||
      typeof value.operator !== 'string' || !OPERATORS.has(value.operator)) return null;
  if (value.operator === 'in') {
    if (!Array.isArray(value.value) || value.value.length < 1 || value.value.length > 20 || !value.value.every(scalar)) return null;
  } else if (!scalar(value.value)) {
    return null;
  }
  if (typeof value.value === 'string' && value.value.length > MAX_TEXT) return null;
  return {
    path: value.path as WorkflowEventPath,
    operator: value.operator as ConditionOperator,
    value: value.value as WorkflowScalar | WorkflowScalar[],
  };
}

function parseAction(value: unknown): WorkflowAction | null {
  if (!isRecord(value) || !exactKeys(value, ACTION_KEYS) || typeof value.type !== 'string' || !ACTIONS.has(value.type)) return null;
  const type = value.type as WorkflowActionType;
  const target = value.target;
  if (target !== 'event.resource' && target !== 'self') return null;
  if ((type === 'workflow.pause') !== (target === 'self')) return null;
  const textAction = type === 'notification.create' || type === 'audit.note' || type === 'shield.create_incident';
  const title = value.title === undefined ? undefined : safeText(value.title, 100) ?? null;
  const message = value.message === undefined ? undefined : safeText(value.message, MAX_TEXT) ?? null;
  if (title === null || message === null) return null;
  if (textAction && (!message || (type !== 'audit.note' && !title))) return null;
  if (!textAction && (title !== undefined || message !== undefined)) return null;
  const severity = value.severity;
  if (severity !== undefined && (!textAction || typeof severity !== 'string' || !SEVERITIES.has(severity))) return null;
  const confirmationPolicy = value.confirmationPolicy;
  if (type === 'node.revoke') {
    if (confirmationPolicy !== 'owner-admin') return null;
  } else if (confirmationPolicy !== undefined) {
    return null;
  }
  return {
    type,
    target,
    ...(title ? { title } : {}),
    ...(message ? { message } : {}),
    ...(severity ? { severity: severity as WorkflowAction['severity'] } : {}),
    ...(confirmationPolicy ? { confirmationPolicy: 'owner-admin' as const } : {}),
  };
}

export function workflowPotentialCycle(definition: WorkflowDefinition): boolean {
  return definition.actions.some((action) =>
    ACTION_EMITTED_EVENTS[action.type]?.includes(definition.trigger.type) ?? false,
  );
}

export function validateWorkflowDefinition(
  value: unknown,
  context: { role: Role; projectId: string | null; zeroMode: boolean },
): WorkflowValidationResult {
  if (!context.zeroMode) {
    return { ok: false, error: 'Workflow publishing requires Zero Mode server-side.', securityCode: 'workflow-zero-mode-bypass' };
  }
  if (containsForbiddenInput(value)) {
    return { ok: false, error: 'URLs, providers, secrets, scripts, commands, and Zero Mode overrides are forbidden.', securityCode: 'workflow-payload-abuse' };
  }
  if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)) {
    return { ok: false, error: 'Workflow definition fields are invalid.' };
  }
  const trigger = parseTrigger(value.trigger);
  if (!trigger) return { ok: false, error: 'Choose one reviewed workflow trigger.' };
  if (!Array.isArray(value.conditions) || value.conditions.length > 8) {
    return { ok: false, error: 'A workflow can have at most 8 conditions.' };
  }
  const conditions = value.conditions.map(parseCondition);
  if (conditions.some((item) => item === null)) {
    return { ok: false, error: 'Conditions must use allowlisted event paths and operators.', securityCode: 'workflow-expression-rejected' };
  }
  const conditionPaths = (conditions as WorkflowCondition[]).map((condition) => condition.path);
  if (trigger.type === 'external.event' && conditionPaths.some((path) => !EXTERNAL_PATHS.has(path)) ||
      trigger.type !== 'external.event' && conditionPaths.some((path) => EXTERNAL_ONLY_PATHS.has(path))) {
    return {
      ok: false,
      error: 'Condition fields must belong to the selected trigger schema.',
      securityCode: 'workflow-expression-rejected',
    };
  }
  if (!Array.isArray(value.actions) || value.actions.length < 1 || value.actions.length > 8) {
    return { ok: false, error: 'A workflow needs between 1 and 8 reviewed actions.' };
  }
  const actions = value.actions.map(parseAction);
  if (actions.some((item) => item === null)) {
    return { ok: false, error: 'Choose only reviewed, bounded workflow actions.', securityCode: 'workflow-action-rejected' };
  }
  if (!isRecord(value.retry) || !exactKeys(value.retry, RETRY_KEYS) ||
      !isRecord(value.concurrency) || !exactKeys(value.concurrency, CONCURRENCY_KEYS)) {
    return { ok: false, error: 'Retry or concurrency policy fields are invalid.' };
  }
  const maxAttempts = integer(value.retry.maxAttempts, 1, 5);
  const initialDelaySeconds = integer(value.retry.initialDelaySeconds, 5, 300);
  const maximumDelaySeconds = integer(value.retry.maximumDelaySeconds, 5, 3_600);
  const timeoutSeconds = integer(value.timeoutSeconds, 5, 300);
  const workflowConcurrency = integer(value.concurrency.workflow, 1, 4);
  const workspaceConcurrency = integer(value.concurrency.workspace, 1, 8);
  if (maxAttempts === null || initialDelaySeconds === null || maximumDelaySeconds === null ||
      maximumDelaySeconds < initialDelaySeconds || timeoutSeconds === null ||
      workflowConcurrency === null || workspaceConcurrency === null ||
      workspaceConcurrency < workflowConcurrency) {
    return { ok: false, error: 'Retry, timeout, or concurrency policy exceeds the Zero Mode bounds.', securityCode: 'workflow-policy-excessive' };
  }
  const typedActions = actions as WorkflowAction[];
  if (context.role === 'viewer') return { ok: false, error: 'Viewers cannot create workflows.' };
  if (context.role === 'developer') {
    if (!context.projectId) return { ok: false, error: 'Developers may create only project-scoped workflows.' };
    if (typedActions.some((action) => ADMIN_ACTIONS.has(action.type))) {
      return { ok: false, error: 'This action requires an owner or admin.', securityCode: 'workflow-privileged-action-denied' };
    }
  }
  const definition: WorkflowDefinition = {
    trigger,
    conditions: conditions as WorkflowCondition[],
    actions: typedActions,
    retry: { maxAttempts, initialDelaySeconds, maximumDelaySeconds },
    timeoutSeconds,
    concurrency: { workflow: workflowConcurrency, workspace: workspaceConcurrency },
  };
  const incompatible = typedActions.find((action) => {
    const prefix = ACTION_TRIGGER_PREFIX[action.type];
    return prefix !== undefined && !definition.trigger.type.startsWith(prefix);
  });
  if (incompatible) {
    return { ok: false, error: `${incompatible.type} requires a matching resource trigger.`, securityCode: 'workflow-resource-action-mismatch' };
  }
  if (workflowPotentialCycle(definition)) {
    return { ok: false, error: 'This trigger/action pair can create an event cycle.', securityCode: 'workflow-cycle-rejected' };
  }
  return { ok: true, definition, warnings: [] };
}

function pathValue(event: TrustedWorkflowEvent, path: WorkflowEventPath): WorkflowScalar | undefined {
  if (path === 'event.type') return event.type;
  if (path === 'event.projectId') return event.projectId;
  if (path === 'event.resourceId') return event.resourceId;
  const key = path.slice('event.payload.'.length);
  return event.payload[key];
}

function comparableNumber(value: WorkflowScalar | undefined): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function conditionMatches(condition: WorkflowCondition, event: TrustedWorkflowEvent): boolean {
  const actual = pathValue(event, condition.path);
  const expected = condition.value;
  switch (condition.operator) {
    case 'equals': return actual === expected;
    case 'not_equals': return actual !== expected;
    case 'in': return Array.isArray(expected) && expected.includes(actual ?? null);
    case 'contains':
      return typeof actual === 'string' && typeof expected === 'string' && actual.includes(expected);
    case 'greater_than': {
      const left = comparableNumber(actual);
      return left !== null && typeof expected === 'number' && left > expected;
    }
    case 'greater_or_equal': {
      const left = comparableNumber(actual);
      return left !== null && typeof expected === 'number' && left >= expected;
    }
    case 'less_than': {
      const left = comparableNumber(actual);
      return left !== null && typeof expected === 'number' && left < expected;
    }
    case 'less_or_equal': {
      const left = comparableNumber(actual);
      return left !== null && typeof expected === 'number' && left <= expected;
    }
  }
}

export function workflowConditionsMatch(definition: WorkflowDefinition, event: TrustedWorkflowEvent): boolean {
  return definition.conditions.every((condition) => conditionMatches(condition, event));
}

export function retryDelayMs(definition: WorkflowDefinition, attempt: number): number {
  const delay = definition.retry.initialDelaySeconds * 2 ** Math.max(0, attempt - 1);
  return Math.min(delay, definition.retry.maximumDelaySeconds) * 1_000;
}

export function executionTerminalState(input: {
  now: number;
  timeoutAt: number;
  cancelRequested: boolean;
  actionFailed: boolean;
  attempt: number;
  maxAttempts: number;
}): WorkflowExecutionState | 'retry' | 'continue' {
  if (input.cancelRequested) return 'cancelled';
  if (input.now >= input.timeoutAt) return 'timed_out';
  if (!input.actionFailed) return 'continue';
  return input.attempt < input.maxAttempts ? 'retry' : 'failed';
}

export function shouldRunSchedule(
  trigger: Extract<WorkflowTrigger, { type: 'schedule' }>,
  now: number,
  lastScheduledAt: number | null,
): boolean {
  const date = new Date(now);
  if (trigger.intervalMinutes !== undefined) {
    return lastScheduledAt === null || now - lastScheduledAt >= trigger.intervalMinutes * 60_000;
  }
  if (!trigger.cron || !validSafeCron(trigger.cron)) return false;
  const [minute, hour] = trigger.cron.split(/\s+/);
  const matches = Number(minute) === date.getUTCMinutes() && (hour === '*' || Number(hour) === date.getUTCHours());
  const minuteStart = Math.floor(now / 60_000) * 60_000;
  return matches && (lastScheduledAt === null || lastScheduledAt < minuteStart);
}

export function redactWorkflowValue(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[REDACTED]';
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redactWorkflowValue(item, depth + 1));
  if (!isRecord(value)) {
    if (typeof value === 'string' && /(?:ysd_sa_|bearer\s|password|secret|token)/i.test(value)) return '[REDACTED]';
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).slice(0, 50).map(([key, item]) => [
      key.slice(0, 64),
      /secret|token|password|prompt|result|content|cipher|credential/i.test(key)
        ? '[REDACTED]'
        : redactWorkflowValue(item, depth + 1),
    ]),
  );
}

export const WORKFLOW_TEMPLATES: readonly {
  id: string;
  name: string;
  description: string;
  projectScoped: boolean;
  definition: WorkflowDefinition;
}[] = [
  {
    id: 'deploy-failed-rollback',
    name: 'Deploy failed → rollback + incident',
    description: 'Roll back to the previous verified artifact and open an internal incident.',
    projectScoped: true,
    definition: {
      trigger: { type: 'deployment.failed' }, conditions: [],
      actions: [
        { type: 'deployment.rollback_to_previous_healthy', target: 'event.resource' },
        { type: 'shield.create_incident', target: 'event.resource', title: 'Deployment rollback', message: 'A failed deployment triggered a guarded rollback.', severity: 'high' },
      ],
      retry: { maxAttempts: 3, initialDelaySeconds: 10, maximumDelaySeconds: 120 },
      timeoutSeconds: 180, concurrency: { workflow: 1, workspace: 4 },
    },
  },
  {
    id: 'node-offline-disable',
    name: 'Node offline → disable assignments + incident',
    description: 'Stop new job assignment to an offline node and open an internal incident.',
    projectScoped: false,
    definition: {
      trigger: { type: 'node.offline' }, conditions: [],
      actions: [
        { type: 'node.disable_assignments', target: 'event.resource' },
        { type: 'shield.create_incident', target: 'event.resource', title: 'Node offline', message: 'Assignments were disabled after the node went offline.', severity: 'high' },
      ],
      retry: { maxAttempts: 3, initialDelaySeconds: 10, maximumDelaySeconds: 120 },
      timeoutSeconds: 120, concurrency: { workflow: 1, workspace: 4 },
    },
  },
  {
    id: 'game-crash-loop-stop',
    name: 'Game crash loop → stop + incident',
    description: 'Stop a crash-looping game server and preserve the failure as an incident.',
    projectScoped: false,
    definition: {
      trigger: { type: 'game_server.crash_loop' }, conditions: [],
      actions: [
        { type: 'game_server.stop', target: 'event.resource' },
        { type: 'shield.create_incident', target: 'event.resource', title: 'Game server crash loop', message: 'The server was stopped after entering a crash loop.', severity: 'high' },
      ],
      retry: { maxAttempts: 2, initialDelaySeconds: 15, maximumDelaySeconds: 120 },
      timeoutSeconds: 120, concurrency: { workflow: 1, workspace: 4 },
    },
  },
  {
    id: 'shield-high-incident',
    name: 'High Shield finding → incident + notification',
    description: 'Open an incident and notify the organization inside YSD Zero Cloud.',
    projectScoped: false,
    definition: {
      trigger: { type: 'shield.finding.opened' },
      conditions: [{ path: 'event.payload.severity', operator: 'in', value: ['high', 'critical'] }],
      actions: [
        { type: 'shield.create_incident', target: 'event.resource', title: 'High Shield finding', message: 'YSD Shield opened a high-severity finding.', severity: 'high' },
        { type: 'notification.create', target: 'event.resource', title: 'Shield needs attention', message: 'A high-severity Shield finding needs owner review.', severity: 'high' },
      ],
      retry: { maxAttempts: 2, initialDelaySeconds: 10, maximumDelaySeconds: 60 },
      timeoutSeconds: 60, concurrency: { workflow: 1, workspace: 4 },
    },
  },
  {
    id: 'ai-repeated-failure',
    name: 'AI failures → incident + self-pause',
    description: 'Flag repeated AI failures and pause the workflow to stop retry storms.',
    projectScoped: false,
    definition: {
      trigger: { type: 'ai.job.failed' },
      conditions: [{ path: 'event.payload.failureCount', operator: 'greater_or_equal', value: 3 }],
      actions: [
        { type: 'shield.create_incident', target: 'event.resource', title: 'Repeated AI failures', message: 'AI execution failed repeatedly and automation was paused.', severity: 'high' },
        { type: 'workflow.pause', target: 'self' },
      ],
      retry: { maxAttempts: 1, initialDelaySeconds: 10, maximumDelaySeconds: 10 },
      timeoutSeconds: 60, concurrency: { workflow: 1, workspace: 2 },
    },
  },
] as const;

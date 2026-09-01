import { atLeast, can, canAccessProject, type Actor } from './roles.ts';

export const INCIDENT_STATUSES = ['open', 'acknowledged', 'resolved'] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export const INCIDENT_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type IncidentSeverity = (typeof INCIDENT_SEVERITIES)[number];

export const INCIDENT_EVENT_TYPES = [
  'incident.created',
  'incident.occurrence',
  'incident.assigned',
  'incident.unassigned',
  'incident.acknowledged',
  'incident.severity_changed',
  'incident.note_added',
  'incident.resolved',
  'incident.reopened',
] as const;
export type IncidentEventType = (typeof INCIDENT_EVENT_TYPES)[number];

export const INCIDENT_LIMITS = {
  requestBytes: 4_096,
  noteCharacters: 1_000,
  resolutionCharacters: 1_000,
  searchCharacters: 80,
  list: 200,
  timeline: 500,
  timelineEventsPerIncident: 10_000,
  activePerWorkspace: 500,
  occurrences: 1_000_000,
} as const;

const INCIDENT_ID = /^incident_[a-f0-9]{24}$/;
const USER_ID = /^[a-z][a-z0-9_-]{2,159}$/i;
const EXECUTABLE_OR_EXTERNAL = /(?:https?:\/\/|file:\/\/|javascript:|<\/?(?:script|iframe|object)|\bon\w+\s*=|\beval\s*\(|\b(?:bash|powershell|cmd\.exe|sh\s+-c|curl\s|wget\s)\b)/i;
const SENSITIVE = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]+=*|\b(?:password|passwd|secret|token|api[_ -]?key|private[_ -]?key|ciphertext|webhook[_ -]?secret|raw[_ -]?payload)\b\s*[:=]|\b(?:sk|pk|ghp|xox[baprs])_[A-Za-z0-9_-]{12,}|\b[A-Fa-f0-9]{64,}\b|\b[A-Za-z0-9+/]{48,}={0,2}\b)/i;

export type IncidentMutation =
  | { operation: 'assign'; assigneeId: string; expectedRevision: number }
  | { operation: 'unassign'; expectedRevision: number }
  | { operation: 'acknowledge'; expectedRevision: number }
  | { operation: 'severity'; severity: IncidentSeverity; expectedRevision: number }
  | { operation: 'note'; note: string; expectedRevision: number }
  | { operation: 'resolve'; resolution: string; expectedRevision: number }
  | { operation: 'reopen'; expectedRevision: number };

export type IncidentFilters = {
  status: IncidentStatus | 'all';
  severity: IncidentSeverity | 'all';
  /** A user id, `all`, or `unassigned`. */
  assignee: string;
  /** A project id or `all`. */
  projectId: string;
  /** A bounded resource type or `all`. */
  resourceType: string;
  search: string;
};

export type IncidentParseResult =
  | { ok: true; mutation: IncidentMutation }
  | { ok: false; error: string; securityCode?: string };

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.length && keys.every((key) => allowed.includes(key));
}

function revision(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1
    ? value
    : null;
}

export function safeIncidentText(value: unknown, maximum: number): string | null {
  if (typeof value !== 'string') return null;
  const clean = value.trim();
  let hasControl = false;
  for (const character of clean) {
    const code = character.charCodeAt(0);
    if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
      hasControl = true;
      break;
    }
  }
  if (!clean || clean.length > maximum || hasControl || clean.startsWith('{') || clean.startsWith('[')) return null;
  if (EXECUTABLE_OR_EXTERNAL.test(clean) || SENSITIVE.test(clean)) return null;
  return clean;
}

export function parseIncidentMutation(value: unknown): IncidentParseResult {
  if (!record(value) || typeof value.operation !== 'string') {
    return { ok: false, error: 'Choose a reviewed incident operation.' };
  }
  const expectedRevision = revision(value.expectedRevision);
  if (!expectedRevision) return { ok: false, error: 'A current incident revision is required.' };
  switch (value.operation) {
    case 'assign':
      return exactKeys(value, ['operation', 'assigneeId', 'expectedRevision']) &&
        typeof value.assigneeId === 'string' && USER_ID.test(value.assigneeId)
        ? { ok: true, mutation: { operation: 'assign', assigneeId: value.assigneeId, expectedRevision } }
        : { ok: false, error: 'Choose an active organization member.' };
    case 'unassign':
    case 'acknowledge':
    case 'reopen':
      return exactKeys(value, ['operation', 'expectedRevision'])
        ? { ok: true, mutation: { operation: value.operation, expectedRevision } }
        : { ok: false, error: 'Unknown incident fields are forbidden.', securityCode: 'incident-payload-abuse' };
    case 'severity':
      return exactKeys(value, ['operation', 'severity', 'expectedRevision']) &&
        typeof value.severity === 'string' && (INCIDENT_SEVERITIES as readonly string[]).includes(value.severity)
        ? { ok: true, mutation: { operation: 'severity', severity: value.severity as IncidentSeverity, expectedRevision } }
        : { ok: false, error: 'Choose a supported severity.' };
    case 'note': {
      const note = safeIncidentText(value.note, INCIDENT_LIMITS.noteCharacters);
      return exactKeys(value, ['operation', 'note', 'expectedRevision']) && note
        ? { ok: true, mutation: { operation: 'note', note, expectedRevision } }
        : { ok: false, error: 'The note is unsafe or outside the size limit.', securityCode: 'incident-sensitive-input' };
    }
    case 'resolve': {
      const resolution = safeIncidentText(value.resolution, INCIDENT_LIMITS.resolutionCharacters);
      return exactKeys(value, ['operation', 'resolution', 'expectedRevision']) && resolution
        ? { ok: true, mutation: { operation: 'resolve', resolution, expectedRevision } }
        : { ok: false, error: 'The resolution is unsafe or outside the size limit.', securityCode: 'incident-sensitive-input' };
    }
    default:
      return { ok: false, error: 'Choose a reviewed incident operation.', securityCode: 'incident-payload-abuse' };
  }
}

export function parseIncidentFilters(params: URLSearchParams): IncidentFilters {
  const rawStatus = params.get('status') ?? 'all';
  const rawSeverity = params.get('severity') ?? 'all';
  const assignee = (params.get('assignee') ?? 'all').slice(0, 160);
  const projectId = (params.get('projectId') ?? 'all').slice(0, 160);
  const rawResourceType = (params.get('resourceType') ?? 'all').slice(0, 80);
  const resourceType = rawResourceType === 'all' || /^[a-z][a-z0-9_-]{1,79}$/i.test(rawResourceType)
    ? rawResourceType
    : 'all';
  const searchValue = params.get('search')?.trim().slice(0, INCIDENT_LIMITS.searchCharacters) ?? '';
  const search = EXECUTABLE_OR_EXTERNAL.test(searchValue) || SENSITIVE.test(searchValue) ? '' : searchValue;
  return {
    status: ((INCIDENT_STATUSES as readonly string[]).includes(rawStatus) ? rawStatus : 'all') as IncidentFilters['status'],
    severity: ((INCIDENT_SEVERITIES as readonly string[]).includes(rawSeverity) ? rawSeverity : 'all') as IncidentFilters['severity'],
    assignee: assignee === 'all' || assignee === 'unassigned' || USER_ID.test(assignee) ? assignee : 'all',
    projectId: projectId === 'all' || USER_ID.test(projectId) ? projectId : 'all',
    resourceType,
    search,
  };
}

export function canManageIncident(actor: Actor, projectId: string | null): boolean {
  return can(actor, 'incident.manage') && canAccessProject(actor, projectId);
}

export function canResolveIncident(actor: Actor, projectId: string | null, severity: IncidentSeverity): boolean {
  if (!canManageIncident(actor, projectId)) return false;
  return severity !== 'critical' || (can(actor, 'incident.resolve-critical') && atLeast(actor.role, 'admin'));
}

export function isIncidentId(value: string): boolean {
  return INCIDENT_ID.test(value);
}

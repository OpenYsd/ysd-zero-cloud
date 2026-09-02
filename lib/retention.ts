import { can, type Actor } from './roles.ts';

/**
 * Retention policy vocabulary.
 *
 * The single most important property of this module: a caller never names a
 * table. A request carries a `dataClass` from the closed list below, and the
 * server maps that class to a fixed statement it wrote itself
 * (`lib/server/retention.ts`). No identifier from a request ever reaches SQL,
 * so there is no interpolation to escape and no injection to filter.
 *
 * The second property: floors. Every class declares a minimum window that the
 * API refuses to go below, backed by a `CHECK (retentionDays >= 7)` in
 * migration 0015. Security evidence carries a higher floor than chatter.
 */

export const RETENTION_DATA_CLASSES = [
  'platform-logs',
  'workflow-events',
  'workflow-executions',
  'workflow-security-events',
  'webhook-deliveries',
  'read-notifications',
  'resolved-shield-findings',
] as const;

export type RetentionDataClass = (typeof RETENTION_DATA_CLASSES)[number];

export type RetentionClassMeta = {
  id: RetentionDataClass;
  label: string;
  /** What an operator is agreeing to delete. */
  description: string;
  /** Applied when a policy row is first created — always while disabled. */
  defaultRetentionDays: number;
  /** The API refuses any window below this. */
  minimumRetentionDays: number;
  /** Ceiling per prune pass, so one tick can never mass-delete. */
  maxRowsPerRun: number;
};

export const RETENTION_CLASS_META: Readonly<
  Record<RetentionDataClass, RetentionClassMeta>
> = {
  'platform-logs': {
    id: 'platform-logs',
    label: 'Platform logs',
    description:
      'Workspace log events. High volume, no downstream reference, and reproducible from the systems that emitted them.',
    defaultRetentionDays: 30,
    minimumRetentionDays: 7,
    maxRowsPerRun: 500,
  },
  'workflow-events': {
    id: 'workflow-events',
    label: 'Workflow events',
    description:
      'Trusted workflow events that have been processed or rejected. Only events no execution still references are eligible.',
    defaultRetentionDays: 60,
    minimumRetentionDays: 14,
    maxRowsPerRun: 300,
  },
  'workflow-executions': {
    id: 'workflow-executions',
    label: 'Workflow executions',
    description:
      'Finished workflow executions in a terminal state. Their action rows are removed by the existing cascade; in-flight work is never touched.',
    defaultRetentionDays: 60,
    minimumRetentionDays: 14,
    maxRowsPerRun: 200,
  },
  'workflow-security-events': {
    id: 'workflow-security-events',
    label: 'Workflow security events',
    description:
      'Denied and suspicious workflow mutations. Security evidence, so it carries a longer floor than operational chatter.',
    defaultRetentionDays: 180,
    minimumRetentionDays: 90,
    maxRowsPerRun: 200,
  },
  'webhook-deliveries': {
    id: 'webhook-deliveries',
    label: 'Webhook deliveries',
    description:
      'Inbound external event gateway delivery records. Replay protection uses its own guard table and is unaffected.',
    defaultRetentionDays: 30,
    minimumRetentionDays: 14,
    maxRowsPerRun: 500,
  },
  'read-notifications': {
    id: 'read-notifications',
    label: 'Read notifications',
    description:
      'Internal notifications a recipient has already read. Unread notifications are never eligible, at any age.',
    defaultRetentionDays: 30,
    minimumRetentionDays: 7,
    maxRowsPerRun: 500,
  },
  'resolved-shield-findings': {
    id: 'resolved-shield-findings',
    label: 'Resolved Shield findings',
    description:
      'Shield findings already resolved. An open finding is never eligible, so nothing hides an unaddressed security issue.',
    defaultRetentionDays: 180,
    minimumRetentionDays: 90,
    maxRowsPerRun: 200,
  },
};

/**
 * Tables Phase 12 will not prune, and why.
 *
 * Each of these carries a `BEFORE DELETE ... RAISE(ABORT)` trigger from an
 * earlier phase. Reclaiming rows from them would mean dropping a guarantee an
 * earlier phase shipped deliberately, so Phase 12 leaves them alone and says
 * so out loud instead.
 */
export const RETENTION_PROTECTED_TABLES = [
  {
    table: 'audit_event',
    guard: 'audit_event_no_delete (migration 0010)',
    reason:
      'Audit history is immutable. Deletion aborts at the database, not merely in application code, and Phase 12 does not weaken that.',
  },
  {
    table: 'incident_event',
    guard: 'incident_event_append_only_delete (migration 0014)',
    reason:
      'The Phase 11 incident timeline is append-only evidence of how a response unfolded.',
  },
  {
    table: 'workflow_version',
    guard: 'workflow_version_no_delete (migration 0012)',
    reason:
      'Published workflow versions are immutable so a historical execution always resolves the definition it actually ran.',
  },
  {
    table: 'retention_run',
    guard: 'retention_run_append_only_delete (migration 0015)',
    reason:
      'Retention must not be able to erase the record of its own deletions.',
  },
] as const;

/** User-facing descriptions deliberately omit SQL table and trigger names. */
export const RETENTION_PROTECTED_RECORDS = [
  {
    id: 'audit-history',
    label: 'Audit history',
    reason:
      'Immutable accountability evidence remains available for review and is never removed by lifecycle automation.',
  },
  {
    id: 'incident-timeline',
    label: 'Incident timelines',
    reason:
      'Response history stays append-only so assignments, notes, acknowledgements, and resolutions remain provable.',
  },
  {
    id: 'workflow-versions',
    label: 'Published workflow versions',
    reason:
      'Historical executions always retain the exact immutable definition they used.',
  },
  {
    id: 'retention-evidence',
    label: 'Retention run evidence',
    reason:
      'Lifecycle automation cannot erase the record of its own previews, deletions, or failures.',
  },
] as const;

export const RETENTION_LIMITS = {
  requestBytes: 2_048,
  /** Absolute ceiling on any configured window. */
  maximumRetentionDays: 3_650,
  /** Absolute floor, mirroring the CHECK in migration 0015. */
  absoluteMinimumRetentionDays: 7,
  /** A dry-run older than this no longer authorises an activation. */
  dryRunFreshnessMs: 24 * 60 * 60 * 1000,
  /** Snapshot cadence. Six hours, deduplicated by slot. */
  snapshotIntervalMs: 6 * 60 * 60 * 1000,
  /** Minimum gap between prune passes for one policy that finished cleanly. */
  pruneIntervalMs: 60 * 60 * 1000,
  /** Policies advanced per tick, across all workspaces. */
  policiesPerTick: 2,
  /** Workspaces snapshotted per tick. Kept at one: a snapshot counts rows. */
  snapshotsPerTick: 1,
  /** Rows deleted per batch inside one prune pass. */
  batchRows: 100,
  /** Snapshots retained per workspace before the oldest are trimmed. */
  snapshotHistory: 180,
  /** Runs returned to the UI per class. */
  runHistory: 10,
  /** Failures before Shield calls the policy broken. */
  failureAlertThreshold: 3,
} as const;

export type RetentionRunMode = 'dry-run' | 'prune';
export type RetentionRunStatus = 'completed' | 'partial' | 'failed' | 'skipped';

export type RetentionMutation =
  | { operation: 'dry-run'; expectedRevision: number }
  | { operation: 'set-window'; retentionDays: number; expectedRevision: number }
  | { operation: 'enable'; expectedRevision: number }
  | { operation: 'disable'; expectedRevision: number };

export type RetentionParseResult =
  | { ok: true; mutation: RetentionMutation }
  | { ok: false; error: string; securityCode?: string };

export function isRetentionDataClass(
  value: unknown,
): value is RetentionDataClass {
  return (
    typeof value === 'string' &&
    (RETENTION_DATA_CLASSES as readonly string[]).includes(value)
  );
}

export function minimumRetentionDays(dataClass: RetentionDataClass): number {
  return Math.max(
    RETENTION_LIMITS.absoluteMinimumRetentionDays,
    RETENTION_CLASS_META[dataClass].minimumRetentionDays,
  );
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === allowed.length && keys.every((key) => allowed.includes(key))
  );
}

function revisionOf(value: unknown): number | null {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 1
    ? value
    : null;
}

/**
 * Parses a retention mutation.
 *
 * Strict-shape: the body must carry exactly the keys the operation declares.
 * An extra key is a rejection rather than something quietly ignored, so a
 * request cannot smuggle a `table`, `sql`, or `where` field past the parser and
 * hope some later layer honours it.
 */
export function parseRetentionMutation(
  body: unknown,
  dataClass: RetentionDataClass,
): RetentionParseResult {
  if (!record(body)) return { ok: false, error: 'A JSON object is required.' };

  const operation = body.operation;
  if (typeof operation !== 'string') {
    return { ok: false, error: 'An operation is required.' };
  }

  // Anything naming a table, a column, or raw SQL is refused loudly. No such
  // field is ever read, but a request carrying one is a probe worth recording.
  for (const forbidden of [
    'table',
    'tableName',
    'sql',
    'query',
    'where',
    'column',
    'predicate',
  ]) {
    if (forbidden in body) {
      return {
        ok: false,
        error: 'Retention operates on reviewed data classes, not identifiers.',
        securityCode: 'retention-identifier-injection',
      };
    }
  }

  const expectedRevision = revisionOf(body.expectedRevision);
  if (expectedRevision === null) {
    return { ok: false, error: 'A valid expectedRevision is required.' };
  }

  if (operation === 'dry-run' || operation === 'enable' || operation === 'disable') {
    if (!exactKeys(body, ['operation', 'expectedRevision'])) {
      return { ok: false, error: 'Unexpected fields in the request body.' };
    }
    return { ok: true, mutation: { operation, expectedRevision } };
  }

  if (operation === 'set-window') {
    if (!exactKeys(body, ['operation', 'retentionDays', 'expectedRevision'])) {
      return { ok: false, error: 'Unexpected fields in the request body.' };
    }
    const days = body.retentionDays;
    if (typeof days !== 'number' || !Number.isSafeInteger(days)) {
      return { ok: false, error: 'retentionDays must be a whole number of days.' };
    }
    const floor = minimumRetentionDays(dataClass);
    if (days < floor) {
      return {
        ok: false,
        error: `${RETENTION_CLASS_META[dataClass].label} cannot be retained for fewer than ${floor} days.`,
        securityCode: 'retention-floor-violation',
      };
    }
    if (days > RETENTION_LIMITS.maximumRetentionDays) {
      return {
        ok: false,
        error: `A retention window cannot exceed ${RETENTION_LIMITS.maximumRetentionDays} days.`,
      };
    }
    return {
      ok: true,
      mutation: { operation: 'set-window', retentionDays: days, expectedRevision },
    };
  }

  return {
    ok: false,
    error: 'Unsupported retention operation.',
    securityCode: 'retention-unsupported-operation',
  };
}

/** Reading capacity and retention state. Every role that can see Usage can. */
export function canReadRetention(actor: Actor): boolean {
  return can(actor, 'retention.read');
}

/**
 * Managing a policy.
 *
 * Retention is workspace-wide, so it is deliberately not a project-bound
 * permission: a developer restricted to two projects must not be able to set a
 * window that deletes rows belonging to every other project in the workspace.
 */
export function canManageRetention(actor: Actor): boolean {
  return can(actor, 'retention.manage');
}

/** A dry-run only authorises activation while it is fresh and still matches. */
export function dryRunAuthorises(input: {
  lastDryRunAt: number | null;
  lastDryRunRevision: number | null;
  lastDryRunRetentionDays: number | null;
  revision: number;
  retentionDays: number;
  now: number;
}): boolean {
  if (
    input.lastDryRunAt === null ||
    input.lastDryRunRevision === null ||
    input.lastDryRunRetentionDays === null
  ) {
    return false;
  }
  if (input.lastDryRunRevision !== input.revision) return false;
  if (input.lastDryRunRetentionDays !== input.retentionDays) return false;
  const age = input.now - input.lastDryRunAt;
  return age >= 0 && age <= RETENTION_LIMITS.dryRunFreshnessMs;
}

/** The snapshot bucket an instant falls into. */
export function snapshotSlot(now: number): number {
  return Math.floor(now / RETENTION_LIMITS.snapshotIntervalMs);
}

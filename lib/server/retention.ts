import {
  forecastCapacity,
  overallCapacityState,
  CAPACITY_THRESHOLDS,
  type CapacityForecast,
} from '@/lib/capacity';
import { createId } from '@/lib/crypto';
import type {
  DataLifecycleState,
  RetentionPolicyView,
  RetentionRunView,
} from '@/lib/domain';
import {
  FREE_TIER_LIMITS,
  readUsage,
  type UsageMetricId,
  type UsageReading,
} from '@/lib/free-tier';
import {
  RETENTION_CLASS_META,
  RETENTION_DATA_CLASSES,
  RETENTION_LIMITS,
  canManageRetention,
  dryRunAuthorises,
  isRetentionDataClass,
  minimumRetentionDays,
  snapshotSlot,
  type RetentionDataClass,
  type RetentionMutation,
  type RetentionRunStatus,
} from '@/lib/retention';
import type { Actor } from '@/lib/roles';
import { recordAudit } from './audit';
import { execute, query, queryOne } from './db';
import { createOrAggregateIncident } from './incidents';
import { collectUsageReadings } from './usage';

/**
 * Data lifecycle: retention policies, usage history, and capacity forecasting.
 *
 * The one rule that matters most in this file: a table name never comes from a
 * request. `CLASS_SPEC` below is the complete set of identifiers retention is
 * allowed to touch, written here as constants. A caller supplies a `dataClass`
 * key which is validated against the closed list, and the key selects a
 * statement this module wrote. There is no interpolation of caller input into
 * SQL anywhere in the retention path, so there is nothing to escape.
 *
 * The second rule: nothing deletes by default. A policy row is created
 * disabled, and the database refuses to enable it without a recorded dry-run
 * matching the exact revision and window being activated.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

type ClassSpec = {
  /** A literal from this file. Never derived from input. */
  table: string;
  timestampColumn: string;
  /**
   * A static extra predicate over alias `t`. These are what keep retention
   * from touching rows that are still referenced or still actionable.
   */
  extra: string;
};

const CLASS_SPEC: Readonly<Record<RetentionDataClass, ClassSpec>> = {
  'platform-logs': {
    table: 'log_event',
    timestampColumn: 'createdAt',
    extra: '',
  },
  'workflow-events': {
    table: 'workflow_event',
    timestampColumn: 'createdAt',
    // `workflow_execution.eventId` is ON DELETE RESTRICT, so an event still
    // referenced by an execution cannot be deleted and is not offered as a
    // candidate. Executions age out first; their events become eligible after.
    // Webhook deliveries also carry an immutable tenant binding around their
    // event reference. Both references must be gone before the event itself
    // can be reclaimed.
    extra:
      'AND NOT EXISTS (SELECT 1 FROM workflow_execution e WHERE e.eventId = t.id) AND NOT EXISTS (SELECT 1 FROM webhook_delivery d WHERE d.workflowEventId = t.id)',
  },
  'workflow-executions': {
    table: 'workflow_execution',
    timestampColumn: 'createdAt',
    // Terminal states only. Queued, running, and waiting work is never a
    // candidate no matter how old the row is.
    // An incident keeps the originating execution reference immutable, so
    // incident-linked executions remain historical evidence even when they
    // are terminal.
    extra:
      "AND t.state IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'skipped') AND NOT EXISTS (SELECT 1 FROM workflow_incident i WHERE i.executionId = t.id)",
  },
  'workflow-security-events': {
    table: 'workflow_security_event',
    timestampColumn: 'createdAt',
    extra: '',
  },
  'webhook-deliveries': {
    table: 'webhook_delivery',
    timestampColumn: 'receivedAt',
    extra: '',
  },
  'read-notifications': {
    table: 'internal_notification',
    timestampColumn: 'createdAt',
    // An unread notification is never eligible, at any age.
    extra: 'AND t.readAt IS NOT NULL',
  },
  'resolved-shield-findings': {
    table: 'shield_finding',
    timestampColumn: 'lastSeenAt',
    // An open finding is never eligible, so retention can never be used to
    // make an unaddressed security issue disappear.
    extra: "AND t.status = 'resolved'",
  },
};

/** Codes stored on a failed run. Never a raw driver message. */
const FAILURE_CODES = {
  prune: 'prune-failed',
  count: 'candidate-count-failed',
  snapshot: 'snapshot-failed',
  maintenance: 'maintenance-failed',
} as const;

type PolicyRow = {
  id: string;
  organizationId: string;
  workspaceId: string;
  dataClass: RetentionDataClass;
  enabled: number;
  retentionDays: number;
  revision: number;
  lastDryRunAt: number | null;
  lastDryRunRevision: number | null;
  lastDryRunRetentionDays: number | null;
  lastDryRunCandidateRows: number | null;
  lastPrunedAt: number | null;
  lastRunStatus: RetentionRunStatus | null;
  consecutiveFailures: number;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
};

type RunRow = {
  id: string;
  dataClass: RetentionDataClass;
  mode: 'dry-run' | 'prune';
  actorType: 'user' | 'system';
  actorId: string;
  retentionDays: number;
  cutoff: number;
  candidateRows: number;
  deletedRows: number;
  status: RetentionRunStatus;
  failureCode: string | null;
  startedAt: number;
  finishedAt: number | null;
};

function specFor(dataClass: RetentionDataClass): ClassSpec {
  // Belt and braces: the caller already validated against the closed list, and
  // the database has a CHECK constraint, but a lookup miss must never fall
  // through to a constructed statement.
  if (!isRetentionDataClass(dataClass)) {
    throw new Error('Unreviewed retention data class.');
  }
  const spec = CLASS_SPEC[dataClass];
  if (!spec) throw new Error('Unreviewed retention data class.');
  return spec;
}

function candidateStatement(dataClass: RetentionDataClass): string {
  const spec = specFor(dataClass);
  return `SELECT COUNT(*) AS total FROM ${spec.table} t
           WHERE t.workspaceId = ? AND t.${spec.timestampColumn} < ? ${spec.extra}`;
}

/**
 * Bounded delete.
 *
 * `DELETE ... LIMIT` is a compile-time SQLite option that is not universally
 * available, so the bound is expressed as an indexed sub-select of primary
 * keys. Oldest rows go first, which makes a partial pass resumable: the next
 * tick simply sees the same query with fewer rows in front of it.
 */
function deleteStatement(dataClass: RetentionDataClass): string {
  const spec = specFor(dataClass);
  return `DELETE FROM ${spec.table} WHERE id IN (
            SELECT t.id FROM ${spec.table} t
             WHERE t.workspaceId = ? AND t.${spec.timestampColumn} < ? ${spec.extra}
             ORDER BY t.${spec.timestampColumn} ASC
             LIMIT ?)`;
}

export function retentionCutoff(retentionDays: number, now: number): number {
  return now - retentionDays * DAY_MS;
}

export async function countRetentionCandidates(input: {
  workspaceId: string;
  dataClass: RetentionDataClass;
  cutoff: number;
}): Promise<number> {
  const row = await queryOne<{ total: number }>(
    candidateStatement(input.dataClass),
    input.workspaceId,
    input.cutoff,
  );
  return row?.total ?? 0;
}

function policyView(row: PolicyRow, candidateRows: number | null): RetentionPolicyView {
  const meta = RETENTION_CLASS_META[row.dataClass];
  return {
    id: row.id,
    dataClass: row.dataClass,
    label: meta.label,
    description: meta.description,
    enabled: row.enabled === 1,
    retentionDays: row.retentionDays,
    minimumRetentionDays: minimumRetentionDays(row.dataClass),
    maximumRowsPerRun: meta.maxRowsPerRun,
    revision: row.revision,
    lastDryRunAt: row.lastDryRunAt,
    lastDryRunRevision: row.lastDryRunRevision,
    lastDryRunRetentionDays: row.lastDryRunRetentionDays,
    lastDryRunCandidateRows: row.lastDryRunCandidateRows,
    lastPrunedAt: row.lastPrunedAt,
    lastRunStatus: row.lastRunStatus,
    consecutiveFailures: row.consecutiveFailures,
    candidateRows,
    updatedAt: row.updatedAt,
  };
}

function runView(row: RunRow): RetentionRunView {
  return {
    id: row.id,
    dataClass: row.dataClass,
    mode: row.mode,
    actorType: row.actorType,
    retentionDays: row.retentionDays,
    cutoff: row.cutoff,
    candidateRows: row.candidateRows,
    deletedRows: row.deletedRows,
    status: row.status,
    failureCode: row.failureCode,
    startedAt: row.startedAt,
    finishedAt: row.finishedAt,
  };
}

/**
 * Creates the missing policy rows for a workspace, always disabled.
 *
 * Lazily rather than in the migration: a workspace created after 0015 gets the
 * same set, and applying the migration to production still changes no row.
 */
export async function ensureRetentionPolicies(input: {
  organizationId: string;
  workspaceId: string;
  actorId: string;
  now: number;
}): Promise<void> {
  const existing = await query<{ dataClass: string }>(
    'SELECT dataClass FROM retention_policy WHERE workspaceId = ?',
    input.workspaceId,
  );
  const present = new Set(existing.map((row) => row.dataClass));
  for (const dataClass of RETENTION_DATA_CLASSES) {
    if (present.has(dataClass)) continue;
    await execute(
      `INSERT OR IGNORE INTO retention_policy
         (id, organizationId, workspaceId, dataClass, enabled, retentionDays,
          revision, consecutiveFailures, createdBy, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, 0, ?, 1, 0, ?, ?, ?)`,
      createId('retention'),
      input.organizationId,
      input.workspaceId,
      dataClass,
      RETENTION_CLASS_META[dataClass].defaultRetentionDays,
      input.actorId.slice(0, 160),
      input.now,
      input.now,
    );
  }
}

async function loadPolicy(
  workspaceId: string,
  dataClass: RetentionDataClass,
): Promise<PolicyRow | null> {
  return queryOne<PolicyRow>(
    'SELECT * FROM retention_policy WHERE workspaceId = ? AND dataClass = ?',
    workspaceId,
    dataClass,
  );
}

async function readSnapshotHistory(
  workspaceId: string,
): Promise<{ capturedAt: number; metrics: Partial<Record<UsageMetricId, number>> }[]> {
  const rows = await query<{ capturedAt: number; metrics: string }>(
    `SELECT capturedAt, metrics FROM usage_snapshot
      WHERE workspaceId = ? ORDER BY capturedAt DESC LIMIT ?`,
    workspaceId,
    RETENTION_LIMITS.snapshotHistory,
  );
  return rows.map((row) => ({
    capturedAt: row.capturedAt,
    metrics: parseMetrics(row.metrics),
  }));
}

/** Only trusted metric ids with finite numeric values survive parsing. */
function parseMetrics(value: string): Partial<Record<UsageMetricId, number>> {
  const allowed = new Set<string>(FREE_TIER_LIMITS.map((entry) => entry.id));
  const out: Partial<Record<UsageMetricId, number>> = {};
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return out;
    for (const [key, item] of Object.entries(parsed as Record<string, unknown>)) {
      if (!allowed.has(key)) continue;
      if (typeof item === 'number' && Number.isFinite(item) && item >= 0) {
        out[key as UsageMetricId] = item;
      }
    }
  } catch {
    return out;
  }
  return out;
}

/** Rebuilds usage readings from a stored snapshot using the trusted catalog. */
function readingsFromSnapshot(
  metrics: Partial<Record<UsageMetricId, number>>,
): UsageReading[] {
  const source: Partial<Record<UsageMetricId, number | null>> = {};
  for (const entry of FREE_TIER_LIMITS) {
    // A metric absent from the snapshot is unmeasured, not zero.
    source[entry.id] = metrics[entry.id] ?? null;
  }
  return readUsage(source);
}

export async function listDataLifecycleState(input: {
  organizationId: string;
  workspaceId: string;
  actor: Actor;
  readings: readonly UsageReading[];
  now: number;
}): Promise<DataLifecycleState> {
  await ensureRetentionPolicies({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    actorId: input.actor.userId,
    now: input.now,
  });

  const [rows, history, runs] = await Promise.all([
    query<PolicyRow>(
      'SELECT * FROM retention_policy WHERE workspaceId = ? ORDER BY dataClass ASC',
      input.workspaceId,
    ),
    readSnapshotHistory(input.workspaceId),
    query<RunRow>(
      `SELECT id, dataClass, mode, actorType, actorId, retentionDays, cutoff,
              candidateRows, deletedRows, status, failureCode, startedAt, finishedAt
         FROM retention_run WHERE workspaceId = ?
        ORDER BY startedAt DESC LIMIT ?`,
      input.workspaceId,
      RETENTION_LIMITS.runHistory * RETENTION_DATA_CLASSES.length,
    ),
  ]);

  const policies: RetentionPolicyView[] = [];
  for (const row of rows) {
    if (!isRetentionDataClass(row.dataClass)) continue;
    let candidateRows: number | null = null;
    try {
      candidateRows = await countRetentionCandidates({
        workspaceId: input.workspaceId,
        dataClass: row.dataClass,
        cutoff: retentionCutoff(row.retentionDays, input.now),
      });
    } catch {
      candidateRows = null;
    }
    policies.push(policyView(row, candidateRows));
  }

  const forecasts = forecastCapacity({
    readings: input.readings,
    history,
    now: input.now,
  });

  return {
    capacity: forecasts,
    capacityState: overallCapacityState(forecasts),
    policies,
    runs: runs.map(runView),
    snapshots: history.length,
    latestSnapshotAt: history.length
      ? Math.max(...history.map((entry) => entry.capturedAt))
      : null,
    snapshotIntervalMs: RETENTION_LIMITS.snapshotIntervalMs,
    canManage: canManageRetention(input.actor),
    zeroModeEnforced: true,
    projectedMonthlyCost: 0,
  };
}

type MutationResult =
  | { ok: true; policy: RetentionPolicyView }
  | { ok: false; status: number; error: string; securityCode?: string };

export async function mutateRetentionPolicy(input: {
  organizationId: string;
  workspaceId: string;
  dataClass: RetentionDataClass;
  actor: Actor;
  mutation: RetentionMutation;
  now: number;
}): Promise<MutationResult> {
  if (!canManageRetention(input.actor)) {
    return {
      ok: false,
      status: 403,
      error: 'Retention policies are managed by owners and admins.',
      securityCode: 'retention-permission-denied',
    };
  }
  if (!isRetentionDataClass(input.dataClass)) {
    return {
      ok: false,
      status: 404,
      error: 'Unknown retention data class.',
      securityCode: 'retention-invalid-class',
    };
  }

  await ensureRetentionPolicies({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    actorId: input.actor.userId,
    now: input.now,
  });

  const policy = await loadPolicy(input.workspaceId, input.dataClass);
  if (!policy || policy.organizationId !== input.organizationId) {
    return {
      ok: false,
      status: 404,
      error: 'Retention policy not found.',
      securityCode: policy ? 'retention-cross-tenant-access' : undefined,
    };
  }
  if (policy.revision !== input.mutation.expectedRevision) {
    return {
      ok: false,
      status: 409,
      error: 'The retention policy changed since it was loaded. Reload and retry.',
    };
  }

  const outcome = await applyMutation({ policy, ...input });
  await recordAudit({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    actorType: 'user',
    actorId: input.actor.userId,
    action: outcome.ok
      ? `retention.${input.mutation.operation}`
      : `retention.${input.mutation.operation}.denied`,
    resourceType: 'retention_policy',
    resourceId: policy.id,
    outcome: outcome.ok ? 'success' : outcome.status === 403 ? 'denied' : 'failed',
    metadata: {
      dataClass: input.dataClass,
      retentionDays: policy.retentionDays,
      zeroCost: true,
    },
  }).catch(() => undefined);
  return outcome;
}

async function applyMutation(input: {
  policy: PolicyRow;
  workspaceId: string;
  organizationId: string;
  dataClass: RetentionDataClass;
  actor: Actor;
  mutation: RetentionMutation;
  now: number;
}): Promise<MutationResult> {
  const { policy, mutation, now } = input;
  const next = policy.revision + 1;

  if (mutation.operation === 'dry-run') {
    const cutoff = retentionCutoff(policy.retentionDays, now);
    let candidates = 0;
    try {
      candidates = await countRetentionCandidates({
        workspaceId: input.workspaceId,
        dataClass: policy.dataClass,
        cutoff,
      });
    } catch {
      await writeRun({
        policy,
        mode: 'dry-run',
        actorType: 'user',
        actorId: input.actor.userId,
        cutoff,
        candidateRows: 0,
        deletedRows: 0,
        status: 'failed',
        failureCode: FAILURE_CODES.count,
        startedAt: now,
        finishedAt: now,
      });
      return { ok: false, status: 500, error: 'The dry-run could not be completed.' };
    }

    // A dry-run deletes nothing. It records what a prune would consider and
    // stamps the exact revision and window it was measured against.
    await writeRun({
      policy,
      mode: 'dry-run',
      actorType: 'user',
      actorId: input.actor.userId,
      cutoff,
      candidateRows: candidates,
      deletedRows: 0,
      status: 'completed',
      failureCode: null,
      startedAt: now,
      finishedAt: now,
    });
    const changed = await execute(
      `UPDATE retention_policy
          SET lastDryRunAt = ?, lastDryRunRevision = ?, lastDryRunRetentionDays = ?,
              lastDryRunCandidateRows = ?, revision = ?, updatedAt = ?
        WHERE id = ? AND workspaceId = ? AND revision = ?`,
      now, next, policy.retentionDays, candidates, next, now,
      policy.id, input.workspaceId, policy.revision,
    );
    return finish(changed, input.workspaceId, policy.dataClass, now);
  }

  if (mutation.operation === 'set-window') {
    if (policy.enabled === 1) {
      return {
        ok: false,
        status: 409,
        error: 'Disable the policy before changing its retention window, then run a new dry-run.',
      };
    }
    const floor = minimumRetentionDays(policy.dataClass);
    if (mutation.retentionDays < floor) {
      return {
        ok: false,
        status: 400,
        error: `${RETENTION_CLASS_META[policy.dataClass].label} cannot be retained for fewer than ${floor} days.`,
        securityCode: 'retention-floor-violation',
      };
    }
    // Changing the window invalidates any prior review.
    const changed = await execute(
      `UPDATE retention_policy
          SET retentionDays = ?, lastDryRunAt = NULL, lastDryRunRevision = NULL,
              lastDryRunRetentionDays = NULL, lastDryRunCandidateRows = NULL,
              revision = ?, updatedAt = ?
        WHERE id = ? AND workspaceId = ? AND revision = ? AND enabled = 0`,
      mutation.retentionDays, next, now,
      policy.id, input.workspaceId, policy.revision,
    );
    return finish(changed, input.workspaceId, policy.dataClass, now);
  }

  if (mutation.operation === 'enable') {
    if (policy.enabled === 1) {
      return { ok: false, status: 409, error: 'The policy is already enabled.' };
    }
    if (
      !dryRunAuthorises({
        lastDryRunAt: policy.lastDryRunAt,
        lastDryRunRevision: policy.lastDryRunRevision,
        lastDryRunRetentionDays: policy.lastDryRunRetentionDays,
        revision: policy.revision,
        retentionDays: policy.retentionDays,
        now,
      })
    ) {
      return {
        ok: false,
        status: 409,
        error:
          'Activation requires a dry-run from the last 24 hours against this exact window.',
        securityCode: 'retention-activation-without-dry-run',
      };
    }
    const changed = await execute(
      `UPDATE retention_policy
          SET enabled = 1, consecutiveFailures = 0, revision = ?, updatedAt = ?
        WHERE id = ? AND workspaceId = ? AND revision = ? AND enabled = 0`,
      next, now, policy.id, input.workspaceId, policy.revision,
    );
    return finish(changed, input.workspaceId, policy.dataClass, now);
  }

  // Disable is always permitted: turning deletion off is never the risky move.
  const changed = await execute(
    `UPDATE retention_policy
        SET enabled = 0, revision = ?, updatedAt = ?
      WHERE id = ? AND workspaceId = ? AND revision = ?`,
    next, now, policy.id, input.workspaceId, policy.revision,
  );
  return finish(changed, input.workspaceId, policy.dataClass, now);
}

async function finish(
  changed: D1Result,
  workspaceId: string,
  dataClass: RetentionDataClass,
  now: number,
): Promise<MutationResult> {
  if ((changed.meta.changes ?? 0) !== 1) {
    return {
      ok: false,
      status: 409,
      error: 'The retention policy changed since it was loaded. Reload and retry.',
    };
  }
  const updated = await loadPolicy(workspaceId, dataClass);
  if (!updated) {
    return { ok: false, status: 404, error: 'Retention policy not found.' };
  }
  let candidates: number | null = null;
  try {
    candidates = await countRetentionCandidates({
      workspaceId,
      dataClass,
      cutoff: retentionCutoff(updated.retentionDays, now),
    });
  } catch {
    candidates = null;
  }
  return { ok: true, policy: policyView(updated, candidates) };
}

async function writeRun(input: {
  policy: PolicyRow;
  mode: 'dry-run' | 'prune';
  actorType: 'user' | 'system';
  actorId: string;
  cutoff: number;
  candidateRows: number;
  deletedRows: number;
  status: RetentionRunStatus;
  failureCode: string | null;
  startedAt: number;
  finishedAt: number | null;
}): Promise<string> {
  const id = createId('retrun');
  await execute(
    `INSERT INTO retention_run
       (id, organizationId, workspaceId, policyId, dataClass, mode, actorType,
        actorId, retentionDays, cutoff, candidateRows, deletedRows, status,
        failureCode, startedAt, finishedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id,
    input.policy.organizationId,
    input.policy.workspaceId,
    input.policy.id,
    input.policy.dataClass,
    input.mode,
    input.actorType,
    input.actorId.slice(0, 160),
    input.policy.retentionDays,
    input.cutoff,
    input.candidateRows,
    input.deletedRows,
    input.status,
    input.failureCode,
    input.startedAt,
    input.finishedAt,
  );
  return id;
}

/**
 * One bounded prune pass for one policy.
 *
 * Small batches rather than one large transaction, capped by the class's
 * `maxRowsPerRun`. A pass that hits the cap finishes as `partial`, which makes
 * the policy immediately due again so the next tick continues where this one
 * stopped instead of waiting out the interval.
 */
export async function prunePolicyOnce(input: {
  policy: PolicyRow;
  actorId: string;
  now: number;
}): Promise<{ deleted: number; status: RetentionRunStatus }> {
  const { policy, now } = input;
  if (policy.enabled !== 1) return { deleted: 0, status: 'skipped' };

  const meta = RETENTION_CLASS_META[policy.dataClass];
  const cutoff = retentionCutoff(policy.retentionDays, now);
  const runId = createId('retrun');

  let candidates = 0;
  try {
    candidates = await countRetentionCandidates({
      workspaceId: policy.workspaceId,
      dataClass: policy.dataClass,
      cutoff,
    });
  } catch {
    await recordFailure(policy, cutoff, FAILURE_CODES.count, now);
    return { deleted: 0, status: 'failed' };
  }

  if (candidates === 0) {
    await writeRun({
      policy,
      mode: 'prune',
      actorType: 'system',
      actorId: input.actorId,
      cutoff,
      candidateRows: 0,
      deletedRows: 0,
      status: 'skipped',
      failureCode: null,
      startedAt: now,
      finishedAt: now,
    });
    await execute(
      `UPDATE retention_policy
          SET lastPrunedAt = ?, lastRunStatus = 'skipped', consecutiveFailures = 0,
              updatedAt = ?
        WHERE id = ? AND workspaceId = ?`,
      now, now, policy.id, policy.workspaceId,
    );
    return { deleted: 0, status: 'skipped' };
  }

  await execute(
    `INSERT INTO retention_run
       (id, organizationId, workspaceId, policyId, dataClass, mode, actorType,
        actorId, retentionDays, cutoff, candidateRows, deletedRows, status,
        failureCode, startedAt, finishedAt)
     VALUES (?, ?, ?, ?, ?, 'prune', 'system', ?, ?, ?, ?, 0, 'partial', NULL, ?, NULL)`,
    runId, policy.organizationId, policy.workspaceId, policy.id, policy.dataClass,
    input.actorId.slice(0, 160), policy.retentionDays, cutoff, candidates, now,
  );

  const cap = Math.min(meta.maxRowsPerRun, candidates);
  const statement = deleteStatement(policy.dataClass);
  let deleted = 0;
  try {
    while (deleted < cap) {
      const batch = Math.min(RETENTION_LIMITS.batchRows, cap - deleted);
      const result = await execute(
        statement,
        policy.workspaceId,
        cutoff,
        batch,
      );
      const changes = result.meta.changes ?? 0;
      deleted += changes;
      if (changes < batch) break;
    }
  } catch {
    await execute(
      `UPDATE retention_run
          SET deletedRows = ?, status = 'failed', failureCode = ?, finishedAt = ?
        WHERE id = ? AND finishedAt IS NULL`,
      deleted, FAILURE_CODES.prune, now, runId,
    );
    await execute(
      `UPDATE retention_policy
          SET lastPrunedAt = ?, lastRunStatus = 'failed',
              consecutiveFailures = consecutiveFailures + 1, updatedAt = ?
        WHERE id = ? AND workspaceId = ?`,
      now, now, policy.id, policy.workspaceId,
    );
    return { deleted, status: 'failed' };
  }

  const status: RetentionRunStatus = deleted < candidates ? 'partial' : 'completed';
  await execute(
    `UPDATE retention_run
        SET deletedRows = ?, status = ?, finishedAt = ?
      WHERE id = ? AND finishedAt IS NULL`,
    deleted, status, now, runId,
  );
  await execute(
    `UPDATE retention_policy
        SET lastPrunedAt = ?, lastRunStatus = ?, consecutiveFailures = 0, updatedAt = ?
      WHERE id = ? AND workspaceId = ?`,
    now, status, now, policy.id, policy.workspaceId,
  );
  return { deleted, status };
}

async function recordFailure(
  policy: PolicyRow,
  cutoff: number,
  failureCode: string,
  now: number,
): Promise<void> {
  await writeRun({
    policy,
    mode: 'prune',
    actorType: 'system',
    actorId: 'system:data-lifecycle',
    cutoff,
    candidateRows: 0,
    deletedRows: 0,
    status: 'failed',
    failureCode,
    startedAt: now,
    finishedAt: now,
  }).catch(() => '');
  await execute(
    `UPDATE retention_policy
        SET lastPrunedAt = ?, lastRunStatus = 'failed',
            consecutiveFailures = consecutiveFailures + 1, updatedAt = ?
      WHERE id = ? AND workspaceId = ?`,
    now, now, policy.id, policy.workspaceId,
  ).catch(() => undefined);
}

export async function captureUsageSnapshot(input: {
  organizationId: string;
  workspaceId: string;
  ownerUserId: string;
  now: number;
  source: 'cron' | 'manual';
}): Promise<{ captured: boolean; readings: UsageReading[] }> {
  const slot = snapshotSlot(input.now);
  const existing = await queryOne<{ id: string }>(
    'SELECT id FROM usage_snapshot WHERE workspaceId = ? AND slot = ?',
    input.workspaceId,
    slot,
  );
  if (existing) return { captured: false, readings: [] };

  // Full workspace scope with the owner as the identity, matching what an
  // owner sees on the Usage surface. The outbound D1 size lookup is skipped.
  const { readings } = await collectUsageReadings({
    workspaceId: input.workspaceId,
    userId: input.ownerUserId,
    organizationId: input.organizationId,
    projectIds: null,
    includeDatabaseBytes: false,
  });

  const metrics: Partial<Record<UsageMetricId, number>> = {};
  let overLimitCount = 0;
  for (const reading of readings) {
    if (!reading.measured) continue;
    metrics[reading.id] = reading.used;
    if (reading.used > reading.limit) overLimitCount += 1;
  }

  const inserted = await execute(
    `INSERT OR IGNORE INTO usage_snapshot
       (id, organizationId, workspaceId, slot, capturedAt, source, metrics, overLimitCount)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    createId('usnap'),
    input.organizationId,
    input.workspaceId,
    slot,
    input.now,
    input.source,
    JSON.stringify(metrics),
    overLimitCount,
  );
  return {
    captured: (inserted.meta.changes ?? 0) === 1,
    readings: (inserted.meta.changes ?? 0) === 1 ? readings : [],
  };
}

/** Keeps snapshot history itself bounded. Not a user-configurable policy. */
async function trimSnapshotHistory(workspaceId: string): Promise<void> {
  await execute(
    `DELETE FROM usage_snapshot WHERE workspaceId = ? AND id NOT IN (
       SELECT id FROM usage_snapshot WHERE workspaceId = ?
        ORDER BY capturedAt DESC LIMIT ?)`,
    workspaceId,
    workspaceId,
    RETENTION_LIMITS.snapshotHistory,
  );
}

/**
 * Opens a capacity incident through the Phase 11 system.
 *
 * No new workflow event type is introduced. `createOrAggregateIncident`
 * already dedupes on the workspace, resource, and title, bumps the occurrence
 * count on an open incident instead of opening a second one, and emits the
 * existing `incident.opened` event, so capacity reaches workflows through the
 * taxonomy that is already there.
 */
async function openCapacityIncident(input: {
  organizationId: string;
  workspaceId: string;
  forecast: CapacityForecast;
  now: number;
}): Promise<boolean> {
  const { forecast } = input;
  const percent = Math.round(forecast.percent);
  const horizon =
    forecast.daysRemaining === null
      ? 'no projection is available'
      : `the projection reaches the ceiling in about ${Math.max(0, Math.round(forecast.daysRemaining))} days`;
  const result = await createOrAggregateIncident({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    projectId: null,
    resourceType: 'capacity',
    resourceId: null,
    // No colon or equals directly after a metric label — the Phase 11 text
    // validator treats `<word>:` shapes as credential-like and would reject it.
    title: `Capacity critical for ${forecast.label}`,
    detail: `${forecast.label} is at ${percent}% of its free-tier allowance and ${horizon}. Review retention policies to reclaim rows before writes are refused.`,
    severity: 'critical',
    createdBy: 'system:capacity-guard',
    correlationId: `capacity-${input.workspaceId}-${forecast.metricId}`,
  });
  return result.ok;
}

export type DataLifecycleTickResult = {
  snapshots: number;
  policiesProcessed: number;
  rowsDeleted: number;
  capacityIncidents: number;
};

/**
 * The maintenance phase of the existing one-minute tick.
 *
 * No new Cron Trigger. Every stage is capped and fair: snapshots go to the
 * workspace that has waited longest, prunes go to the policy that has waited
 * longest, and a failure in one workspace is caught so the rest still run.
 */
export async function runDataLifecycleMaintenance(
  now = Date.now(),
): Promise<DataLifecycleTickResult> {
  const result: DataLifecycleTickResult = {
    snapshots: 0,
    policiesProcessed: 0,
    rowsDeleted: 0,
    capacityIncidents: 0,
  };
  const slot = snapshotSlot(now);

  const due = await query<{
    id: string;
    organizationId: string;
    ownerUserId: string;
  }>(
    `SELECT w.id, w.organizationId, w.ownerUserId
       FROM workspace w
      WHERE w.archivedAt IS NULL AND w.organizationId IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM usage_snapshot s
           WHERE s.workspaceId = w.id AND s.slot = ?
        )
      ORDER BY COALESCE(
        (SELECT MAX(s2.capturedAt) FROM usage_snapshot s2 WHERE s2.workspaceId = w.id),
        0
      ) ASC, w.id ASC
      LIMIT ?`,
    slot,
    RETENTION_LIMITS.snapshotsPerTick,
  );

  for (const workspace of due) {
    try {
      const captured = await captureUsageSnapshot({
        organizationId: workspace.organizationId,
        workspaceId: workspace.id,
        ownerUserId: workspace.ownerUserId,
        now,
        source: 'cron',
      });
      if (!captured.captured) continue;
      result.snapshots += 1;
      await trimSnapshotHistory(workspace.id);

      const history = await readSnapshotHistory(workspace.id);
      const forecasts = forecastCapacity({
        readings: captured.readings,
        history,
        now,
      });
      for (const forecast of forecasts) {
        if (forecast.state !== 'critical') continue;
        if (await openCapacityIncident({
          organizationId: workspace.organizationId,
          workspaceId: workspace.id,
          forecast,
          now,
        })) {
          result.capacityIncidents += 1;
        }
      }
    } catch {
      // A workspace that cannot be sampled must not stop the tick.
      continue;
    }
  }

  const policies = await query<PolicyRow>(
    `SELECT p.* FROM retention_policy p
       JOIN workspace w ON w.id = p.workspaceId
      WHERE p.enabled = 1 AND w.archivedAt IS NULL
        AND (
          p.lastPrunedAt IS NULL
          OR p.lastRunStatus = 'partial'
          OR p.lastPrunedAt <= ?
        )
      ORDER BY COALESCE(p.lastPrunedAt, 0) ASC, p.id ASC
      LIMIT ?`,
    now - RETENTION_LIMITS.pruneIntervalMs,
    RETENTION_LIMITS.policiesPerTick,
  );

  for (const policy of policies) {
    if (!isRetentionDataClass(policy.dataClass)) continue;
    try {
      const pass = await prunePolicyOnce({
        policy,
        actorId: 'system:data-lifecycle',
        now,
      });
      result.policiesProcessed += 1;
      result.rowsDeleted += pass.deleted;
    } catch {
      // Failures are isolated per policy and recorded with an allowlisted
      // code. No raw D1 message is persisted or returned to an operator.
      await recordFailure(
        policy,
        retentionCutoff(policy.retentionDays, now),
        FAILURE_CODES.maintenance,
        now,
      );
      continue;
    }
  }

  return result;
}

export type CapacityShieldState = {
  approachingLimit: number;
  forecastBreachSoon: number;
  retentionDisabledUnderPressure: number;
  failingRetentionPolicies: number;
  noUsageHistory: number;
};

/**
 * Capacity signals for Shield.
 *
 * Derived from stored snapshots rather than a live recount, so a scan stays
 * cheap and never triggers the outbound D1 size lookup.
 */
export async function capacityForShield(
  workspaceId: string,
  now = Date.now(),
): Promise<CapacityShieldState> {
  const history = await readSnapshotHistory(workspaceId);
  const state: CapacityShieldState = {
    approachingLimit: 0,
    forecastBreachSoon: 0,
    retentionDisabledUnderPressure: 0,
    failingRetentionPolicies: 0,
    noUsageHistory: history.length === 0 ? 1 : 0,
  };

  const [failing, disabled] = await Promise.all([
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM retention_policy
        WHERE workspaceId = ? AND consecutiveFailures >= ?`,
      workspaceId,
      RETENTION_LIMITS.failureAlertThreshold,
    ),
    queryOne<{ total: number }>(
      'SELECT COUNT(*) AS total FROM retention_policy WHERE workspaceId = ? AND enabled = 0',
      workspaceId,
    ),
  ]);
  state.failingRetentionPolicies = failing?.total ?? 0;

  if (history.length === 0) return state;

  const latest = history.reduce((newest, entry) =>
    entry.capturedAt > newest.capturedAt ? entry : newest,
  );
  const forecasts = forecastCapacity({
    readings: readingsFromSnapshot(latest.metrics),
    history,
    now,
  });

  let pressured = false;
  for (const forecast of forecasts) {
    if (forecast.state === 'at-risk' || forecast.state === 'critical') {
      state.approachingLimit += 1;
      pressured = true;
    }
    if (
      forecast.daysRemaining !== null &&
      forecast.daysRemaining <= CAPACITY_THRESHOLDS.atRiskDays
    ) {
      state.forecastBreachSoon += 1;
      pressured = true;
    }
  }
  // Disabled retention is only a finding while the workspace is actually under
  // pressure. A quiet workspace with retention off is a deliberate default,
  // not a security problem.
  if (pressured) state.retentionDisabledUnderPressure = disabled?.total ?? 0;

  return state;
}

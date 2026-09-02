import {
  projectedMonthlyCost,
  readUsage,
  type UsageReading,
} from '@/lib/free-tier';
import { count, queryOne } from './db';
import { countDeployments } from './deployments';
import { countProjects } from './projects';
import { countSecrets } from './secrets';
import { databaseBytes, listTables } from './studio';
import { listStorage } from './storage';

/**
 * Usage is measured, not estimated.
 *
 * Every number here is a count taken from D1 at request time. Nothing is
 * sampled or projected forward, so the reported cost of zero is a statement
 * about what exists rather than a forecast.
 *
 * Phase 12 adds history on top of this without adding a second set of
 * counters. `collectUsageReadings` is the one implementation, and both the
 * Usage surface and the scheduled snapshot call it, so a stored snapshot can
 * never disagree with the meter a user is looking at.
 */

export type UsageSummary = {
  readings: UsageReading[];
  /** Always 0 while the workspace stays inside its allowances. */
  projectedMonthlyCost: number;
  overLimit: UsageReading[];
  /** `null` when the provider does not expose the figure. */
  databaseBytes: number | null;
  tableCount: number;
  measuredAt: number;
};

export type UsageCollectionScope = {
  workspaceId: string;
  userId: string;
  organizationId?: string;
  projectIds?: readonly string[] | null;
  /**
   * The D1 file size comes from the Cloudflare REST API, which is an outbound
   * call. The scheduled path passes `false` so a cron tick never depends on
   * the network; the metric is then reported as unmeasured rather than as zero.
   */
  includeDatabaseBytes: boolean;
  /**
   * How the `database-rows` total and the table count are obtained.
   *
   * `inventory` walks every table with a PRAGMA and a COUNT — exact, and with
   * 67 tables in production that is 135 sequential D1 round-trips. It belongs
   * to the scheduled collector and to Studio, never to an interactive page.
   *
   * `summary` costs two statements: one count of tables, and the most recent
   * Phase 12 `usage_snapshot`, which the cron already captured through this
   * same reader. Nothing is estimated — an absent snapshot reports the metric
   * as unmeasured rather than inventing a number.
   */
  databaseRows: 'inventory' | 'summary';
};

/** Table count without walking each table. One statement. */
async function countTables(): Promise<number> {
  return count(
    `SELECT COUNT(*) AS total FROM sqlite_master
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'`,
  );
}

/**
 * The newest stored row total for this workspace, or `null` when no snapshot
 * has been captured yet. Read directly rather than through the retention module
 * to keep `usage` free of a circular import.
 */
async function snapshotDatabaseRows(workspaceId: string): Promise<number | null> {
  const row = await queryOne<{ metrics: string }>(
    'SELECT metrics FROM usage_snapshot WHERE workspaceId = ? ORDER BY capturedAt DESC LIMIT 1',
    workspaceId,
  );
  if (!row) return null;
  try {
    const parsed = JSON.parse(row.metrics) as Record<string, unknown>;
    const value = parsed['database-rows'];
    return typeof value === 'number' && Number.isFinite(value) && value >= 0
      ? value
      : null;
  } catch {
    return null;
  }
}

export async function collectUsageReadings(
  scope: UsageCollectionScope,
): Promise<{
  readings: UsageReading[];
  databaseBytes: number | null;
  tableCount: number;
}> {
  const inventory =
    scope.databaseRows === 'inventory'
      ? await listTables({
          workspaceId: scope.workspaceId,
          userId: scope.userId,
          ...(scope.organizationId ? { organizationId: scope.organizationId } : {}),
          ...(scope.projectIds !== undefined ? { projectIds: scope.projectIds } : {}),
        })
      : null;

  const [databaseRows, tableCount] = inventory
    ? [inventory.reduce((total, table) => total + table.rows, 0), inventory.length]
    : await Promise.all([snapshotDatabaseRows(scope.workspaceId), countTables()]);

  const [projects, deployments, secrets, logEvents, bytes, storage] =
    await Promise.all([
      countProjects(scope.workspaceId, scope.projectIds),
      countDeployments(scope.workspaceId, scope.projectIds),
      countSecrets(scope.workspaceId, scope.projectIds),
      count(
        'SELECT COUNT(*) AS total FROM log_event WHERE workspaceId = ?',
        scope.workspaceId,
      ),
      scope.includeDatabaseBytes ? databaseBytes() : Promise.resolve(null),
      listStorage(scope.workspaceId),
    ]);

  const readings = readUsage({
    projects,
    deployments,
    secrets,
    'log-events': logEvents,
    'database-rows': databaseRows,
    'database-bytes': bytes,
    'storage-bytes': storage.usage.bytesUsed,
    'storage-objects': storage.usage.objectCount,
    'storage-writes': storage.usage.classAWrites,
    'storage-reads': storage.usage.classBReads,
  });

  return { readings, databaseBytes: bytes, tableCount };
}

export async function summarizeUsage(
  workspaceId: string,
  userId: string,
  scope: {
    organizationId?: string;
    projectIds?: readonly string[] | null;
    /** Defaults to the cheap path; only Studio-grade callers ask for exact. */
    databaseRows?: 'inventory' | 'summary';
  } = {},
): Promise<UsageSummary> {
  const { databaseRows = 'summary', ...tenant } = scope;
  const collected = await collectUsageReadings({
    workspaceId,
    userId,
    ...tenant,
    includeDatabaseBytes: true,
    databaseRows,
  });

  return {
    readings: collected.readings,
    projectedMonthlyCost: projectedMonthlyCost(collected.readings),
    overLimit: collected.readings.filter(
      (reading) => reading.used > reading.limit,
    ),
    databaseBytes: collected.databaseBytes,
    tableCount: collected.tableCount,
    measuredAt: Date.now(),
  };
}

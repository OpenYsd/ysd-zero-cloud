import {
  projectedMonthlyCost,
  readUsage,
  type UsageReading,
} from '@/lib/free-tier';
import { count } from './db';
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
};

export async function collectUsageReadings(
  scope: UsageCollectionScope,
): Promise<{
  readings: UsageReading[];
  databaseBytes: number | null;
  tableCount: number;
}> {
  const tables = await listTables({
    workspaceId: scope.workspaceId,
    userId: scope.userId,
    ...(scope.organizationId ? { organizationId: scope.organizationId } : {}),
    ...(scope.projectIds !== undefined ? { projectIds: scope.projectIds } : {}),
  });

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
    'database-rows': tables.reduce((total, table) => total + table.rows, 0),
    'database-bytes': bytes,
    'storage-bytes': storage.usage.bytesUsed,
    'storage-objects': storage.usage.objectCount,
    'storage-writes': storage.usage.classAWrites,
    'storage-reads': storage.usage.classBReads,
  });

  return { readings, databaseBytes: bytes, tableCount: tables.length };
}

export async function summarizeUsage(
  workspaceId: string,
  userId: string,
  scope: { organizationId?: string; projectIds?: readonly string[] | null } = {},
): Promise<UsageSummary> {
  const collected = await collectUsageReadings({
    workspaceId,
    userId,
    ...scope,
    includeDatabaseBytes: true,
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

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

export async function summarizeUsage(
  workspaceId: string,
  userId: string,
): Promise<UsageSummary> {
  const tables = await listTables({ workspaceId, userId });

  const [projects, deployments, secrets, logEvents, bytes, storage] =
    await Promise.all([
      countProjects(workspaceId),
      countDeployments(workspaceId),
      countSecrets(workspaceId),
      count(
        'SELECT COUNT(*) AS total FROM log_event WHERE workspaceId = ?',
        workspaceId,
      ),
      databaseBytes(),
      listStorage(workspaceId),
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

  return {
    readings,
    projectedMonthlyCost: projectedMonthlyCost(readings),
    overLimit: readings.filter((reading) => reading.used > reading.limit),
    databaseBytes: bytes,
    tableCount: tables.length,
    measuredAt: Date.now(),
  };
}

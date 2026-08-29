/**
 * Free-tier limits YSD Zero Cloud is allowed to consume.
 *
 * Every entry is a published no-cost allowance. Nothing in this catalog may
 * describe a paid plan: Zero Mode reads `limit` as a hard ceiling and the
 * usage surfaces refuse to project a bill above zero.
 */

export type UsageMetricId =
  | 'projects'
  | 'deployments'
  | 'database-rows'
  | 'database-bytes'
  | 'storage-bytes'
  | 'storage-objects'
  | 'storage-writes'
  | 'storage-reads'
  | 'secrets'
  | 'log-events'
  | 'requests';

export type FreeTierLimit = {
  id: UsageMetricId;
  label: string;
  provider: string;
  /** Hard ceiling for the current period. */
  limit: number;
  unit: 'count' | 'bytes' | 'requests';
  /** Accent used by the usage meters. */
  color: string;
  note: string;
};

/**
 * Cloudflare's documented free allowances, scaled down to the slice a single
 * workspace may claim so one workspace can never exhaust the account.
 */
export const FREE_TIER_LIMITS: readonly FreeTierLimit[] = [
  {
    id: 'projects',
    label: 'Projects',
    provider: 'YSD',
    limit: 25,
    unit: 'count',
    color: '#b7ff3c',
    note: 'Workspace projects',
  },
  {
    id: 'deployments',
    label: 'Deployments',
    provider: 'Cloudflare Workers',
    limit: 500,
    unit: 'count',
    color: '#4ac7ff',
    note: 'Recorded this period',
  },
  {
    id: 'database-rows',
    label: 'Database rows',
    provider: 'Cloudflare D1',
    limit: 100_000,
    unit: 'count',
    color: '#7569ff',
    note: 'Across workspace tables',
  },
  {
    id: 'database-bytes',
    label: 'Database size',
    provider: 'Cloudflare D1',
    limit: 500 * 1024 * 1024,
    unit: 'bytes',
    color: '#ffb84a',
    note: '500 MB free storage',
  },
  {
    id: 'storage-bytes',
    label: 'Private object storage',
    provider: 'Cloudflare R2',
    limit: 256 * 1024 * 1024,
    unit: 'bytes',
    color: '#79d6ff',
    note: 'Workspace hard guard',
  },
  {
    id: 'storage-objects',
    label: 'Stored objects',
    provider: 'Cloudflare R2',
    limit: 500,
    unit: 'count',
    color: '#5ce0a8',
    note: 'Workspace hard guard',
  },
  {
    id: 'storage-writes',
    label: 'Storage writes',
    provider: 'Cloudflare R2',
    limit: 5_000,
    unit: 'requests',
    color: '#ef78ff',
    note: 'Monthly Class A guard',
  },
  {
    id: 'storage-reads',
    label: 'Storage reads',
    provider: 'Cloudflare R2',
    limit: 50_000,
    unit: 'requests',
    color: '#4ac7ff',
    note: 'Monthly Class B guard',
  },
  {
    id: 'secrets',
    label: 'Secrets',
    provider: 'YSD',
    limit: 200,
    unit: 'count',
    color: '#ef78ff',
    note: 'Encrypted at rest',
  },
  {
    id: 'log-events',
    label: 'Log events',
    provider: 'YSD',
    limit: 20_000,
    unit: 'count',
    color: '#5ce0a8',
    note: 'Retained events',
  },
] as const;

export type UsageReading = {
  id: UsageMetricId;
  label: string;
  provider: string;
  used: number;
  limit: number;
  unit: FreeTierLimit['unit'];
  color: string;
  note: string;
  /** 0-100, clamped. Zero for an unmeasured metric. */
  percent: number;
  state: 'healthy' | 'watch' | 'critical' | 'unmeasured';
  /**
   * False when the provider does not expose the figure. An unmeasured metric
   * is reported as unknown rather than as zero, which would read as "empty".
   */
  measured: boolean;
};

/**
 * @param used Value per metric. `null` marks a metric the provider will not
 * report; a missing key means the workspace genuinely has none.
 */
export function readUsage(
  used: Partial<Record<UsageMetricId, number | null>>,
): UsageReading[] {
  return FREE_TIER_LIMITS.map((entry) => {
    const raw = used[entry.id];
    const measured = raw !== null;
    const value = measured ? Math.max(0, raw ?? 0) : 0;
    const percent =
      measured && entry.limit > 0
        ? Math.min(100, (value / entry.limit) * 100)
        : 0;
    return {
      id: entry.id,
      label: entry.label,
      provider: entry.provider,
      used: value,
      limit: entry.limit,
      unit: entry.unit,
      color: entry.color,
      note: entry.note,
      percent,
      state: !measured
        ? 'unmeasured'
        : percent >= 90
          ? 'critical'
          : percent >= 70
            ? 'watch'
            : 'healthy',
      measured,
    };
  });
}

/**
 * A workspace that stays inside every free allowance costs nothing. The value
 * is derived rather than stored so no surface can invent a charge.
 *
 * @returns `0`, or `NaN` when a measured allowance has been exceeded — the
 * function refuses to name a price rather than guessing at one.
 */
export function projectedMonthlyCost(
  readings: readonly UsageReading[],
): number {
  return readings.some(
    (reading) => reading.measured && reading.used > reading.limit,
  )
    ? Number.NaN
    : 0;
}

export function formatUsage(
  reading: Pick<UsageReading, 'used' | 'limit' | 'unit'> & {
    measured?: boolean;
  },
): string {
  const limit =
    reading.unit === 'bytes'
      ? formatBytes(reading.limit)
      : reading.limit.toLocaleString('en-US');

  if (reading.measured === false) return `not reported / ${limit}`;

  const value =
    reading.unit === 'bytes'
      ? formatBytes(reading.used)
      : reading.used.toLocaleString('en-US');
  return `${value} / ${limit}`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const rounded =
    value >= 100 || unit === 0 ? Math.round(value) : Number(value.toFixed(1));
  return `${rounded} ${units[unit]}`;
}

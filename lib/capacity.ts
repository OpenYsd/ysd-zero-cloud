import {
  FREE_TIER_LIMITS,
  type UsageMetricId,
  type UsageReading,
} from './free-tier.ts';

/**
 * Capacity forecasting.
 *
 * Every function here is pure. It takes measured usage plus a history of
 * snapshots and returns a projection; it never reads a clock, a database, or
 * an environment variable, so the tests drive it with fixed instants.
 *
 * Two rules shape the whole module. A limit is only ever read from
 * `FREE_TIER_LIMITS` — the same trusted catalog the Usage surface renders, so
 * a forecast can never disagree with the meter beside it. And a projection is
 * refused rather than invented: too few samples, too short a span, or
 * non-positive growth all yield `null` instead of a confident-looking date.
 */

export const CAPACITY_STATES = [
  'healthy',
  'watch',
  'at-risk',
  'critical',
  'insufficient-data',
] as const;

export type CapacityState = (typeof CAPACITY_STATES)[number];

/**
 * Thresholds live in one place so the UI, Shield, and the incident path all
 * describe the same risk with the same word.
 */
export const CAPACITY_THRESHOLDS = {
  /** A slope needs at least this many distinct snapshots. */
  minimumSamples: 3,
  /** ...spread over at least this long. Six hours is one snapshot cadence. */
  minimumSpanMs: 6 * 60 * 60 * 1000,
  /** Fraction of the trusted limit already consumed. */
  watchRatio: 0.7,
  atRiskRatio: 0.85,
  criticalRatio: 0.95,
  /** Projected days until the trusted limit is reached. */
  watchDays: 30,
  atRiskDays: 14,
  criticalDays: 7,
  /** Projections beyond this are indistinguishable from "not growing". */
  maxProjectionDays: 3_650,
} as const;

const DAY_MS = 24 * 60 * 60 * 1000;

const SEVERITY_ORDER: Record<CapacityState, number> = {
  'insufficient-data': 0,
  healthy: 1,
  watch: 2,
  'at-risk': 3,
  critical: 4,
};

export type CapacitySample = {
  capturedAt: number;
  used: number;
};

export type CapacityForecast = {
  metricId: UsageMetricId;
  label: string;
  unit: 'count' | 'bytes' | 'requests';
  used: number;
  limit: number;
  /** 0-100, clamped for display. `state` uses the unclamped ratio. */
  percent: number;
  state: CapacityState;
  measured: boolean;
  samples: number;
  spanMs: number;
  /** Units consumed per day, or `null` when no slope could be derived. */
  growthPerDay: number | null;
  /** `null` when growth is flat, falling, or beyond the projection horizon. */
  daysRemaining: number | null;
  projectedBreachAt: number | null;
  insufficientHistory: boolean;
};

/**
 * The trusted ceiling for a metric. Nothing in Phase 12 hardcodes a provider
 * number; every limit is looked up here.
 */
export function trustedLimit(metricId: UsageMetricId): number | null {
  const entry = FREE_TIER_LIMITS.find((limit) => limit.id === metricId);
  return entry ? entry.limit : null;
}

export function worseState(a: CapacityState, b: CapacityState): CapacityState {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

/** State implied by how full the metric already is, ignoring any trend. */
export function stateForRatio(ratio: number): CapacityState {
  if (!Number.isFinite(ratio)) return 'insufficient-data';
  if (ratio >= CAPACITY_THRESHOLDS.criticalRatio) return 'critical';
  if (ratio >= CAPACITY_THRESHOLDS.atRiskRatio) return 'at-risk';
  if (ratio >= CAPACITY_THRESHOLDS.watchRatio) return 'watch';
  return 'healthy';
}

/** State implied by how soon the metric is projected to reach its limit. */
export function stateForDaysRemaining(days: number | null): CapacityState {
  if (days === null || !Number.isFinite(days)) return 'healthy';
  if (days <= CAPACITY_THRESHOLDS.criticalDays) return 'critical';
  if (days <= CAPACITY_THRESHOLDS.atRiskDays) return 'at-risk';
  if (days <= CAPACITY_THRESHOLDS.watchDays) return 'watch';
  return 'healthy';
}

/**
 * Least-squares slope in units per day.
 *
 * Least squares rather than first-to-last so a single noisy snapshot cannot
 * dominate the projection. Returns `null` when the samples share one instant
 * (zero variance) or when the arithmetic does not stay finite.
 */
export function growthPerDay(samples: readonly CapacitySample[]): number | null {
  const usable = samples.filter(
    (sample) =>
      Number.isFinite(sample.capturedAt) && Number.isFinite(sample.used),
  );
  if (usable.length < 2) return null;

  let sumX = 0;
  let sumY = 0;
  for (const sample of usable) {
    sumX += sample.capturedAt / DAY_MS;
    sumY += sample.used;
  }
  const meanX = sumX / usable.length;
  const meanY = sumY / usable.length;

  let numerator = 0;
  let denominator = 0;
  for (const sample of usable) {
    const dx = sample.capturedAt / DAY_MS - meanX;
    numerator += dx * (sample.used - meanY);
    denominator += dx * dx;
  }
  if (denominator <= 0) return null;

  const slope = numerator / denominator;
  return Number.isFinite(slope) ? slope : null;
}

function spanOf(samples: readonly CapacitySample[]): number {
  if (samples.length < 2) return 0;
  let low = Number.POSITIVE_INFINITY;
  let high = Number.NEGATIVE_INFINITY;
  for (const sample of samples) {
    if (!Number.isFinite(sample.capturedAt)) continue;
    if (sample.capturedAt < low) low = sample.capturedAt;
    if (sample.capturedAt > high) high = sample.capturedAt;
  }
  const span = high - low;
  return Number.isFinite(span) && span > 0 ? span : 0;
}

/**
 * Projects one metric.
 *
 * `measured: false` marks a figure the provider will not report — the D1 file
 * size is one, because reading it needs an outbound Cloudflare API call the
 * scheduled path deliberately never makes. An unmeasured metric is reported as
 * unknown, never as zero.
 */
export function forecastMetric(input: {
  metricId: UsageMetricId;
  label: string;
  unit: 'count' | 'bytes' | 'requests';
  used: number;
  limit: number;
  measured: boolean;
  samples: readonly CapacitySample[];
  now: number;
}): CapacityForecast {
  const base = {
    metricId: input.metricId,
    label: input.label,
    unit: input.unit,
    used: Number.isFinite(input.used) ? Math.max(0, input.used) : 0,
    limit: input.limit,
    samples: input.samples.length,
    spanMs: spanOf(input.samples),
  };

  if (!input.measured || !Number.isFinite(input.limit) || input.limit <= 0) {
    return {
      ...base,
      percent: 0,
      state: 'insufficient-data',
      measured: false,
      growthPerDay: null,
      daysRemaining: null,
      projectedBreachAt: null,
      insufficientHistory: true,
    };
  }

  const ratio = base.used / input.limit;
  const percent = Math.min(100, Math.max(0, ratio * 100));
  const ratioState = stateForRatio(ratio);

  const enoughSamples = base.samples >= CAPACITY_THRESHOLDS.minimumSamples;
  const enoughSpan = base.spanMs >= CAPACITY_THRESHOLDS.minimumSpanMs;
  if (!enoughSamples || !enoughSpan) {
    return {
      ...base,
      percent,
      // A metric already near its ceiling stays loud even without history.
      state: ratioState === 'healthy' ? 'insufficient-data' : ratioState,
      measured: true,
      growthPerDay: null,
      daysRemaining: null,
      projectedBreachAt: null,
      insufficientHistory: true,
    };
  }

  const slope = growthPerDay(input.samples);
  // A flat or falling metric never produces a breach date. Clamping to zero
  // rather than extrapolating backwards keeps a shrinking table from reading
  // as "safe forever" in one place and "unknown" in another.
  const growth = slope === null ? null : Math.max(0, slope);

  let daysRemaining: number | null = null;
  let projectedBreachAt: number | null = null;
  if (growth !== null && growth > 0) {
    const headroom = Math.max(0, input.limit - base.used);
    const days = headroom / growth;
    if (Number.isFinite(days) && days <= CAPACITY_THRESHOLDS.maxProjectionDays) {
      daysRemaining = Math.max(0, days);
      const breachAt = input.now + daysRemaining * DAY_MS;
      projectedBreachAt = Number.isFinite(breachAt) ? Math.round(breachAt) : null;
    }
  }

  return {
    ...base,
    percent,
    state: worseState(ratioState, stateForDaysRemaining(daysRemaining)),
    measured: true,
    growthPerDay: growth,
    daysRemaining,
    projectedBreachAt,
    insufficientHistory: false,
  };
}

export type CapacitySnapshotHistory = {
  capturedAt: number;
  metrics: Partial<Record<UsageMetricId, number>>;
};

/**
 * Projects every metric the Usage surface already renders, using the same
 * readings so the two can never disagree.
 */
export function forecastCapacity(input: {
  readings: readonly UsageReading[];
  history: readonly CapacitySnapshotHistory[];
  now: number;
}): CapacityForecast[] {
  const ordered = [...input.history].sort(
    (left, right) => left.capturedAt - right.capturedAt,
  );
  return input.readings.map((reading) => {
    const samples: CapacitySample[] = [];
    for (const snapshot of ordered) {
      const value = snapshot.metrics[reading.id];
      if (typeof value === 'number' && Number.isFinite(value)) {
        samples.push({ capturedAt: snapshot.capturedAt, used: value });
      }
    }
    return forecastMetric({
      metricId: reading.id,
      label: reading.label,
      unit: reading.unit,
      used: reading.used,
      limit: reading.limit,
      measured: reading.measured,
      samples,
      now: input.now,
    });
  });
}

/** The loudest state across every metric, used for the section headline. */
export function overallCapacityState(
  forecasts: readonly CapacityForecast[],
): CapacityState {
  let state: CapacityState = 'insufficient-data';
  for (const forecast of forecasts) state = worseState(state, forecast.state);
  return state;
}

export const CAPACITY_STATE_LABELS: Readonly<Record<CapacityState, string>> = {
  healthy: 'Healthy',
  watch: 'Watch',
  'at-risk': 'At risk',
  critical: 'Critical',
  'insufficient-data': 'Insufficient data',
};

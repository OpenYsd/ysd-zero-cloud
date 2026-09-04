import type { ShieldFinding } from './shield.ts';

/**
 * Shield continuous posture: scheduling policy and finding reconciliation,
 * as pure functions.
 *
 * Everything here is deliberately free of database access so the two things
 * that actually matter can be tested directly: that a scheduled sweep does a
 * bounded amount of work whatever the workspace count, and that reconciling
 * findings costs a bounded number of round trips whatever the finding count.
 *
 * The measurement that produced the constants below, taken from the 0.14.0
 * source before any change:
 *
 *   collectSnapshot   one parallel batch, fixed, independent of findings
 *   reconcile         1 SELECT + 1 write PER REPORTED FINDING, sequential
 *   resolve           1 SELECT + 1 write PER RESOLVED FINDING, sequential
 *   events            ~3 round trips each, transitions only
 *
 * So reconciliation alone cost roughly `2N + R` sequential round trips. That
 * was survivable for a button a human presses; it is not something to put on
 * a timer. Finding counts are not bounded by the rule catalog either -- codes
 * are templated per resource (`table-no-primary-key:<table>`,
 * `secret-overdue:<name>:<env>`, `public-project:<id>`), so a workspace with
 * 67 tables can report far more findings than there are rules.
 *
 * After this module: one read, then writes in fixed-size batches. Events stay
 * one-at-a-time on purpose -- `emitWorkflowEvent` verifies the resource really
 * belongs to the workspace before it writes, and that check is not something
 * to batch away for speed. They are bounded instead by only ever firing on a
 * real transition, which in a steady state is zero.
 */

export const POSTURE_LIMITS = {
  /**
   * How old a workspace's last scheduled attempt must be before it is eligible
   * again. This is an eligibility threshold, NOT a delivery guarantee: a
   * workspace becomes a candidate after this long, and is then scanned when
   * the bounded scheduler reaches it.
   */
  eligibleAfterMs: 6 * 60 * 60 * 1000,
  /**
   * Workspaces a single cron tick may scan. The tick runs every minute, so
   * this is the real throughput limit, and it is what keeps the work O(cap)
   * instead of O(workspaces).
   *
   * Full-sweep floor at 2/tick (120/hour), assuming every workspace is due:
   *   100 workspaces     ~50 minutes
   *   1,000 workspaces   ~8.3 hours
   *   10,000 workspaces  ~3.5 days
   *
   * At 10,000 the sweep is slower than the 6h eligibility threshold, which is
   * exactly why the threshold is not advertised as a schedule. The system
   * degrades by scanning less often, never by doing more work per tick.
   */
  workspacesPerTick: 2,
  /** Scans kept per workspace. Older ones are trimmed oldest-first. */
  historyPerWorkspace: 30,
  /** Scans the trend UI reads. Deliberately far below the history cap. */
  trendWindow: 10,
  /** Statements per `database.batch` chunk. */
  writeBatchSize: 25,
} as const;

export type ScanTrigger = 'manual' | 'scheduled';
/** A scan that failed partway must never be readable as a completed one. */
export type ScanStatus = 'completed' | 'failed';

export type PostureDelta = {
  opened: number;
  resolved: number;
  reopened: number;
  severityChanged: number;
  unchanged: number;
};

/**
 * The part of a delta that is persisted. `unchanged` is deliberately absent:
 * migration 0019 adds four counters and no fifth, and `unchanged` cannot be
 * recovered from the four that exist because a single finding can both reopen
 * and change severity in the same scan. Reading it back as zero would be
 * inventing a number, so the stored shape simply does not claim to have it.
 */
export type StoredPostureDelta = Omit<PostureDelta, 'unchanged'>;

/** How many findings actually moved. Zero is a quiet scan, not a failed one. */
export function postureMovementCount(delta: StoredPostureDelta): number {
  return delta.opened + delta.resolved + delta.reopened + delta.severityChanged;
}

export const EMPTY_DELTA: PostureDelta = {
  opened: 0,
  resolved: 0,
  reopened: 0,
  severityChanged: 0,
  unchanged: 0,
};

/** A finding as already stored, narrowed to what reconciliation needs. */
export type ExistingFinding = {
  id: string;
  code: string;
  status: string;
  severity: string;
};

export type ReconciliationPlan = {
  /** Findings seen for the first time. */
  inserts: { code: string; finding: ShieldFinding }[];
  /** Findings still reported. Rewritten so detail and severity stay current. */
  updates: { id: string; finding: ShieldFinding }[];
  /** Open findings the rules no longer report. */
  resolves: { id: string; code: string }[];
  /**
   * Lifecycle transitions only. An unchanged finding produces nothing here,
   * which is what keeps a steady-state scheduled scan from re-announcing the
   * same problem every six hours.
   */
  events: (
    | { type: 'opened'; findingId: string; severity: string; reopened: boolean }
    | { type: 'resolved'; findingId: string }
    | { type: 'severity_changed'; findingId: string; previousSeverity: string; severity: string }
  )[];
  delta: PostureDelta;
};

/**
 * Works out every write a scan implies, from data already in memory.
 *
 * `inserts` carry no id: the caller mints one, because id generation is not
 * pure. Everything else -- which findings moved, what moved them, and what the
 * posture delta is -- is decided here where it can be tested.
 */
export function planFindingReconciliation(input: {
  existing: readonly ExistingFinding[];
  reported: readonly ShieldFinding[];
  /** Ids for the inserts, in order. Supplied by the caller. */
  newIds: readonly string[];
}): ReconciliationPlan {
  const byCode = new Map<string, ExistingFinding>();
  for (const row of input.existing) byCode.set(row.code, row);

  const reportedCodes = new Set(input.reported.map((finding) => finding.code));
  const plan: ReconciliationPlan = {
    inserts: [],
    updates: [],
    resolves: [],
    events: [],
    delta: { ...EMPTY_DELTA },
  };

  let nextId = 0;
  for (const finding of input.reported) {
    const existing = byCode.get(finding.code);

    if (!existing) {
      const id = input.newIds[nextId] ?? '';
      nextId += 1;
      plan.inserts.push({ code: finding.code, finding });
      plan.events.push({
        type: 'opened',
        findingId: id,
        severity: finding.severity,
        reopened: false,
      });
      plan.delta.opened += 1;
      continue;
    }

    plan.updates.push({ id: existing.id, finding });

    // Reopened is its own movement, not a new finding: the operator has seen
    // this one before, and calling it "new" would misreport the history.
    const reopened = existing.status !== 'open';
    if (reopened) {
      plan.events.push({
        type: 'opened',
        findingId: existing.id,
        severity: finding.severity,
        reopened: true,
      });
      plan.delta.reopened += 1;
    }

    if (existing.severity !== finding.severity) {
      plan.events.push({
        type: 'severity_changed',
        findingId: existing.id,
        previousSeverity: existing.severity,
        severity: finding.severity,
      });
      plan.delta.severityChanged += 1;
    }

    if (!reopened && existing.severity === finding.severity) {
      plan.delta.unchanged += 1;
    }
  }

  for (const row of input.existing) {
    if (row.status !== 'open') continue;
    if (reportedCodes.has(row.code)) continue;
    plan.resolves.push({ id: row.id, code: row.code });
    plan.events.push({ type: 'resolved', findingId: row.id });
    plan.delta.resolved += 1;
  }

  return plan;
}

/** How many `database.batch` round trips a plan's writes require. */
export function batchRoundTrips(statementCount: number, batchSize: number = POSTURE_LIMITS.writeBatchSize): number {
  if (statementCount <= 0) return 0;
  return Math.ceil(statementCount / batchSize);
}

/** Splits statements into fixed-size chunks, so a batch is never unbounded. */
export function chunk<T>(items: readonly T[], size: number = POSTURE_LIMITS.writeBatchSize): T[][] {
  if (size < 1) throw new Error('chunk size must be at least 1');
  const out: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    out.push(items.slice(index, index + size));
  }
  return out;
}

/** A workspace as the scheduler sees it. */
export type SchedulableWorkspace = {
  id: string;
  autoScan: boolean;
  archivedAt: number | null;
  /**
   * When a scheduled scan was last ATTEMPTED -- success or failure alike.
   * Using the attempt rather than the success is what stops a workspace that
   * always fails from being permanently first in the queue and taking every
   * tick: a failed attempt pushes it to the back exactly like a good one.
   */
  lastScheduledAttemptAt: number | null;
};

/** Whether a workspace may be picked up by the scheduler right now. */
export function isEligibleForScheduledScan(
  workspace: SchedulableWorkspace,
  now: number,
  eligibleAfterMs: number = POSTURE_LIMITS.eligibleAfterMs,
): boolean {
  if (!workspace.autoScan) return false;
  if (workspace.archivedAt !== null) return false;
  if (workspace.lastScheduledAttemptAt === null) return true;
  return now - workspace.lastScheduledAttemptAt >= eligibleAfterMs;
}

/**
 * Fair ordering: least-recently-attempted first, never-attempted first of all.
 * Ties break on id so the order is deterministic and a stable subset of
 * workspaces cannot be starved by an unstable sort.
 */
export function orderForScheduling(
  workspaces: readonly SchedulableWorkspace[],
): SchedulableWorkspace[] {
  return [...workspaces].sort((left, right) => {
    const a = left.lastScheduledAttemptAt ?? -1;
    const b = right.lastScheduledAttemptAt ?? -1;
    if (a !== b) return a - b;
    return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
  });
}

/** The bounded set a single tick will attempt. */
export function selectForScheduledScan(
  workspaces: readonly SchedulableWorkspace[],
  now: number,
  cap: number = POSTURE_LIMITS.workspacesPerTick,
  eligibleAfterMs: number = POSTURE_LIMITS.eligibleAfterMs,
): SchedulableWorkspace[] {
  const eligible = workspaces.filter((workspace) =>
    isEligibleForScheduledScan(workspace, now, eligibleAfterMs),
  );
  return orderForScheduling(eligible).slice(0, Math.max(0, cap));
}

/**
 * Which scan ids to delete so a workspace keeps at most `cap` scans.
 * Oldest first, and only ever the excess.
 */
export function planScanHistoryTrim(
  scans: readonly { id: string; createdAt: number }[],
  cap: number = POSTURE_LIMITS.historyPerWorkspace,
): string[] {
  if (scans.length <= cap) return [];
  const ordered = [...scans].sort((left, right) => {
    if (left.createdAt !== right.createdAt) return right.createdAt - left.createdAt;
    return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
  });
  return ordered.slice(cap).map((scan) => scan.id);
}

/** The grades a completed scan can carry. */
export type ScanGrade = 'strong' | 'fair' | 'at-risk';

/**
 * The grade a failed attempt stores. It is not one of the grades on purpose:
 * a row that never finished has no posture, and any real grade written there
 * would be readable as one.
 */
export const UNKNOWN_GRADE = 'unknown';

/** Narrows a stored grade, so a failed attempt can never render as a posture. */
export function displayGrade(grade: string | null | undefined): ScanGrade | null {
  return grade === 'strong' || grade === 'fair' || grade === 'at-risk' ? grade : null;
}

/** How the UI labels where a scan came from. */
export function scanTriggerLabel(trigger: string | null | undefined): string {
  if (trigger === 'scheduled') return 'Automatic';
  if (trigger === 'manual') return 'Manual';
  // Rows written before 0.15.0 carry no provenance. Guessing would be a lie.
  return 'Legacy';
}

/**
 * How long a finding has been open, as a short span (`4h`, `12d`, `3mo`).
 *
 * Separate from `relativeTime` on purpose: "3d ago" answers when a finding
 * appeared, and this answers how long it has been a live problem. Once scans
 * run on their own, the second question is the one an operator triages on.
 */
export function findingAge(firstSeenAt: number, now: number): string {
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;
  const delta = Math.max(0, now - firstSeenAt);
  if (delta < hour) return `${Math.floor(delta / minute)}m`;
  if (delta < day) return `${Math.floor(delta / hour)}h`;
  if (delta < 30 * day) return `${Math.floor(delta / day)}d`;
  return `${Math.floor(delta / (30 * day))}mo`;
}

/**
 * One line describing what a scan moved.
 *
 * A pre-0.15.0 row says so rather than rendering four zeros, because "nothing
 * changed" and "nobody recorded what changed" are different facts and the
 * second one must not be dressed up as the first.
 */
export function describePostureDelta(delta: StoredPostureDelta | null): string {
  if (!delta) return 'Movement was not recorded for this scan.';
  const parts: string[] = [];
  if (delta.opened > 0) parts.push(`${delta.opened} new`);
  if (delta.reopened > 0) parts.push(`${delta.reopened} reopened`);
  if (delta.resolved > 0) parts.push(`${delta.resolved} resolved`);
  if (delta.severityChanged > 0) {
    parts.push(`${delta.severityChanged} severity changed`);
  }
  if (parts.length === 0) return 'No change since the previous scan.';
  return parts.join(' · ');
}

/**
 * The only sentence the product is allowed to say about cadence.
 *
 * It describes eligibility and a queue, never an interval, because
 * `workspacesPerTick` cannot guarantee one: past roughly
 * `eligibleAfterMs / 60000 * workspacesPerTick` workspaces a full sweep takes
 * longer than the eligibility threshold itself. Built from the constants so a
 * change to either cannot leave the copy behind, and pinned by a test so a
 * future edit cannot quietly turn it into a promise.
 */
export function cadenceCopy(
  eligibleAfterMs: number = POSTURE_LIMITS.eligibleAfterMs,
): string {
  const hours = Math.round(eligibleAfterMs / (60 * 60 * 1000));
  return (
    `A workspace becomes eligible about ${hours} hours after its last automatic`
    + ' attempt, then is scanned when the queue reaches it. There is no'
    + ' guaranteed interval.'
  );
}

/**
 * The full-sweep floor, for documentation and for the test that keeps the UI
 * wording honest. Returns minutes.
 */
export function fullSweepMinutes(
  workspaceCount: number,
  cap: number = POSTURE_LIMITS.workspacesPerTick,
): number {
  if (workspaceCount <= 0 || cap <= 0) return 0;
  return Math.ceil(workspaceCount / cap);
}

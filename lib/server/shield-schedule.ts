import { POSTURE_LIMITS } from '@/lib/shield-posture';
import { recordEvidence } from './audit';
import { query } from './db';
import { runScan } from './shield-scan';

/**
 * The Shield sweep: the part of the one-minute tick that scans workspaces
 * nobody has scanned by hand.
 *
 * `workspace.autoScan` has been stored, defaulted on, and shown in Settings
 * since Phase 10, and until now no code path read it. Shield only ever ran
 * when someone pressed the button, so a workspace whose owner stopped logging
 * in had a posture frozen at whatever it was the last time they looked.
 *
 * Three properties hold this together, and each of them is a release gate
 * rather than a nice-to-have:
 *
 *   BOUNDED     One SQL statement with a `LIMIT` picks the workspaces. There is
 *               no read-everything-then-slice step, so the tick costs the same
 *               with four workspaces as with forty thousand.
 *
 *   FAIR        Ordering is by the last scheduled ATTEMPT, oldest first, ties
 *               broken on id. Attempt, not success: a workspace that fails
 *               every time is pushed to the back exactly like one that
 *               succeeds, so it cannot sit at the front of the queue and
 *               consume every tick for ever. `runScan` guarantees the attempt
 *               is recorded even when the scan throws.
 *
 *   ISOLATED    Each workspace runs in its own try/catch, and the whole sweep
 *               runs after the workflow engine in `worker.ts` where its own
 *               failure is caught. One broken workspace cannot stop the others
 *               and cannot stop workflow execution.
 *
 * What this deliberately is NOT: a guarantee. `POSTURE_LIMITS.eligibleAfterMs`
 * is when a workspace becomes a candidate, not when it is promised a scan. At
 * `workspacesPerTick` the floor for a full sweep is `ceil(workspaces / 2)`
 * minutes, which passes six hours at about 720 workspaces. Above that the
 * system scans less often; it never does more work per tick. No wording in the
 * product may promise a cadence this cannot hold.
 */

export type ShieldSweepResult = {
  /** Workspaces the selector returned this tick. Never above the cap. */
  selected: number;
  /** Scans that completed and recorded a posture. */
  scanned: number;
  /** Attempts that threw. Each still recorded a `failed` scan row. */
  failed: number;
  /** Findings opened for the first time, summed across this tick. */
  opened: number;
  /** Findings the rules no longer report, summed across this tick. */
  resolved: number;
  /** Findings that had been resolved and came back. */
  reopened: number;
  /** Findings whose severity moved. */
  severityChanged: number;
};

const EMPTY_SWEEP: ShieldSweepResult = {
  selected: 0,
  scanned: 0,
  failed: 0,
  opened: 0,
  resolved: 0,
  reopened: 0,
  severityChanged: 0,
};

type DueWorkspace = {
  id: string;
  organizationId: string;
  ownerUserId: string;
  lastAttemptAt: number;
};

/**
 * The workspaces this tick will attempt.
 *
 * One statement, capped by `LIMIT`. `MAX(s.createdAt)` over scheduled scans is
 * the last attempt: the join deliberately does not filter on `scanStatus`,
 * because a failed attempt has to count as an attempt or the fairness property
 * above collapses. A workspace that has never been swept has no matching rows,
 * `COALESCE` gives it 0, and it sorts to the front — which is what should
 * happen the first time this ships.
 *
 * `organizationId IS NOT NULL` matches the retention sweep: a workspace with
 * no organization predates Phase 10 and has nowhere to file evidence.
 */
export async function selectWorkspacesForSweep(
  now = Date.now(),
  cap: number = POSTURE_LIMITS.workspacesPerTick,
  eligibleAfterMs: number = POSTURE_LIMITS.eligibleAfterMs,
): Promise<DueWorkspace[]> {
  if (cap <= 0) return [];
  const cutoff = now - eligibleAfterMs;

  return query<DueWorkspace>(
    `SELECT w.id AS id,
            w.organizationId AS organizationId,
            w.ownerUserId AS ownerUserId,
            COALESCE(
              (SELECT MAX(s.createdAt) FROM shield_scan s
                WHERE s.workspaceId = w.id AND s.scanTrigger = 'scheduled'),
              0
            ) AS lastAttemptAt
       FROM workspace w
      WHERE w.autoScan = 1
        AND w.archivedAt IS NULL
        AND w.organizationId IS NOT NULL
        AND COALESCE(
              (SELECT MAX(s2.createdAt) FROM shield_scan s2
                WHERE s2.workspaceId = w.id AND s2.scanTrigger = 'scheduled'),
              0
            ) <= ?
      ORDER BY lastAttemptAt ASC, w.id ASC
      LIMIT ?`,
    cutoff,
    cap,
  );
}

/**
 * Runs the sweep for one tick.
 *
 * The scan runs as the workspace's own owner. That is not an elevation: the
 * manual path already collects its snapshot at owner privilege regardless of
 * who pressed the button, so this only names the right principal instead of
 * borrowing the identity of whoever happened to be signed in. Nothing here
 * crosses a workspace boundary — every query inside `runScan` is scoped to the
 * one workspace it was handed.
 */
export async function runShieldPostureSweep(
  now = Date.now(),
): Promise<ShieldSweepResult> {
  const result: ShieldSweepResult = { ...EMPTY_SWEEP };

  const due = await selectWorkspacesForSweep(now);
  result.selected = due.length;

  for (const workspace of due) {
    try {
      const outcome = await runScan(
        workspace.id,
        workspace.ownerUserId,
        'system:shield-scheduler',
        'scheduled',
      );

      const delta = outcome.scan.delta;
      result.scanned += 1;
      result.opened += delta?.opened ?? 0;
      result.resolved += delta?.resolved ?? 0;
      result.reopened += delta?.reopened ?? 0;
      result.severityChanged += delta?.severityChanged ?? 0;

      await recordEvidence({
        action: 'shield.scan.scheduled',
        organizationId: workspace.organizationId,
        workspaceId: workspace.id,
        actorType: 'system',
        actorId: 'system:shield-scheduler',
        resourceId: outcome.scan.id,
        outcome: 'success',
        metadata: {
          score: outcome.scan.score,
          grade: outcome.scan.grade,
          findingCount: outcome.scan.findingCount,
          opened: delta?.opened ?? 0,
          resolved: delta?.resolved ?? 0,
          reopened: delta?.reopened ?? 0,
          severityChanged: delta?.severityChanged ?? 0,
          durationMs: outcome.scan.durationMs,
        },
      });
    } catch {
      // Isolated on purpose: the next workspace still runs. `runScan` has
      // already written the `failed` row that keeps the queue fair, and the
      // cause is not recorded here for the same reason it is not recorded
      // there -- an error message can carry SQL, a resource name, or a path.
      result.failed += 1;
      try {
        await recordEvidence({
          action: 'shield.scan.scheduled',
          organizationId: workspace.organizationId,
          workspaceId: workspace.id,
          actorType: 'system',
          actorId: 'system:shield-scheduler',
          outcome: 'failed',
        });
      } catch {
        // Non-critical evidence. Losing it must not abort the sweep.
      }
    }
  }

  return result;
}

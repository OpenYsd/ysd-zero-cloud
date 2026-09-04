import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { EVIDENCE_ACTIONS, narrowEvidenceMetadata } from '../lib/audit-actions.ts';
import {
  EMPTY_DELTA,
  POSTURE_LIMITS,
  batchRoundTrips,
  cadenceCopy,
  chunk,
  describePostureDelta,
  displayGrade,
  findingAge,
  fullSweepMinutes,
  isEligibleForScheduledScan,
  orderForScheduling,
  planFindingReconciliation,
  planScanHistoryTrim,
  postureMovementCount,
  scanTriggerLabel,
  selectForScheduledScan,
  type ExistingFinding,
  type SchedulableWorkspace,
} from '../lib/shield-posture.ts';
import type { ShieldFinding } from '../lib/shield.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

/**
 * Source with comments removed.
 *
 * Phase 14 learned this the hard way: a prose assertion kept passing because
 * the sentence it was looking for lived in a comment explaining why the code
 * did NOT do that thing.
 */
function code(path: string): string {
  return source(path)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/(^|\s)\/\/.*$/, '$1'))
    .join('\n');
}

function finding(code: string, severity: ShieldFinding['severity'] = 'high'): ShieldFinding {
  return {
    code,
    title: `Title ${code}`,
    detail: `Detail ${code}`,
    resource: `resource/${code}`,
    severity,
    remediation: `Fix ${code}`,
  };
}

function stored(
  id: string,
  code: string,
  status: 'open' | 'resolved' = 'open',
  severity = 'high',
): ExistingFinding {
  return { id, code, status, severity };
}

function ids(count: number): string[] {
  return Array.from({ length: count }, (_, index) => `fnd_new_${index}`);
}

// ---------------------------------------------------------------------------
// Reconciliation: what a scan decides, before any database is involved.
// ---------------------------------------------------------------------------

void test('a finding nobody has seen before is inserted and announced once', () => {
  const plan = planFindingReconciliation({
    existing: [],
    reported: [finding('secret-overdue:api:prod')],
    newIds: ids(1),
  });

  assert.equal(plan.inserts.length, 1);
  assert.equal(plan.updates.length, 0);
  assert.equal(plan.resolves.length, 0);
  assert.deepEqual(plan.events, [
    { type: 'opened', findingId: 'fnd_new_0', severity: 'high', reopened: false },
  ]);
  assert.equal(plan.delta.opened, 1);
  assert.equal(plan.delta.reopened, 0);
});

void test('a finding that is still true is refreshed and says nothing', () => {
  const plan = planFindingReconciliation({
    existing: [stored('fnd_1', 'table-no-primary-key:log_event')],
    reported: [finding('table-no-primary-key:log_event')],
    newIds: [],
  });

  assert.equal(plan.inserts.length, 0);
  assert.equal(plan.updates.length, 1);
  assert.equal(plan.updates[0]!.id, 'fnd_1');
  // The whole point. A scan that runs on a timer must not re-announce a
  // problem the operator already knows about, or the evidence trail becomes
  // noise and people stop reading it.
  assert.deepEqual(plan.events, []);
  assert.deepEqual(plan.delta, { ...EMPTY_DELTA, unchanged: 1 });
});

void test('a finding that comes back is reopened, never counted as new', () => {
  const plan = planFindingReconciliation({
    existing: [stored('fnd_1', 'public-project:p1', 'resolved')],
    reported: [finding('public-project:p1')],
    newIds: ids(1),
  });

  assert.equal(plan.inserts.length, 0, 'a returning finding must not create a second row');
  assert.equal(plan.updates.length, 1);
  assert.deepEqual(plan.events, [
    { type: 'opened', findingId: 'fnd_1', severity: 'high', reopened: true },
  ]);
  // Reopened is its own number. Folding it into `opened` would tell an
  // operator they have a new problem when what they have is a regression.
  assert.equal(plan.delta.opened, 0);
  assert.equal(plan.delta.reopened, 1);
  assert.equal(plan.delta.unchanged, 0);
});

void test('a severity change is recorded with both the old and the new level', () => {
  const plan = planFindingReconciliation({
    existing: [stored('fnd_1', 'weak-policy', 'open', 'medium')],
    reported: [finding('weak-policy', 'critical')],
    newIds: [],
  });

  assert.deepEqual(plan.events, [
    {
      type: 'severity_changed',
      findingId: 'fnd_1',
      previousSeverity: 'medium',
      severity: 'critical',
    },
  ]);
  assert.equal(plan.delta.severityChanged, 1);
  assert.equal(plan.delta.unchanged, 0);
});

void test('a finding the rules stopped reporting is resolved and kept', () => {
  const plan = planFindingReconciliation({
    existing: [stored('fnd_1', 'gone')],
    reported: [],
    newIds: [],
  });

  assert.deepEqual(plan.resolves, [{ id: 'fnd_1', code: 'gone' }]);
  assert.deepEqual(plan.events, [{ type: 'resolved', findingId: 'fnd_1' }]);
  assert.equal(plan.delta.resolved, 1);
});

void test('an already-resolved finding is not resolved a second time', () => {
  const plan = planFindingReconciliation({
    existing: [stored('fnd_1', 'gone', 'resolved')],
    reported: [],
    newIds: [],
  });

  assert.deepEqual(plan.resolves, []);
  assert.deepEqual(plan.events, []);
  assert.deepEqual(plan.delta, EMPTY_DELTA);
});

void test('a finding can reopen and change severity in the same scan', () => {
  const plan = planFindingReconciliation({
    existing: [stored('fnd_1', 'both', 'resolved', 'low')],
    reported: [finding('both', 'critical')],
    newIds: [],
  });

  assert.equal(plan.events.length, 2);
  assert.equal(plan.delta.reopened, 1);
  assert.equal(plan.delta.severityChanged, 1);
  // Which is exactly why `unchanged` is not persisted: these two counters
  // describe one finding, so the four stored numbers cannot be subtracted from
  // findingCount to recover it.
  assert.equal(plan.delta.unchanged, 0);
});

void test('an unchanged workspace scanned repeatedly produces no events at all', () => {
  const existing = [
    stored('fnd_1', 'a'),
    stored('fnd_2', 'b', 'open', 'low'),
    stored('fnd_3', 'c', 'resolved'),
  ];
  const reported = [finding('a'), finding('b', 'low')];

  for (let tick = 0; tick < 20; tick += 1) {
    const plan = planFindingReconciliation({ existing, reported, newIds: [] });
    assert.deepEqual(plan.events, [], `tick ${tick} emitted an event`);
    assert.equal(plan.inserts.length, 0);
    assert.equal(plan.resolves.length, 0);
    assert.equal(postureMovementCount(plan.delta), 0);
  }
});

void test('reconciliation is decided per code, so two workspaces cannot collide', () => {
  // Codes are templated per resource, so the same rule produces different
  // codes for different resources. Planning keys on the code alone because the
  // caller has already narrowed `existing` to one workspace -- which is the
  // property the source assertion below pins.
  const plan = planFindingReconciliation({
    existing: [stored('fnd_1', 'table-no-primary-key:alpha')],
    reported: [finding('table-no-primary-key:alpha'), finding('table-no-primary-key:beta')],
    newIds: ids(1),
  });
  assert.equal(plan.updates.length, 1);
  assert.equal(plan.inserts.length, 1);
  assert.equal(plan.inserts[0]!.code, 'table-no-primary-key:beta');
});

// ---------------------------------------------------------------------------
// Cost. Discovery measured the old shape; this pins the new one.
// ---------------------------------------------------------------------------

void test('write batching is capped and never returns an oversized group', () => {
  assert.throws(() => chunk([1, 2, 3], 0), /at least 1/);
  assert.deepEqual(chunk([], 25), []);

  for (const size of [1, 7, 25, 26, 100, 501]) {
    const groups = chunk(Array.from({ length: size }, (_, i) => i));
    assert.equal(groups.flat().length, size, 'chunking must not drop or duplicate work');
    for (const group of groups) {
      assert.ok(
        group.length <= POSTURE_LIMITS.writeBatchSize,
        `a batch of ${group.length} exceeds the cap`,
      );
      assert.ok(group.length > 0);
    }
  }
});

void test('round trips grow by the batch ceiling, not by the finding count', () => {
  assert.equal(batchRoundTrips(0), 0);
  assert.equal(batchRoundTrips(1), 1);
  assert.equal(batchRoundTrips(25), 1);
  assert.equal(batchRoundTrips(26), 2);
  assert.equal(batchRoundTrips(100), 4);
  assert.equal(batchRoundTrips(500), 20);

  // The comparison that justified the change. `writes` is inserts + updates +
  // resolves; the old code did one SELECT and one write per reported finding,
  // sequentially, plus one write per resolution.
  const matrix = [
    { reported: 1, resolved: 0 },
    { reported: 10, resolved: 2 },
    { reported: 67, resolved: 5 },
    { reported: 250, resolved: 40 },
  ];
  for (const row of matrix) {
    const before = 2 * row.reported + row.resolved;
    const after = 1 + batchRoundTrips(row.reported + row.resolved);
    assert.ok(
      after <= before,
      `${row.reported} findings: ${after} round trips is worse than ${before}`,
    );
    // A single finding is a tie (2 either way) and is stated as one rather
    // than dressed up: the change is about how the cost GROWS, and it starts
    // paying from the second finding onwards.
    if (row.reported > 1) {
      assert.ok(
        after < before,
        `${row.reported} findings: ${after} round trips is not fewer than ${before}`,
      );
    }
  }
  assert.equal(1 + batchRoundTrips(1), 2);
  assert.equal(2 * 1 + 0, 2);

  // At the largest case above the improvement is an order of magnitude, and it
  // is the growth rate that matters: `after` is bounded by the batch ceiling.
  assert.equal(2 * 250 + 40, 540);
  assert.equal(1 + batchRoundTrips(290), 13);
});

// ---------------------------------------------------------------------------
// Scheduling policy.
// ---------------------------------------------------------------------------

function workspace(
  id: string,
  overrides: Partial<SchedulableWorkspace> = {},
): SchedulableWorkspace {
  return { id, autoScan: true, archivedAt: null, lastScheduledAttemptAt: null, ...overrides };
}

void test('automatic scanning is off unless the workspace asked for it', () => {
  const now = 100 * DAY;
  assert.equal(isEligibleForScheduledScan(workspace('a', { autoScan: false }), now), false);
  assert.equal(isEligibleForScheduledScan(workspace('b', { archivedAt: now - DAY }), now), false);
  assert.equal(isEligibleForScheduledScan(workspace('c'), now), true);
});

void test('eligibility is a threshold on the last attempt, and only that', () => {
  const now = 100 * DAY;
  const justBefore = workspace('a', {
    lastScheduledAttemptAt: now - POSTURE_LIMITS.eligibleAfterMs + 1,
  });
  const exactly = workspace('b', {
    lastScheduledAttemptAt: now - POSTURE_LIMITS.eligibleAfterMs,
  });

  assert.equal(isEligibleForScheduledScan(justBefore, now), false);
  assert.equal(isEligibleForScheduledScan(exactly, now), true);
});

void test('the queue is least-recently-attempted first with a deterministic tiebreak', () => {
  const now = 100 * DAY;
  const ordered = orderForScheduling([
    workspace('zulu', { lastScheduledAttemptAt: now - 10 * HOUR }),
    workspace('alpha', { lastScheduledAttemptAt: now - 10 * HOUR }),
    workspace('never'),
    workspace('older', { lastScheduledAttemptAt: now - 40 * HOUR }),
  ]);

  assert.deepEqual(
    ordered.map((entry) => entry.id),
    ['never', 'older', 'alpha', 'zulu'],
  );
});

void test('a tick never attempts more workspaces than the cap', () => {
  const now = 100 * DAY;
  const many = Array.from({ length: 500 }, (_, index) =>
    workspace(`ws_${String(index).padStart(4, '0')}`),
  );
  const selected = selectForScheduledScan(many, now);
  assert.equal(selected.length, POSTURE_LIMITS.workspacesPerTick);
  assert.equal(selectForScheduledScan(many, now, 0).length, 0);
});

void test('a workspace that always fails cannot starve the others', () => {
  // The release gate. `lastScheduledAttemptAt` records the ATTEMPT, so a
  // workspace whose scan throws every single time is pushed to the back of the
  // queue exactly like one that succeeds. Simulated over a day of ticks: if
  // failure did not update the timestamp, `broken` would be selected on every
  // tick and nothing else would ever run.
  let now = 100 * DAY;
  const pool: SchedulableWorkspace[] = [
    workspace('broken'),
    workspace('good_a'),
    workspace('good_b'),
    workspace('good_c'),
    workspace('good_d'),
  ];
  const attempts = new Map<string, number>(pool.map((entry) => [entry.id, 0]));

  for (let tick = 0; tick < 60 * 24; tick += 1) {
    for (const picked of selectForScheduledScan(pool, now)) {
      attempts.set(picked.id, (attempts.get(picked.id) ?? 0) + 1);
      // `broken` throws; the attempt is still recorded, which is what
      // `runScan`'s failure path guarantees by writing a `failed` scan row.
      picked.lastScheduledAttemptAt = now;
    }
    now += 60_000;
  }

  for (const entry of pool) {
    assert.ok(
      (attempts.get(entry.id) ?? 0) >= 3,
      `${entry.id} was attempted ${attempts.get(entry.id)} times in a day`,
    );
  }
  const counts = [...attempts.values()];
  assert.ok(
    Math.max(...counts) - Math.min(...counts) <= 1,
    `attempts were not evenly shared: ${JSON.stringify([...attempts])}`,
  );
});

void test('the advertised sweep floor is the arithmetic, not a wish', () => {
  assert.equal(POSTURE_LIMITS.workspacesPerTick, 2);
  assert.equal(fullSweepMinutes(100), 50);
  assert.equal(fullSweepMinutes(1_000), 500);
  assert.equal(fullSweepMinutes(10_000), 5_000);

  // The number that makes the cadence wording a lie if it is ever phrased as a
  // promise: past this many workspaces a full sweep takes longer than the
  // eligibility threshold itself.
  const thresholdMinutes = POSTURE_LIMITS.eligibleAfterMs / 60_000;
  const breakEven = thresholdMinutes * POSTURE_LIMITS.workspacesPerTick;
  assert.equal(breakEven, 720);
  assert.ok(fullSweepMinutes(breakEven) <= thresholdMinutes);
  assert.ok(fullSweepMinutes(breakEven + 2) > thresholdMinutes);
});

// ---------------------------------------------------------------------------
// History is bounded, and bounded is not the same as deleted.
// ---------------------------------------------------------------------------

void test('scan history is trimmed oldest first and only above the cap', () => {
  const scans = Array.from({ length: POSTURE_LIMITS.historyPerWorkspace }, (_, index) => ({
    id: `scan_${index}`,
    createdAt: index,
  }));
  assert.deepEqual(planScanHistoryTrim(scans), []);

  const overflowing = [...scans, { id: 'scan_new', createdAt: 9_999 }];
  assert.deepEqual(planScanHistoryTrim(overflowing), ['scan_0']);

  // A scan written this instant is always one of the survivors, never one of
  // the rows counted out -- `runScan` trims after its own insert.
  const trimmed = planScanHistoryTrim(overflowing);
  assert.ok(!trimmed.includes('scan_new'));
});

void test('the trim is deterministic when two scans share a timestamp', () => {
  const scans = [
    { id: 'b', createdAt: 5 },
    { id: 'a', createdAt: 5 },
    { id: 'c', createdAt: 9 },
  ];
  assert.deepEqual(planScanHistoryTrim(scans, 2), ['b']);
  assert.deepEqual(planScanHistoryTrim(scans, 2), ['b'], 'the same input must trim the same row');
});

void test('trimming touches shield_scan and nothing else', () => {
  const scan = code('lib/server/shield-scan.ts');
  const trim = scan.slice(scan.indexOf('async function trimScanHistory'));
  const body = trim.slice(0, trim.indexOf('\n}\n') + 3);

  assert.match(body, /DELETE FROM shield_scan WHERE id = \? AND workspaceId = \?/);
  // Bounded history is a cap on one table, not a retention mechanism. Findings
  // carry the age of a problem, and evidence is append-only by trigger.
  for (const table of [
    'shield_finding', 'audit_event', 'audit_sequence', 'workflow_event',
    'workflow_incident', 'retention_run', 'log_event', 'secret',
  ]) {
    assert.doesNotMatch(body, new RegExp(`DELETE FROM ${table}`));
  }
});

// ---------------------------------------------------------------------------
// The database side: every write is scoped, and none of them is per-finding.
// ---------------------------------------------------------------------------

void test('the N+1 that discovery measured is gone', () => {
  const scan = code('lib/server/shield-scan.ts');
  const start = scan.indexOf('async function reconcileFindings');
  const end = scan.indexOf('async function trimScanHistory');
  assert.ok(start > 0 && end > start);
  const region = scan.slice(start, end);

  // One read of this workspace's findings, and no SELECT inside a loop.
  assert.equal(
    (region.match(/SELECT id, code, status, severity FROM shield_finding WHERE workspaceId = \?/g) ?? []).length,
    1,
  );
  assert.doesNotMatch(region, /FROM shield_finding WHERE workspaceId = \? AND code = \?/);
  assert.match(region, /database\.batch\(/);
  assert.match(region, /chunk\(statements, POSTURE_LIMITS\.writeBatchSize\)/);

  // `queryOne` inside reconciliation was the per-finding read. It must not
  // reappear there, whatever else the file uses it for.
  assert.doesNotMatch(region, /\bqueryOne\b/);
});

void test('every reconciliation write names the workspace as well as the row', () => {
  const scan = code('lib/server/shield-scan.ts');
  const start = scan.indexOf('async function applyReconciliationPlan');
  const region = scan.slice(start, scan.indexOf('async function emitReconciliationEvents'));

  // Read the SQL constants whole. Matching up to the next quote would stop
  // inside `status = 'open'` and silently check half a statement.
  const updates = region.match(/UPDATE shield_finding[\s\S]*?;/g) ?? [];
  assert.ok(updates.length >= 2, 'expected the refresh and the resolve statements');
  for (const statement of updates) {
    assert.match(
      statement,
      /WHERE id = \? AND workspaceId = \?/,
      `a write without a workspace predicate: ${statement}`,
    );
  }
  assert.match(region, /INSERT INTO shield_finding/);
  assert.match(region, /\(id, workspaceId, code/);
});

void test('a scan that dies halfway cannot leave a completed row behind', () => {
  const scan = code('lib/server/shield-scan.ts');
  const start = scan.indexOf('export async function runScan');
  const region = scan.slice(start, scan.indexOf('export type ShieldState'));

  const reconcileAt = region.indexOf('await reconcileFindings(');
  const insertAt = region.indexOf('INSERT_SCAN_SQL,');
  assert.ok(reconcileAt > 0 && insertAt > reconcileAt, 'findings must be reconciled first');

  // The failure path records the attempt and rethrows; it never writes a
  // completed row.
  assert.match(region, /catch \(error\) \{\s*await recordFailedAttempt\([\s\S]*?throw error;/);
  assert.match(region, /'completed' satisfies ScanStatus/);
  // The `failed` sentinel belongs to `recordFailedAttempt`, which is the only
  // place allowed to write one.
  const failurePath = scan.slice(
    scan.indexOf('async function recordFailedAttempt'),
    scan.indexOf('export async function runScan'),
  );
  assert.match(failurePath, /'failed' satisfies ScanStatus/);
  assert.equal((scan.match(/'failed' satisfies ScanStatus/g) ?? []).length, 1);
});

void test('a failed attempt stores nothing a reader could mistake for a result', () => {
  const scan = source('lib/server/shield-scan.ts');
  assert.match(scan, /const FAILED_SCAN = \{\s*score: -1,/);
  assert.match(scan, /grade: 'unknown'/);

  // Scores are 0..100 and grades are three words. Neither placeholder is a
  // member of its own domain, so a stray reader gets something obviously wrong
  // rather than a plausible zero.
  assert.equal(displayGrade('unknown'), null);
  assert.equal(displayGrade('strong'), 'strong');
  assert.equal(displayGrade(null), null);

  // And the posture read filters failures out regardless.
  assert.match(scan, /scanStatus IS NULL OR scanStatus <> 'failed'/);
});

void test('the scan failure path records no cause', () => {
  const scan = code('lib/server/shield-scan.ts');
  const start = scan.indexOf('async function recordFailedAttempt');
  const region = scan.slice(start, scan.indexOf('export async function runScan'));

  // An error message can carry SQL, a resource name, or a filesystem path, and
  // the log surface is readable in-app.
  assert.doesNotMatch(region, /error\.message/);
  assert.doesNotMatch(region, /String\(error\)/);
  assert.doesNotMatch(region, /\bcause\b/);
  assert.match(region, /message: 'Scan did not complete\./);
});

// ---------------------------------------------------------------------------
// The scheduler: bounded, tenant-scoped, and not a request handler.
// ---------------------------------------------------------------------------

void test('workspace selection is one bounded statement, not a filtered fetch-all', () => {
  const scheduler = code('lib/server/shield-schedule.ts');
  assert.match(scheduler, /LIMIT \?/);
  assert.match(scheduler, /ORDER BY lastAttemptAt ASC, w\.id ASC/);
  assert.match(scheduler, /WHERE w\.autoScan = 1/);
  assert.match(scheduler, /AND w\.archivedAt IS NULL/);

  // A read-everything-then-slice would make the tick cost grow with the
  // platform. There is no `.slice(` and no unbounded workspace read.
  assert.doesNotMatch(scheduler, /\.slice\(/);
  assert.doesNotMatch(scheduler, /FROM workspace w\s*(?!.*LIMIT)[^`]*`\s*\)/);

  // The attempt, not the success: filtering the join on scanStatus would let a
  // permanently failing workspace look permanently overdue.
  assert.doesNotMatch(scheduler, /scanStatus/);
  assert.match(scheduler, /s\.scanTrigger = 'scheduled'/);
});

void test('the sweep isolates each workspace and cannot cross a tenant boundary', () => {
  const scheduler = code('lib/server/shield-schedule.ts');

  // One try/catch per workspace inside the loop, so a broken workspace does
  // not end the tick for the rest.
  const loopAt = scheduler.indexOf('for (const workspace of due)');
  assert.ok(loopAt > 0);
  assert.match(scheduler.slice(loopAt), /try \{/);

  // Nothing here queries by anything but a workspace the selector returned.
  assert.match(scheduler, /runScan\(\s*workspace\.id,\s*workspace\.ownerUserId,/);
  assert.doesNotMatch(scheduler, /workspaceId IN/);
  assert.doesNotMatch(scheduler, /FROM shield_finding/);

  // No request surface at all, so nothing user-supplied can reach the sweep.
  assert.doesNotMatch(scheduler, /request/i);
  assert.doesNotMatch(scheduler, /session/i);
  assert.doesNotMatch(scheduler, /token/i);
  assert.doesNotMatch(scheduler, /cookie/i);
});

void test('the sweep is the third cron phase and swallows its own failure', () => {
  const worker = code('worker.ts');
  const workflowAt = worker.indexOf('runWorkflowEngineTick(');
  const lifecycleAt = worker.indexOf('runDataLifecycleMaintenance(');
  const sweepAt = worker.indexOf('runShieldPostureSweep(');

  assert.ok(workflowAt > 0 && lifecycleAt > workflowAt && sweepAt > lifecycleAt);
  // The workflow engine still rethrows; the two maintenance phases do not.
  assert.match(worker.slice(sweepAt), /catch \{/);
  assert.doesNotMatch(worker.slice(sweepAt), /throw error/);

  // Still one trigger. Zero Mode forbids a second.
  const wrangler = source('wrangler.jsonc');
  assert.equal((wrangler.match(/"\* \* \* \* \*"/g) ?? []).length, 1);
});

// ---------------------------------------------------------------------------
// Evidence.
// ---------------------------------------------------------------------------

void test('an automatic scan is evidence, and carries nothing sensitive', () => {
  const entry = EVIDENCE_ACTIONS.find((row) => row.action === 'shield.scan.scheduled');
  assert.ok(entry, 'the scheduled scan must be a catalogued evidence action');
  assert.equal(entry.resourceType, 'shield_scan');
  assert.equal(entry.route, 'lib/server/shield-schedule.ts');
  assert.deepEqual(
    [...entry.metadataKeys].sort(),
    ['durationMs', 'findingCount', 'grade', 'opened', 'reopened', 'resolved', 'score', 'severityChanged'],
  );

  for (const forbidden of [
    'token', 'secret', 'password', 'header', 'ip', 'email', 'sql', 'command',
    'env', 'rule', 'output', 'detail', 'resource',
  ]) {
    assert.ok(
      !entry.metadataKeys.some((key) => key.toLowerCase().includes(forbidden)),
      `shield.scan.scheduled must not carry a "${forbidden}"-shaped key`,
    );
  }

  // Anything not declared is dropped rather than truncated, so a future caller
  // cannot smuggle a finding's text through by adding a field.
  const narrowed = narrowEvidenceMetadata('shield.scan.scheduled', {
    score: 72,
    detail: 'secret ACME_KEY is 400 days old',
    resource: 'secret/ACME_KEY',
    ipAddress: '203.0.113.4',
  });
  assert.deepEqual(narrowed, { score: 72 });
});

void test('a failed sweep is recorded as an outcome, not as a second action', () => {
  const scheduler = code('lib/server/shield-schedule.ts');
  assert.equal((scheduler.match(/action: 'shield\.scan\.scheduled'/g) ?? []).length, 2);
  assert.match(scheduler, /outcome: 'success'/);
  assert.match(scheduler, /outcome: 'failed'/);
  // Two actions could drift apart; one action with two outcomes cannot.
  assert.equal(
    EVIDENCE_ACTIONS.filter((row) => row.action.startsWith('shield.scan.')).length,
    1,
  );
});

// ---------------------------------------------------------------------------
// Migration 0019.
// ---------------------------------------------------------------------------

void test('0019 is additive and does nothing else', () => {
  const sql = source('db/migrations/0019_shield_posture.sql');
  const statements = splitStatements(stripSqlComments(sql));

  assert.equal(statements.length, 6);
  for (const statement of statements) {
    assert.match(statement, /^ALTER TABLE shield_scan ADD COLUMN /);
  }
  const body = stripSqlComments(sql);
  for (const forbidden of [
    /DROP\s/i, /DELETE\s/i, /\bUPDATE\s/i, /CREATE TABLE/i, /CREATE INDEX/i,
    /CREATE TRIGGER/i, /NOT NULL/i, /DEFAULT/i,
  ]) {
    assert.doesNotMatch(body, forbidden);
  }

  // `trigger` is a SQL keyword; the column is deliberately not called that.
  assert.match(body, /ADD COLUMN scanTrigger TEXT/);
  assert.doesNotMatch(body, /ADD COLUMN trigger\b/);
});

void test('the lazy runner and the wrangler ledger both know about 0019', () => {
  const db = source('lib/server/db.ts');
  assert.match(db, /0019_shield_posture\.sql\?raw/);
  assert.match(db, /\{ name: '0019_shield_posture', sql: shieldPostureSchema \}/);
});

void test('0019 applies cleanly, replays safely, and keeps the old insert working', () => {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = OFF');
  database.exec(stripSqlComments(source('db/migrations/0002_workspace.sql')));

  // The previous Worker's insert: nine columns, no provenance.
  const legacyInsert = `INSERT INTO shield_scan
      (id, workspaceId, score, grade, headline, checks, findingCount, durationMs, createdAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
  database.prepare(legacyInsert).run('scan_before', 'ws_1', 80, 'fair', 'h', '[]', 1, 5, 1);

  for (const statement of splitStatements(stripSqlComments(source('db/migrations/0019_shield_posture.sql')))) {
    database.exec(statement);
  }

  // A pre-0019 row survives with NULLs, which is a real state the UI names
  // rather than a gap it fills in.
  const before = database
    .prepare('SELECT scanTrigger, scanStatus, newFindings FROM shield_scan WHERE id = ?')
    .get('scan_before') as Record<string, unknown>;
  assert.equal(before.scanTrigger, null);
  assert.equal(before.scanStatus, null);
  assert.equal(before.newFindings, null);
  assert.equal(scanTriggerLabel(before.scanTrigger as null), 'Legacy');

  // The old Worker keeps writing while the new columns exist. This is what
  // makes it safe to apply the migration before the new code ships.
  database.prepare(legacyInsert).run('scan_during', 'ws_1', 81, 'fair', 'h', '[]', 1, 5, 2);

  // A replay hits "duplicate column name", which the lazy runner treats as
  // already-applied rather than as a failure.
  let replayError: unknown;
  try {
    database.exec('ALTER TABLE shield_scan ADD COLUMN scanTrigger TEXT');
  } catch (error) {
    replayError = error;
  }
  assert.match(
    replayError instanceof Error ? replayError.message : String(replayError),
    /duplicate column name/i,
  );
  assert.match(source('lib/server/db.ts'), /already exists\|duplicate column name/);
});

void test('the sweep selector picks the right rows against a real database', () => {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = OFF');
  // 0010 adds organizationId and archivedAt and reaches for user_role, so the
  // sweep predicates cannot be exercised without the migrations that build it.
  for (const name of [
    '0001_auth.sql', '0002_workspace.sql', '0003_auth_rate_limit.sql',
    '0004_security.sql', '0010_organizations.sql', '0019_shield_posture.sql',
  ]) {
    for (const statement of splitStatements(stripSqlComments(source(`db/migrations/${name}`)))) {
      database.exec(statement);
    }
  }

  // 0010 guards the denormalized keys with triggers, so the organization has
  // to exist before a workspace can name it. That guard is the reason the
  // sweep can trust w.organizationId as the tenant.
  database.exec(`
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt)
      VALUES ('owner_1','Owner','owner@test.invalid',1,NULL,1,1);
    INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt)
      VALUES ('org_1','One','one','owner_1','active',1,1,1);
  `);
  const now = 100 * DAY;
  const insertWorkspace = database.prepare(
    `INSERT INTO workspace
       (id, organizationId, name, ownerUserId, zeroMode, autoScan, sleepIdleServers,
        previewDeployments, createdAt, updatedAt, archivedAt)
     VALUES (?, ?, ?, ?, 1, ?, 1, 0, 1, 1, ?)`,
  );
  insertWorkspace.run('ws_never', 'org_1', 'Never', 'owner_1', 1, null);
  insertWorkspace.run('ws_old', 'org_1', 'Old', 'owner_1', 1, null);
  insertWorkspace.run('ws_recent', 'org_1', 'Recent', 'owner_1', 1, null);
  insertWorkspace.run('ws_off', 'org_1', 'Off', 'owner_1', 0, null);
  insertWorkspace.run('ws_archived', 'org_1', 'Archived', 'owner_1', 1, now - DAY);

  const insertScan = database.prepare(
    `INSERT INTO shield_scan
       (id, workspaceId, score, grade, headline, checks, findingCount, durationMs,
        createdAt, scanTrigger, scanStatus)
     VALUES (?, ?, 70, 'fair', 'h', '[]', 0, 5, ?, ?, ?)`,
  );
  insertScan.run('s_old', 'ws_old', now - 40 * HOUR, 'scheduled', 'failed');
  insertScan.run('s_recent', 'ws_recent', now - 2 * HOUR, 'scheduled', 'completed');
  // A manual scan is not an automatic attempt and must not defer the sweep.
  insertScan.run('s_manual', 'ws_never', now - 60_000, 'manual', 'completed');
  insertScan.run('s_off', 'ws_off', now - 90 * DAY, 'scheduled', 'completed');
  insertScan.run('s_arch', 'ws_archived', now - 90 * DAY, 'scheduled', 'completed');

  // The statement the scheduler runs, kept in step with the source below.
  const rows = database
    .prepare(
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
    )
    .all(now - POSTURE_LIMITS.eligibleAfterMs, POSTURE_LIMITS.workspacesPerTick) as {
      id: string;
    }[];

  assert.deepEqual(rows.map((row) => row.id), ['ws_never', 'ws_old']);

  // A failed attempt still counted: `ws_old` is behind `ws_never`, not ahead
  // of it, even though its only scheduled scan failed.
  const scheduler = source('lib/server/shield-schedule.ts');
  assert.match(scheduler, /ORDER BY lastAttemptAt ASC, w\.id ASC/);
  assert.match(scheduler, /LIMIT \?/);
});

// ---------------------------------------------------------------------------
// What the product is allowed to say.
// ---------------------------------------------------------------------------

void test('the cadence sentence describes a queue and never a schedule', () => {
  const copy = cadenceCopy();
  assert.match(copy, /eligible/i);
  assert.match(copy, /no guaranteed interval/i);
  assert.match(copy, /about 6 hours/);

  for (const promise of [
    /every \d+ hours/i, /every six hours/i, /hourly/i, /guaranteed to/i,
    /will be scanned/i, /scanned every/i, /always scanned/i, /within \d/i,
  ]) {
    assert.doesNotMatch(copy, promise, `the cadence copy promises: ${promise}`);
  }

  // Derived from the constant, so changing the threshold cannot leave the
  // sentence behind.
  assert.match(cadenceCopy(2 * HOUR), /about 2 hours/);
});

void test('no surface promises a cadence the scheduler cannot hold', () => {
  for (const path of [
    'components/shield-view.tsx',
    'components/settings-view.tsx',
    'lib/shield-posture.ts',
    'lib/server/shield-schedule.ts',
  ]) {
    const body = code(path);
    for (const promise of [
      /scanned every \d/i, /every 6 hours/i, /every six hours/i,
      /rescanned every/i, /guaranteed to/i, /we guarantee/i,
    ]) {
      assert.doesNotMatch(body, promise, `${path} promises a cadence`);
    }
    // "guaranteed" is allowed only in the sentence that denies one.
    for (const hit of body.match(/[^.]*guarantee[^.]*\./gi) ?? []) {
      assert.match(
        hit,
        /\b(no|not|cannot|never)\b/i,
        `${path} uses "guarantee" as a promise: ${hit.trim()}`,
      );
    }
  }
});

void test('the settings toggle no longer describes a feature that never existed', () => {
  const settings = code('components/settings-view.tsx');
  // It claimed a deployment triggered a scan. Nothing ever read the setting.
  assert.doesNotMatch(settings, /after a deployment plan is recorded/);
  assert.match(settings, /re-scan this workspace on its own/);
  assert.match(settings, /Eligible about 6 hours/);
});

void test('the Shield page shows provenance, movement, and finding age', () => {
  const view = code('components/shield-view.tsx');

  assert.match(view, /scanTriggerLabel\(data\.scanTrigger\)/);
  assert.match(view, /describePostureDelta\(data\.delta\)/);
  assert.match(view, /findingAge\(finding\.firstSeenAt, data\.now\)/);
  assert.match(view, /Last automatic scan/);
  assert.match(view, /has not been swept automatically yet/);
  assert.match(view, /Off for this workspace/);

  // A failed attempt is named rather than hidden, and its placeholder score is
  // never printed.
  assert.match(view, /did not complete, so it recorded no/);
  assert.match(view, /failed \? '—' : `\$\{attempt\.score\}/);

  // The score card reads from the last COMPLETED scan.
  const page = code('app/[section]/page.tsx');
  assert.match(page, /score: state\.scan\?\.score \?\? null/);
  assert.match(page, /lastAttempt: state\.lastAttempt/);
  assert.match(page, /autoScan: workspace\.autoScan/);
});

void test('a scan with no recorded movement says so instead of showing zeros', () => {
  assert.equal(describePostureDelta(null), 'Movement was not recorded for this scan.');
  assert.equal(
    describePostureDelta({ opened: 0, resolved: 0, reopened: 0, severityChanged: 0 }),
    'No change since the previous scan.',
  );
  assert.equal(
    describePostureDelta({ opened: 2, resolved: 1, reopened: 1, severityChanged: 0 }),
    '2 new · 1 reopened · 1 resolved',
  );
});

void test('provenance labels never guess', () => {
  assert.equal(scanTriggerLabel('scheduled'), 'Automatic');
  assert.equal(scanTriggerLabel('manual'), 'Manual');
  assert.equal(scanTriggerLabel(null), 'Legacy');
  assert.equal(scanTriggerLabel(undefined), 'Legacy');
  assert.equal(scanTriggerLabel('something-else'), 'Legacy');
});

void test('finding age answers how long, not when', () => {
  const now = 100 * DAY;
  assert.equal(findingAge(now, now), '0m');
  assert.equal(findingAge(now - 45 * 60_000, now), '45m');
  assert.equal(findingAge(now - 5 * HOUR, now), '5h');
  assert.equal(findingAge(now - 12 * DAY, now), '12d');
  assert.equal(findingAge(now - 200 * DAY, now), '6mo');
  // A clock that ran backwards must not produce a negative age.
  assert.equal(findingAge(now + DAY, now), '0m');
});

// ---------------------------------------------------------------------------
// Zero Mode.
// ---------------------------------------------------------------------------

void test('Phase 15 adds no binding, no table, and no second trigger', () => {
  const wrangler = source('wrangler.jsonc');
  assert.equal((wrangler.match(/"binding": "DB"/g) ?? []).length, 1);
  for (const forbidden of [
    'r2_buckets', 'durable_objects', 'queues', 'analytics_engine_datasets',
    'vectorize', 'hyperdrive', 'workflows', 'browser', 'mtls_certificates',
  ]) {
    assert.doesNotMatch(wrangler, new RegExp(forbidden));
  }

  const migration = source('db/migrations/0019_shield_posture.sql');
  assert.doesNotMatch(stripSqlComments(migration), /CREATE TABLE/i);

  // No new outbound call, no timer, no polling loop.
  for (const path of ['lib/server/shield-schedule.ts', 'lib/shield-posture.ts']) {
    const body = code(path);
    assert.doesNotMatch(body, /\bfetch\(/);
    assert.doesNotMatch(body, /setInterval|setTimeout/);
  }
});

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  CAPACITY_STATES,
  CAPACITY_THRESHOLDS,
  forecastCapacity,
  forecastMetric,
  growthPerDay,
  overallCapacityState,
  stateForDaysRemaining,
  stateForRatio,
  trustedLimit,
} from '../lib/capacity.ts';
import { FREE_TIER_LIMITS, readUsage } from '../lib/free-tier.ts';
import {
  RETENTION_CLASS_META,
  RETENTION_DATA_CLASSES,
  RETENTION_LIMITS,
  RETENTION_PROTECTED_TABLES,
  canManageRetention,
  canReadRetention,
  dryRunAuthorises,
  isRetentionDataClass,
  minimumRetentionDays,
  parseRetentionMutation,
  snapshotSlot,
} from '../lib/retention.ts';
import { permissionForRequest, type Actor } from '../lib/roles.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function migration(name: string): string {
  return source(`db/migrations/${name}`);
}

function apply(database: DatabaseSync, name: string): void {
  const sql = migration(name);
  if (name >= '0010_organizations.sql') {
    for (const statement of splitStatements(stripSqlComments(sql))) database.exec(statement);
  } else {
    database.exec(sql);
  }
}

function phase11Database(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  for (const name of [
    '0001_auth.sql', '0002_workspace.sql', '0003_auth_rate_limit.sql',
    '0004_security.sql', '0005_storage.sql', '0006_compute_nodes.sql',
    '0007_ai_compute.sql', '0008_game_servers.sql', '0009_app_runtime.sql',
    '0010_organizations.sql', '0011_public_exposure.sql', '0012_workflows.sql',
    '0013_external_event_gateway.sql', '0014_incident_operations.sql',
  ]) apply(database, name);
  database.exec(`
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES
      ('owner_one','Owner One','one@test.invalid',1,NULL,1,1),
      ('owner_two','Owner Two','two@test.invalid',1,NULL,1,1);
    INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt) VALUES
      ('org_one','One','one','owner_one','active',1,1,1),
      ('org_two','Two','two','owner_two','active',1,1,1);
    INSERT INTO workspace (id,organizationId,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt) VALUES
      ('ws_one','org_one','One','owner_one',1,1,1,0,1,1),
      ('ws_two','org_two','Two','owner_two',1,1,1,0,1,1);
    INSERT INTO organization_member (id,organizationId,userId,role,status,acceptedAt,createdBy,createdAt,updatedAt) VALUES
      ('member_one','org_one','owner_one','owner','active',1,'owner_one',1,1),
      ('member_two','org_two','owner_two','owner','active',1,'owner_two',1,1);
    INSERT INTO project (id,workspaceId,name,framework,environment,region,status,visibility,createdAt,updatedAt) VALUES
      ('project_one','ws_one','One','Node.js','Production','Local','idle','private',1,1),
      ('project_two','ws_two','Two','Node.js','Production','Local','idle','private',1,1);
    INSERT INTO audit_event
      (id,organizationId,workspaceId,actorType,actorId,action,resourceType,outcome,metadata,createdAt)
      VALUES ('audit_phase11','org_one','ws_one','user','owner_one','incident.note','incident','success','{}',2);
    INSERT INTO workflow
      (id,organizationId,workspaceId,projectId,name,description,status,latestVersion,ownerUserId,failureStreak,createdBy,createdAt,updatedAt)
      VALUES ('wf_history','org_one','ws_one','project_one','History','History','active',1,'owner_one',0,'owner_one',2,2);
    INSERT INTO workflow_version
      (id,workflowId,organizationId,workspaceId,projectId,version,kind,triggerType,definition,definitionHash,createdBy,createdAt,publishedAt)
      VALUES ('wfver_history','wf_history','org_one','ws_one','project_one',1,'published','manual','{}','hash','owner_one',2,2);
    UPDATE workflow SET activeVersionId='wfver_history' WHERE id='wf_history';
    INSERT INTO workflow_incident
      (id,organizationId,workspaceId,projectId,workflowId,resourceType,title,detail,severity,status,createdBy,createdAt,updatedAt,correlationId,dedupeKey,occurrenceCount,lastSeenAt,revision)
      VALUES ('incident_history','org_one','ws_one','project_one','wf_history','capacity','History','History detail','high','open','system',2,2,'corr_history','dedupe_history',1,2,1);
    INSERT INTO incident_event
      (id,organizationId,workspaceId,projectId,incidentId,type,actorType,actorId,correlationId,toStatus,metadata,idempotencyKey,createdAt)
      VALUES ('incevt_history','org_one','ws_one','project_one','incident_history','incident.created','system','system','corr_history','open','{}','created:history',2);
  `);
  return database;
}

function phase12Database(): DatabaseSync {
  const database = phase11Database();
  apply(database, '0015_data_lifecycle.sql');
  return database;
}

const owner: Actor = { userId: 'owner_one', role: 'owner', suspended: false, projectIds: null };
const admin: Actor = { userId: 'admin_one', role: 'admin', suspended: false, projectIds: null };
const developer: Actor = { userId: 'dev_one', role: 'developer', suspended: false, projectIds: ['project_one'] };
const viewer: Actor = { userId: 'viewer_one', role: 'viewer', suspended: false, projectIds: null };

void test('retention registry is closed, disabled by default, and excludes immutable evidence', () => {
  assert.equal(RETENTION_DATA_CLASSES.length, 7);
  assert.equal(new Set(RETENTION_DATA_CLASSES).size, RETENTION_DATA_CLASSES.length);
  for (const dataClass of RETENTION_DATA_CLASSES) {
    assert.equal(isRetentionDataClass(dataClass), true);
    assert.ok(RETENTION_CLASS_META[dataClass].defaultRetentionDays >= minimumRetentionDays(dataClass));
    assert.ok(RETENTION_CLASS_META[dataClass].maxRowsPerRun <= 500);
  }
  assert.equal(isRetentionDataClass('audit_event'), false);
  assert.equal(isRetentionDataClass('incident_event'), false);
  assert.equal(isRetentionDataClass('workflow_version'), false);
  assert.deepEqual(
    RETENTION_PROTECTED_TABLES.map((entry) => entry.table),
    ['audit_event', 'incident_event', 'workflow_version', 'retention_run'],
  );
});

void test('retention mutation parser rejects floors, malformed revisions, and identifier injection', () => {
  assert.equal(parseRetentionMutation({ operation: 'dry-run', expectedRevision: 1 }, 'platform-logs').ok, true);
  assert.equal(parseRetentionMutation({ operation: 'set-window', retentionDays: 14, expectedRevision: 1 }, 'workflow-events').ok, true);
  assert.equal(parseRetentionMutation({ operation: 'set-window', retentionDays: 13, expectedRevision: 1 }, 'workflow-events').ok, false);
  assert.equal(parseRetentionMutation({ operation: 'enable', expectedRevision: 0 }, 'platform-logs').ok, false);
  for (const forbidden of ['table', 'tableName', 'sql', 'query', 'where', 'column', 'predicate']) {
    const parsed = parseRetentionMutation({ operation: 'dry-run', expectedRevision: 1, [forbidden]: 'audit_event; DROP TABLE audit_event' }, 'platform-logs');
    assert.equal(parsed.ok, false, forbidden);
    if (!parsed.ok) assert.equal(parsed.securityCode, 'retention-identifier-injection');
  }
  assert.equal(parseRetentionMutation({ operation: 'dry-run', expectedRevision: 1, zeroMode: false }, 'platform-logs').ok, false);
  assert.equal(parseRetentionMutation({ operation: 'delete', expectedRevision: 1 }, 'platform-logs').ok, false);
});

void test('matching fresh dry-run is required and stale or old-revision evidence is rejected', () => {
  const now = 50 * DAY;
  const base = {
    lastDryRunAt: now - HOUR,
    lastDryRunRevision: 4,
    lastDryRunRetentionDays: 30,
    revision: 4,
    retentionDays: 30,
    now,
  };
  assert.equal(dryRunAuthorises(base), true);
  assert.equal(dryRunAuthorises({ ...base, lastDryRunAt: now - RETENTION_LIMITS.dryRunFreshnessMs - 1 }), false);
  assert.equal(dryRunAuthorises({ ...base, lastDryRunRevision: 3 }), false);
  assert.equal(dryRunAuthorises({ ...base, lastDryRunRetentionDays: 31 }), false);
  assert.equal(dryRunAuthorises({ ...base, lastDryRunAt: now + 1 }), false);
});

void test('retention RBAC is workspace-wide and suspended actors fail closed', () => {
  assert.equal(canReadRetention(viewer), true);
  assert.equal(canManageRetention(viewer), false);
  assert.equal(canManageRetention(developer), false);
  assert.equal(canManageRetention(admin), true);
  assert.equal(canManageRetention(owner), true);
  assert.equal(canManageRetention({ ...owner, suspended: true }), false);
  assert.equal(permissionForRequest('GET', '/api/retention'), 'retention.read');
  assert.equal(permissionForRequest('PATCH', '/api/retention/platform-logs'), 'retention.manage');
});

void test('migration 0015 upgrades Phase 11 without changing existing evidence and replays safely', () => {
  const database = phase11Database();
  try {
    const before = {
      audit: Number((database.prepare('SELECT COUNT(*) AS total FROM audit_event').get() as { total: number }).total),
      incidents: Number((database.prepare('SELECT COUNT(*) AS total FROM workflow_incident').get() as { total: number }).total),
      events: Number((database.prepare('SELECT COUNT(*) AS total FROM incident_event').get() as { total: number }).total),
      versions: Number((database.prepare('SELECT COUNT(*) AS total FROM workflow_version').get() as { total: number }).total),
    };
    apply(database, '0015_data_lifecycle.sql');
    apply(database, '0015_data_lifecycle.sql');
    const after = {
      audit: Number((database.prepare('SELECT COUNT(*) AS total FROM audit_event').get() as { total: number }).total),
      incidents: Number((database.prepare('SELECT COUNT(*) AS total FROM workflow_incident').get() as { total: number }).total),
      events: Number((database.prepare('SELECT COUNT(*) AS total FROM incident_event').get() as { total: number }).total),
      versions: Number((database.prepare('SELECT COUNT(*) AS total FROM workflow_version').get() as { total: number }).total),
    };
    assert.deepEqual(after, before);
    assert.equal(database.prepare('PRAGMA foreign_key_check').all().length, 0);
    assert.equal(Number((database.prepare('SELECT COUNT(*) AS total FROM retention_policy').get() as { total: number }).total), 0);
  } finally {
    database.close();
  }
});

void test('D1 defaults policies to disabled and enforces tenant, uniqueness, and per-class floors', () => {
  const database = phase12Database();
  try {
    const insert = database.prepare(`INSERT INTO retention_policy
      (id,organizationId,workspaceId,dataClass,retentionDays,createdBy,createdAt,updatedAt)
      VALUES (?,?,?,?,?,?,?,?)`);
    insert.run('policy_logs','org_one','ws_one','platform-logs',30,'owner_one',10,10);
    const row = database.prepare("SELECT enabled,revision FROM retention_policy WHERE id='policy_logs'").get() as { enabled: number; revision: number };
    assert.deepEqual({ ...row }, { enabled: 0, revision: 1 });
    assert.throws(() => insert.run('policy_duplicate','org_one','ws_one','platform-logs',30,'owner_one',10,10), /UNIQUE/);
    assert.throws(() => insert.run('policy_cross','org_two','ws_one','read-notifications',30,'owner_two',10,10), /tenant mismatch/);
    assert.throws(() => insert.run('policy_security','org_one','ws_one','workflow-security-events',89,'owner_one',10,10), /class floor/);
    insert.run('policy_security','org_one','ws_one','workflow-security-events',90,'owner_one',10,10);
    assert.throws(() => database.prepare("UPDATE retention_policy SET retentionDays=89 WHERE id='policy_security'").run(), /class floor/);
    assert.throws(() => insert.run('policy_too_long','org_one','ws_one','read-notifications',3651,'owner_one',10,10), /CHECK/);
  } finally {
    database.close();
  }
});

void test('D1 activation guard requires exact reviewed revision and window', () => {
  const database = phase12Database();
  try {
    database.exec(`INSERT INTO retention_policy
      (id,organizationId,workspaceId,dataClass,retentionDays,createdBy,createdAt,updatedAt)
      VALUES ('policy_activation','org_one','ws_one','platform-logs',30,'owner_one',10,10)`);
    assert.throws(() => database.prepare("UPDATE retention_policy SET enabled=1,revision=2 WHERE id='policy_activation'").run(), /matching dry-run/);
    database.prepare(`UPDATE retention_policy SET lastDryRunAt=20,lastDryRunRevision=2,
      lastDryRunRetentionDays=30,lastDryRunCandidateRows=0,revision=2 WHERE id='policy_activation'`).run();
    database.prepare("UPDATE retention_policy SET enabled=1,revision=3 WHERE id='policy_activation'").run();
    assert.equal(Number((database.prepare("SELECT enabled FROM retention_policy WHERE id='policy_activation'").get() as { enabled: number }).enabled), 1);
    assert.throws(() => database.prepare("UPDATE retention_policy SET retentionDays=31 WHERE id='policy_activation'").run(), /requires disabling/);
  } finally {
    database.close();
  }
});

void test('retention run evidence is tenant checked, append-only, and undeletable', () => {
  const database = phase12Database();
  try {
    database.exec(`INSERT INTO retention_policy
      (id,organizationId,workspaceId,dataClass,retentionDays,createdBy,createdAt,updatedAt)
      VALUES ('policy_run','org_one','ws_one','platform-logs',30,'owner_one',10,10)`);
    database.exec(`INSERT INTO retention_run
      (id,organizationId,workspaceId,policyId,dataClass,mode,actorType,actorId,retentionDays,cutoff,candidateRows,deletedRows,status,startedAt,finishedAt)
      VALUES ('run_one','org_one','ws_one','policy_run','platform-logs','dry-run','user','owner_one',30,1,8,0,'completed',10,10)`);
    assert.throws(() => database.prepare("UPDATE retention_run SET deletedRows=1 WHERE id='run_one'").run(), /append-only/);
    assert.throws(() => database.prepare("DELETE FROM retention_run WHERE id='run_one'").run(), /cannot be deleted/);
    assert.throws(() => database.exec(`INSERT INTO retention_run
      (id,organizationId,workspaceId,policyId,dataClass,mode,actorType,actorId,retentionDays,cutoff,status,startedAt,finishedAt)
      VALUES ('run_cross','org_two','ws_two','policy_run','platform-logs','prune','system','system',30,1,'skipped',10,10)`), /tenant mismatch/);
  } finally {
    database.close();
  }
});

void test('audit, incident timeline, and workflow versions remain D1-protected', () => {
  const database = phase12Database();
  try {
    assert.throws(() => database.prepare("DELETE FROM audit_event WHERE id='audit_phase11'").run(), /append-only/);
    assert.throws(() => database.prepare("DELETE FROM incident_event WHERE id='incevt_history'").run(), /append-only/);
    assert.throws(() => database.prepare("DELETE FROM workflow_version WHERE id='wfver_history'").run(), /append-only/);
  } finally {
    database.close();
  }
});

void test('bounded prune SQL deletes only the oldest rows of one workspace', () => {
  const database = phase12Database();
  try {
    const insert = database.prepare('INSERT INTO log_event (id,workspaceId,level,source,message,createdAt) VALUES (?,?,?,?,?,?)');
    for (let index = 0; index < 230; index += 1) insert.run(`old_${index}`,'ws_one','INFO','test','safe',index);
    for (let index = 0; index < 10; index += 1) insert.run(`new_${index}`,'ws_one','INFO','test','safe',10000 + index);
    for (let index = 0; index < 20; index += 1) insert.run(`foreign_${index}`,'ws_two','INFO','test','safe',index);
    const prune = database.prepare(`DELETE FROM log_event WHERE id IN (
      SELECT id FROM log_event WHERE workspaceId=? AND createdAt<? ORDER BY createdAt ASC LIMIT ?)`);
    assert.equal(prune.run('ws_one',10000,RETENTION_LIMITS.batchRows).changes, RETENTION_LIMITS.batchRows);
    assert.equal(prune.run('ws_one',10000,RETENTION_LIMITS.batchRows).changes, RETENTION_LIMITS.batchRows);
    assert.equal(Number((database.prepare("SELECT COUNT(*) AS total FROM log_event WHERE workspaceId='ws_one' AND createdAt<10000").get() as { total: number }).total), 30);
    assert.equal(Number((database.prepare("SELECT COUNT(*) AS total FROM log_event WHERE workspaceId='ws_two'").get() as { total: number }).total), 20);
  } finally {
    database.close();
  }
});

void test('terminal workflow retention preserves incident-linked executions and referenced events', () => {
  const server = source('lib/server/retention.ts');
  assert.match(server, /NOT EXISTS \(SELECT 1 FROM workflow_incident i WHERE i\.executionId = t\.id\)/);
  assert.match(server, /NOT EXISTS \(SELECT 1 FROM workflow_execution e WHERE e\.eventId = t\.id\)/);
  assert.match(server, /NOT EXISTS \(SELECT 1 FROM webhook_delivery d WHERE d\.workflowEventId = t\.id\)/);
  assert.match(server, /state IN \('succeeded', 'failed', 'cancelled', 'timed_out', 'skipped'\)/);
  assert.doesNotMatch(server, /DELETE FROM (?:audit_event|incident_event|workflow_version)/);
});

void test('snapshot cadence uses deterministic six-hour slots and D1 deduplicates each workspace slot', () => {
  assert.equal(RETENTION_LIMITS.snapshotIntervalMs, 6 * HOUR);
  assert.equal(snapshotSlot(0), 0);
  assert.equal(snapshotSlot(6 * HOUR - 1), 0);
  assert.equal(snapshotSlot(6 * HOUR), 1);
  const database = phase12Database();
  try {
    const insert = database.prepare(`INSERT INTO usage_snapshot
      (id,organizationId,workspaceId,slot,capturedAt,source,metrics,overLimitCount)
      VALUES (?,?,?,?,?,'cron','{}',0)`);
    insert.run('snapshot_one','org_one','ws_one',1,6 * HOUR);
    assert.throws(() => insert.run('snapshot_duplicate','org_one','ws_one',1,6 * HOUR + 1), /UNIQUE/);
    insert.run('snapshot_other','org_two','ws_two',1,6 * HOUR + 1);
    assert.throws(() => insert.run('snapshot_cross','org_two','ws_one',2,12 * HOUR), /tenant mismatch/);
    assert.throws(() => database.prepare("UPDATE usage_snapshot SET metrics='{\"x\":1}' WHERE id='snapshot_one'").run(), /immutable/);
  } finally {
    database.close();
  }
});

void test('forecast refuses short evidence and never returns NaN or Infinity', () => {
  const now = 20 * DAY;
  const cases = [
    [],
    [{ capturedAt: now - HOUR, used: 10 }, { capturedAt: now, used: 20 }],
    [{ capturedAt: Number.POSITIVE_INFINITY, used: 1 }, { capturedAt: now, used: Number.NaN }],
  ];
  for (const samples of cases) {
    const forecast = forecastMetric({ metricId: 'projects', label: 'Projects', unit: 'count', used: 20, limit: 100, measured: true, samples, now });
    assert.equal(forecast.projectedBreachAt, null);
    for (const value of [forecast.percent, forecast.used, forecast.limit, forecast.spanMs]) assert.equal(Number.isFinite(value), true);
  }
});

void test('positive, flat, negative, and noisy trends produce deterministic projections', () => {
  const now = 50 * DAY;
  const positive = [
    { capturedAt: now - 2 * DAY, used: 20 },
    { capturedAt: now - DAY, used: 30 },
    { capturedAt: now, used: 40 },
  ];
  assert.equal(growthPerDay(positive), 10);
  const forecast = forecastMetric({ metricId: 'projects', label: 'Projects', unit: 'count', used: 40, limit: 100, measured: true, samples: positive, now });
  assert.equal(forecast.daysRemaining, 6);
  assert.equal(forecast.projectedBreachAt, now + 6 * DAY);
  assert.equal(growthPerDay(positive.map((sample) => ({ ...sample, used: 20 }))), 0);
  assert.ok((growthPerDay(positive.map((sample, index) => ({ ...sample, used: 40 - index * 10 }))) ?? 0) < 0);
  const noisy = [
    { capturedAt: now - 3 * DAY, used: 10 },
    { capturedAt: now - 2 * DAY, used: 35 },
    { capturedAt: now - DAY, used: 25 },
    { capturedAt: now, used: 50 },
  ];
  assert.ok((growthPerDay(noisy) ?? 0) > 0);
  assert.equal(forecastMetric({ metricId: 'projects', label: 'Projects', unit: 'count', used: 40, limit: 100, measured: true, samples: positive.map((sample) => ({ ...sample, used: 20 })), now }).projectedBreachAt, null);
});

void test('capacity threshold boundaries and state ordering are centralized', () => {
  assert.deepEqual(CAPACITY_STATES, ['healthy', 'watch', 'at-risk', 'critical', 'insufficient-data']);
  assert.equal(stateForRatio(CAPACITY_THRESHOLDS.watchRatio), 'watch');
  assert.equal(stateForRatio(CAPACITY_THRESHOLDS.atRiskRatio), 'at-risk');
  assert.equal(stateForRatio(CAPACITY_THRESHOLDS.criticalRatio), 'critical');
  assert.equal(stateForDaysRemaining(CAPACITY_THRESHOLDS.watchDays), 'watch');
  assert.equal(stateForDaysRemaining(CAPACITY_THRESHOLDS.atRiskDays), 'at-risk');
  assert.equal(stateForDaysRemaining(CAPACITY_THRESHOLDS.criticalDays), 'critical');
  const critical = forecastMetric({ metricId: 'projects', label: 'Projects', unit: 'count', used: 96, limit: 100, measured: true, samples: [], now: 0 });
  const unknown = forecastMetric({ metricId: 'database-bytes', label: 'Database', unit: 'bytes', used: 0, limit: 100, measured: false, samples: [], now: 0 });
  assert.equal(overallCapacityState([unknown, critical]), 'critical');
});

void test('forecasts use the trusted free-tier catalog and current Usage readings', () => {
  for (const limit of FREE_TIER_LIMITS) assert.equal(trustedLimit(limit.id), limit.limit);
  const readings = readUsage({ projects: 2, 'database-bytes': null });
  const forecasts = forecastCapacity({ readings, history: [], now: 0 });
  assert.equal(forecasts.length, readings.length);
  for (const forecast of forecasts) assert.equal(forecast.limit, trustedLimit(forecast.metricId));
  assert.equal(forecasts.find((item) => item.metricId === 'database-bytes')?.state, 'insufficient-data');
});

void test('scheduled maintenance is bounded, fair, sequential, and makes no outbound usage call', () => {
  const server = source('lib/server/retention.ts');
  const worker = source('worker.ts');
  const wrangler = source('wrangler.jsonc');
  assert.equal(RETENTION_LIMITS.snapshotsPerTick, 1);
  assert.equal(RETENTION_LIMITS.policiesPerTick, 2);
  assert.equal(RETENTION_LIMITS.batchRows, 100);
  assert.match(server, /ORDER BY COALESCE\([\s\S]*MAX\(s2\.capturedAt\)[\s\S]*ASC, w\.id ASC[\s\S]*LIMIT \?/);
  assert.match(server, /ORDER BY COALESCE\(p\.lastPrunedAt, 0\) ASC, p\.id ASC[\s\S]*LIMIT \?/);
  assert.match(server, /includeDatabaseBytes: false/);
  assert.doesNotMatch(server, /databaseBytes\(/);
  assert.ok(worker.indexOf('await runWorkflowEngineTick') < worker.indexOf('await runDataLifecycleMaintenance'));
  assert.equal((worker.match(/context\.waitUntil\(/g) ?? []).length, 1);
  assert.equal((worker.match(/scheduled\(/g) ?? []).length, 1);
  assert.match(wrangler, /"crons": \["\* \* \* \* \*"\]/);
});

void test('partial failures are isolated and stored errors stay allowlisted', () => {
  const server = source('lib/server/retention.ts');
  assert.match(server, /for \(const workspace of due\)[\s\S]*catch \{[\s\S]*continue;/);
  assert.match(server, /for \(const policy of policies\)[\s\S]*FAILURE_CODES\.maintenance[\s\S]*continue;/);
  assert.match(server, /prune-failed/);
  assert.match(server, /candidate-count-failed/);
  assert.match(server, /maintenance-failed/);
  assert.doesNotMatch(migration('0015_data_lifecycle.sql'), /errorMessage|stackTrace|rawError/i);
});

void test('Shield and incident integration use stable root causes without a new event taxonomy', () => {
  const shield = source('lib/shield.ts');
  const server = source('lib/server/retention.ts');
  for (const code of [
    'capacity-forecast-breach',
    'capacity-approaching-limit',
    'capacity-retention-failing',
    'capacity-retention-disabled',
    'capacity-no-history',
  ]) assert.match(shield, new RegExp(code));
  assert.match(shield, /resource: 'capacity\/workspace'/);
  assert.match(server, /createOrAggregateIncident/);
  assert.match(server, /correlationId: `capacity-\$\{input\.workspaceId\}-\$\{forecast\.metricId\}`/);
  assert.match(server, /forecast\.state !== 'critical'/);
  assert.doesNotMatch(server, /emitWorkflowEvent/);
});

void test('Phase 12 API and UI expose only reviewed lifecycle operations', () => {
  const route = source('app/api/retention/[id]/route.ts');
  const view = source('components/capacity-view.tsx');
  assert.match(route, /readBoundedJson\(request, RETENTION_LIMITS\.requestBytes\)/);
  assert.match(route, /enforceRateLimit\('api:write'/);
  assert.match(route, /application\/json/);
  assert.match(route, /recordWorkflowSecurityEvent/);
  assert.match(view, /Dry run \(deletes nothing\)/);
  assert.match(view, /Start deleting permanently/);
  assert.match(view, /Retention policies are managed by owners and admins/);
  assert.doesNotMatch(view, /entry\.table|entry\.guard|audit_event_no_delete|incident_event_append_only/);
  assert.doesNotMatch(route, /eval\(|child_process|powershell|curl|https?:\/\//i);
});

void test('Phase 12 adds no billable binding, queue, object, workflow, R2, or second database', () => {
  const wrangler = source('wrangler.jsonc');
  const lifecycleFiles = [
    source('lib/capacity.ts'),
    source('lib/retention.ts'),
    source('lib/server/retention.ts'),
    migration('0015_data_lifecycle.sql'),
  ].join('\n');
  assert.equal((wrangler.match(/"binding": "DB"/g) ?? []).length, 1);
  assert.equal((wrangler.match(/"database_id"/g) ?? []).length, 1);
  assert.doesNotMatch(wrangler, /durable_objects|queues|workflows|r2_buckets|analytics_engine_datasets/i);
  assert.doesNotMatch(lifecycleFiles, /fetch\(|eval\(|new Function|child_process|shell|generic http/i);
});

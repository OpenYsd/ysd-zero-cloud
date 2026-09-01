import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { can, canAccessProject, type Actor, type Role } from '../lib/roles.ts';
import { runShieldRules, type ShieldSnapshot } from '../lib/shield.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';
import {
  MAX_WORKFLOW_CHAIN_DEPTH,
  WORKFLOW_TEMPLATES,
  executionTerminalState,
  redactWorkflowValue,
  retryDelayMs,
  shouldRunSchedule,
  validateWorkflowDefinition,
  workflowConditionsMatch,
  workflowPotentialCycle,
  type TrustedWorkflowEvent,
  type WorkflowDefinition,
} from '../lib/workflows.ts';

const NOW = Date.UTC(2026, 7, 31, 12, 0, 0);

const MANUAL: WorkflowDefinition = {
  trigger: { type: 'manual' },
  conditions: [],
  actions: [{
    type: 'notification.create', target: 'event.resource',
    title: 'Manual run', message: 'The bounded manual workflow ran.', severity: 'low',
  }],
  retry: { maxAttempts: 3, initialDelaySeconds: 5, maximumDelaySeconds: 60 },
  timeoutSeconds: 60,
  concurrency: { workflow: 1, workspace: 4 },
};

const EVENT: TrustedWorkflowEvent = {
  id: 'wfevt_test', type: 'deployment.failed', organizationId: 'org_1',
  workspaceId: 'ws_1', projectId: 'project_1', resourceId: 'dpl_1',
  payload: { status: 'failed', severity: 'high', failureCount: 3 },
  correlationId: 'corr_1', causationId: null, sourceWorkflowId: null,
  chainDepth: 0, createdAt: NOW,
};

function validation(definition: unknown, role: Role = 'owner', projectId: string | null = null, zeroMode = true) {
  return validateWorkflowDefinition(definition, { role, projectId, zeroMode });
}

void test('manual trigger succeeds through the deterministic bounded contract', () => {
  const result = validation(MANUAL);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(workflowConditionsMatch(result.definition, { ...EVENT, type: 'manual' }), true);
  assert.equal(executionTerminalState({
    now: NOW, timeoutAt: NOW + 60_000, cancelRequested: false,
    actionFailed: false, attempt: 1, maxAttempts: 3,
  }), 'continue');
});

void test('real event templates contain the requested guarded resource actions', () => {
  const expectations = new Map([
    ['deployment.failed', 'deployment.rollback_to_previous_healthy'],
    ['node.offline', 'node.disable_assignments'],
    ['game_server.crash_loop', 'game_server.stop'],
    ['shield.finding.opened', 'shield.create_incident'],
    ['ai.job.failed', 'workflow.pause'],
  ]);
  for (const [trigger, action] of expectations) {
    const template = WORKFLOW_TEMPLATES.find((item) => item.definition.trigger.type === trigger);
    assert.ok(template, trigger);
    assert.equal(template.definition.actions.some((item) => item.type === action), true, action);
    assert.equal(validation(template.definition).ok, true, template.name);
  }
});

void test('conditions take deterministic true and false branches without eval', () => {
  const definition: WorkflowDefinition = {
    ...MANUAL,
    trigger: { type: 'deployment.failed' },
    conditions: [
      { path: 'event.payload.status', operator: 'equals', value: 'failed' },
      { path: 'event.payload.failureCount', operator: 'greater_or_equal', value: 3 },
      { path: 'event.payload.severity', operator: 'in', value: ['high', 'critical'] },
    ],
  };
  assert.equal(validation(definition).ok, true);
  assert.equal(workflowConditionsMatch(definition, EVENT), true);
  assert.equal(workflowConditionsMatch(definition, { ...EVENT, payload: { ...EVENT.payload, failureCount: 2 } }), false);
});

void test('malicious expressions, URLs, shell payloads, arbitrary keys, and paid providers are rejected', () => {
  const attacks = [
    { ...MANUAL, expression: 'process.mainModule.require("child_process")' },
    { ...MANUAL, actions: [{ ...MANUAL.actions[0], script: 'eval(1)' }] },
    { ...MANUAL, actions: [{ ...MANUAL.actions[0], endpoint: 'http://127.0.0.1/admin' }] },
    { ...MANUAL, actions: [{ ...MANUAL.actions[0], command: 'powershell -c whoami' }] },
    { ...MANUAL, provider: 'paid-automation' },
    { ...MANUAL, actions: [{ ...MANUAL.actions[0], message: 'https://169.254.169.254/' }] },
  ];
  for (const attack of attacks) assert.equal(validation(attack).ok, false, JSON.stringify(attack));
  assert.equal(validation(MANUAL, 'owner', null, false).ok, false, 'zeroMode=false');
});

void test('viewer/developer/admin/owner permissions and privileged action policy are enforced', () => {
  const actor = (role: Role): Actor => ({ userId: role, role, suspended: false, projectIds: null });
  assert.equal(can(actor('viewer'), 'workflow.read'), true);
  assert.equal(can(actor('viewer'), 'workflow.create'), false);
  assert.equal(can(actor('developer'), 'workflow.create'), true);
  assert.equal(can(actor('developer'), 'workflow.manage'), false);
  assert.equal(can(actor('admin'), 'workflow.manage'), true);
  assert.equal(can(actor('owner'), 'workflow.retry'), true);
  assert.equal(can({ ...actor('owner'), suspended: true }, 'workflow.manage'), false);
  assert.equal(canAccessProject({ ...actor('developer'), projectIds: ['project_1'] }, 'project_1'), true);
  assert.equal(canAccessProject({ ...actor('developer'), projectIds: ['project_1'] }, 'project_2'), false);
  assert.equal(validation(MANUAL, 'developer', null).ok, false, 'developer needs project scope');
  const privileged: WorkflowDefinition = {
    ...MANUAL, trigger: { type: 'node.offline' },
    actions: [{ type: 'node.disable_assignments', target: 'event.resource' }],
  };
  assert.equal(validation(privileged, 'developer', 'project_1').ok, false);
  assert.equal(validation(privileged, 'admin').ok, true);
});

void test('retry then success, max retries, timeout, and cancellation terminate predictably', () => {
  assert.equal(executionTerminalState({ now: NOW, timeoutAt: NOW + 1, cancelRequested: false, actionFailed: true, attempt: 1, maxAttempts: 3 }), 'retry');
  assert.equal(retryDelayMs(MANUAL, 1), 5_000);
  assert.equal(retryDelayMs(MANUAL, 2), 10_000);
  assert.equal(executionTerminalState({ now: NOW, timeoutAt: NOW + 1, cancelRequested: false, actionFailed: false, attempt: 2, maxAttempts: 3 }), 'continue');
  assert.equal(executionTerminalState({ now: NOW, timeoutAt: NOW + 1, cancelRequested: false, actionFailed: true, attempt: 3, maxAttempts: 3 }), 'failed');
  assert.equal(executionTerminalState({ now: NOW, timeoutAt: NOW, cancelRequested: false, actionFailed: false, attempt: 1, maxAttempts: 3 }), 'timed_out');
  assert.equal(executionTerminalState({ now: NOW, timeoutAt: NOW + 1, cancelRequested: true, actionFailed: false, attempt: 1, maxAttempts: 3 }), 'cancelled');
});

void test('loop prevention rejects direct cycles and chain depth is bounded', () => {
  const cycle: WorkflowDefinition = {
    ...MANUAL, trigger: { type: 'node.revoked' },
    actions: [{ type: 'node.revoke', target: 'event.resource', confirmationPolicy: 'owner-admin' }],
  };
  assert.equal(workflowPotentialCycle(cycle), true);
  assert.equal(validation(cycle).ok, false);
  assert.equal(MAX_WORKFLOW_CHAIN_DEPTH, 5);
});

void test('safe interval and limited UTC cron schedules are deterministic', () => {
  assert.equal(shouldRunSchedule({ type: 'schedule', intervalMinutes: 15 }, NOW, NOW - 15 * 60_000), true);
  assert.equal(shouldRunSchedule({ type: 'schedule', intervalMinutes: 15 }, NOW, NOW - 14 * 60_000), false);
  assert.equal(shouldRunSchedule({ type: 'schedule', cron: '0 12 * * *' }, NOW, null), true);
  assert.equal(validation({ ...MANUAL, trigger: { type: 'schedule', intervalMinutes: 1 } }).ok, false);
  assert.equal(validation({ ...MANUAL, trigger: { type: 'schedule', cron: '* * * * *' } }).ok, false);
});

void test('secret-shaped execution and log metadata is recursively redacted', () => {
  assert.deepEqual(redactWorkflowValue({
    token: 'ysd_sa_secret', nested: { prompt: 'sensitive', safe: 'ok' },
    text: 'Bearer abcdef',
  }), {
    token: '[REDACTED]', nested: { prompt: '[REDACTED]', safe: 'ok' }, text: '[REDACTED]',
  });
});

function migration(name: string): string {
  return readFileSync(new URL(`../db/migrations/${name}`, import.meta.url), 'utf8');
}

function apply(database: DatabaseSync, name: string): void {
  const sql = migration(name);
  if (name >= '0010_organizations.sql') {
    for (const statement of splitStatements(stripSqlComments(sql))) database.exec(statement);
  } else {
    database.exec(sql);
  }
}

function workflowDatabase(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  for (const name of [
    '0001_auth.sql', '0002_workspace.sql', '0003_auth_rate_limit.sql',
    '0004_security.sql', '0005_storage.sql', '0006_compute_nodes.sql',
    '0007_ai_compute.sql', '0008_game_servers.sql', '0009_app_runtime.sql',
    '0010_organizations.sql', '0011_public_exposure.sql', '0012_workflows.sql',
    '0013_external_event_gateway.sql',
  ]) apply(database, name);
  database.exec(`
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt)
      VALUES ('user_1','Owner','owner@one.test',1,NULL,1,1), ('user_2','Other','owner@two.test',1,NULL,1,1);
    INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt)
      VALUES ('org_1','One','one','user_1','active',1,1,1), ('org_2','Two','two','user_2','active',1,1,1);
    INSERT INTO workspace (id,organizationId,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt)
      VALUES ('ws_1','org_1','One','user_1',1,1,1,0,1,1), ('ws_2','org_2','Two','user_2',1,1,1,0,1,1);
    INSERT INTO organization_member (id,organizationId,userId,role,status,acceptedAt,createdBy,createdAt,updatedAt)
      VALUES ('member_1','org_1','user_1','owner','active',1,'user_1',1,1), ('member_2','org_2','user_2','owner','active',1,'user_2',1,1);
    INSERT INTO project (id,workspaceId,name,framework,environment,region,status,visibility,createdAt,updatedAt)
      VALUES ('project_1','ws_1','App','Node.js','Production','Local','idle','private',1,1), ('project_2','ws_2','Other','Node.js','Production','Local','idle','private',1,1);
    INSERT INTO secret (id,workspaceId,name,scope,environment,ciphertext,fingerprint,rotationDays,createdAt,updatedAt)
      VALUES ('secret_1','ws_1','SAFE_SECRET','Project:project_1','Production','ciphertext-never-read','fingerprint',30,1,1),
             ('secret_2','ws_2','FOREIGN_SECRET','Workspace','Production','foreign-ciphertext','foreign-print',30,1,1);
    INSERT INTO workflow (id,organizationId,workspaceId,projectId,name,description,status,activeVersionId,latestVersion,ownerUserId,failureStreak,createdBy,createdAt,updatedAt)
      VALUES ('wf_1','org_1','ws_1','project_1','Deploy rollback','safe','active','wfver_1',1,'user_1',0,'user_1',1,1);
    INSERT INTO workflow_version (id,workflowId,organizationId,workspaceId,projectId,version,kind,triggerType,definition,definitionHash,createdBy,createdAt,publishedAt)
      VALUES ('wfver_1','wf_1','org_1','ws_1','project_1',1,'published','deployment.failed','{}','hash','user_1',1,1);
    INSERT INTO workflow_event (id,organizationId,workspaceId,projectId,type,resourceType,resourceId,payload,source,trusted,dedupeKey,correlationId,chainDepth,createdAt)
      VALUES ('wfevt_1','org_1','ws_1','project_1','deployment.failed','deployment','dpl_1','{}','system',1,'deploy-failed:dpl_1:1','corr_1',0,1);
    INSERT INTO workflow_execution (id,organizationId,workspaceId,projectId,workflowId,versionId,eventId,state,idempotencyKey,correlationId,chainDepth,actionIndex,attempts,maxAttempts,timeoutAt,createdBy,createdAt,updatedAt)
      VALUES ('wfexec_1','org_1','ws_1','project_1','wf_1','wfver_1','wfevt_1','queued','wf_1:wfver_1:wfevt_1','corr_1',0,0,0,3,999999,'system',1,1);
  `);
  return database;
}

void test('migration 0012 preserves existing Phase 8 exposure and audit data', () => {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  try {
    for (const name of [
      '0001_auth.sql', '0002_workspace.sql', '0003_auth_rate_limit.sql',
      '0004_security.sql', '0005_storage.sql', '0006_compute_nodes.sql',
      '0007_ai_compute.sql', '0008_game_servers.sql', '0009_app_runtime.sql',
      '0010_organizations.sql', '0011_public_exposure.sql',
    ]) apply(database, name);
    database.exec(`
      INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt)
        VALUES ('legacy_owner','Legacy','legacy@phase8.test',1,NULL,1,1);
      INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt)
        VALUES ('legacy_org','Legacy','legacy','legacy_owner','active',1,1,1);
      INSERT INTO workspace (id,organizationId,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt)
        VALUES ('legacy_ws','legacy_org','Legacy','legacy_owner',1,1,1,0,1,1);
      INSERT INTO organization_member (id,organizationId,userId,role,status,acceptedAt,createdBy,createdAt,updatedAt)
        VALUES ('legacy_member','legacy_org','legacy_owner','owner','active',1,'legacy_owner',1,1);
      INSERT INTO audit_event (id,organizationId,workspaceId,actorType,actorId,action,resourceType,resourceId,outcome,metadata,createdAt)
        VALUES ('legacy_audit','legacy_org','legacy_ws','user','legacy_owner','exposure.domain.inventory','domain','legacy_domain','success','{}',1);
      INSERT INTO exposure_domain
        (id,organizationId,workspaceId,hostname,dnsRecordName,tokenHash,tokenPrefix,ownershipState,providerState,attachState,tlsState,createdBy,createdAt,updatedAt)
        VALUES ('legacy_domain','legacy_org','legacy_ws','app.legacy.test','_ysd-verification.app.legacy.test','hash','prefix','pending','no_owned_zone','detached','unavailable','legacy_owner',1,1);
    `);
    const before = {
      audit: (database.prepare('SELECT COUNT(*) AS total FROM audit_event').get() as { total: number }).total,
      domains: (database.prepare('SELECT COUNT(*) AS total FROM exposure_domain').get() as { total: number }).total,
      zeroMode: (database.prepare("SELECT zeroMode FROM workspace WHERE id = 'legacy_ws'").get() as { zeroMode: number }).zeroMode,
    };
    apply(database, '0012_workflows.sql');
    const after = {
      audit: (database.prepare('SELECT COUNT(*) AS total FROM audit_event').get() as { total: number }).total,
      domains: (database.prepare('SELECT COUNT(*) AS total FROM exposure_domain').get() as { total: number }).total,
      zeroMode: (database.prepare("SELECT zeroMode FROM workspace WHERE id = 'legacy_ws'").get() as { zeroMode: number }).zeroMode,
    };
    assert.deepEqual({ ...after }, { ...before });
    assert.equal((database.prepare('PRAGMA foreign_key_check').all()).length, 0);
    assert.equal((database.prepare('SELECT COUNT(*) AS total FROM workflow').get() as { total: number }).total, 0);
    assert.equal((database.prepare('SELECT COUNT(*) AS total FROM workflow_execution').get() as { total: number }).total, 0);
  } finally {
    database.close();
  }
});

void test('D1 dedupes events and duplicate executions idempotently', () => {
  const database = workflowDatabase();
  try {
    assert.throws(() => database.prepare(`INSERT INTO workflow_event
      (id,organizationId,workspaceId,projectId,type,resourceType,resourceId,payload,source,trusted,dedupeKey,correlationId,chainDepth,createdAt)
      VALUES ('wfevt_duplicate','org_1','ws_1','project_1','deployment.failed','deployment','dpl_1','{}','system',1,'deploy-failed:dpl_1:1','corr_2',0,2)`).run(), /UNIQUE constraint failed/);
    assert.throws(() => database.prepare(`INSERT INTO workflow_execution
      (id,organizationId,workspaceId,projectId,workflowId,versionId,eventId,state,idempotencyKey,correlationId,chainDepth,actionIndex,attempts,maxAttempts,timeoutAt,createdBy,createdAt,updatedAt)
      VALUES ('wfexec_duplicate','org_1','ws_1','project_1','wf_1','wfver_1','wfevt_1','queued','other-key','corr_1',0,0,0,3,999999,'system',2,2)`).run(), /UNIQUE constraint failed/);
  } finally {
    database.close();
  }
});

void test('D1 immutable versions and version rollback snapshots remain pinned', () => {
  const database = workflowDatabase();
  try {
    assert.throws(() => database.prepare("UPDATE workflow_version SET definition = '{\"changed\":true}' WHERE id = 'wfver_1'").run(), /append-only/);
    assert.throws(() => database.prepare("DELETE FROM workflow_version WHERE id = 'wfver_1'").run(), /append-only/);
    database.prepare(`INSERT INTO workflow_version
      (id,workflowId,organizationId,workspaceId,projectId,version,kind,triggerType,definition,definitionHash,sourceVersionId,createdBy,createdAt,publishedAt)
      VALUES ('wfver_2','wf_1','org_1','ws_1','project_1',2,'rollback','deployment.failed','{}','hash2','wfver_1','user_1',2,2)`).run();
    database.prepare("UPDATE workflow SET activeVersionId = 'wfver_2', latestVersion = 2 WHERE id = 'wf_1'").run();
    const execution = database.prepare("SELECT versionId FROM workflow_execution WHERE id = 'wfexec_1'").get() as { versionId: string };
    assert.equal(execution.versionId, 'wfver_1', 'existing execution stays on the version it started with');
    assert.equal((database.prepare("SELECT activeVersionId FROM workflow WHERE id = 'wf_1'").get() as { activeVersionId: string }).activeVersionId, 'wfver_2');
  } finally {
    database.close();
  }
});

void test('D1 rejects cross-organization workflow, event, execution, and secret references', () => {
  const database = workflowDatabase();
  try {
    assert.throws(() => database.prepare(`INSERT INTO workflow
      (id,organizationId,workspaceId,name,description,status,latestVersion,ownerUserId,failureStreak,createdBy,createdAt,updatedAt)
      VALUES ('wf_cross','org_2','ws_1','Cross','bad','draft',0,'user_2',0,'user_2',2,2)`).run(), /tenant mismatch/);
    assert.throws(() => database.prepare(`INSERT INTO workflow_event
      (id,organizationId,workspaceId,projectId,type,resourceType,resourceId,payload,source,trusted,dedupeKey,correlationId,chainDepth,createdAt)
      VALUES ('wfevt_cross','org_2','ws_1','project_1','deployment.failed','deployment','dpl_1','{}','system',1,'cross-event-key','corr_cross',0,2)`).run(), /tenant mismatch/);
    assert.throws(() => database.prepare(`INSERT INTO workflow_variable
      (id,workflowId,organizationId,workspaceId,projectId,name,kind,value,secretId,createdBy,createdAt,updatedAt)
      VALUES ('wfvar_cross','wf_1','org_1','ws_1','project_1','FOREIGN','secret',NULL,'secret_2','user_1',2,2)`).run(), /tenant mismatch/);
  } finally {
    database.close();
  }
});

void test('D1 enforces chain depth, execution states, action idempotency, and dead-letter fields', () => {
  const database = workflowDatabase();
  try {
    assert.throws(() => database.prepare(`INSERT INTO workflow_event
      (id,organizationId,workspaceId,projectId,type,resourceType,resourceId,payload,source,trusted,dedupeKey,correlationId,chainDepth,createdAt)
      VALUES ('wfevt_deep','org_1','ws_1','project_1','deployment.failed','deployment','dpl_1','{}','system',1,'deep-event-key','corr_deep',6,2)`).run(), /CHECK constraint failed/);
    database.prepare("UPDATE workflow_execution SET state = 'failed', attempts = 3, lastError = 'bounded failure', finishedAt = 3, deadLetterAt = 3 WHERE id = 'wfexec_1'").run();
    const failed = database.prepare("SELECT state, attempts, deadLetterAt FROM workflow_execution WHERE id = 'wfexec_1'").get() as { state: string; attempts: number; deadLetterAt: number };
    assert.equal(failed.state, 'failed');
    assert.equal(failed.attempts, 3);
    assert.equal(failed.deadLetterAt, 3);
    assert.throws(() => database.prepare("UPDATE workflow_execution SET state = 'retrying' WHERE id = 'wfexec_1'").run(), /CHECK constraint failed/);
    database.prepare(`INSERT INTO workflow_action_execution
      (id,organizationId,workspaceId,workflowId,executionId,actionIndex,attempt,actionType,state,idempotencyKey,startedAt)
      VALUES ('wfact_1','org_1','ws_1','wf_1','wfexec_1',0,1,'deployment.rollback_to_previous_healthy','succeeded','wf:wfexec_1:0',2)`).run();
    assert.throws(() => database.prepare(`INSERT INTO workflow_action_execution
      (id,organizationId,workspaceId,workflowId,executionId,actionIndex,attempt,actionType,state,idempotencyKey,startedAt)
      VALUES ('wfact_2','org_1','ws_1','wf_1','wfexec_1',0,1,'deployment.rollback_to_previous_healthy','succeeded','different',2)`).run(), /UNIQUE constraint failed/);
  } finally {
    database.close();
  }
});

void test('paused and draft workflows are excluded while active concurrency is bounded', () => {
  const database = workflowDatabase();
  try {
    database.prepare("UPDATE workflow SET status = 'paused' WHERE id = 'wf_1'").run();
    assert.equal((database.prepare("SELECT COUNT(*) AS total FROM workflow WHERE status = 'active' AND activeVersionId IS NOT NULL").get() as { total: number }).total, 0);
    database.prepare("UPDATE workflow SET status = 'draft', activeVersionId = NULL WHERE id = 'wf_1'").run();
    assert.equal((database.prepare("SELECT COUNT(*) AS total FROM workflow WHERE status = 'active' AND activeVersionId IS NOT NULL").get() as { total: number }).total, 0);
    database.prepare("UPDATE workflow SET status = 'active', activeVersionId = 'wfver_1' WHERE id = 'wf_1'").run();
    assert.equal((database.prepare("SELECT COUNT(*) AS total FROM workflow WHERE status = 'active' AND activeVersionId IS NOT NULL").get() as { total: number }).total, 1, 'published workflow is dispatchable');
    const engine = readFileSync(new URL('../lib/server/workflows.ts', import.meta.url), 'utf8');
    assert.match(engine, /COUNT\(\*\).*active[\s\S]*workflowId[\s\S]*concurrency\.workflow/);
    assert.match(engine, /COUNT\(\*\).*active[\s\S]*workspaceId[\s\S]*concurrency\.workspace/);
    assert.match(engine, /leaseToken/);
    assert.match(engine, /leaseExpiresAt/);
  } finally {
    database.close();
  }
});

void test('orphan workflow references are detected and all workflow tenant guards exist', () => {
  const database = workflowDatabase();
  try {
    database.prepare("UPDATE workflow SET activeVersionId = 'missing_version' WHERE id = 'wf_1'").run();
    const orphan = database.prepare(`SELECT COUNT(*) AS total FROM workflow w
      LEFT JOIN workflow_version v ON v.id = w.activeVersionId AND v.workflowId = w.id
      WHERE w.activeVersionId IS NOT NULL AND v.id IS NULL`).get() as { total: number };
    assert.equal(orphan.total, 1);
    const guards = database.prepare("SELECT COUNT(*) AS total FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'workflow_%tenant%guard'").get() as { total: number };
    assert.ok(guards.total >= 10);
    assert.equal((database.prepare('PRAGMA foreign_key_check').all()).length, 0);
  } finally {
    database.close();
  }
});

void test('forged event ingestion has no raw public endpoint and validates server resources', () => {
  const events = readFileSync(new URL('../lib/server/workflow-events.ts', import.meta.url), 'utf8');
  const route = readFileSync(new URL('../app/api/workflows/route.ts', import.meta.url), 'utf8');
  assert.match(events, /There is intentionally no public raw-event/);
  assert.match(events, /resourceProject/);
  assert.match(events, /workflow-forged-event/);
  assert.doesNotMatch(route, /emitWorkflowEvent/);
});

void test('event hooks use server-derived dedupe keys and preserve asynchronous causation', () => {
  const sources = [
    '../lib/server/deployments.ts', '../lib/server/nodes.ts',
    '../lib/server/app-runtime-control.ts', '../lib/server/shield-scan.ts',
    '../lib/server/organizations.ts',
  ].map((path) => readFileSync(new URL(path, import.meta.url), 'utf8'));
  for (const source of sources) {
    assert.match(source, /emitWorkflowEvent/);
    assert.match(source, /dedupeKey/);
  }
  const nodes = sources[1]!;
  const runtime = sources[2]!;
  const engine = readFileSync(new URL('../lib/server/workflows.ts', import.meta.url), 'utf8');
  const migrationSql = migration('0012_workflows.sql');
  for (const field of ['workflowId', 'workflowExecutionId', 'workflowCorrelationId', 'workflowChainDepth']) {
    assert.match(nodes, new RegExp(field));
    assert.match(migrationSql, new RegExp(field));
  }
  assert.match(runtime, /sourceWorkflowId: input\.job\.workflowId/);
  assert.match(runtime, /causationId: input\.job\.workflowExecutionId/);
  assert.match(engine, /workflow-self-trigger-blocked/);
  assert.match(engine, /sourceWorkflowId === workflow\.id/);
  assert.match(engine, /Maximum workflow event chain depth reached/);
});

void test('client-generated privileged events are absent and only authorized manual runs exist', () => {
  const workflowRoutes = [
    '../app/api/workflows/route.ts', '../app/api/workflows/[id]/route.ts',
    '../app/api/workflows/executions/[id]/route.ts',
  ].map((path) => readFileSync(new URL(path, import.meta.url), 'utf8')).join('\n');
  assert.doesNotMatch(workflowRoutes, /eventType|resourceId.*event|trusted\s*:/i);
  assert.match(workflowRoutes, /manual-run/);
  assert.match(workflowRoutes, /requireApiSession/);
});

void test('secret references expose metadata only and internal notifications remain tenant isolated', () => {
  const database = workflowDatabase();
  try {
    database.prepare(`INSERT INTO workflow_variable
      (id,workflowId,organizationId,workspaceId,projectId,name,kind,value,secretId,createdBy,createdAt,updatedAt)
      VALUES ('wfvar_1','wf_1','org_1','ws_1','project_1','SAFE_SECRET','secret',NULL,'secret_1','user_1',2,2)`).run();
    database.prepare(`INSERT INTO internal_notification
      (id,organizationId,workspaceId,projectId,userId,workflowId,executionId,title,message,severity,resourceType,resourceId,href,dedupeKey,createdAt)
      VALUES ('note_1','org_1','ws_1','project_1','user_1','wf_1','wfexec_1','Incident','Internal only','high','deployment','dpl_1','/workflows','note-key-1',2)`).run();
    assert.equal((database.prepare("SELECT COUNT(*) AS total FROM internal_notification WHERE organizationId = 'org_2'").get() as { total: number }).total, 0);
    assert.throws(() => database.prepare(`INSERT INTO internal_notification
      (id,organizationId,workspaceId,title,message,severity,resourceType,dedupeKey,createdAt)
      VALUES ('note_cross','org_2','ws_1','Cross','bad','high','workflow','note-cross',2)`).run(), /tenant mismatch/);
    const workflowServer = readFileSync(new URL('../lib/server/workflows.ts', import.meta.url), 'utf8');
    assert.match(workflowServer, /CASE WHEN v\.kind = 'secret' THEN NULL ELSE v\.value END/);
    assert.doesNotMatch(workflowServer, /SELECT\s+.*ciphertext.*workflow_variable/i);
    assert.doesNotMatch(migration('0012_workflows.sql'), /ciphertext|plaintext/i);
  } finally {
    database.close();
  }
});

void test('audit, runtime permission denial, Zero Mode validation, and action outcomes are recorded', () => {
  const engine = readFileSync(new URL('../lib/server/workflows.ts', import.meta.url), 'utf8');
  const route = readFileSync(new URL('../app/api/workflows/[id]/route.ts', import.meta.url), 'utf8');
  for (const action of [
    'workflow.execution.start', 'workflow.execution.end', 'workflow.execution.retry',
    'workflow.execution.manual_retry', 'workflow.action.outcome',
    'workflow.action.permission_denied',
  ]) assert.match(engine, new RegExp(action.replaceAll('.', '\\.')));
  assert.match(engine, /workflow owner no longer has permission|workflow owner is no longer active/i);
  assert.match(engine, /validateWorkflowDefinition/);
  assert.match(route, /recordAudit/);
  assert.match(route, /workflow\.change\.denied/);
});

void test('workflow Shield identifies every requested anomaly class', () => {
  const base: ShieldSnapshot = {
    zeroModeEnabled: true,
    protections: {
      turnstileConfigured: true, emailProviderConfigured: true,
      emailVerificationRequired: true, rateLimitEnabled: true,
      recentBlocks: 0, failingNetworks: 0, owners: 1, admins: 0,
      suspended: 0, unverifiedPrivileged: 0,
      securityHeaders: { present: [], missing: [], observed: false },
      orphanRoles: 0, suspendedPrivileged: 0, unscopedTables: [],
      sqlEditorRestricted: true,
    },
    billableResources: 0, secrets: [], users: { total: 1, unverified: 0 },
    sessions: { total: 0, expired: 0 }, tables: [], integrations: [],
    publicProjects: [], now: NOW,
    workflows: {
      privilegedLowOwner: 1, excessiveRetry: 1, potentialCycles: 1,
      noTimeout: 1, highConcurrency: 1, stale: 1, repeatedFailures: 1,
      suspiciousVolume: 1, orphanReferences: 1, crossOrgAttempts: 1,
      secretExposure: 1, zeroModeBypass: 1,
    },
  };
  const codes = new Set(runShieldRules(base).findings.map((item) => item.code));
  for (const code of [
    'workflow-privileged-low-owner', 'workflow-excessive-retry',
    'workflow-potential-cycle', 'workflow-timeout-policy',
    'workflow-concurrency-policy', 'workflow-stale',
    'workflow-repeated-failures', 'workflow-suspicious-volume',
    'workflow-orphan-reference', 'workflow-cross-org-attempt',
    'workflow-secret-exposure', 'workflow-zero-mode-bypass',
  ]) assert.equal(codes.has(code), true, code);
});

void test('Phase 9 stays on the existing Worker and D1 with one free cron trigger', () => {
  const wrangler = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
  const worker = readFileSync(new URL('../worker.ts', import.meta.url), 'utf8');
  assert.match(wrangler, /"name": "ysd-zero-cloud"/);
  assert.match(wrangler, /"database_name": "ysd-zero-cloud"/);
  assert.match(wrangler, /"crons": \["\* \* \* \* \*"\]/);
  assert.doesNotMatch(wrangler, /durable_objects|queues|workflows|r2_buckets/i);
  assert.match(worker, /runWorkflowEngineTick/);
  assert.match(worker, /scheduled\(/);
});

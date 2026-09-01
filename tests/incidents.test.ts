import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  INCIDENT_LIMITS,
  canManageIncident,
  canResolveIncident,
  isIncidentId,
  parseIncidentFilters,
  parseIncidentMutation,
  safeIncidentText,
} from '../lib/incidents.ts';
import { can, permissionForRequest, type Actor } from '../lib/roles.ts';
import { runShieldRules, type ShieldSnapshot } from '../lib/shield.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';
import { validateWorkflowDefinition, workflowPotentialCycle, type WorkflowDefinition } from '../lib/workflows.ts';

function migration(name: string): string {
  return readFileSync(new URL(`../db/migrations/${name}`, import.meta.url), 'utf8');
}

function apply(database: DatabaseSync, name: string): void {
  const sql = migration(name);
  if (name >= '0010_organizations.sql') {
    for (const statement of splitStatements(stripSqlComments(sql))) database.exec(statement);
  } else database.exec(sql);
}

function databaseBeforePhase11(): DatabaseSync {
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
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES
      ('user_owner','Owner','owner@test.invalid',1,NULL,1,1),
      ('user_dev','Developer','dev@test.invalid',1,NULL,1,1),
      ('user_other','Other','other@test.invalid',1,NULL,1,1);
    INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt) VALUES
      ('org_one','One','one','user_owner','active',1,1,1),
      ('org_two','Two','two','user_other','active',1,1,1);
    INSERT INTO workspace (id,organizationId,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt) VALUES
      ('ws_one','org_one','One','user_owner',1,1,1,0,1,1),
      ('ws_three','org_one','Three','user_dev',1,1,1,0,1,1),
      ('ws_two','org_two','Two','user_other',1,1,1,0,1,1);
    INSERT INTO organization_member (id,organizationId,userId,role,status,acceptedAt,createdBy,createdAt,updatedAt) VALUES
      ('member_owner','org_one','user_owner','owner','active',1,'user_owner',1,1),
      ('member_dev','org_one','user_dev','developer','active',1,'user_owner',1,1),
      ('member_other','org_two','user_other','owner','active',1,'user_other',1,1);
    INSERT INTO project (id,workspaceId,name,framework,environment,region,status,visibility,createdAt,updatedAt) VALUES
      ('project_one','ws_one','One','Node.js','Production','Local','idle','private',1,1),
      ('project_three','ws_three','Three','Node.js','Production','Local','idle','private',1,1),
      ('project_two','ws_two','Two','Node.js','Production','Local','idle','private',1,1);
  `);
  return database;
}

function incidentDatabase(): DatabaseSync {
  const database = databaseBeforePhase11();
  apply(database, '0014_incident_operations.sql');
  return database;
}

const owner: Actor = { userId: 'user_owner', role: 'owner', suspended: false, projectIds: null };
const admin: Actor = { userId: 'user_admin', role: 'admin', suspended: false, projectIds: null };
const developer: Actor = { userId: 'user_dev', role: 'developer', suspended: false, projectIds: ['project_one'] };
const viewer: Actor = { userId: 'user_viewer', role: 'viewer', suspended: false, projectIds: null };

void test('incident mutation parser allows only reviewed operations and safe bounded text', () => {
  assert.equal(parseIncidentMutation({ operation: 'acknowledge', expectedRevision: 1 }).ok, true);
  assert.equal(parseIncidentMutation({ operation: 'assign', assigneeId: 'user_dev', expectedRevision: 2 }).ok, true);
  assert.equal(parseIncidentMutation({ operation: 'note', note: 'Investigating node heartbeat.', expectedRevision: 3 }).ok, true);
  for (const note of [
    'https://internal.invalid/admin',
    'password=do-not-store',
    'Bearer abc.def.ghi',
    '<script>alert(1)</script>',
    'powershell -c whoami',
    '-----BEGIN PRIVATE KEY-----',
  ]) {
    const parsed = parseIncidentMutation({ operation: 'note', note, expectedRevision: 1 });
    assert.equal(parsed.ok, false, note);
  }
  assert.equal(safeIncidentText('a'.repeat(INCIDENT_LIMITS.noteCharacters + 1), INCIDENT_LIMITS.noteCharacters), null);
  assert.equal(parseIncidentMutation({ operation: 'resolve', resolution: 'Fixed.', expectedRevision: 1, eval: '1' }).ok, false);
  assert.equal(parseIncidentMutation({ operation: 'delete', expectedRevision: 1 }).ok, false);
});

void test('incident filters are allowlisted and strip unsafe search input', () => {
  const safe = parseIncidentFilters(new URLSearchParams('status=open&severity=critical&assignee=unassigned&projectId=project_one&search=node'));
  assert.deepEqual(safe, { status: 'open', severity: 'critical', assignee: 'unassigned', projectId: 'project_one', resourceType: 'all', search: 'node' });
  const unsafe = parseIncidentFilters(new URLSearchParams('status=owned&severity=root&search=https://127.0.0.1'));
  assert.equal(unsafe.status, 'all');
  assert.equal(unsafe.severity, 'all');
  assert.equal(unsafe.search, '');
});

void test('viewer/developer/admin/owner incident permissions and critical resolution are enforced', () => {
  assert.equal(can(viewer, 'incident.read'), true);
  assert.equal(canManageIncident(viewer, 'project_one'), false);
  assert.equal(canManageIncident(developer, 'project_one'), true);
  assert.equal(canManageIncident(developer, 'project_two'), false);
  assert.equal(canResolveIncident(developer, 'project_one', 'high'), true);
  assert.equal(canResolveIncident(developer, 'project_one', 'critical'), false);
  assert.equal(canResolveIncident(admin, null, 'critical'), true);
  assert.equal(canResolveIncident(owner, null, 'critical'), true);
  assert.equal(permissionForRequest('GET', '/api/incidents'), 'incident.read');
  assert.equal(permissionForRequest('PATCH', '/api/incidents/incident_abc'), 'incident.manage');
  assert.equal(isIncidentId('incident_0123456789abcdef01234567'), true);
  assert.equal(isIncidentId('incident_forged'), false);
});

void test('migration 0014 preserves and backfills Phase 9 incident rows', () => {
  const database = databaseBeforePhase11();
  try {
    database.exec(`
      INSERT INTO workflow
        (id,organizationId,workspaceId,projectId,name,description,status,latestVersion,ownerUserId,failureStreak,createdBy,createdAt,updatedAt)
      VALUES ('wf_legacy','org_one','ws_one','project_one','Legacy','Archived workflow history','paused',0,'user_owner',0,'user_owner',1,1);
      INSERT INTO workflow_incident
        (id,organizationId,workspaceId,projectId,workflowId,resourceType,resourceId,title,detail,severity,status,createdBy,createdAt,updatedAt)
      VALUES ('incident_111111111111111111111111','org_one','ws_one','project_one','wf_legacy','shield_finding','fnd_legacy','Legacy incident','Legacy safe detail','high','open','workflow:legacy',10,11)
    `);
    apply(database, '0014_incident_operations.sql');
    const row = database.prepare(`SELECT correlationId,dedupeKey,occurrenceCount,lastSeenAt,revision
      FROM workflow_incident WHERE id='incident_111111111111111111111111'`).get() as Record<string, unknown>;
    assert.deepEqual({ ...row }, {
      correlationId: 'incident:incident_111111111111111111111111',
      dedupeKey: 'legacy:incident_111111111111111111111111',
      occurrenceCount: 1,
      lastSeenAt: 11,
      revision: 1,
    });
    const event = database.prepare(`SELECT type,toStatus,metadata FROM incident_event
      WHERE incidentId='incident_111111111111111111111111'`).get() as { type: string; toStatus: string; metadata: string };
    assert.equal(event.type, 'incident.created');
    assert.equal(event.toStatus, 'open');
    assert.deepEqual(JSON.parse(event.metadata), { backfilled: 1 });
    database.prepare("UPDATE workflow SET deletedAt=20 WHERE id='wf_legacy'").run();
    assert.equal((database.prepare("SELECT workflowId FROM workflow_incident WHERE id='incident_111111111111111111111111'").get() as { workflowId: string }).workflowId, 'wf_legacy');
    assert.equal(database.prepare('PRAGMA foreign_key_check').all().length, 0);
  } finally { database.close(); }
});

void test('D1 incident dedupe is race-safe and timelines are append-only', () => {
  const database = incidentDatabase();
  try {
    const insert = `INSERT INTO workflow_incident
      (id,organizationId,workspaceId,projectId,resourceType,resourceId,title,detail,severity,status,createdBy,createdAt,updatedAt,correlationId,dedupeKey,occurrenceCount,lastSeenAt,revision)
      VALUES (?,?,?,?,?,?,?,?,?,'open','workflow:test',1,1,?,?,1,1,1)`;
    database.prepare(insert).run('incident_aaaaaaaaaaaaaaaaaaaaaaaa','org_one','ws_one','project_one','shield_finding','fnd_one','Title','Detail','high','corr_one','same-root');
    assert.throws(() => database.prepare(insert).run('incident_bbbbbbbbbbbbbbbbbbbbbbbb','org_one','ws_one','project_one','shield_finding','fnd_one','Title','Detail','high','corr_two','same-root'), /UNIQUE constraint failed/);
    database.prepare(`INSERT INTO incident_event
      (id,organizationId,workspaceId,projectId,incidentId,type,actorType,actorId,correlationId,toStatus,metadata,idempotencyKey,createdAt)
      VALUES ('incevt_one','org_one','ws_one','project_one','incident_aaaaaaaaaaaaaaaaaaaaaaaa','incident.created','workflow','workflow:test','corr_one','open','{}','created:one',1)`).run();
    assert.throws(() => database.prepare("UPDATE incident_event SET message='changed' WHERE id='incevt_one'").run(), /append-only/);
    assert.throws(() => database.prepare("DELETE FROM incident_event WHERE id='incevt_one'").run(), /append-only/);
    assert.throws(() => database.prepare(`INSERT INTO incident_event
      (id,organizationId,workspaceId,projectId,incidentId,type,actorType,actorId,correlationId,metadata,idempotencyKey,createdAt)
      VALUES ('incevt_cross','org_two','ws_two','project_two','incident_aaaaaaaaaaaaaaaaaaaaaaaa','incident.note_added','user','user_other','corr_one','{}','cross',2)`).run(), /tenant mismatch/);
  } finally { database.close(); }
});

void test('D1 rejects cross-tenant resources and non-member assignees', () => {
  const database = incidentDatabase();
  try {
    const columns = `(id,organizationId,workspaceId,projectId,resourceType,title,detail,severity,status,createdBy,createdAt,updatedAt,correlationId,dedupeKey,occurrenceCount,lastSeenAt,revision,assignedTo)`;
    assert.throws(() => database.prepare(`INSERT INTO workflow_incident ${columns}
      VALUES ('incident_cccccccccccccccccccccccc','org_two','ws_one','project_one','node','Cross','Detail','high','open','system',1,1,'corr_cross','dedupe_cross',1,1,1,NULL)`).run(), /tenant/);
    assert.throws(() => database.prepare(`INSERT INTO workflow_incident ${columns}
      VALUES ('incident_333333333333333333333333','org_one','ws_one','project_three','node','Cross workspace','Detail','high','open','system',1,1,'corr_workspace','dedupe_workspace',1,1,1,NULL)`).run(), /tenant/);
    assert.throws(() => database.prepare(`INSERT INTO workflow_incident ${columns}
      VALUES ('incident_dddddddddddddddddddddddd','org_one','ws_one','project_one','node','Assignee','Detail','high','open','system',1,1,'corr_assignee','dedupe_assignee',1,1,1,'user_other')`).run(), /assignee/);
    database.prepare(`INSERT INTO workflow_incident ${columns}
      VALUES ('incident_eeeeeeeeeeeeeeeeeeeeeeee','org_one','ws_one','project_one','node','Safe','Detail','critical','open','system',1,1,'corr_safe','dedupe_safe',1,1,1,'user_dev')`).run();
    assert.throws(() => database.prepare("UPDATE workflow_incident SET assignedTo='user_other' WHERE id='incident_eeeeeeeeeeeeeeeeeeeeeeee'").run(), /assignee/);
    database.prepare("UPDATE organization_member SET suspendedAt=2,status='suspended' WHERE id='member_dev'").run();
    database.prepare("UPDATE workflow_incident SET assignedTo=NULL WHERE id='incident_eeeeeeeeeeeeeeeeeeeeeeee'").run();
    assert.throws(() => database.prepare("UPDATE workflow_incident SET assignedTo='user_dev' WHERE id='incident_eeeeeeeeeeeeeeeeeeeeeeee'").run(), /assignee/);
  } finally { database.close(); }
});

void test('optimistic revision permits one winner and rejects the stale writer', () => {
  const database = incidentDatabase();
  try {
    database.exec(`INSERT INTO workflow_incident
      (id,organizationId,workspaceId,projectId,resourceType,title,detail,severity,status,createdBy,createdAt,updatedAt,correlationId,dedupeKey,occurrenceCount,lastSeenAt,revision)
      VALUES ('incident_ffffffffffffffffffffffff','org_one','ws_one','project_one','node','Race','Detail','medium','open','system',1,1,'corr_race','dedupe_race',1,1,1)`);
    const first = database.prepare(`UPDATE workflow_incident SET status='acknowledged',revision=revision+1,updatedAt=2 WHERE id=? AND revision=?`).run('incident_ffffffffffffffffffffffff', 1);
    const stale = database.prepare(`UPDATE workflow_incident SET status='resolved',revision=revision+1,updatedAt=3 WHERE id=? AND revision=?`).run('incident_ffffffffffffffffffffffff', 1);
    assert.equal(first.changes, 1);
    assert.equal(stale.changes, 0);
    assert.deepEqual({ ...database.prepare(`SELECT status,revision FROM workflow_incident WHERE id='incident_ffffffffffffffffffffffff'`).get() }, { status: 'acknowledged', revision: 2 });
  } finally { database.close(); }
});

void test('complete D1 lifecycle retains assignment, notes, resolution, reopen, occurrence and timeline evidence', () => {
  const database = incidentDatabase();
  try {
    database.exec(`INSERT INTO workflow_incident
      (id,organizationId,workspaceId,projectId,resourceType,resourceId,title,detail,severity,status,createdBy,createdAt,updatedAt,correlationId,dedupeKey,occurrenceCount,lastSeenAt,revision)
      VALUES ('incident_121212121212121212121212','org_one','ws_one','project_one','node','node_one','Lifecycle','Safe detail','medium','open','system',1,1,'corr_lifecycle','dedupe_lifecycle',1,1,1)`);
    const addEvent = database.prepare(`INSERT INTO incident_event
      (id,organizationId,workspaceId,projectId,incidentId,type,actorType,actorId,correlationId,fromStatus,toStatus,message,metadata,idempotencyKey,createdAt)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    addEvent.run('incevt_created','org_one','ws_one','project_one','incident_121212121212121212121212','incident.created','system','system','corr_lifecycle',null,'open',null,'{}','lifecycle:created',1);
    database.prepare("UPDATE workflow_incident SET assignedTo='user_dev',revision=2,updatedAt=2 WHERE id='incident_121212121212121212121212' AND revision=1").run();
    addEvent.run('incevt_assigned','org_one','ws_one','project_one','incident_121212121212121212121212','incident.assigned','user','user_owner','corr_lifecycle','open','open',null,'{"assigneeId":"user_dev"}','lifecycle:assigned',2);
    database.prepare("UPDATE workflow_incident SET status='acknowledged',acknowledgedAt=3,acknowledgedBy='user_dev',revision=3,updatedAt=3 WHERE id='incident_121212121212121212121212' AND revision=2").run();
    addEvent.run('incevt_ack','org_one','ws_one','project_one','incident_121212121212121212121212','incident.acknowledged','user','user_dev','corr_lifecycle','open','acknowledged',null,'{}','lifecycle:ack',3);
    database.prepare("UPDATE workflow_incident SET severity='high',revision=4,updatedAt=4 WHERE id='incident_121212121212121212121212' AND revision=3").run();
    addEvent.run('incevt_severity','org_one','ws_one','project_one','incident_121212121212121212121212','incident.severity_changed','user','user_dev','corr_lifecycle','acknowledged','acknowledged',null,'{"severity":"high"}','lifecycle:severity',4);
    database.prepare("UPDATE workflow_incident SET revision=5,updatedAt=5 WHERE id='incident_121212121212121212121212' AND revision=4").run();
    addEvent.run('incevt_note','org_one','ws_one','project_one','incident_121212121212121212121212','incident.note_added','user','user_dev','corr_lifecycle','acknowledged','acknowledged','Safe internal note.','{}','lifecycle:note',5);
    database.prepare("UPDATE workflow_incident SET occurrenceCount=2,lastSeenAt=6,revision=6,updatedAt=6 WHERE id='incident_121212121212121212121212' AND revision=5").run();
    addEvent.run('incevt_occurrence','org_one','ws_one','project_one','incident_121212121212121212121212','incident.occurrence','workflow','workflow:test','corr_lifecycle','acknowledged','acknowledged',null,'{"occurrenceCount":2}','lifecycle:occurrence',6);
    database.prepare("UPDATE workflow_incident SET status='resolved',resolvedAt=7,resolvedBy='user_owner',resolution='Recovered safely.',revision=7,updatedAt=7 WHERE id='incident_121212121212121212121212' AND revision=6").run();
    addEvent.run('incevt_resolved','org_one','ws_one','project_one','incident_121212121212121212121212','incident.resolved','user','user_owner','corr_lifecycle','acknowledged','resolved','Recovered safely.','{}','lifecycle:resolved',7);
    database.prepare("UPDATE workflow_incident SET status='open',resolvedAt=NULL,resolvedBy=NULL,resolution=NULL,revision=8,updatedAt=8 WHERE id='incident_121212121212121212121212' AND revision=7").run();
    addEvent.run('incevt_reopened','org_one','ws_one','project_one','incident_121212121212121212121212','incident.reopened','user','user_owner','corr_lifecycle','resolved','open',null,'{}','lifecycle:reopened',8);
    const incident = database.prepare("SELECT status,severity,assignedTo,occurrenceCount,acknowledgedAt,resolvedAt,revision FROM workflow_incident WHERE id='incident_121212121212121212121212'").get() as Record<string, unknown>;
    assert.deepEqual({ ...incident }, { status: 'open', severity: 'high', assignedTo: 'user_dev', occurrenceCount: 2, acknowledgedAt: 3, resolvedAt: null, revision: 8 });
    assert.equal((database.prepare("SELECT COUNT(*) total FROM incident_event WHERE incidentId='incident_121212121212121212121212'").get() as { total: number }).total, 8);
    assert.throws(() => addEvent.run('incevt_duplicate','org_one','ws_one','project_one','incident_121212121212121212121212','incident.reopened','user','user_owner','corr_lifecycle','resolved','open',null,'{}','lifecycle:reopened',9), /UNIQUE constraint failed/);
    database.prepare(`INSERT OR IGNORE INTO internal_notification
      (id,organizationId,workspaceId,projectId,userId,title,message,severity,resourceType,resourceId,href,dedupeKey,createdAt)
      VALUES ('note_one','org_one','ws_one','project_one','user_dev','Assigned','Lifecycle','high','incident','incident_121212121212121212121212','/incidents','incident-assigned:once',8)`).run();
    database.prepare(`INSERT OR IGNORE INTO internal_notification
      (id,organizationId,workspaceId,projectId,userId,title,message,severity,resourceType,resourceId,href,dedupeKey,createdAt)
      VALUES ('note_two','org_one','ws_one','project_one','user_dev','Assigned','Lifecycle','high','incident','incident_121212121212121212121212','/incidents','incident-assigned:once',8)`).run();
    assert.equal((database.prepare("SELECT COUNT(*) total FROM internal_notification WHERE dedupeKey='incident-assigned:once'").get() as { total: number }).total, 1);
  } finally { database.close(); }
});

void test('incident workflow triggers validate and incident-to-incident creation cycles are rejected', () => {
  const definition: WorkflowDefinition = {
    trigger: { type: 'incident.opened' },
    conditions: [{ path: 'event.payload.severity', operator: 'equals', value: 'critical' }],
    actions: [{ type: 'notification.create', target: 'event.resource', title: 'Incident opened', message: 'Review in Operations Center.', severity: 'critical' }],
    retry: { maxAttempts: 2, initialDelaySeconds: 5, maximumDelaySeconds: 30 },
    timeoutSeconds: 60,
    concurrency: { workflow: 1, workspace: 4 },
  };
  assert.equal(validateWorkflowDefinition(definition, { role: 'owner', projectId: null, zeroMode: true }).ok, true);
  const cycle: WorkflowDefinition = { ...definition, actions: [{ type: 'shield.create_incident', target: 'event.resource', title: 'Loop', message: 'Loop incident.', severity: 'high' }] };
  assert.equal(workflowPotentialCycle(cycle), true);
  assert.equal(validateWorkflowDefinition(cycle, { role: 'owner', projectId: null, zeroMode: true }).ok, false);
});

void test('Shield reports stale, unassigned, storm, orphan, tenant and denied-mutation incident signals', () => {
  const base: ShieldSnapshot = {
    zeroModeEnabled: true,
    protections: {
      turnstileConfigured: true, emailProviderConfigured: true, emailVerificationRequired: true,
      emailVerificationState: 'enabled', rateLimitEnabled: true, recentBlocks: 0, failingNetworks: 0,
      owners: 1, admins: 0, suspended: 0, unverifiedPrivileged: 0,
      securityHeaders: { present: [], missing: [], observed: true }, orphanRoles: 0,
      suspendedPrivileged: 0, unscopedTables: [], sqlEditorRestricted: true,
    },
    billableResources: 0, secrets: [], users: { total: 1, unverified: 0 }, sessions: { total: 1, expired: 0 },
    tables: [], integrations: [], publicProjects: [], now: 1,
    incidents: { staleCritical: 1, unassignedCritical: 1, storms: 1, orphanReferences: 1, crossTenantAnomalies: 1, suspiciousDeniedMutations: 1 },
  };
  const codes = new Set(runShieldRules(base).findings.map((finding) => finding.code));
  for (const code of ['incident-stale-critical','incident-critical-unassigned','incident-occurrence-storm','incident-orphan-reference','incident-cross-tenant-anomaly','incident-suspicious-denials']) assert.equal(codes.has(code), true, code);
});

void test('Operations implementation contains audit, notifications, hard limits and no outbound executor', () => {
  const server = readFileSync(new URL('../lib/server/incidents.ts', import.meta.url), 'utf8');
  const route = readFileSync(new URL('../app/api/incidents/[id]/route.ts', import.meta.url), 'utf8');
  const migrationSql = migration('0014_incident_operations.sql');
  assert.match(route, /recordAudit/);
  assert.match(route, /recordWorkflowSecurityEvent/);
  assert.match(server, /internal_notification/);
  assert.match(server, /occurrenceCount/);
  assert.match(server, /expectedRevision|revision/);
  assert.doesNotMatch(server, /fetch\s*\(/);
  assert.doesNotMatch(server, /eval\s*\(/);
  assert.match(migrationSql, /incident_event_append_only_update/);
  assert.match(migrationSql, /workflow_incident_active_dedupe_idx/);
});

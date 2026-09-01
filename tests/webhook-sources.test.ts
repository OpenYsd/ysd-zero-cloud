import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { consume, RATE_LIMIT_RULES } from '../lib/rate-limit.ts';
import { can, permissionForRequest, type Actor } from '../lib/roles.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';
import {
  createWebhookSignature,
  parseWebhookHeaders,
  parseWebhookPayload,
  verifyWebhookSignature,
  WEBHOOK_MAX_BODY_BYTES,
  WEBHOOK_TIMESTAMP_WINDOW_SECONDS,
  webhookBodySizeAllowed,
  webhookSigningPayload,
  webhookSourceAccepts,
  webhookTimestampAccepted,
} from '../lib/webhook-gateway.ts';
import {
  WORKFLOW_ACTION_TYPES,
  validateWorkflowDefinition,
  workflowConditionsMatch,
  type TrustedWorkflowEvent,
  type WorkflowDefinition,
} from '../lib/workflows.ts';

const NOW = Date.UTC(2026, 8, 1, 12, 0, 0);
const SOURCE_ID = 'whsrc_0123456789abcdef01234567';
const SECRET = 'ysd_whsec_test-only-value-with-entropy';
const RAW = '{"event":"build.completed","subject":"build_42","data":{"status":"ok","count":2,"success":true}}';
const EXTERNAL: WorkflowDefinition = {
  trigger: { type: 'external.event', sourceId: SOURCE_ID },
  conditions: [{ path: 'event.payload.externalEventType', operator: 'equals', value: 'build.completed' }],
  actions: [{
    type: 'notification.create', target: 'event.resource',
    title: 'External event accepted', message: 'A signed allowlisted event matched.', severity: 'low',
  }],
  retry: { maxAttempts: 3, initialDelaySeconds: 5, maximumDelaySeconds: 60 },
  timeoutSeconds: 60,
  concurrency: { workflow: 1, workspace: 4 },
};

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

function phase10Database(): DatabaseSync {
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
    INSERT INTO project (id,workspaceId,name,framework,environment,region,status,visibility,createdAt,updatedAt)
      VALUES ('project_1','ws_1','App','Node.js','Production','Local','idle','private',1,1), ('project_2','ws_2','Other','Node.js','Production','Local','idle','private',1,1);
    INSERT INTO webhook_source
      (id,organizationId,workspaceId,projectId,name,description,status,secretCiphertext,secretFingerprint,secretVersion,createdBy,createdAt,updatedAt)
      VALUES ('${SOURCE_ID}','org_1','ws_1','project_1','Build source','safe','enabled','v1.encrypted-only','fingerprint',1,'user_1',1,1);
  `);
  return database;
}

void test('valid signed event uses the exact versioned HMAC contract', async () => {
  const timestamp = Math.floor(NOW / 1_000);
  const eventId = 'evt_build_0001';
  const nonce = 'nonce_0123456789abcdef';
  const message = webhookSigningPayload(timestamp, eventId, nonce, RAW);
  const signature = await createWebhookSignature(SECRET, message);
  assert.match(signature, /^v1=[a-f0-9]{64}$/);
  assert.equal(await verifyWebhookSignature(SECRET, message, signature), true);
  assert.equal(await verifyWebhookSignature(`${SECRET}x`, message, signature), false);
  const headers = new Headers({
    'x-ysd-timestamp': String(timestamp), 'x-ysd-event-id': eventId,
    'x-ysd-nonce': nonce, 'x-ysd-signature': signature,
  });
  assert.equal(parseWebhookHeaders(headers).ok, true);
  assert.equal(parseWebhookPayload(JSON.parse(RAW)).ok, true);
});

void test('invalid signatures, malformed headers, and expired timestamps fail closed', async () => {
  const timestamp = Math.floor(NOW / 1_000);
  const message = webhookSigningPayload(timestamp, 'evt_build_0001', 'nonce_0123456789abcdef', RAW);
  const signature = await createWebhookSignature(SECRET, message);
  assert.equal(await verifyWebhookSignature(SECRET, `${message} `, signature), false);
  assert.equal(await verifyWebhookSignature(SECRET, message, 'v1=not-a-signature'), false);
  assert.equal(parseWebhookHeaders(new Headers()).ok, false);
  assert.equal(webhookTimestampAccepted(timestamp, NOW), true);
  assert.equal(webhookTimestampAccepted(timestamp - WEBHOOK_TIMESTAMP_WINDOW_SECONDS - 1, NOW), false);
  assert.equal(webhookTimestampAccepted(timestamp + WEBHOOK_TIMESTAMP_WINDOW_SECONDS + 1, NOW), false);
});

void test('JSON v1 is bounded and accepts only reviewed scalar fields', () => {
  assert.equal(WEBHOOK_MAX_BODY_BYTES, 32 * 1024);
  assert.equal(webhookBodySizeAllowed(String(WEBHOOK_MAX_BODY_BYTES)), true);
  assert.equal(webhookBodySizeAllowed(String(WEBHOOK_MAX_BODY_BYTES + 1)), false);
  assert.equal(webhookBodySizeAllowed(null), false);
  assert.throws(() => JSON.parse('{malformed'));
  for (const payload of [
    { event: 'build.completed', data: { unknown: 'value' } },
    { event: 'build.completed', data: { ref: 'https://169.254.169.254/latest' } },
    { event: 'build.completed', data: { action: 'powershell -c whoami' } },
    { event: 'build.completed', data: { value: '${process.env.SECRET}' } },
    { event: 'build.completed', provider: 'paid' },
    { event: 'Build Completed', data: {} },
    { event: 'build.completed', data: { count: 1_000_001 } },
    { event: 'build.completed', data: { nested: { arbitrary: true } } },
  ]) assert.equal(parseWebhookPayload(payload).ok, false, JSON.stringify(payload));
  const valid = parseWebhookPayload({
    event: 'deployment.observed', subject: 'deployment_42',
    data: { status: 'failed', severity: 'high', category: 'release', ref: 'abc123', count: 2, value: 0.5, success: false },
  });
  assert.equal(valid.ok, true);
});

void test('disabled and archived sources are refused before event creation', () => {
  assert.equal(webhookSourceAccepts('enabled', null), true);
  assert.equal(webhookSourceAccepts('disabled', null), false);
  assert.equal(webhookSourceAccepts('enabled', NOW), false);
  assert.equal(webhookSourceAccepts('archived', NOW), false);
});

void test('source and workspace rate limits exhaust at their independent Zero Mode caps', () => {
  let sourceState = null;
  for (let request = 0; request < RATE_LIMIT_RULES['webhook:source'].limit; request += 1) {
    const decision = consume(RATE_LIMIT_RULES['webhook:source'], sourceState, NOW);
    assert.equal(decision.allowed, true);
    sourceState = decision.next;
  }
  assert.equal(consume(RATE_LIMIT_RULES['webhook:source'], sourceState, NOW).allowed, false);
  assert.equal(RATE_LIMIT_RULES['webhook:workspace'].limit, 240);
});

void test('External Event trigger is source-bound and conditions read only allowlisted paths', () => {
  const validation = validateWorkflowDefinition(EXTERNAL, { role: 'owner', projectId: 'project_1', zeroMode: true });
  assert.equal(validation.ok, true);
  const event: TrustedWorkflowEvent = {
    id: 'wfevt_1', type: 'external.event', organizationId: 'org_1', workspaceId: 'ws_1',
    projectId: 'project_1', resourceId: SOURCE_ID,
    payload: { sourceId: SOURCE_ID, externalEventType: 'build.completed', externalEventId: 'evt_build_0001' },
    correlationId: 'whcorr_1', causationId: null, sourceWorkflowId: null,
    chainDepth: 0, createdAt: NOW,
  };
  if (validation.ok) assert.equal(workflowConditionsMatch(validation.definition, event), true);
  assert.equal(validateWorkflowDefinition({ ...EXTERNAL, trigger: { type: 'external.event', sourceId: 'forged' } }, { role: 'owner', projectId: 'project_1', zeroMode: true }).ok, false);
  assert.equal(validateWorkflowDefinition({ ...EXTERNAL, trigger: { type: 'external.event', sourceId: SOURCE_ID, endpoint: 'http://localhost' } }, { role: 'owner', projectId: 'project_1', zeroMode: true }).ok, false);
  assert.equal(validateWorkflowDefinition({ ...EXTERNAL, conditions: [{ path: 'event.payload.constructor', operator: 'equals', value: 'x' }] }, { role: 'owner', projectId: 'project_1', zeroMode: true }).ok, false);
});

void test('webhook permissions are owner/admin managed and viewer readable', () => {
  const actor = (role: Actor['role']): Actor => ({ userId: role, role, suspended: false, projectIds: null });
  assert.equal(can(actor('viewer'), 'webhook.read'), true);
  assert.equal(can(actor('viewer'), 'webhook.manage'), false);
  assert.equal(can(actor('developer'), 'webhook.manage'), false);
  assert.equal(can(actor('admin'), 'webhook.manage'), true);
  assert.equal(can(actor('owner'), 'webhook.manage'), true);
  assert.equal(permissionForRequest('GET', '/api/webhook-sources'), 'webhook.read');
  assert.equal(permissionForRequest('POST', '/api/webhook-sources'), 'webhook.manage');
});

void test('D1 deduplicates external event IDs and nonce hashes per source', () => {
  const database = phase10Database();
  try {
    database.prepare(`INSERT INTO webhook_replay_guard
      (organizationId,workspaceId,sourceId,externalEventId,nonceHash,receivedAt)
      VALUES ('org_1','ws_1',?,'evt_build_0001','nonce_hash_1',1)`).run(SOURCE_ID);
    assert.throws(() => database.prepare(`INSERT INTO webhook_replay_guard
      (organizationId,workspaceId,sourceId,externalEventId,nonceHash,receivedAt)
      VALUES ('org_1','ws_1',?,'evt_build_0001','nonce_hash_2',2)`).run(SOURCE_ID), /UNIQUE constraint failed/);
    assert.throws(() => database.prepare(`INSERT INTO webhook_replay_guard
      (organizationId,workspaceId,sourceId,externalEventId,nonceHash,receivedAt)
      VALUES ('org_1','ws_1',?,'evt_build_0002','nonce_hash_1',2)`).run(SOURCE_ID), /UNIQUE constraint failed/);
  } finally {
    database.close();
  }
});

void test('D1 blocks cross-workspace sources, deliveries, and forged source identities', () => {
  const database = phase10Database();
  try {
    assert.throws(() => database.prepare(`INSERT INTO webhook_source
      (id,organizationId,workspaceId,name,description,status,secretCiphertext,secretFingerprint,secretVersion,createdBy,createdAt,updatedAt)
      VALUES ('whsrc_aaaaaaaaaaaaaaaaaaaaaaaa','org_2','ws_1','Cross','bad','enabled','cipher','fp',1,'user_2',2,2)`).run(), /tenant mismatch/);
    assert.throws(() => database.prepare(`INSERT INTO webhook_replay_guard
      (organizationId,workspaceId,sourceId,externalEventId,nonceHash,receivedAt)
      VALUES ('org_2','ws_2',?,'evt_forged_001','nonce_hash',2)`).run(SOURCE_ID), /tenant mismatch/);
    assert.throws(() => database.prepare(`INSERT INTO webhook_delivery
      (id,organizationId,workspaceId,sourceId,projectId,status,receivedAt)
      VALUES ('whdel_cross','org_2','ws_2',?,'project_2','rejected',2)`).run(SOURCE_ID), /tenant mismatch/);
    assert.throws(() => database.prepare(`INSERT INTO webhook_source
      (id,organizationId,workspaceId,projectId,name,description,status,secretCiphertext,secretFingerprint,secretVersion,createdBy,createdAt,updatedAt)
      VALUES ('whsrc_bbbbbbbbbbbbbbbbbbbbbbbb','org_1','ws_1','project_2','Forged','bad','enabled','cipher','fp',1,'user_1',2,2)`).run(), /tenant mismatch/);
    database.prepare(`INSERT INTO webhook_delivery
      (id,organizationId,workspaceId,sourceId,projectId,status,receivedAt)
      VALUES ('whdel_1','org_1','ws_1',?,'project_1','accepted',2)`).run(SOURCE_ID);
    assert.throws(() => database.prepare(`UPDATE webhook_delivery
      SET organizationId = 'org_2', workspaceId = 'ws_2' WHERE id = 'whdel_1'`).run(), /tenant is immutable/);
    assert.equal(database.prepare('PRAGMA foreign_key_check').all().length, 0);
  } finally {
    database.close();
  }
});

void test('migration 0013 preserves Phase 9 workflow and execution history', () => {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  try {
    for (const name of [
      '0001_auth.sql', '0002_workspace.sql', '0003_auth_rate_limit.sql',
      '0004_security.sql', '0005_storage.sql', '0006_compute_nodes.sql',
      '0007_ai_compute.sql', '0008_game_servers.sql', '0009_app_runtime.sql',
      '0010_organizations.sql', '0011_public_exposure.sql', '0012_workflows.sql',
    ]) apply(database, name);
    database.exec(`
      INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES ('user_1','Owner','owner@test.invalid',1,NULL,1,1);
      INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt) VALUES ('org_1','One','one','user_1','active',1,1,1);
      INSERT INTO workspace (id,organizationId,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt) VALUES ('ws_1','org_1','One','user_1',1,1,1,0,1,1);
      INSERT INTO workflow (id,organizationId,workspaceId,name,description,status,latestVersion,ownerUserId,failureStreak,createdBy,createdAt,updatedAt) VALUES ('wf_1','org_1','ws_1','Phase 9','kept','draft',0,'user_1',0,'user_1',1,1);
    `);
    const before = (database.prepare('SELECT COUNT(*) AS total FROM workflow').get() as { total: number }).total;
    apply(database, '0013_external_event_gateway.sql');
    assert.equal((database.prepare('SELECT COUNT(*) AS total FROM workflow').get() as { total: number }).total, before);
    assert.equal((database.prepare('SELECT COUNT(*) AS total FROM webhook_source').get() as { total: number }).total, 0);
    assert.equal(database.prepare('PRAGMA foreign_key_check').all().length, 0);
  } finally {
    database.close();
  }
});

void test('secret and payload exposure are absent from views, deliveries, audit, and logs', () => {
  const server = readFileSync(new URL('../lib/server/webhook-sources.ts', import.meta.url), 'utf8');
  const migrationSql = migration('0013_external_event_gateway.sql');
  assert.match(server, /encryptSecret\(secret, masterKey\(\)\)/);
  assert.match(server, /Copy this secret now|secretCiphertext/);
  assert.match(server, /No payload was retained/);
  assert.doesNotMatch(migrationSql, /rawPayload|rawBody|signature\s+TEXT|nonce\s+TEXT/i);
  assert.doesNotMatch(server, /console\.(?:log|warn|error)\([^\n]*(?:raw|secret|signature|nonce)/i);
  assert.match(server, /secretCiphertext: _secretCiphertext/);
  assert.match(server, /metadata: \{ reasonCode: input\.code \}/);
  const studio = readFileSync(new URL('../lib/server/studio.ts', import.meta.url), 'utf8');
  assert.match(studio, /webhook_source: \['secretCiphertext', 'secretFingerprint'\]/);
});

void test('inbound route is HMAC-authenticated and no generic outbound executor exists', () => {
  const inbound = readFileSync(new URL('../app/api/webhooks/inbound/[sourceId]/route.ts', import.meta.url), 'utf8');
  const gateway = readFileSync(new URL('../lib/server/webhook-sources.ts', import.meta.url), 'utf8');
  const worker = readFileSync(new URL('../worker.ts', import.meta.url), 'utf8');
  const wrangler = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
  assert.match(inbound, /ingestWebhook/);
  assert.doesNotMatch(inbound, /requireApiSession/);
  assert.match(gateway, /verifyWebhookSignature/);
  assert.match(gateway, /type: 'external\.event'/);
  assert.match(gateway, /emitWorkflowEvent/);
  assert.equal(WORKFLOW_ACTION_TYPES.some((action) => /http|shell|script|command|provider/i.test(action)), false);
  assert.doesNotMatch(gateway, /fetch\(|eval\(|child_process|exec\(/);
  assert.match(worker, /workflow tick complete/);
  assert.match(wrangler, /"crons": \["\* \* \* \* \*"\]/);
  assert.doesNotMatch(wrangler, /durable_objects|queues|workflows|r2_buckets/i);
});

void test('observability and security rejection paths contain only safe metadata', () => {
  const gateway = readFileSync(new URL('../lib/server/webhook-sources.ts', import.meta.url), 'utf8');
  const contract = readFileSync(new URL('../lib/webhook-gateway.ts', import.meta.url), 'utf8');
  const engine = readFileSync(new URL('../lib/server/workflows.ts', import.meta.url), 'utf8');
  for (const counter of [
    'receivedCount', 'acceptedCount', 'rejectedCount',
    'deduplicatedCount', 'workflowExecutionsCreated',
  ]) assert.match(gateway + engine, new RegExp(counter));
  for (const code of [
    'invalid-signature', 'expired-timestamp', 'malformed-json', 'body-size',
    'source-disabled', 'source-archived', 'rate-limited', 'duplicate-event',
    'replayed-event', 'unsafe-payload',
  ]) assert.match(gateway + contract, new RegExp(code));
  assert.match(gateway, /recordWorkflowSecurityEvent/);
  assert.match(gateway, /recordAudit/);
  assert.match(engine, /externalEventId/);
  assert.match(engine, /correlationId/);
});

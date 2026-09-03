import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  EVIDENCE_ACTIONS,
  EVIDENCE_LIMITS,
  EVIDENCE_TABLES,
  evidenceAction,
  isEvidenceAction,
  narrowEvidenceMetadata,
} from '../lib/audit-actions.ts';
import { RETENTION_DATA_CLASSES } from '../lib/retention.ts';
import { runShieldRules, type ShieldSnapshot } from '../lib/shield.ts';
import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

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

const MIGRATIONS = readdirSync(new URL('../db/migrations', import.meta.url))
  .filter((file) => file.endsWith('.sql'))
  .sort();

/** Everything up to but excluding Phase 13, so the upgrade can be exercised. */
function databaseBeforePhase13(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  for (const name of MIGRATIONS.filter((file) => file < '0016_audit_integrity.sql')) {
    apply(database, name);
  }
  database.exec(`
    INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES
      ('user_one','One','one@test.invalid',1,NULL,1,1),
      ('user_two','Two','two@test.invalid',1,NULL,1,1);
    INSERT INTO organization (id,name,slug,ownerUserId,status,adminCanRevokeSessions,createdAt,updatedAt) VALUES
      ('org_one','One','one','user_one','active',1,1,1),
      ('org_two','Two','two','user_two','active',1,1,1);
    INSERT INTO workspace (id,organizationId,name,ownerUserId,zeroMode,autoScan,sleepIdleServers,previewDeployments,createdAt,updatedAt) VALUES
      ('ws_one','org_one','One','user_one',1,1,1,0,1,1),
      ('ws_two','org_two','Two','user_two',1,1,1,0,1,1);
  `);
  return database;
}

function insertAudit(
  database: DatabaseSync,
  id: string,
  organizationId: string,
  workspaceId: string | null,
  createdAt: number,
  action = 'test.action',
): void {
  database
    .prepare(
      `INSERT INTO audit_event
         (id,organizationId,workspaceId,actorType,actorId,action,resourceType,outcome,metadata,createdAt)
       VALUES (?,?,?,'user','user_one',?,'test','success','{}',?)`,
    )
    .run(id, organizationId, workspaceId, action, createdAt);
}

function phase13Database(): DatabaseSync {
  const database = databaseBeforePhase13();
  apply(database, '0016_audit_integrity.sql');
  return database;
}

function sequences(database: DatabaseSync, organizationId: string): number[] {
  return (
    database
      .prepare('SELECT sequence FROM audit_sequence WHERE organizationId = ? ORDER BY sequence')
      .all(organizationId) as { sequence: number }[]
  ).map((row) => Number(row.sequence));
}

void test('migration 0016 backfills existing audit history deterministically and replays safely', () => {
  const database = databaseBeforePhase13();
  try {
    // Deliberately inserted out of order, and with a createdAt collision, so the
    // stable tie-breaker is exercised rather than assumed.
    insertAudit(database, 'audit_c', 'org_one', 'ws_one', 300);
    insertAudit(database, 'audit_a', 'org_one', 'ws_one', 100);
    insertAudit(database, 'audit_b', 'org_one', 'ws_one', 100);
    insertAudit(database, 'audit_z', 'org_two', 'ws_two', 200);

    apply(database, '0016_audit_integrity.sql');

    const ordered = database
      .prepare('SELECT auditId, sequence FROM audit_sequence WHERE organizationId = ? ORDER BY sequence')
      .all('org_one') as { auditId: string; sequence: number }[];
    // createdAt ascending, then id ascending.
    assert.deepEqual(
      ordered.map((row) => row.auditId),
      ['audit_a', 'audit_b', 'audit_c'],
    );
    assert.deepEqual(ordered.map((row) => Number(row.sequence)), [1, 2, 3]);
    // Each organization numbers from 1 independently.
    assert.deepEqual(sequences(database, 'org_two'), [1]);

    // The lazy migration runner may execute the file again on a cold isolate.
    const before = Number(
      (database.prepare('SELECT COUNT(*) AS total FROM audit_sequence').get() as { total: number }).total,
    );
    apply(database, '0016_audit_integrity.sql');
    const after = Number(
      (database.prepare('SELECT COUNT(*) AS total FROM audit_sequence').get() as { total: number }).total,
    );
    assert.equal(after, before);

    // Existing evidence is untouched by the upgrade.
    assert.equal(
      Number((database.prepare('SELECT COUNT(*) AS total FROM audit_event').get() as { total: number }).total),
      4,
    );
  } finally {
    database.close();
  }
});

void test('D1 numbers every new audit record monotonically and per organization', () => {
  const database = phase13Database();
  try {
    insertAudit(database, 'audit_1', 'org_one', 'ws_one', 10);
    insertAudit(database, 'audit_2', 'org_one', 'ws_one', 20);
    insertAudit(database, 'audit_3', 'org_two', 'ws_two', 30);
    insertAudit(database, 'audit_4', 'org_one', null, 40);

    assert.deepEqual(sequences(database, 'org_one'), [1, 2, 3]);
    assert.deepEqual(sequences(database, 'org_two'), [1]);

    // The application never supplies the value; it is assigned by the trigger.
    const assigned = database
      .prepare('SELECT sequence FROM audit_sequence WHERE auditId = ?')
      .get('audit_4') as { sequence: number };
    assert.equal(Number(assigned.sequence), 3);
  } finally {
    database.close();
  }
});

void test('audit evidence and its numbering are both immutable and cannot be forged', () => {
  const database = phase13Database();
  try {
    insertAudit(database, 'audit_1', 'org_one', 'ws_one', 10);

    assert.throws(
      () => database.prepare("UPDATE audit_event SET action='changed' WHERE id='audit_1'").run(),
      /append-only/,
    );
    assert.throws(
      () => database.prepare("DELETE FROM audit_event WHERE id='audit_1'").run(),
      /append-only/,
    );
    assert.throws(
      () => database.prepare("UPDATE audit_sequence SET sequence=99 WHERE auditId='audit_1'").run(),
      /append-only/,
    );
    assert.throws(
      () => database.prepare("DELETE FROM audit_sequence WHERE auditId='audit_1'").run(),
      /append-only/,
    );

    // A number may not be attributed to another organization.
    assert.throws(
      () =>
        database
          .prepare(
            "INSERT INTO audit_sequence (auditId,organizationId,sequence,createdAt) VALUES ('audit_1','org_two',7,1)",
          )
          .run(),
      /tenant mismatch/,
    );

    // Nor may a position be reused inside one organization.
    insertAudit(database, 'audit_2', 'org_one', 'ws_one', 20);
    assert.throws(
      () =>
        database
          .prepare(
            "INSERT INTO audit_sequence (auditId,organizationId,sequence,createdAt) VALUES ('audit_2','org_one',1,1)",
          )
          .run(),
      /UNIQUE|constraint/i,
    );
  } finally {
    database.close();
  }
});

void test('every evidence action is recorded by the route the catalog names', () => {
  // The 0.12.1 lesson: an inventory is only trustworthy when something compares
  // it against the real surface. This asserts catalog and routes cannot drift.
  const routeSources = new Map<string, string>();
  const records = (action: string): boolean => {
    const entry = evidenceAction(action);
    if (!entry) return false;
    if (!routeSources.has(entry.route)) routeSources.set(entry.route, source(entry.route));
    const text = routeSources.get(entry.route)!;
    return text.includes('recordEvidence') && text.includes(`'${action}'`);
  };

  for (const entry of EVIDENCE_ACTIONS) {
    assert.ok(records(entry.action), `${entry.action} is not recorded by ${entry.route}`);
    assert.ok(entry.resourceType.length > 0, `${entry.action} has no resourceType`);
    assert.ok(entry.why.length > 0, `${entry.action} has no rationale`);
  }

  // The detector discriminates: an action nothing records must fail the same
  // check, otherwise the assertions above would pass vacuously.
  assert.equal(records('never.recorded.anywhere'), false);

  const names = EVIDENCE_ACTIONS.map((entry) => entry.action);
  assert.equal(new Set(names).size, names.length, 'action names must be unique');
  assert.equal(isEvidenceAction('secret.delete'), true);
  assert.equal(isEvidenceAction('not.an.action'), false);
});

void test('high-impact privileged routes no longer rely on operational logging alone', () => {
  // Each of these previously existed only as `writeLog`, which lands in the
  // mutable, retention-prunable `log_event` table.
  for (const action of [
    'secret.write',
    'secret.delete',
    'deployment.action',
    'node.revoke',
    'project.delete',
    'storage.delete',
    'game-server.action',
    'workspace.settings.update',
    'admin.user.update',
    'database.query.execute',
  ]) {
    const entry = evidenceAction(action);
    assert.ok(entry, `${action} must be catalogued`);
    assert.ok(source(entry.route).includes('recordEvidence'), `${action} route must write evidence`);
  }
});

void test('the SQL Editor records that a statement ran without storing the statement', () => {
  const route = source('app/api/database/query/route.ts');
  assert.match(route, /statementFingerprint\(sql\)/);
  // The raw text must never reach the evidence trail under any metadata key.
  assert.doesNotMatch(route, /metadata:\s*\{[^}]*\bsql\b\s*[,}]/);
  assert.doesNotMatch(route, /statement:\s*sql/);
  // Refusals are evidence too: a closed editor and a blocked statement both record.
  assert.match(route, /outcome: 'denied'/);
  assert.match(route, /outcome: 'failed'/);
  assert.match(route, /outcome: 'success'/);

  const audit = source('lib/server/audit.ts');
  assert.match(audit, /sha256Hex\(statement\)/);
  assert.match(audit, /EVIDENCE_LIMITS\.hashLength/);
  assert.ok(EVIDENCE_LIMITS.hashLength <= 64 && EVIDENCE_LIMITS.hashLength >= 16);
});

void test('evidence metadata is narrowed to the keys each action declares', () => {
  const audit = source('lib/server/audit.ts');
  // Per-action allowlist (executed above) on top of the global forbidden-key
  // filter that every audit write passes through.
  assert.match(audit, /narrowEvidenceMetadata\(entry\.action, input\.metadata\)/);
  assert.match(audit, /FORBIDDEN_METADATA_KEY/);

  // No catalogued action may declare a key the global filter would strip,
  // which would otherwise read as permitted while never being written.
  const forbidden = /secret|token|password|prompt|result|payload|content/i;
  for (const entry of EVIDENCE_ACTIONS) {
    for (const key of entry.metadataKeys) {
      assert.doesNotMatch(key, forbidden, `${entry.action} declares unwritable key ${key}`);
    }
    assert.ok(
      entry.metadataKeys.length <= EVIDENCE_LIMITS.metadataKeys,
      `${entry.action} declares too many metadata keys`,
    );
  }

  // Secret operations must never describe the material itself.
  const secretWrite = evidenceAction('secret.write');
  assert.ok(secretWrite);
  for (const banned of ['value', 'ciphertext', 'fingerprint', 'plaintext', 'name']) {
    assert.ok(
      !secretWrite.metadataKeys.includes(banned),
      `secret.write must not record ${banned}`,
    );
  }
});

void test('metadata narrowing drops undeclared keys and bounds the values it keeps', () => {
  // Executed, not merely asserted from source: this is the rule that keeps a
  // caller from writing a field an action never declared.
  assert.deepEqual(
    narrowEvidenceMetadata('secret.write', {
      environment: 'Production',
      scope: 'Workspace',
      rotated: true,
      // None of these are declared by secret.write and must all disappear.
      value: 'super-secret-value',
      ciphertext: 'AAAA',
      fingerprint: 'abcd',
      name: 'STRIPE_KEY',
    }),
    { environment: 'Production', scope: 'Workspace', rotated: true },
  );

  // Long strings are bounded rather than stored whole.
  const long = narrowEvidenceMetadata('database.query.execute', {
    statementHash: 'x'.repeat(1_000),
  });
  assert.equal((long.statementHash as string).length, EVIDENCE_LIMITS.stringValue);

  // An action with no declared keys keeps nothing.
  assert.deepEqual(narrowEvidenceMetadata('node.revoke', { anything: 1 }), {});
  // An unknown action keeps nothing at all.
  assert.deepEqual(narrowEvidenceMetadata('not.an.action', { a: 1 }), {});
  // Absent metadata is an empty object, never undefined.
  assert.deepEqual(narrowEvidenceMetadata('secret.delete', undefined), {});
});

void test('retention can never select an evidence table', () => {
  const registry = source('lib/server/retention.ts');
  for (const table of EVIDENCE_TABLES) {
    assert.ok(
      !registry.includes(`table: '${table}'`),
      `${table} must not be a retention data class`,
    );
    assert.ok(
      !(RETENTION_DATA_CLASSES as readonly string[]).includes(table),
      `${table} must not appear as a data class name`,
    );
  }
  // The prunable class that motivated this phase still exists and still targets
  // the operational log, so telemetry stays reclaimable.
  assert.ok(registry.includes("table: 'log_event'"));
  assert.ok((RETENTION_DATA_CLASSES as readonly string[]).includes('platform-logs'));
  // And retention writes no DELETE against evidence.
  assert.doesNotMatch(registry, /DELETE FROM (?:audit_event|audit_sequence)/);
});

void test('pruning platform logs cannot remove audit evidence', () => {
  const database = phase13Database();
  try {
    insertAudit(database, 'audit_1', 'org_one', 'ws_one', 10, 'secret.delete');
    database
      .prepare(
        `INSERT INTO log_event (id,workspaceId,level,source,message,createdAt)
         VALUES ('log_1','ws_one','WARN','secret','Deleted a secret',10)`,
      )
      .run();

    // The exact bounded statement Phase 12 retention runs for platform logs.
    database
      .prepare(
        `DELETE FROM log_event WHERE id IN (
           SELECT t.id FROM log_event t WHERE t.workspaceId = ? AND t.createdAt < ?
            ORDER BY t.createdAt ASC LIMIT ?)`,
      )
      .run('ws_one', 1_000, 100);

    assert.equal(
      Number((database.prepare('SELECT COUNT(*) AS total FROM log_event').get() as { total: number }).total),
      0,
    );
    // The evidence survives the prune that removed the telemetry.
    assert.equal(
      Number((database.prepare('SELECT COUNT(*) AS total FROM audit_event').get() as { total: number }).total),
      1,
    );
    assert.deepEqual(sequences(database, 'org_one'), [1]);
  } finally {
    database.close();
  }
});

void test('previously silent retention refusals now leave evidence', () => {
  const route = source('app/api/retention/[id]/route.ts');
  const server = source('lib/server/retention.ts');

  // Unknown data-class probe: recorded, and the identifier is hashed rather
  // than replayed into the trail.
  assert.match(route, /'retention\.unknown-class\.denied'/);
  assert.match(route, /classHash: await statementFingerprint\(id\)/);
  // Scoped to the unknown-class block: the later `retention.invalid.denied`
  // record may name the class, because by then it is a validated catalog value
  // rather than attacker-supplied text.
  const probeBlock = route.slice(
    route.indexOf('if (!isRetentionDataClass(id))'),
    route.indexOf('const parsedBody'),
  );
  assert.ok(probeBlock.includes('classHash'));
  assert.doesNotMatch(probeBlock, /dataClass: id/);

  // Optimistic-concurrency conflict: recorded before the 409 returns.
  assert.match(server, /'retention\.change\.conflict'/);
  const conflictIndex = server.indexOf("'retention.change.conflict'");
  const returnIndex = server.indexOf(
    'The retention policy changed since it was loaded',
    conflictIndex,
  );
  assert.ok(conflictIndex > 0 && returnIndex > conflictIndex, 'evidence must precede the 409');

  // The client response stays safe: no internal code is leaked.
  assert.doesNotMatch(route, /error: securityCode/);
});

function auditSnapshot(state: ShieldSnapshot['auditIntegrity']): ShieldSnapshot {
  // A complete-enough snapshot: the audit rules are the subject, so everything
  // else is set to a quiet baseline rather than left undefined.
  return {
    zeroModeEnabled: true,
    protections: {
      turnstileConfigured: true,
      emailProviderConfigured: true,
      emailVerificationRequired: true,
      emailVerificationState: 'enabled',
      rateLimitEnabled: true,
      recentBlocks: 0,
      failingNetworks: 0,
      owners: 1,
      admins: 0,
      suspended: 0,
      unverifiedPrivileged: 0,
      securityHeaders: {
        present: [
          'content-security-policy',
          'strict-transport-security',
          'x-content-type-options',
          'x-frame-options',
          'referrer-policy',
        ],
        missing: [],
        observed: true,
      },
      orphanRoles: 0,
      suspendedPrivileged: 0,
      unscopedTables: [],
      sqlEditorRestricted: true,
    },
    billableResources: 0,
    secrets: [],
    users: { total: 1, unverified: 0 },
    sessions: { total: 1, expired: 0 },
    tables: [{ name: 'project', hasPrimaryKey: true, rows: 4 }],
    integrations: [{ id: 'cloudflare-d1', status: 'configured' }],
    publicProjects: [],
    auditIntegrity: state,
    now: 1,
  } as unknown as ShieldSnapshot;
}

void test('Shield reports audit integrity and stays quiet when the trail is intact', () => {
  const clean = runShieldRules(
    auditSnapshot({ unnumbered: 0, orphanNumbering: 0, sequenceGap: false, latestSequence: 12 }),
  );
  const cleanCodes = clean.findings.map((finding) => finding.code);
  for (const code of ['audit-evidence-unnumbered', 'audit-evidence-missing', 'audit-sequence-gap']) {
    assert.ok(!cleanCodes.includes(code), `${code} must not fire on an intact trail`);
  }
  assert.equal(clean.checks.find((check) => check.id === 'audit-integrity')?.state, 'passed');

  const broken = runShieldRules(
    auditSnapshot({ unnumbered: 2, orphanNumbering: 1, sequenceGap: true, latestSequence: 9 }),
  );
  const brokenCodes = broken.findings.map((finding) => finding.code);
  assert.ok(brokenCodes.includes('audit-evidence-unnumbered'));
  assert.ok(brokenCodes.includes('audit-evidence-missing'));
  assert.ok(brokenCodes.includes('audit-sequence-gap'));
  assert.equal(broken.checks.find((check) => check.id === 'audit-integrity')?.state, 'failed');

  // Removed evidence is the loudest possible signal.
  assert.equal(
    broken.findings.find((finding) => finding.code === 'audit-evidence-missing')?.severity,
    'critical',
  );

  // Codes and resources are constants, so a repeat scan updates one finding
  // instead of opening a second.
  const repeat = runShieldRules(
    auditSnapshot({ unnumbered: 2, orphanNumbering: 1, sequenceGap: true, latestSequence: 9 }),
  );
  assert.deepEqual(
    repeat.findings.map((finding) => `${finding.code}:${finding.resource}`).sort(),
    broken.findings.map((finding) => `${finding.code}:${finding.resource}`).sort(),
  );
});

void test('evidence writes take tenancy from the session and never from the request', () => {
  for (const entry of EVIDENCE_ACTIONS) {
    const route = source(entry.route);
    // Every evidence call reads organization and workspace from a resolved
    // session — as `auth.session` in a route, or as an already-resolved
    // session or tenant passed into a service. What matters is that none of
    // these can originate in a request body; the next two assertions enforce
    // that directly.
    assert.match(
      route,
      /organizationId: (?:auth\.session\.organization\.id|input\.session\.organization\.id|input\.organizationId)/,
    );
    // A request body must never be able to name the tenant of an audit record.
    assert.doesNotMatch(route, /organizationId: (?:body|parsed\.body)\./);
    assert.doesNotMatch(route, /actorId: (?:body|parsed\.body)\./);
  }
});

void test('Phase 13 adds no billable binding and no new database', () => {
  const wrangler = source('wrangler.jsonc');
  assert.equal((wrangler.match(/"binding": "DB"/g) ?? []).length, 1);
  assert.equal((wrangler.match(/"database_id"/g) ?? []).length, 1);
  assert.doesNotMatch(wrangler, /durable_objects|queues|workflows|r2_buckets|analytics_engine_datasets|kv_namespaces/i);
  assert.match(wrangler, /"crons": \["\* \* \* \* \*"\]/);

  const phase13 = [source('lib/audit-actions.ts'), source('lib/server/audit.ts')].join('\n');
  assert.doesNotMatch(phase13, /fetch\(|eval\(|new Function|child_process/);
  assert.doesNotMatch(migration('0016_audit_integrity.sql'), /DROP TABLE|DELETE FROM audit_event/i);
});

/**
 * The one gate that failed Production acceptance for 0.13.1.
 *
 * The sequence column shipped and worked, but the only thing explaining it was
 * a native `title` on each data cell. Hover never fires on touch, a `title` is
 * not announced as a column description, and a bare integer nobody can
 * interpret is not usable evidence — the number has to say what a break in it
 * means, or an operator cannot act on it.
 */
void test('the audit table explains what a position is and what a gap means', () => {
  const view = source('components/collaboration-views.tsx');

  // The column is named, not just "#".
  assert.match(view, /<TableHead scope="col" aria-describedby=\{AUDIT_POSITION_HELP_ID\}>Position<\/TableHead>/);

  // The description is a real element, carrying the same id the header points at.
  assert.match(view, /const AUDIT_POSITION_HELP_ID = 'audit-position-help';/);
  assert.match(view, /id=\{AUDIT_POSITION_HELP_ID\}/);

  // Fixed id, so the association survives hydration. A generated one is what
  // broke this release once already.
  assert.doesNotMatch(view, /AUDIT_POSITION_HELP_ID = (useId|`|.*Math\.random)/);

  // The explanation has to carry the semantics, not just the word "position".
  const helpStart = view.indexOf('id={AUDIT_POSITION_HELP_ID}');
  assert.ok(helpStart > 0, 'the description element must exist');
  const help = view.slice(helpStart, view.indexOf('</p>', helpStart));
  assert.match(help, /permanent/i);
  assert.match(help, /assigned in order/i);
  assert.match(help, /missing position/i);
  assert.match(help, /investigated/i);

  // The old per-cell tooltip is gone: it was the thing that failed acceptance,
  // and repeating it on every row only adds screen-reader noise.
  assert.doesNotMatch(view, /<TableCell[^>]*title="Position in this organization/);

  // The icon is decorative — the sentence beside it is the accessible text.
  assert.match(view, /<Info aria-hidden="true"/);
});

void test('Phase 14 catalog grew by exactly the two implemented readiness actions', () => {
  // Pinned deliberately: 23 (Phase 13 + P0) + 2 (readiness) = 25. A silent
  // removal or rename of either action must fail this assertion by name, not
  // just as a shrinking total.
  assert.equal(EVIDENCE_ACTIONS.length, 25);

  const readinessActions = EVIDENCE_ACTIONS.filter((entry) =>
    entry.action.startsWith('project.readiness.'),
  ).map((entry) => entry.action);
  assert.deepEqual(readinessActions.sort(), [
    'project.readiness.analyze',
    'project.readiness.denied',
  ]);

  const analyze = EVIDENCE_ACTIONS.find((entry) => entry.action === 'project.readiness.analyze')!;
  // Never manifest content, dependency names, tokens, or headers -- only the
  // identity of what was analyzed and the verdict reached.
  assert.deepEqual(
    [...analyze.metadataKeys].sort(),
    ['blockedCount', 'branch', 'commit', 'framework', 'owner', 'reportVersion', 'repository', 'verdict'].sort(),
  );
  for (const forbidden of ['manifest', 'dependenc', 'token', 'header', 'sql', 'password']) {
    assert.ok(
      !analyze.metadataKeys.some((key) => key.toLowerCase().includes(forbidden)),
      `project.readiness.analyze must not carry a "${forbidden}"-shaped key`,
    );
  }

  const denied = EVIDENCE_ACTIONS.find((entry) => entry.action === 'project.readiness.denied')!;
  assert.deepEqual([...denied.metadataKeys], ['reason']);
});

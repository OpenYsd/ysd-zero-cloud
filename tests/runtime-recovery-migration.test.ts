import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

const migrationNames = readdirSync(new URL('../db/migrations', import.meta.url))
  .filter((name) => name.endsWith('.sql'))
  .sort();

function source(name: string): string {
  return readFileSync(new URL(`../db/migrations/${name}`, import.meta.url), 'utf8');
}

function apply(database: DatabaseSync, name: string): void {
  for (const statement of splitStatements(stripSqlComments(source(name)))) database.exec(statement);
}

function databaseAt0019(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  for (const name of migrationNames.filter((name) => name < '0020_runtime_recovery.sql')) {
    apply(database, name);
  }
  return database;
}

void test('migration 0020 is additive, bounded, and registered by the lazy runner', () => {
  const sql = source('0020_runtime_recovery.sql');
  assert.doesNotMatch(sql, /DROP\s+(?:TABLE|COLUMN)|DELETE\s+FROM|CREATE\s+TRIGGER/i);
  assert.match(sql, /desiredState/);
  assert.match(sql, /observedState/);
  assert.match(sql, /availabilityState/);
  const runner = readFileSync(new URL('../lib/server/db.ts', import.meta.url), 'utf8');
  assert.match(runner, /0020_runtime_recovery\.sql\?raw/);
  assert.match(runner, /\{ name: '0020_runtime_recovery', sql: runtimeRecoverySchema \}/);
});

void test('a fresh database migrates through 0020 with desired and observed state separated', () => {
  const database = new DatabaseSync(':memory:');
  try {
    for (const name of migrationNames) apply(database, name);
    const deploymentColumns = database.prepare('SELECT name FROM pragma_table_info(?)').all('deployment')
      .map((row) => (row as { name: string }).name);
    const artifactColumns = database.prepare('SELECT name FROM pragma_table_info(?)').all('app_artifact')
      .map((row) => (row as { name: string }).name);
    for (const name of ['desiredState', 'desiredRevision', 'observedState', 'lastReconciledAt',
      'recoveryStatus', 'recoveryReasonCode', 'recoveryRevision', 'recoveryGeneration']) {
      assert.ok(deploymentColumns.includes(name), `missing deployment.${name}`);
    }
    for (const name of ['availabilityState', 'lastVerifiedOnNodeAt']) {
      assert.ok(artifactColumns.includes(name), `missing app_artifact.${name}`);
    }
  } finally {
    database.close();
  }
});

void test('0019 to 0020 preserves rows and performs conservative compatibility backfill', () => {
  const database = databaseAt0019();
  try {
    database.exec('PRAGMA foreign_keys = OFF');
    database.exec(`
      INSERT INTO deployment
        (id,workspaceId,projectId,repository,target,framework,commitSha,state,
         estimatedMonthlyCost,zeroModeEnabled,plan,createdAt,finishedAt)
      VALUES
        ('dpl_running','ws_one',NULL,'OpenYsd/app','user-node','Node.js','aaa','healthy',0,1,'{}',1,NULL),
        ('dpl_stopped','ws_one',NULL,'OpenYsd/app','user-node','Node.js','bbb','stopped',0,1,'{}',2,2);
      INSERT INTO app_artifact
        (id,workspaceId,deploymentId,projectId,nodeId,commitSha,version,state,manifest,sizeBytes,createdAt)
      VALUES ('art_existing','ws_one','dpl_running','prj_one','node_one','aaa',1,'verified','{}',7,1);
    `);
    const beforeDeployment = database.prepare(
      'SELECT id,repository,commitSha,state,estimatedMonthlyCost,zeroModeEnabled FROM deployment ORDER BY id',
    ).all();
    const beforeArtifact = database.prepare(
      'SELECT id,deploymentId,commitSha,version,state,sizeBytes FROM app_artifact',
    ).all();
    apply(database, '0020_runtime_recovery.sql');
    assert.deepEqual(database.prepare(
      'SELECT id,repository,commitSha,state,estimatedMonthlyCost,zeroModeEnabled FROM deployment ORDER BY id',
    ).all(), beforeDeployment);
    assert.deepEqual(database.prepare(
      'SELECT id,deploymentId,commitSha,version,state,sizeBytes FROM app_artifact',
    ).all(), beforeArtifact);
    assert.deepEqual(database.prepare(
      'SELECT id,desiredState,desiredRevision,observedState FROM deployment ORDER BY id',
    ).all().map((row) => ({ ...row })), [
      { id: 'dpl_running', desiredState: 'running', desiredRevision: 1, observedState: 'unknown' },
      { id: 'dpl_stopped', desiredState: 'stopped', desiredRevision: 1, observedState: 'stopped' },
    ]);
    assert.equal((database.prepare(
      'SELECT availabilityState FROM app_artifact WHERE id = ?'
    ).get('art_existing') as { availabilityState: string }).availabilityState, 'unknown');
  } finally {
    database.close();
  }
});

void test('0020 remains readable by the 0.17 column projection after schema-first rollout', () => {
  const database = databaseAt0019();
  try {
    database.exec('PRAGMA foreign_keys = OFF');
    database.exec(`INSERT INTO deployment
      (id,workspaceId,repository,target,framework,commitSha,state,estimatedMonthlyCost,
       zeroModeEnabled,plan,createdAt) VALUES
      ('dpl_old','ws_one','OpenYsd/app','user-node','Node.js','aaa','healthy',0,1,'{}',1)`);
    apply(database, '0020_runtime_recovery.sql');
    const oldWorkerProjection = { ...database.prepare(
      'SELECT id,repository,state,zeroModeEnabled,createdAt FROM deployment WHERE id = ?'
    ).get('dpl_old')! };
    assert.deepEqual(oldWorkerProjection, {
      id: 'dpl_old', repository: 'OpenYsd/app', state: 'healthy', zeroModeEnabled: 1, createdAt: 1,
    });
  } finally {
    database.close();
  }
});

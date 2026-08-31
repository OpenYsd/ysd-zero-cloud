import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DENY_ALL,
  isSchemaOnlyTable,
  scopeForTable,
  type TenantScope,
} from '../lib/tenancy.ts';

const SCOPE: TenantScope = {
  organizationId: 'org_1',
  workspaceId: 'ws_1',
  userId: 'usr_1',
};

void test('workspace-owned tables are limited by workspaceId', () => {
  for (const table of [
    'project',
    'deployment',
    'log_event',
    'secret',
    'shield_scan',
    'shield_finding',
    'storage_object',
    'storage_meter',
    'node_pairing',
    'compute_node',
    'node_request_nonce',
    'node_job',
    'node_metric',
    'node_job_event',
    'node_security_event',
    'ai_model',
    'ai_model_cache',
    'ai_inference',
  ]) {
    const predicate = scopeForTable(
      table,
      ['id', 'workspaceId', 'createdAt'],
      SCOPE,
    );
    assert.equal(
      predicate.sql,
      'workspaceId = ?',
      `${table} must be workspace-scoped`,
    );
    assert.deepEqual(predicate.params, ['ws_1']);
  }
});

void test('the workspace row is matched by its own id', () => {
  const predicate = scopeForTable(
    'workspace',
    ['id', 'name', 'ownerUserId'],
    SCOPE,
  );
  assert.equal(predicate.sql, 'id = ?');
  assert.deepEqual(predicate.params, ['ws_1']);
});

void test('organization-owned tables are limited by organizationId', () => {
  for (const table of ['organization_member', 'organization_invitation', 'audit_event']) {
    const predicate = scopeForTable(table, ['id', 'organizationId'], SCOPE);
    assert.equal(predicate.sql, 'organizationId = ?');
    assert.deepEqual(predicate.params, ['org_1']);
  }
  const organization = scopeForTable('organization', ['id', 'name'], SCOPE);
  assert.equal(organization.sql, 'id = ?');
  assert.deepEqual(organization.params, ['org_1']);
});

void test('project-restricted callers fail closed outside project-attributable tables', () => {
  const restricted = { ...SCOPE, projectIds: ['project_a', 'project_b'] };
  assert.deepEqual(
    scopeForTable('project', ['id', 'workspaceId'], restricted),
    {
      sql: 'workspaceId = ? AND id IN (?, ?)',
      params: ['ws_1', 'project_a', 'project_b'],
    },
  );
  assert.deepEqual(
    scopeForTable('deployment', ['id', 'workspaceId', 'projectId'], restricted),
    {
      sql: 'workspaceId = ? AND projectId IN (?, ?)',
      params: ['ws_1', 'project_a', 'project_b'],
    },
  );
  assert.deepEqual(
    scopeForTable('node_job', ['id', 'workspaceId'], restricted),
    DENY_ALL,
  );
  assert.deepEqual(
    scopeForTable('project', ['id', 'workspaceId'], { ...SCOPE, projectIds: [] }),
    DENY_ALL,
  );
});

void test('a caller sees only their own user row', () => {
  const predicate = scopeForTable('user', ['id', 'email', 'name'], SCOPE);
  assert.equal(predicate.sql, 'id = ?');
  assert.deepEqual(predicate.params, ['usr_1']);
});

void test('auth records are limited to the caller', () => {
  for (const table of ['account', 'session']) {
    const predicate = scopeForTable(
      table,
      ['id', 'userId', 'createdAt'],
      SCOPE,
    );
    assert.equal(predicate.sql, 'userId = ?', `${table} must be user-scoped`);
    assert.deepEqual(predicate.params, ['usr_1']);
  }
});

void test('verification rows cannot be attributed to a caller, so none are shown', () => {
  // Keyed by email address with no owner column: showing any row would show
  // another operator's pending verification.
  const predicate = scopeForTable(
    'verification',
    ['id', 'identifier', 'value'],
    SCOPE,
  );
  assert.deepEqual(predicate, DENY_ALL);
});

void test('an unclassified table fails closed rather than open', () => {
  const predicate = scopeForTable(
    'some_future_table',
    ['id', 'payload'],
    SCOPE,
  );
  assert.deepEqual(
    predicate,
    DENY_ALL,
    'a new table must be invisible until scoped',
  );
});

void test('schema-only tables carry no tenant data and stay visible', () => {
  for (const table of ['d1_migrations', 'ysd_migration']) {
    assert.equal(isSchemaOnlyTable(table), true);
    const predicate = scopeForTable(table, ['name', 'appliedAt'], SCOPE);
    assert.equal(predicate.sql, '1 = 1');
    assert.deepEqual(predicate.params, []);
  }
});

void test('workspaceId wins over userId when a table carries both', () => {
  const predicate = scopeForTable(
    'deployment',
    ['id', 'workspaceId', 'userId'],
    SCOPE,
  );
  assert.equal(predicate.sql, 'workspaceId = ?');
  assert.deepEqual(predicate.params, ['ws_1']);
});

void test('every predicate is a bound expression, never an interpolated value', () => {
  for (const [table, columns] of [
    ['project', ['workspaceId']],
    ['workspace', ['id']],
    ['user', ['id']],
    ['session', ['userId']],
    ['verification', ['identifier']],
  ] as const) {
    const predicate = scopeForTable(table, columns, {
      workspaceId: "ws' OR 1=1 --",
      userId: "usr' OR 1=1 --",
    });
    assert.doesNotMatch(
      predicate.sql,
      /OR 1=1/,
      `${table} interpolated a scope value into SQL`,
    );
  }
});

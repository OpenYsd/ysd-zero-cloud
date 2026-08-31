import assert from 'node:assert/strict';
import test from 'node:test';
import {
  atLeast,
  can,
  canAccessProject,
  canChangeRole,
  canSuspend,
  isRole,
  isServiceTokenScope,
  normalizeRole,
  permissionForRequest,
  ROLES,
  type Actor,
} from '../lib/roles.ts';

const owner: Actor = { userId: 'u_owner', role: 'owner', suspended: false };
const admin: Actor = { userId: 'u_admin', role: 'admin', suspended: false };
const developer: Actor = { userId: 'u_developer', role: 'developer', suspended: false };
const viewer: Actor = { userId: 'u_viewer', role: 'viewer', suspended: false };

void test('role guard and legacy normalization accept only the four organization roles', () => {
  for (const role of ROLES) assert.equal(isRole(role), true);
  assert.equal(isRole('member'), false);
  assert.equal(normalizeRole('member'), 'developer');
  assert.equal(normalizeRole('superuser'), 'viewer');
});

void test('rank ordering is owner, admin, developer, viewer', () => {
  assert.equal(atLeast('owner', 'admin'), true);
  assert.equal(atLeast('admin', 'developer'), true);
  assert.equal(atLeast('developer', 'viewer'), true);
  assert.equal(atLeast('viewer', 'developer'), false);
  assert.equal(atLeast('admin', 'owner'), false);
});

void test('the permission matrix separates member administration and ordinary work', () => {
  assert.equal(can(owner, 'member.transfer-ownership'), true);
  assert.equal(can(admin, 'member.manage'), true);
  assert.equal(can(developer, 'deployment.deploy'), true);
  assert.equal(can(developer, 'member.manage'), false);
  assert.equal(can(viewer, 'project.read'), true);
  assert.equal(can(viewer, 'project.create'), false);
  assert.equal(can(viewer, 'invitation.read'), false);
  assert.equal(can(viewer, 'exposure.read'), true);
  assert.equal(can(viewer, 'exposure.preview'), false);
  assert.equal(can(developer, 'exposure.preview'), true);
  assert.equal(can(developer, 'exposure.manage'), false);
  assert.equal(can(admin, 'exposure.manage'), true);
  assert.equal(can(admin, 'domain.manage'), true);
  assert.equal(can(owner, 'domain.manage'), true);
});

void test('raw SQL and legacy instance-wide user administration are disabled for every role', () => {
  for (const actor of [owner, admin, developer, viewer]) {
    assert.equal(can(actor, 'sql-editor.run'), false);
    assert.equal(can(actor, 'admin.users.read'), false);
    assert.equal(can(actor, 'admin.users.write'), false);
  }
});

void test('a suspended account loses every capability', () => {
  const suspendedOwner: Actor = { ...owner, suspended: true };
  assert.equal(can(suspendedOwner, 'organization.read'), false);
  assert.equal(can(suspendedOwner, 'workspace.use'), false);
  assert.equal(can(suspendedOwner, 'member.transfer-ownership'), false);
});

void test('nobody may change their own role', () => {
  const decision = canChangeRole(owner, { userId: owner.userId, role: 'owner' }, 'viewer', 1);
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.equal(decision.reason, 'self');
});

void test('an admin cannot act on another admin or the owner', () => {
  const peer = canChangeRole(admin, { userId: 'u_other', role: 'admin' }, 'viewer', 2);
  assert.equal(peer.allowed, false);
  if (!peer.allowed) assert.equal(peer.reason, 'outranked');

  const superior = canChangeRole(admin, { userId: 'u_owner', role: 'owner' }, 'viewer', 2);
  assert.equal(superior.allowed, false);
  if (!superior.allowed) assert.equal(superior.reason, 'outranked');
});

void test('an admin may promote a developer to admin but never to owner', () => {
  assert.deepEqual(
    canChangeRole(admin, { userId: 'u_d', role: 'developer' }, 'admin', 1),
    { allowed: true },
  );
  const grantOwner = canChangeRole(admin, { userId: 'u_d', role: 'developer' }, 'owner', 1);
  assert.equal(grantOwner.allowed, false);
  if (!grantOwner.allowed) assert.equal(grantOwner.reason, 'cannot-grant-owner');
});

void test('the last owner cannot be demoted by the generic role flow', () => {
  const decision = canChangeRole(
    { userId: 'u_second_owner', role: 'owner', suspended: false },
    { userId: 'u_designated_owner', role: 'owner' },
    'admin',
    1,
  );
  assert.equal(decision.allowed, false);
  if (!decision.allowed) assert.equal(decision.reason, 'last-owner');
});

void test('developers and viewers cannot manage members', () => {
  for (const actor of [developer, viewer]) {
    const decision = canChangeRole(actor, { userId: 'u_x', role: 'viewer' }, 'developer', 1);
    assert.equal(decision.allowed, false);
    if (!decision.allowed) assert.equal(decision.reason, 'not-permitted');
  }
});

void test('suspension follows role rank and self-protection rules', () => {
  assert.equal(canSuspend(admin, { userId: 'u_d', role: 'developer' }).allowed, true);
  assert.equal(canSuspend(admin, { userId: 'u_a2', role: 'admin' }).allowed, false);
  const onSelf = canSuspend(admin, { userId: admin.userId, role: 'admin' });
  assert.equal(onSelf.allowed, false);
  if (!onSelf.allowed) assert.equal(onSelf.reason, 'self');
});

void test('project-restricted actors can access only allowed project resources', () => {
  const restricted: Actor = { ...developer, projectIds: ['project_a'] };
  assert.equal(canAccessProject(restricted, 'project_a'), true);
  assert.equal(canAccessProject(restricted, 'project_b'), false);
  assert.equal(can(restricted, 'deployment.deploy'), true);
  assert.equal(can(restricted, 'node.manage'), false);
  assert.equal(can(restricted, 'database.read'), false);
});

void test('service tokens are the intersection of role, scope, and project boundary', () => {
  assert.equal(isServiceTokenScope('deployment.deploy'), true);
  assert.equal(isServiceTokenScope('secret.write'), true);
  assert.equal(isServiceTokenScope('member.manage'), false);
  const token: Actor = {
    ...developer,
    serviceAccountId: 'sa_1',
    projectIds: ['project_a'],
    tokenScopes: ['deployment.deploy', 'node.read'],
  };
  assert.equal(can(token, 'deployment.deploy'), true);
  assert.equal(can(token, 'deployment.read'), false);
  assert.equal(can(token, 'node.read'), false);
  assert.equal(can(token, 'member.manage'), false);
});

void test('route policy maps collaboration-safe project and database operations', () => {
  assert.equal(permissionForRequest('GET', '/api/projects'), 'project.read');
  assert.equal(permissionForRequest('POST', '/api/projects'), 'project.create');
  assert.equal(permissionForRequest('POST', '/api/deployments/x/actions'), 'deployment.lifecycle');
  assert.equal(permissionForRequest('POST', '/api/database/query'), 'sql-editor.run');
  assert.equal(permissionForRequest('GET', '/api/exposures'), 'exposure.read');
  assert.equal(permissionForRequest('POST', '/api/exposures'), 'exposure.preview');
  assert.equal(permissionForRequest('GET', '/api/domains'), 'exposure.read');
  assert.equal(permissionForRequest('POST', '/api/domains'), 'domain.manage');
});

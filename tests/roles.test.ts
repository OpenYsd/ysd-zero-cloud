import assert from 'node:assert/strict';
import test from 'node:test';
import {
  atLeast,
  can,
  canChangeRole,
  canSuspend,
  isRole,
  ROLES,
  type Actor,
} from '../lib/roles.ts';

const owner: Actor = { userId: 'u_owner', role: 'owner', suspended: false };
const admin: Actor = { userId: 'u_admin', role: 'admin', suspended: false };
const member: Actor = { userId: 'u_member', role: 'member', suspended: false };

void test('role guard accepts only real roles', () => {
  for (const role of ROLES) assert.equal(isRole(role), true);
  assert.equal(isRole('superuser'), false);
  assert.equal(isRole('Owner'), false);
  assert.equal(isRole(''), false);
});

void test('rank ordering is owner over admin over member', () => {
  assert.equal(atLeast('owner', 'admin'), true);
  assert.equal(atLeast('admin', 'admin'), true);
  assert.equal(atLeast('member', 'admin'), false);
  assert.equal(atLeast('admin', 'owner'), false);
});

void test('only owner and admin may administer accounts', () => {
  assert.equal(can(owner, 'admin.users.read'), true);
  assert.equal(can(admin, 'admin.users.write'), true);
  assert.equal(can(member, 'admin.users.read'), false);
});

void test('the SQL Editor stays owner-only and admins do not inherit it', () => {
  // A raw statement cannot be scoped to one workspace, so widening this
  // would hand every tenant's rows to anyone with the admin role.
  assert.equal(can(owner, 'sql-editor.run'), true);
  assert.equal(can(admin, 'sql-editor.run'), false);
  assert.equal(can(member, 'sql-editor.run'), false);
});

void test('a suspended account loses every capability including its own workspace', () => {
  const suspendedOwner: Actor = { ...owner, suspended: true };
  assert.equal(can(suspendedOwner, 'admin.users.read'), false);
  assert.equal(can(suspendedOwner, 'sql-editor.run'), false);
  assert.equal(can(suspendedOwner, 'workspace.use'), false);
});

void test('nobody may change their own role', () => {
  const decision = canChangeRole(owner, { userId: owner.userId, role: 'owner' }, 'member', 2);
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'self');
});

void test('an admin cannot act on another admin or on the owner', () => {
  const peer = canChangeRole(admin, { userId: 'u_other', role: 'admin' }, 'member', 1);
  assert.equal(peer.allowed, false);
  assert.equal(peer.reason, 'outranked');

  const superior = canChangeRole(admin, { userId: 'u_owner', role: 'owner' }, 'member', 1);
  assert.equal(superior.allowed, false);
  assert.equal(superior.reason, 'outranked');
});

void test('an admin may promote a member to admin but never to owner', () => {
  const promote = canChangeRole(admin, { userId: 'u_m', role: 'member' }, 'admin', 1);
  assert.equal(promote.allowed, true);

  const grantOwner = canChangeRole(admin, { userId: 'u_m', role: 'member' }, 'owner', 1);
  assert.equal(grantOwner.allowed, false);
  assert.equal(grantOwner.reason, 'cannot-grant-owner');
});

void test('the last owner cannot be demoted', () => {
  const lastOne = canChangeRole(owner, { userId: 'u_other', role: 'owner' }, 'member', 1);
  // An owner acting on an equal is refused first, which is itself correct.
  assert.equal(lastOne.allowed, false);
});

void test('a member cannot manage anyone', () => {
  const decision = canChangeRole(member, { userId: 'u_x', role: 'member' }, 'admin', 1);
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'not-permitted');
});

void test('a suspended admin cannot manage accounts', () => {
  const decision = canChangeRole(
    { ...admin, suspended: true },
    { userId: 'u_m', role: 'member' },
    'admin',
    1,
  );
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'not-permitted');
});

void test('suspension follows the same rank rules as role changes', () => {
  assert.equal(canSuspend(admin, { userId: 'u_m', role: 'member' }).allowed, true);
  assert.equal(canSuspend(admin, { userId: 'u_a2', role: 'admin' }).allowed, false);

  const onSelf = canSuspend(admin, { userId: admin.userId, role: 'admin' });
  assert.equal(onSelf.allowed, false);
  if (!onSelf.allowed) assert.equal(onSelf.reason, 'self');

  const byMember = canSuspend(member, { userId: 'u_m2', role: 'member' });
  assert.equal(byMember.allowed, false);
  if (!byMember.allowed) assert.equal(byMember.reason, 'not-permitted');
});

void test('every refusal carries a message worth showing', () => {
  const refusals = [
    canChangeRole(member, { userId: 'x', role: 'member' }, 'admin', 1),
    canChangeRole(admin, { userId: 'x', role: 'admin' }, 'member', 1),
    canSuspend(admin, { userId: admin.userId, role: 'admin' }),
  ];
  for (const refusal of refusals) {
    assert.equal(refusal.allowed, false);
    if (!refusal.allowed) assert.ok(refusal.message.length > 10, refusal.reason);
  }
});

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { splitStatements, stripSqlComments } from '../lib/sql-guard.ts';

function migration(name: string): string {
  return readFileSync(new URL(`../db/migrations/${name}`, import.meta.url), 'utf8');
}

function apply(database: DatabaseSync, sql: string): void {
  for (const statement of splitStatements(stripSqlComments(sql))) database.exec(statement);
}

function seededDatabase(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  database.exec(migration('0001_auth.sql'));
  database.exec(migration('0002_workspace.sql'));
  database.exec(migration('0004_security.sql'));
  database.prepare(
    `INSERT INTO "user" (id, name, email, emailVerified, image, createdAt, updatedAt)
     VALUES (?, ?, ?, 1, NULL, ?, ?)`,
  ).run('user_owner', 'Owner', 'owner@example.test', 1, 1);
  database.prepare(
    `INSERT INTO workspace
       (id, name, ownerUserId, zeroMode, autoScan, sleepIdleServers,
        previewDeployments, createdAt, updatedAt)
     VALUES ('ws_legacy', 'Legacy workspace', 'user_owner', 1, 1, 1, 0, 1, 1)`,
  ).run();
  database.prepare(
    `INSERT INTO project
       (id, workspaceId, name, framework, environment, region, status,
        visibility, createdAt, updatedAt)
     VALUES ('project_legacy', 'ws_legacy', 'Legacy app', 'Node.js',
             'Production', 'Global Edge', 'idle', 'private', 1, 1)`,
  ).run();
  database.prepare(
    `INSERT INTO user_role (userId, role, updatedAt)
     VALUES ('user_owner', 'owner', 1)`,
  ).run();
  apply(database, migration('0010_organizations.sql'));
  return database;
}

function addUser(database: DatabaseSync, id: string, email = `${id}@example.test`): void {
  database.prepare(
    `INSERT INTO "user" (id, name, email, emailVerified, image, createdAt, updatedAt)
     VALUES (?, ?, ?, 1, NULL, 2, 2)`,
  ).run(id, id, email);
}

void test('organization migration preserves legacy ids, Zero Mode, and owner access', () => {
  const database = seededDatabase();
  try {
    const workspace = database.prepare(
      'SELECT id, organizationId, zeroMode FROM workspace WHERE id = ?',
    ).get('ws_legacy') as { id: string; organizationId: string; zeroMode: number };
    assert.equal(workspace.id, 'ws_legacy');
    assert.equal(workspace.organizationId, 'org_legacy_ws_legacy');
    assert.equal(workspace.zeroMode, 1);
    const membership = database.prepare(
        `SELECT role, status FROM organization_member
          WHERE organizationId = ? AND userId = ?`,
      ).get('org_legacy_ws_legacy', 'user_owner') as { role: string; status: string };
    assert.equal(membership.role, 'owner');
    assert.equal(membership.status, 'active');
    assert.equal(
      (database.prepare('SELECT role FROM user_role WHERE userId = ?').get('user_owner') as { role: string }).role,
      'owner',
    );
    assert.equal(
      (database.prepare('SELECT projects FROM workspace_limit WHERE workspaceId = ?').get('ws_legacy') as { projects: number }).projects,
      25,
    );
  } finally {
    database.close();
  }
});

void test('append-only audit and tenant consistency triggers fail closed', () => {
  const database = seededDatabase();
  try {
    database.prepare(
      `INSERT INTO audit_event
       (id, organizationId, workspaceId, actorType, actorId, action,
        resourceType, resourceId, outcome, metadata, createdAt)
       VALUES ('audit_1', 'org_legacy_ws_legacy', 'ws_legacy', 'user',
               'user_owner', 'project.read', 'project', 'project_legacy',
               'success', '{}', 2)`,
    ).run();
    assert.throws(
      () => database.prepare("UPDATE audit_event SET outcome = 'failed' WHERE id = 'audit_1'").run(),
      /append-only/,
    );
    assert.throws(
      () => database.prepare("DELETE FROM audit_event WHERE id = 'audit_1'").run(),
      /append-only/,
    );

    addUser(database, 'user_other');
    database.prepare(
      `INSERT INTO organization
       (id, name, slug, ownerUserId, status, adminCanRevokeSessions, createdAt, updatedAt)
       VALUES ('org_other', 'Other', 'other', 'user_other', 'active', 1, 2, 2)`,
    ).run();
    database.prepare(
      `INSERT INTO organization_member
       (id, organizationId, userId, role, status, acceptedAt, createdBy, createdAt, updatedAt)
       VALUES ('member_other', 'org_other', 'user_other', 'owner', 'active', 2, 'user_other', 2, 2)`,
    ).run();
    database.prepare(
      `INSERT INTO workspace
       (id, organizationId, name, ownerUserId, zeroMode, autoScan,
        sleepIdleServers, previewDeployments, createdAt, updatedAt)
       VALUES ('ws_other', 'org_other', 'Other', 'user_other', 1, 1, 1, 0, 2, 2)`,
    ).run();
    assert.throws(
      () => database.prepare(
        `INSERT INTO workspace_member
         (id, organizationId, workspaceId, userId, createdBy, createdAt)
         VALUES ('cross_tenant', 'org_legacy_ws_legacy', 'ws_other',
                 'user_owner', 'user_owner', 2)`,
      ).run(),
      /tenant mismatch/,
    );
    assert.throws(
      () => database.prepare(
        "UPDATE workspace SET organizationId = 'org_other' WHERE id = 'ws_legacy'",
      ).run(),
      /organization is immutable/,
    );
  } finally {
    database.close();
  }
});

void test('last-owner protection requires the atomic ownership-transfer sequence', () => {
  const database = seededDatabase();
  try {
    addUser(database, 'user_target');
    database.prepare(
      `INSERT INTO organization_member
       (id, organizationId, userId, role, status, acceptedAt, createdBy, createdAt, updatedAt)
       VALUES ('member_target', 'org_legacy_ws_legacy', 'user_target', 'admin',
               'active', 2, 'user_owner', 2, 2)`,
    ).run();
    assert.throws(
      () => database.prepare(
        "UPDATE organization_member SET role = 'admin' WHERE organizationId = 'org_legacy_ws_legacy' AND userId = 'user_owner'",
      ).run(),
      /retain its designated owner/,
    );
    assert.throws(
      () => database.prepare(
        "DELETE FROM organization_member WHERE organizationId = 'org_legacy_ws_legacy' AND userId = 'user_owner'",
      ).run(),
      /retain its designated owner/,
    );

    database.exec('BEGIN IMMEDIATE');
    try {
      database.prepare("UPDATE organization_member SET role = 'owner' WHERE id = 'member_target'").run();
      database.prepare(
        "UPDATE organization SET ownerUserId = 'user_target' WHERE id = 'org_legacy_ws_legacy'",
      ).run();
      database.prepare(
        "UPDATE organization_member SET role = 'admin' WHERE organizationId = 'org_legacy_ws_legacy' AND userId = 'user_owner'",
      ).run();
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
    const transferred = database.prepare(
        `SELECT o.ownerUserId, m.role
           FROM organization o JOIN organization_member m
             ON m.organizationId = o.id AND m.userId = o.ownerUserId
          WHERE o.id = 'org_legacy_ws_legacy'`,
      ).get() as { ownerUserId: string; role: string };
    assert.equal(transferred.ownerUserId, 'user_target');
    assert.equal(transferred.role, 'owner');
  } finally {
    database.close();
  }
});

void test('invitations are one-time, role-bounded, and unique while pending', () => {
  const database = seededDatabase();
  try {
    addUser(database, 'user_invited', 'invitee@example.test');
    database.prepare(
      `INSERT INTO organization_invitation
       (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix,
        status, expiresAt, createdBy, createdAt, updatedAt)
       VALUES ('invite_1', 'org_legacy_ws_legacy', 'ws_legacy',
               'invitee@example.test', 'developer', 'hash_only', 'ysd_inv_',
               'pending', 999999, 'user_owner', 2, 2)`,
    ).run();
    assert.throws(
      () => database.prepare(
        `INSERT INTO organization_invitation
         (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix,
          status, expiresAt, createdBy, createdAt, updatedAt)
         VALUES ('invite_2', 'org_legacy_ws_legacy', 'ws_legacy',
                 'invitee@example.test', 'viewer', 'hash_2', 'ysd_inv_',
                 'pending', 999999, 'user_owner', 2, 2)`,
      ).run(),
      /UNIQUE constraint failed/,
    );
    assert.throws(
      () => database.prepare(
        `INSERT INTO organization_invitation
         (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix,
          status, expiresAt, createdBy, createdAt, updatedAt)
         VALUES ('invite_owner', 'org_legacy_ws_legacy', 'ws_legacy',
                 'other@example.test', 'owner', 'hash_owner', 'ysd_inv_',
                 'pending', 999999, 'user_owner', 2, 2)`,
      ).run(),
      /CHECK constraint failed/,
    );
    database.exec('BEGIN IMMEDIATE');
    try {
      database.prepare(
        `UPDATE organization_invitation
            SET status = 'accepted', usedAt = 3, usedBy = 'user_invited', updatedAt = 3
          WHERE id = 'invite_1' AND status = 'pending' AND expiresAt > 3`,
      ).run();
      database.prepare(
        `INSERT INTO organization_member
           (id, organizationId, userId, role, status, suspendedAt, suspendedReason,
            acceptedAt, lastActiveAt, createdBy, createdAt, updatedAt)
         SELECT 'member_invited', i.organizationId, 'user_invited', i.role,
                'active', NULL, NULL, 3, NULL, 'user_invited', 3, 3
           FROM organization_invitation i
          WHERE i.id = 'invite_1' AND i.status = 'accepted'
            AND i.usedBy = 'user_invited' AND i.usedAt = 3
         ON CONFLICT(organizationId, userId) DO UPDATE SET
           status = 'active', role = excluded.role, updatedAt = excluded.updatedAt`,
      ).run();
      database.prepare(
        `INSERT OR IGNORE INTO workspace_member
           (id, organizationId, workspaceId, userId, createdBy, createdAt)
         SELECT 'wmem_invited', i.organizationId, i.workspaceId,
                'user_invited', 'user_invited', 3
           FROM organization_invitation i
          WHERE i.id = 'invite_1' AND i.status = 'accepted'
            AND i.usedBy = 'user_invited' AND i.usedAt = 3`,
      ).run();
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
    assert.equal(
      (database.prepare('SELECT status FROM organization_invitation WHERE id = ?').get('invite_1') as { status: string }).status,
      'accepted',
    );
    assert.equal(
      (database.prepare(
        `SELECT COUNT(*) AS total FROM workspace_member
          WHERE workspaceId = 'ws_legacy' AND userId = 'user_invited'`,
      ).get() as { total: number }).total,
      1,
    );
  } finally {
    database.close();
  }
});

void test('expired and revoked invitations cannot be accepted or duplicated while pending', () => {
  const database = seededDatabase();
  try {
    database.prepare(
      `INSERT INTO organization_invitation
       (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix,
        status, expiresAt, createdBy, createdAt, updatedAt)
       VALUES ('invite_expired', 'org_legacy_ws_legacy', 'ws_legacy',
               'expired@example.test', 'viewer', 'hash_expired', 'ysd_inv_exp',
               'pending', 2, 'user_owner', 1, 1)`,
    ).run();
    database.prepare(
      `UPDATE organization_invitation SET status = 'expired', updatedAt = 3
        WHERE id = 'invite_expired' AND status = 'pending' AND expiresAt <= 3`,
    ).run();
    assert.equal(
      (database.prepare(
        "SELECT status FROM organization_invitation WHERE id = 'invite_expired'",
      ).get() as { status: string }).status,
      'expired',
    );

    database.prepare(
      `INSERT INTO organization_invitation
       (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix,
        status, expiresAt, createdBy, createdAt, updatedAt)
       VALUES ('invite_revoked', 'org_legacy_ws_legacy', 'ws_legacy',
               'revoked@example.test', 'developer', 'hash_revoked', 'ysd_inv_rev',
               'pending', 999999, 'user_owner', 1, 1)`,
    ).run();
    database.prepare(
      `UPDATE organization_invitation
          SET status = 'revoked', revokedAt = 3, revokedBy = 'user_owner', updatedAt = 3
        WHERE id = 'invite_revoked' AND status = 'pending'`,
    ).run();
    const accepted = database.prepare(
      `UPDATE organization_invitation
          SET status = 'accepted', usedAt = 4, usedBy = 'user_owner', updatedAt = 4
        WHERE id IN ('invite_expired', 'invite_revoked')
          AND status = 'pending' AND expiresAt > 4`,
    ).run();
    assert.equal(accepted.changes, 0);

    database.prepare(
      `INSERT INTO organization_invitation
       (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix,
        status, expiresAt, createdBy, createdAt, updatedAt)
       VALUES ('invite_replacement', 'org_legacy_ws_legacy', 'ws_legacy',
               'revoked@example.test', 'viewer', 'hash_replacement', 'ysd_inv_new',
               'pending', 999999, 'user_owner', 4, 4)`,
    ).run();
    assert.throws(
      () => database.prepare(
        `INSERT INTO organization_invitation
         (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix,
          status, expiresAt, createdBy, createdAt, updatedAt)
         VALUES ('invite_duplicate', 'org_legacy_ws_legacy', 'ws_legacy',
                 'revoked@example.test', 'viewer', 'hash_duplicate', 'ysd_inv_dup',
                 'pending', 999999, 'user_owner', 5, 5)`,
      ).run(),
      /UNIQUE constraint failed/,
    );
  } finally {
    database.close();
  }
});

void test('suspended members and archived organizations are excluded from access resolution', () => {
  const database = seededDatabase();
  try {
    addUser(database, 'user_suspended');
    database.prepare(
      `INSERT INTO organization_member
       (id, organizationId, userId, role, status, suspendedAt, suspendedReason,
        acceptedAt, createdBy, createdAt, updatedAt)
       VALUES ('member_suspended', 'org_legacy_ws_legacy', 'user_suspended',
               'developer', 'suspended', 2, 'security review', 1,
               'user_owner', 1, 2)`,
    ).run();
    database.prepare(
      `INSERT INTO workspace_member
       (id, organizationId, workspaceId, userId, projectScope, createdBy, createdAt)
       VALUES ('wmem_suspended', 'org_legacy_ws_legacy', 'ws_legacy',
               'user_suspended', 'restricted', 'user_owner', 1)`,
    ).run();
    database.prepare(
      `INSERT INTO member_project_access
       (id, organizationId, workspaceId, userId, projectId, grantedBy, createdAt)
       VALUES ('access_suspended', 'org_legacy_ws_legacy', 'ws_legacy',
               'user_suspended', 'project_legacy', 'user_owner', 1)`,
    ).run();

    const accessible = () => (database.prepare(
      `SELECT COUNT(*) AS total
         FROM organization_member m
         JOIN organization o ON o.id = m.organizationId AND o.status = 'active'
         JOIN workspace_member wm
           ON wm.organizationId = m.organizationId AND wm.userId = m.userId
         JOIN workspace w ON w.id = wm.workspaceId AND w.archivedAt IS NULL
        WHERE m.userId = 'user_suspended' AND m.status = 'active'
          AND m.suspendedAt IS NULL`,
    ).get() as { total: number }).total;

    assert.equal(accessible(), 0);
    database.prepare(
      `UPDATE organization_member
          SET status = 'active', suspendedAt = NULL, suspendedReason = NULL
        WHERE id = 'member_suspended'`,
    ).run();
    assert.equal(accessible(), 1);
    database.prepare(
      `UPDATE organization SET status = 'archived', archivedAt = 4
        WHERE id = 'org_legacy_ws_legacy'`,
    ).run();
    assert.equal(accessible(), 0);
  } finally {
    database.close();
  }
});

void test('service credentials store hashes only and session revocation is member-scoped', () => {
  const database = seededDatabase();
  try {
    addUser(database, 'user_member');
    database.prepare(
      `INSERT INTO organization_member
       (id, organizationId, userId, role, status, acceptedAt, createdBy, createdAt, updatedAt)
       VALUES ('member_user', 'org_legacy_ws_legacy', 'user_member', 'viewer',
               'active', 2, 'user_owner', 2, 2)`,
    ).run();
    database.prepare(
      `INSERT INTO service_account
       (id, organizationId, workspaceId, projectId, name, status, createdBy, createdAt, updatedAt)
       VALUES ('service_1', 'org_legacy_ws_legacy', 'ws_legacy', 'project_legacy',
               'deploy-bot', 'active', 'user_owner', 2, 2)`,
    ).run();
    database.prepare(
      `INSERT INTO service_account_token
       (id, serviceAccountId, tokenPrefix, tokenHash, scopes, expiresAt, createdAt)
       VALUES ('token_1', 'service_1', 'ysd_sa_abcd', 'sha256-digest',
               '["deployment.deploy"]', 999999, 2)`,
    ).run();
    const columns = database.prepare('PRAGMA table_info(service_account_token)').all() as { name: string }[];
    assert.equal(columns.some((column) => column.name === 'token'), false);
    assert.equal(columns.some((column) => column.name === 'tokenHash'), true);

    const activeTokens = (now: number) => (database.prepare(
      `SELECT COUNT(*) AS total
         FROM service_account_token t
         JOIN service_account a ON a.id = t.serviceAccountId
         JOIN organization o ON o.id = a.organizationId
         JOIN workspace w ON w.id = a.workspaceId
        WHERE t.tokenHash = 'sha256-digest' AND t.revokedAt IS NULL
          AND a.status = 'active' AND o.status = 'active'
          AND w.archivedAt IS NULL
          AND (t.expiresAt IS NULL OR t.expiresAt > ?)`,
    ).get(now) as { total: number }).total;
    assert.equal(activeTokens(3), 1);
    database.prepare(
      `UPDATE service_account_token
          SET revokedAt = 4, revokedBy = 'user_owner'
        WHERE id = 'token_1'`,
    ).run();
    assert.equal(activeTokens(5), 0);
    database.prepare(
      `INSERT INTO service_account_token
       (id, serviceAccountId, tokenPrefix, tokenHash, scopes, expiresAt, createdAt)
       VALUES ('token_expired', 'service_1', 'ysd_sa_expired', 'sha256-expired',
               '["deployment.deploy"]', 2, 1)`,
    ).run();
    assert.equal(
      (database.prepare(
        `SELECT COUNT(*) AS total FROM service_account_token
          WHERE id = 'token_expired' AND revokedAt IS NULL
            AND (expiresAt IS NULL OR expiresAt > 3)`,
      ).get() as { total: number }).total,
      0,
    );

    database.prepare(
      `INSERT INTO "session"
       (id, expiresAt, token, createdAt, updatedAt, userId)
       VALUES ('session_owner', 999999, 'owner-token', 2, 2, 'user_owner')`,
    ).run();
    database.prepare(
      `INSERT INTO "session"
       (id, expiresAt, token, createdAt, updatedAt, userId)
       VALUES ('session_member', 999999, 'member-token', 2, 2, 'user_member')`,
    ).run();
    database.prepare('DELETE FROM "session" WHERE id = ? AND userId = ?')
      .run('session_member', 'user_member');
    assert.equal((database.prepare('SELECT COUNT(*) AS total FROM "session"').get() as { total: number }).total, 1);
    assert.equal(
      (database.prepare('SELECT userId FROM "session"').get() as { userId: string }).userId,
      'user_owner',
    );
  } finally {
    database.close();
  }
});

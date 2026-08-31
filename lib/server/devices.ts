import { recordAudit } from './audit';
import { execute, query, queryOne } from './db';
import { normalizeRole, rankOf, type Role } from '@/lib/roles';

export type DeviceSession = {
  id: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  ipAddress: string | null;
  userAgent: string | null;
};

export async function listOwnSessions(userId: string): Promise<DeviceSession[]> {
  return query<DeviceSession>(
    `SELECT id, createdAt, updatedAt, expiresAt, ipAddress, userAgent
       FROM "session" WHERE userId = ? ORDER BY updatedAt DESC`,
    userId,
  );
}

export async function revokeOwnSession(userId: string, sessionId: string): Promise<boolean> {
  const result = await execute('DELETE FROM "session" WHERE id = ? AND userId = ?', sessionId, userId);
  return (result.meta.changes ?? 0) === 1;
}

export async function revokeAllOwnSessions(userId: string): Promise<number> {
  const result = await execute('DELETE FROM "session" WHERE userId = ?', userId);
  return result.meta.changes ?? 0;
}

export async function revokeMemberSessions(input: {
  organizationId: string;
  actorId: string;
  actorRole: Role;
  targetUserId: string;
}): Promise<{ ok: true; revoked: number } | { ok: false; error: string }> {
  if (input.actorId === input.targetUserId) return { ok: false, error: 'Use your own session controls.' };
  const policy = await queryOne<{ adminCanRevokeSessions: number }>(
    'SELECT adminCanRevokeSessions FROM organization WHERE id = ? AND status = \'active\'',
    input.organizationId,
  );
  if (!policy?.adminCanRevokeSessions) return { ok: false, error: 'Organization policy forbids admin session revocation.' };
  const target = await queryOne<{ role: string }>(
    `SELECT role FROM organization_member
      WHERE organizationId = ? AND userId = ? AND status = 'active'`,
    input.organizationId, input.targetUserId,
  );
  if (!target || rankOf(normalizeRole(target.role)) >= rankOf(input.actorRole)) {
    return { ok: false, error: 'Member not found or protected.' };
  }
  const revoked = await revokeAllOwnSessions(input.targetUserId);
  await recordAudit({
    organizationId: input.organizationId, actorType: 'user', actorId: input.actorId,
    action: 'session.revoke-member', resourceType: 'member', resourceId: input.targetUserId,
    outcome: 'success', metadata: { revoked },
  });
  return { ok: true, revoked };
}

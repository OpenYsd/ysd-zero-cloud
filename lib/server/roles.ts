import { isRole, type Actor, type Role } from '@/lib/roles';
import { count, execute, query, queryOne } from './db';
import { runtimeEnv } from './env';

/**
 * Role storage and the owner bootstrap.
 *
 * A row in `user_role` is authoritative. When one is missing the account is a
 * member, so a brand-new sign-up has no instance powers until someone grants
 * them.
 */

export type UserRoleRow = {
  userId: string;
  role: Role;
  suspendedAt: number | null;
  suspendedReason: string | null;
  updatedAt: number;
  updatedBy: string | null;
};

function normalizeRole(value: string | null | undefined): Role {
  return value && isRole(value) ? value : 'member';
}

/**
 * Resolves the actor for a session.
 *
 * Also performs the one-time owner bootstrap: an instance with no owner row
 * yet promotes the account matching `YSD_OWNER_EMAIL`, or the earliest
 * account when that is unset. Without this a fresh deployment would have
 * nobody able to administer it.
 */
export async function resolveActor(userId: string, email: string): Promise<Actor> {
  const bootstrapped = await bootstrapOwner(userId, email);
  if (bootstrapped) return bootstrapped;

  const row = await queryOne<UserRoleRow>(
    'SELECT userId, role, suspendedAt, suspendedReason, updatedAt, updatedBy FROM user_role WHERE userId = ?',
    userId,
  );

  return {
    userId,
    role: normalizeRole(row?.role),
    suspended: Boolean(row?.suspendedAt),
  };
}

/**
 * Grants ownership on an instance that has none.
 *
 * @returns The owner actor when this call performed the bootstrap, else null.
 */
async function bootstrapOwner(userId: string, email: string): Promise<Actor | null> {
  const owners = await count("SELECT COUNT(*) AS total FROM user_role WHERE role = 'owner'");
  if (owners > 0) return null;

  const configured = runtimeEnv.YSD_OWNER_EMAIL?.trim().toLowerCase();
  let entitled = false;

  if (configured) {
    entitled = configured === email.trim().toLowerCase();
  } else {
    const first = await queryOne<{ id: string }>(
      'SELECT id FROM "user" ORDER BY createdAt ASC, id ASC LIMIT 1',
    );
    entitled = first?.id === userId;
  }

  if (!entitled) return null;

  const now = Date.now();
  await execute(
    `INSERT INTO user_role (userId, role, suspendedAt, suspendedReason, updatedAt, updatedBy)
     VALUES (?, 'owner', NULL, NULL, ?, 'bootstrap')
     ON CONFLICT(userId) DO UPDATE SET role = 'owner', updatedAt = excluded.updatedAt, updatedBy = 'bootstrap'`,
    userId,
    now,
  );

  return { userId, role: 'owner', suspended: false };
}

export async function countOwners(): Promise<number> {
  return count("SELECT COUNT(*) AS total FROM user_role WHERE role = 'owner'");
}

export async function countByRole(role: Role): Promise<number> {
  return count('SELECT COUNT(*) AS total FROM user_role WHERE role = ?', role);
}

export async function countSuspended(): Promise<number> {
  return count('SELECT COUNT(*) AS total FROM user_role WHERE suspendedAt IS NOT NULL');
}

export type ManagedUser = {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  createdAt: string;
  role: Role;
  suspendedAt: number | null;
  suspendedReason: string | null;
  lastSignInAt: number | null;
  activeSessions: number;
};

type ManagedUserRow = Omit<ManagedUser, 'role' | 'emailVerified'> & {
  role: string | null;
  emailVerified: number;
};

/**
 * The account list for the admin surface.
 *
 * This is the one place that reads across every account, and it is gated on
 * `admin.users.read`. It exposes identity and status only — never workspace
 * contents, which stay scoped by `lib/tenancy.ts` regardless of role.
 */
export async function listManagedUsers(limit = 200): Promise<ManagedUser[]> {
  const rows = await query<ManagedUserRow>(
    `SELECT
       u.id,
       u.email,
       u.name,
       u.emailVerified,
       u.createdAt,
       r.role,
       r.suspendedAt,
       r.suspendedReason,
       (SELECT MAX(a.createdAt) FROM auth_attempt a
         WHERE a.email = u.email AND a.outcome = 'success') AS lastSignInAt,
       (SELECT COUNT(*) FROM "session" s WHERE s.userId = u.id) AS activeSessions
     FROM "user" u
     LEFT JOIN user_role r ON r.userId = u.id
     ORDER BY u.createdAt ASC
     LIMIT ?`,
    Math.min(500, Math.max(1, limit)),
  );

  return rows.map((row) => ({
    ...row,
    role: normalizeRole(row.role),
    emailVerified: row.emailVerified === 1,
  }));
}

export async function getManagedUser(userId: string): Promise<ManagedUser | null> {
  const users = await listManagedUsers(500);
  return users.find((user) => user.id === userId) ?? null;
}

export async function setRole(userId: string, role: Role, actorId: string): Promise<void> {
  await execute(
    `INSERT INTO user_role (userId, role, suspendedAt, suspendedReason, updatedAt, updatedBy)
     VALUES (?, ?, NULL, NULL, ?, ?)
     ON CONFLICT(userId) DO UPDATE SET role = excluded.role, updatedAt = excluded.updatedAt, updatedBy = excluded.updatedBy`,
    userId,
    role,
    Date.now(),
    actorId,
  );
}

/**
 * Suspends or restores an account.
 *
 * Suspending also drops every session that account holds, so the block takes
 * effect immediately rather than when their current session happens to expire.
 */
export async function setSuspended(
  userId: string,
  suspended: boolean,
  reason: string | null,
  actorId: string,
): Promise<void> {
  const now = Date.now();
  await execute(
    `INSERT INTO user_role (userId, role, suspendedAt, suspendedReason, updatedAt, updatedBy)
     VALUES (?, 'member', ?, ?, ?, ?)
     ON CONFLICT(userId) DO UPDATE SET
       suspendedAt = excluded.suspendedAt,
       suspendedReason = excluded.suspendedReason,
       updatedAt = excluded.updatedAt,
       updatedBy = excluded.updatedBy`,
    userId,
    suspended ? now : null,
    suspended ? reason : null,
    now,
    actorId,
  );

  if (suspended) {
    await execute('DELETE FROM "session" WHERE userId = ?', userId);
  }
}

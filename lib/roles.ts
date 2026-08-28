/**
 * Instance roles.
 *
 * Every operator still owns exactly one workspace; roles govern what someone
 * may do to the *instance* — manage other accounts, reach the raw SQL Editor —
 * never what they may see inside another workspace. Tenant isolation is
 * enforced separately in `lib/tenancy.ts` and is not weakened by any role:
 * an admin administers accounts, they do not read other people's data.
 */

export const ROLES = ['owner', 'admin', 'member'] as const;

export type Role = (typeof ROLES)[number];

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

/** Higher rank wins. Used for comparisons, never persisted. */
const RANK: Record<Role, number> = { owner: 3, admin: 2, member: 1 };

export function rankOf(role: Role): number {
  return RANK[role];
}

export function atLeast(role: Role, minimum: Role): boolean {
  return RANK[role] >= RANK[minimum];
}

export type Actor = {
  userId: string;
  role: Role;
  suspended: boolean;
};

export type Target = {
  userId: string;
  role: Role;
};

/**
 * What a role may do.
 *
 * A suspended account keeps its role but loses every capability, so a
 * suspension cannot be sat out by an admin who still holds a session.
 */
export type Capability =
  | 'admin.users.read'
  | 'admin.users.write'
  | 'sql-editor.run'
  | 'workspace.use';

export function can(actor: Actor, capability: Capability): boolean {
  if (actor.suspended) return false;
  switch (capability) {
    case 'workspace.use':
      return true;
    case 'admin.users.read':
    case 'admin.users.write':
      return atLeast(actor.role, 'admin');
    case 'sql-editor.run':
      // Unchanged from before roles existed: a raw statement cannot be scoped
      // to one workspace, so only the instance owner may run one. Admins
      // deliberately do not inherit this.
      return actor.role === 'owner';
    default:
      return false;
  }
}

export type RoleChangeRefusal =
  | 'not-permitted'
  | 'self'
  | 'outranked'
  | 'cannot-grant-owner'
  | 'last-owner';

export type RoleChangeDecision =
  | { allowed: true }
  | { allowed: false; reason: RoleChangeRefusal; message: string };

/**
 * Whether `actor` may change `target` to `nextRole`.
 *
 * The rules exist to stop an instance from being taken over or locked out:
 *
 * - Nobody edits their own role, so an admin cannot promote themselves.
 * - Nobody may act on an account that outranks them, or on an equal, so one
 *   admin cannot demote another.
 * - Only an owner may hand out `owner`, and doing so is an explicit transfer.
 * - The last remaining owner cannot be demoted, or the instance would have no
 *   one able to administer it.
 */
export function canChangeRole(
  actor: Actor,
  target: Target,
  nextRole: Role,
  ownerCount: number,
): RoleChangeDecision {
  if (!can(actor, 'admin.users.write')) {
    return { allowed: false, reason: 'not-permitted', message: 'You cannot manage accounts.' };
  }
  if (actor.userId === target.userId) {
    return { allowed: false, reason: 'self', message: 'You cannot change your own role.' };
  }
  if (rankOf(target.role) >= rankOf(actor.role)) {
    return {
      allowed: false,
      reason: 'outranked',
      message: 'You cannot change an account at or above your own role.',
    };
  }
  if (nextRole === 'owner' && actor.role !== 'owner') {
    return {
      allowed: false,
      reason: 'cannot-grant-owner',
      message: 'Only the owner can grant ownership.',
    };
  }
  if (target.role === 'owner' && nextRole !== 'owner' && ownerCount <= 1) {
    return {
      allowed: false,
      reason: 'last-owner',
      message: 'The instance must keep at least one owner.',
    };
  }
  return { allowed: true };
}

/** Whether `actor` may suspend or restore `target`. */
export function canSuspend(actor: Actor, target: Target): RoleChangeDecision {
  if (!can(actor, 'admin.users.write')) {
    return { allowed: false, reason: 'not-permitted', message: 'You cannot manage accounts.' };
  }
  if (actor.userId === target.userId) {
    return { allowed: false, reason: 'self', message: 'You cannot suspend your own account.' };
  }
  if (rankOf(target.role) >= rankOf(actor.role)) {
    return {
      allowed: false,
      reason: 'outranked',
      message: 'You cannot suspend an account at or above your own role.',
    };
  }
  return { allowed: true };
}

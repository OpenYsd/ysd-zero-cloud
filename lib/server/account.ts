import {
  EMAIL_CHANGE_AVAILABILITY,
  accountDisplayName,
  accountInitials,
} from '@/lib/account';
import type { AccountProfile } from '@/lib/domain';
import type { WorkspaceSession } from './session';
import { getAuth } from './auth';
import { recordEvidence } from './audit';
import { execute, queryOne } from './db';
import { listOwnSessions } from './devices';

/**
 * The Account area.
 *
 * Two rules shape this module.
 *
 * It never implements authentication. Better Auth already owns credential
 * hashing, the 12–256 character policy, current-password verification, and
 * session revocation, so the password path calls `auth.api.changePassword`
 * rather than reaching into `account.password` directly. Building a second
 * credential path would mean a second thing to get wrong.
 *
 * And it never trusts the request for identity. Every function here takes the
 * resolved `WorkspaceSession`; nothing accepts a user, organization, or
 * workspace id from a body. A caller cannot address another account.
 */

/** What the Account page renders. No credential material appears here. */
export async function readAccountProfile(
  session: WorkspaceSession,
): Promise<AccountProfile> {
  // Name, email and verification come from the row rather than from
  // `session.user`. The session is a snapshot resolved at the start of the
  // request, so immediately after a rename it still carries the old name — and
  // this function is what the PATCH response echoes back. Reading the stored
  // values costs nothing extra (the row is already being fetched) and stops the
  // Account page from snapping the field back to the previous name and looking
  // like the save failed.
  const [row, sessions] = await Promise.all([
    queryOne<{
      name: string | null;
      email: string | null;
      emailVerified: number | boolean | null;
      createdAt: string | number;
      passwordChangedAt: number | null;
    }>(
      'SELECT name, email, emailVerified, createdAt, passwordChangedAt FROM "user" WHERE id = ?',
      session.user.id,
    ),
    listOwnSessions(session.user.id),
  ]);

  const createdAt = row?.createdAt ?? null;
  // The session values remain the fallback: a missing row means the account was
  // removed mid-request, and reporting nothing at all would be worse.
  const name = row?.name ?? session.user.name;
  const email = row?.email ?? session.user.email;
  return {
    displayName: accountDisplayName({ name, email }),
    name,
    email,
    // Reported exactly as stored. With no sending domain configured this is
    // false for every account, and the UI says "unverified" rather than
    // implying a verification that never happened.
    emailVerified:
      row === null ? session.user.emailVerified : Boolean(row.emailVerified),
    initials: accountInitials(name, email),
    role: session.actor.role,
    organizationName: session.organization.name,
    workspaceName: session.workspace.name,
    suspended: session.actor.suspended,
    createdAt:
      typeof createdAt === 'number'
        ? createdAt
        : createdAt
          ? Date.parse(String(createdAt)) || null
          : null,
    passwordChangedAt: row?.passwordChangedAt ?? null,
    // Session rows carry no token here: only when and from where.
    sessions: sessions.map((item) => ({
      id: item.id,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
      expiresAt: item.expiresAt,
      ipAddress: item.ipAddress,
      userAgent: item.userAgent,
    })),
    emailChange: {
      available: EMAIL_CHANGE_AVAILABILITY.available,
      reason: EMAIL_CHANGE_AVAILABILITY.reason,
    },
  };
}

type MutationResult =
  | { ok: true }
  | { ok: false; status: number; error: string };

/** A suspended account may read its profile but may not change anything. */
function guard(session: WorkspaceSession): MutationResult | null {
  if (session.principal !== 'user') {
    return { ok: false, status: 403, error: 'A user session is required.' };
  }
  if (session.actor.suspended) {
    return { ok: false, status: 403, error: 'This account is suspended.' };
  }
  return null;
}

export async function updateDisplayName(input: {
  session: WorkspaceSession;
  displayName: string;
  request: Request;
}): Promise<MutationResult> {
  const denied = guard(input.session);
  if (denied) return denied;

  // Scoped to the authenticated id. There is no path by which another user's
  // row can be addressed, because the id never comes from the request.
  const changed = await execute(
    'UPDATE "user" SET name = ?, updatedAt = ? WHERE id = ?',
    input.displayName,
    Date.now(),
    input.session.user.id,
  );
  if ((changed.meta.changes ?? 0) !== 1) {
    return { ok: false, status: 404, error: 'Account not found.' };
  }

  await recordEvidence({
    action: 'account.profile.update',
    organizationId: input.session.organization.id,
    workspaceId: input.session.workspace.id,
    actorType: 'user',
    actorId: input.session.user.id,
    resourceId: input.session.user.id,
    outcome: 'success',
    request: input.request,
    // The field that changed, never its value: a display name is user-supplied
    // text and the evidence trail is not the place to accumulate it.
    metadata: { field: 'displayName' },
  });
  return { ok: true };
}

/**
 * Changes the password through Better Auth.
 *
 * `revokeOtherSessions` is the safe default: a password change is what someone
 * does after suspecting exposure, so every other signed-in browser is dropped
 * while this one survives. Better Auth verifies the current password before it
 * writes anything, so a wrong current password never reaches the store.
 *
 * Surviving is not automatic. Better Auth implements "revoke the others" by
 * clearing the user's sessions and issuing a *fresh* token for the caller,
 * handed back as a `Set-Cookie` on its own response. This function is called
 * server-side, so that response is never sent to the browser: without
 * `returnHeaders` the caller keeps a token that was just revoked and is signed
 * out on its next request — the browser that changed the password is the one
 * that gets locked out. The headers are therefore returned to the route, which
 * replays them onto its own response. The cookie is passed through untouched
 * and never read, logged, or stored.
 *
 * Ordering is deliberate and its failure window is documented rather than
 * hidden. The credential update commits first; the evidence write follows and
 * is `critical`, so a failure there surfaces as an error instead of a silent
 * success. That leaves a narrow window in which the password has changed but
 * the evidence has not. Closing it would need the credential write and the
 * audit insert in one D1 transaction, which is not possible while the
 * credential write happens inside Better Auth's own handler.
 */
export async function changeAccountPassword(input: {
  session: WorkspaceSession;
  currentPassword: string;
  newPassword: string;
  request: Request;
}): Promise<
  MutationResult & { revokedOtherSessions?: boolean; setCookie?: string[] }
> {
  const denied = guard(input.session);
  if (denied) return denied;

  const auth = await getAuth();
  let setCookie: string[] = [];
  try {
    const changed = await auth.api.changePassword({
      body: {
        currentPassword: input.currentPassword,
        newPassword: input.newPassword,
        revokeOtherSessions: true,
      },
      headers: input.request.headers,
      // Keeps the rotated session cookie so this browser stays signed in.
      returnHeaders: true,
    });
    setCookie = changed.headers.getSetCookie();
  } catch {
    // Better Auth distinguishes a wrong current password from a policy
    // rejection, but both are answered the same way on purpose: telling a
    // caller which half was wrong is a probing aid. Nothing from the
    // exception is surfaced — it can carry the submitted value.
    return {
      ok: false,
      status: 400,
      error:
        'That did not work. Check your current password, and make sure the new one meets the policy.',
    };
  }

  await execute(
    'UPDATE "user" SET passwordChangedAt = ?, updatedAt = ? WHERE id = ?',
    Date.now(),
    Date.now(),
    input.session.user.id,
  );

  await recordEvidence({
    action: 'account.password.change',
    organizationId: input.session.organization.id,
    workspaceId: input.session.workspace.id,
    actorType: 'user',
    actorId: input.session.user.id,
    resourceId: input.session.user.id,
    outcome: 'success',
    request: input.request,
    // No password, no hash, no session token — only that other sessions went.
    metadata: { revokedOtherSessions: true },
  });

  return { ok: true, revokedOtherSessions: true, setCookie };
}

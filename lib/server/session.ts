import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

import { can, type Actor, type Capability } from '@/lib/roles';
import { getSessionUser, type SessionUser } from './auth';
import { resolveActor } from './roles';
import { ensureWorkspace, type Workspace } from './workspace';

/**
 * Session resolution for pages and for API routes.
 *
 * Pages redirect an anonymous visitor to the sign-in screen; API routes answer
 * 401 so a fetch sees an error rather than a login page. Both paths go through
 * the same lookup so they can never disagree about who is signed in.
 *
 * Every resolution also carries the caller's instance role, and a suspended
 * account is treated as signed out everywhere. Suspension therefore takes
 * effect on the next request rather than when a session happens to expire.
 */

export type WorkspaceSession = {
  user: SessionUser;
  workspace: Workspace;
  actor: Actor;
};

async function resolve(requestHeaders: Headers): Promise<WorkspaceSession | null> {
  const user = await getSessionUser(requestHeaders);
  if (!user) return null;

  const actor = await resolveActor(user.id, user.email);
  if (actor.suspended) return null;

  const workspace = await ensureWorkspace(user.id, user.name, user.email);
  return { user, workspace, actor };
}

/** For server components. Returns null instead of redirecting. */
export async function readSession(): Promise<WorkspaceSession | null> {
  return resolve(await headers());
}

/** For server components that require a signed-in operator. */
export async function requireSession(): Promise<WorkspaceSession> {
  const session = await readSession();
  if (!session) redirect('/sign-in');
  return session;
}

/**
 * For server components behind a capability, such as the admin surface.
 *
 * Sends someone without the capability to the overview rather than showing a
 * forbidden page: they are legitimately signed in, just not for this.
 */
export async function requireCapability(capability: Capability): Promise<WorkspaceSession> {
  const session = await requireSession();
  if (!can(session.actor, capability)) redirect('/');
  return session;
}

export type ApiSession =
  | { ok: true; session: WorkspaceSession }
  | { ok: false; response: Response };

/** For route handlers. Callers return `result.response` when `ok` is false. */
export async function requireApiSession(request: Request): Promise<ApiSession> {
  const session = await resolve(request.headers);
  if (!session) {
    return {
      ok: false,
      response: Response.json({ error: 'Sign in to use this endpoint.' }, { status: 401 }),
    };
  }
  return { ok: true, session };
}

/** For route handlers behind a capability. */
export async function requireApiCapability(
  request: Request,
  capability: Capability,
): Promise<ApiSession> {
  const result = await requireApiSession(request);
  if (!result.ok) return result;
  if (!can(result.session.actor, capability)) {
    return {
      ok: false,
      response: Response.json(
        { error: 'Your role does not allow this.' },
        { status: 403 },
      ),
    };
  }
  return result;
}

import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

import { getSessionUser, type SessionUser } from './auth';
import { ensureWorkspace, type Workspace } from './workspace';

/**
 * Session resolution for pages and for API routes.
 *
 * Pages redirect an anonymous visitor to the sign-in screen; API routes answer
 * 401 so a fetch sees an error rather than a login page. Both paths go through
 * the same lookup so they can never disagree about who is signed in.
 */

export type WorkspaceSession = {
  user: SessionUser;
  workspace: Workspace;
};

async function resolve(requestHeaders: Headers): Promise<WorkspaceSession | null> {
  const user = await getSessionUser(requestHeaders);
  if (!user) return null;
  const workspace = await ensureWorkspace(user.id, user.name, user.email);
  return { user, workspace };
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

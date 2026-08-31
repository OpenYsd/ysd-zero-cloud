import { headers } from 'next/headers';
import { redirect } from 'next/navigation';

import {
  can,
  permissionForRequest,
  type Actor,
  type Capability,
  type Permission,
} from '@/lib/roles';
import { getSessionUser, type SessionUser } from './auth';
import { recordAudit, requestAuditContext } from './audit';
import {
  getOrganization,
  getOrganizationWorkspace,
  resolveOrganizationAccess,
} from './organizations';
import { authenticateServiceToken } from './service-accounts';
import type { Organization, Workspace } from '@/lib/domain';

export type WorkspaceSession = {
  user: SessionUser;
  organization: Organization;
  workspace: Workspace;
  actor: Actor;
  principal: 'user' | 'service_account';
};

function cookie(headersValue: Headers, name: string): string | null {
  const source = headersValue.get('cookie') ?? '';
  for (const part of source.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

async function resolveUser(requestHeaders: Headers): Promise<WorkspaceSession | null> {
  const user = await getSessionUser(requestHeaders);
  if (!user) return null;
  const access = await resolveOrganizationAccess({
    userId: user.id,
    userName: user.name,
    email: user.email,
    organizationId:
      requestHeaders.get('x-ysd-organization-id') ?? cookie(requestHeaders, 'ysd_organization'),
    workspaceId:
      requestHeaders.get('x-ysd-workspace-id') ?? cookie(requestHeaders, 'ysd_workspace'),
  });
  if (!access) return null;
  const actor: Actor = {
    userId: user.id,
    role: access.membership.role,
    suspended: false,
    organizationId: access.organization.id,
    workspaceId: access.workspace.id,
    projectIds: access.projectIds,
  };
  return {
    user,
    organization: access.organization,
    workspace: access.workspace,
    actor,
    principal: 'user',
  };
}

async function resolveService(request: Request): Promise<WorkspaceSession | null> {
  const principal = await authenticateServiceToken(request);
  if (!principal) return null;
  const [organization, workspace] = await Promise.all([
    getOrganization(principal.organizationId),
    getOrganizationWorkspace(principal.workspaceId),
  ]);
  if (!organization || !workspace || workspace.organizationId !== organization.id) return null;
  return {
    user: {
      id: principal.serviceAccountId,
      name: principal.name,
      email: `${principal.serviceAccountId}@service.ysd.invalid`,
      emailVerified: true,
      image: null,
    },
    organization,
    workspace,
    actor: {
      userId: principal.serviceAccountId,
      role: 'developer',
      suspended: false,
      organizationId: organization.id,
      workspaceId: workspace.id,
      projectIds: principal.projectId ? [principal.projectId] : null,
      serviceAccountId: principal.serviceAccountId,
      tokenScopes: principal.scopes,
    },
    principal: 'service_account',
  };
}

/** For server components. Service tokens are never accepted by pages. */
export async function readSession(): Promise<WorkspaceSession | null> {
  return resolveUser(await headers());
}

export async function requireSession(): Promise<WorkspaceSession> {
  const session = await readSession();
  if (!session) redirect('/sign-in');
  return session;
}

export async function requireCapability(capability: Capability): Promise<WorkspaceSession> {
  const session = await requireSession();
  if (!can(session.actor, capability)) redirect('/');
  return session;
}

export type ApiSession =
  | { ok: true; session: WorkspaceSession }
  | { ok: false; response: Response };

async function denied(
  request: Request,
  session: WorkspaceSession,
  permission: Permission,
): Promise<ApiSession> {
  const context = requestAuditContext(request);
  await recordAudit({
    organizationId: session.organization.id,
    workspaceId: session.workspace.id,
    actorType: session.principal,
    actorId: session.actor.userId,
    action: 'permission.denied',
    resourceType: 'api',
    resourceId: new URL(request.url).pathname,
    outcome: 'denied',
    ...context,
    metadata: { permission },
  }).catch(() => undefined);
  return {
    ok: false,
    response: Response.json({ error: 'Your organization role does not allow this action.' }, { status: 403 }),
  };
}

/**
 * Resolves cookie or scoped service-token authentication and applies the
 * central route policy before the handler can read or mutate workspace data.
 */
export async function requireApiSession(request: Request): Promise<ApiSession> {
  const bearer = request.headers.get('authorization')?.startsWith('Bearer ysd_sa_') ?? false;
  const session = bearer ? await resolveService(request) : await resolveUser(request.headers);
  if (!session) {
    return {
      ok: false,
      response: Response.json({ error: 'Sign in or provide a valid scoped token.' }, { status: 401 }),
    };
  }
  const permission = permissionForRequest(request.method, new URL(request.url).pathname);
  if (permission && !can(session.actor, permission)) return denied(request, session, permission);
  if (!permission && session.principal === 'service_account') {
    return denied(request, session, 'workspace.use');
  }
  return { ok: true, session };
}

export async function requireApiCapability(
  request: Request,
  capability: Capability,
): Promise<ApiSession> {
  const result = await requireApiSession(request);
  if (!result.ok) return result;
  if (!can(result.session.actor, capability)) return denied(request, result.session, capability);
  return result;
}

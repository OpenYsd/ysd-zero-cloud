import { can } from '@/lib/roles';
import { listOrganizations, resolveOrganizationAccess } from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (auth.session.principal !== 'user') return Response.json({ error: 'User session required.' }, { status: 403 });
  return Response.json({
    organizations: await listOrganizations(auth.session.user.id),
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    role: auth.session.actor.role,
  });
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (auth.session.principal !== 'user' || !can(auth.session.actor, 'organization.read')) {
    return Response.json({ error: 'User session required.' }, { status: 403 });
  }
  let body: { organizationId?: unknown; workspaceId?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: 'Expected JSON.' }, { status: 400 });
  }
  if (typeof body.organizationId !== 'string' || typeof body.workspaceId !== 'string') {
    return Response.json({ error: 'organizationId and workspaceId are required.' }, { status: 400 });
  }
  const access = await resolveOrganizationAccess({
    userId: auth.session.user.id,
    userName: auth.session.user.name,
    email: auth.session.user.email,
    organizationId: body.organizationId,
    workspaceId: body.workspaceId,
  });
  if (!access || access.organization.id !== body.organizationId || access.workspace.id !== body.workspaceId) {
    return Response.json({ error: 'Organization context not found.' }, { status: 404 });
  }
  const response = Response.json({ organization: access.organization, workspace: access.workspace });
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  response.headers.append('Set-Cookie', `ysd_organization=${encodeURIComponent(access.organization.id)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${secure}`);
  response.headers.append('Set-Cookie', `ysd_workspace=${encodeURIComponent(access.workspace.id)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${secure}`);
  return response;
}

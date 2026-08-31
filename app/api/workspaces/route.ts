import { can } from '@/lib/roles';
import { createWorkspace, listOrganizations } from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const organizations = await listOrganizations(auth.session.user.id);
  const selected = organizations.find((item) => item.id === auth.session.organization.id);
  return Response.json({ workspaces: selected?.workspaces ?? [] });
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'workspace.create')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  let body: { name?: unknown };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  try {
    const workspace = await createWorkspace({
      organizationId: auth.session.organization.id,
      actorId: auth.session.actor.userId,
      name: typeof body.name === 'string' ? body.name : '',
    });
    return Response.json({ workspace }, { status: 201 });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : 'Workspace could not be created.' }, { status: 409 });
  }
}

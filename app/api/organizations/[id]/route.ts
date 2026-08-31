import { can } from '@/lib/roles';
import { archiveOrganization, updateOrganization } from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { id } = await context.params;
  if (id !== auth.session.organization.id) return Response.json({ error: 'Organization not found.' }, { status: 404 });
  if (!can(auth.session.actor, 'organization.update')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  let body: { name?: unknown; adminCanRevokeSessions?: unknown };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  const organization = await updateOrganization({
    organizationId: id,
    actorId: auth.session.actor.userId,
    name: typeof body.name === 'string' ? body.name : undefined,
    adminCanRevokeSessions: typeof body.adminCanRevokeSessions === 'boolean' ? body.adminCanRevokeSessions : undefined,
  });
  return organization ? Response.json({ organization }) : Response.json({ error: 'Organization not found.' }, { status: 404 });
}

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { id } = await context.params;
  if (id !== auth.session.organization.id) return Response.json({ error: 'Organization not found.' }, { status: 404 });
  if (!can(auth.session.actor, 'organization.archive')) return Response.json({ error: 'Only the owner can archive this organization.' }, { status: 403 });
  const archived = await archiveOrganization(id, auth.session.actor.userId);
  return archived ? Response.json({ archived: true }) : Response.json({ error: 'Organization not found.' }, { status: 404 });
}

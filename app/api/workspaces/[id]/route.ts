import { can } from '@/lib/roles';
import { archiveWorkspace } from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'workspace.archive')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  const { id } = await context.params;
  const archived = await archiveWorkspace(auth.session.organization.id, id, auth.session.actor.userId);
  return archived ? Response.json({ archived: true }) : Response.json({ error: 'Workspace not found or it is the last active workspace.' }, { status: 409 });
}

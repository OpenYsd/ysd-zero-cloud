import { deleteProject } from '@/lib/server/projects';
import { recordEvidence } from '@/lib/server/audit';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const removed = await deleteProject(
    auth.session.workspace.id,
    id,
    auth.session.user.email,
    auth.session.actor.projectIds,
  );
  if (!removed) return Response.json({ error: 'Project not found.' }, { status: 404 });
  await recordEvidence({
    action: 'project.delete',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
  });
  return Response.json({ deleted: id });
}

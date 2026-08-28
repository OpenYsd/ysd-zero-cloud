import { deleteProject } from '@/lib/server/projects';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const removed = await deleteProject(auth.session.workspace.id, id, auth.session.user.email);
  if (!removed) return Response.json({ error: 'Project not found.' }, { status: 404 });
  return Response.json({ deleted: id });
}

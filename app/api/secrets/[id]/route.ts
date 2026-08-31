import { deleteSecret } from '@/lib/server/secrets';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const removed = await deleteSecret(
    auth.session.workspace.id,
    id,
    auth.session.user.email,
    auth.session.actor.projectIds,
  );
  if (!removed) return Response.json({ error: 'Secret not found.' }, { status: 404 });
  return Response.json({ deleted: id });
}

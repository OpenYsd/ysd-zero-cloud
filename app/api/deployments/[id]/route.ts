import { getDeployment } from '@/lib/server/deployments';
import { requireApiSession } from '@/lib/server/session';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  if (!/^dpl_[a-f0-9]{24}$/.test(id)) return Response.json({ error: 'Deployment not found.' }, { status: 404 });
  const deployment = await getDeployment(auth.session.workspace.id, id);
  return deployment
    ? Response.json({ deployment })
    : Response.json({ error: 'Deployment not found.' }, { status: 404 });
}

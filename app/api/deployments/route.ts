import { listDeployments } from '@/lib/server/deployments';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limit = Number(new URL(request.url).searchParams.get('limit') ?? 50);
  return Response.json({
    deployments: await listDeployments(auth.session.workspace.id, Number.isFinite(limit) ? limit : 50),
  });
}

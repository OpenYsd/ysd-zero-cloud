import { requireApiSession } from '@/lib/server/session';
import { runScan } from '@/lib/server/shield-scan';

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { user, workspace } = auth.session;
  return Response.json(await runScan(workspace.id, user.id, user.email));
}

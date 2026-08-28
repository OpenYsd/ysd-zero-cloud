import { requireApiSession } from '@/lib/server/session';
import { readShieldState } from '@/lib/server/shield-scan';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json(await readShieldState(auth.session.workspace.id));
}

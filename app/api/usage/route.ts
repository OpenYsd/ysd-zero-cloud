import { requireApiSession } from '@/lib/server/session';
import { summarizeUsage } from '@/lib/server/usage';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json(await summarizeUsage(auth.session.workspace.id));
}

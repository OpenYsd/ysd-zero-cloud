import { readAiState } from '@/lib/server/ai';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json(await readAiState(auth.session.workspace.id));
}

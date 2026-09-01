import { parseIncidentFilters } from '@/lib/incidents';
import { requireApiSession } from '@/lib/server/session';
import { listIncidentState } from '@/lib/server/incidents';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const state = await listIncidentState({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    filters: parseIncidentFilters(new URL(request.url).searchParams),
  });
  return Response.json(state);
}

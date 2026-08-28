import { isLogLevel, isLogSource, listLogs } from '@/lib/server/logs';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const params = new URL(request.url).searchParams;
  const source = params.get('source') ?? '';
  const level = params.get('level') ?? '';
  const limit = Number(params.get('limit') ?? 100);

  return Response.json({
    events: await listLogs(auth.session.workspace.id, {
      search: params.get('search') ?? undefined,
      source: isLogSource(source) ? source : undefined,
      level: isLogLevel(level) ? level : undefined,
      limit: Number.isFinite(limit) ? limit : 100,
    }),
  });
}

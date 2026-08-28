import { requireApiSession } from '@/lib/server/session';
import { readTable } from '@/lib/server/studio';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const params = new URL(request.url).searchParams;
  const table = params.get('table') ?? '';
  if (!table) return Response.json({ error: 'table is required' }, { status: 400 });

  const limit = Number(params.get('limit') ?? 50);
  const offset = Number(params.get('offset') ?? 0);

  const page = await readTable(table, {
    limit: Number.isFinite(limit) ? limit : 50,
    offset: Number.isFinite(offset) ? offset : 0,
    filter: params.get('filter') ?? undefined,
  });

  if (!page) return Response.json({ error: `Unknown table: ${table}` }, { status: 404 });
  return Response.json(page);
}

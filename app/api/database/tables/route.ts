import { requireApiSession } from '@/lib/server/session';
import { databaseBytes, listTables } from '@/lib/server/studio';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json({ tables: await listTables(), bytes: await databaseBytes() });
}

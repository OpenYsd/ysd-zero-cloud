import { requireApiSession } from '@/lib/server/session';
import { databaseBytes, listTables } from '@/lib/server/studio';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { user, workspace } = auth.session;
  return Response.json({
    tables: await listTables({ workspaceId: workspace.id, userId: user.id }),
    bytes: await databaseBytes(),
  });
}

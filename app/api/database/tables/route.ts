import { requireApiSession } from '@/lib/server/session';
import { databaseBytes, listTables } from '@/lib/server/studio';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { user, organization, workspace, actor } = auth.session;
  return Response.json({
    tables: await listTables({
      organizationId: organization.id,
      workspaceId: workspace.id,
      userId: user.id,
      projectIds: actor.projectIds,
    }),
    bytes: await databaseBytes(),
  });
}

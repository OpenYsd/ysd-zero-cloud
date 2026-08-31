import { requireApiSession } from '@/lib/server/session';
import { summarizeUsage } from '@/lib/server/usage';
import { readCollaborationLimits } from '@/lib/server/organization-limits';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { user, workspace, organization } = auth.session;
  const [usage, collaboration] = await Promise.all([
    summarizeUsage(workspace.id, user.id, {
      organizationId: organization.id,
      projectIds: auth.session.actor.projectIds,
    }),
    readCollaborationLimits(organization.id, workspace.id),
  ]);
  return Response.json({ ...usage, collaboration });
}

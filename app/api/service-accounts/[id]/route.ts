import { can } from '@/lib/roles';
import { revokeServiceAccount } from '@/lib/server/service-accounts';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'service-account.manage')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  const { id } = await context.params;
  const revoked = await revokeServiceAccount({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    accountId: id,
    actorId: auth.session.actor.userId,
  });
  return revoked ? Response.json({ revoked: true }) : Response.json({ error: 'Service account not found.' }, { status: 404 });
}

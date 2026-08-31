import { can } from '@/lib/roles';
import { revokeInvitation } from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'invitation.manage')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  const { id } = await context.params;
  const revoked = await revokeInvitation(auth.session.organization.id, id, auth.session.actor.userId);
  return revoked ? Response.json({ revoked: true }) : Response.json({ error: 'Invitation not found.' }, { status: 404 });
}

import { can } from '@/lib/roles';
import { revokeMemberSessions } from '@/lib/server/devices';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'session.revoke-member')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  const { id } = await context.params;
  const result = await revokeMemberSessions({
    organizationId: auth.session.organization.id,
    actorId: auth.session.actor.userId,
    actorRole: auth.session.actor.role,
    targetUserId: id,
  });
  return result.ok ? Response.json(result) : Response.json({ error: result.error }, { status: 403 });
}

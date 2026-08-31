import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { markNotificationRead } from '@/lib/server/workflows';

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!/^note_[a-f0-9]{24}$/.test(id)) return Response.json({ error: 'Notification not found.' }, { status: 404 });
  const updated = await markNotificationRead({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    notificationId: id,
    userId: auth.session.user.id,
  });
  return updated
    ? Response.json({ ok: true }, { headers: limited.headers })
    : Response.json({ error: 'Notification not found.' }, { status: 404, headers: limited.headers });
}

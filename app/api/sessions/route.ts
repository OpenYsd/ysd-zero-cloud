import { can } from '@/lib/roles';
import { listOwnSessions, revokeAllOwnSessions, revokeOwnSession } from '@/lib/server/devices';
import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (auth.session.principal !== 'user' || !can(auth.session.actor, 'session.read-own')) return Response.json({ error: 'User session required.' }, { status: 403 });
  return Response.json({ sessions: await listOwnSessions(auth.session.user.id) });
}

export async function DELETE(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (auth.session.principal !== 'user' || !can(auth.session.actor, 'session.revoke-own')) return Response.json({ error: 'User session required.' }, { status: 403 });
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('id');
  const all = url.searchParams.get('all') === 'true';
  const revoked = all
    ? await revokeAllOwnSessions(auth.session.user.id)
    : sessionId && await revokeOwnSession(auth.session.user.id, sessionId) ? 1 : 0;
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: 'user', actorId: auth.session.user.id,
    action: all ? 'session.revoke-all-own' : 'session.revoke-own',
    resourceType: 'session', resourceId: all ? null : sessionId,
    outcome: revoked > 0 ? 'success' : 'failed',
    ...requestAuditContext(request),
    metadata: { revoked },
  });
  return revoked > 0 ? Response.json({ revoked }) : Response.json({ error: 'Session not found.' }, { status: 404 });
}

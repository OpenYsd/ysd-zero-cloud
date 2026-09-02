import { revokeNode } from '@/lib/server/nodes';
import { recordEvidence } from '@/lib/server/audit';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit(
    'api:write',
    auth.session.actor.userId,
  );
  if (limited.response) return limited.response;
  const { id } = await params;
  const revoked = await revokeNode({
    workspaceId: auth.session.workspace.id,
    nodeId: id,
    actor: auth.session.user.email,
  });
  if (!revoked) {
    return Response.json({ error: 'Node not found.' }, { status: 404 });
  }
  await recordEvidence({
    action: 'node.revoke',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
  });
  return Response.json({ revoked: id });
}

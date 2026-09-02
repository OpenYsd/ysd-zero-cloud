import { queueGameServerRequest } from '@/lib/server/game-servers';
import { recordEvidence } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function POST(
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
  const parsed = await readBoundedJson(request, 32 * 1024);
  if (!parsed.ok) return parsed.response;
  const { id } = await params;
  const result = await queueGameServerRequest({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    serverId: id,
    body: parsed.body,
    idempotencyKey: request.headers.get('idempotency-key'),
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  await recordEvidence({
    action: 'game-server.action',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
    metadata: {
      operation:
        typeof (parsed.body as { operation?: unknown }).operation === 'string'
          ? ((parsed.body as { operation: string }).operation)
          : 'unknown',
    },
  });
  return Response.json(result, { status: result.created ? 201 : 200 });
}

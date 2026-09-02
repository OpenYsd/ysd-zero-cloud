import { queueModelCache } from '@/lib/server/ai';
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
  const parsed = await readBoundedJson(request, 2048);
  if (!parsed.ok) return parsed.response;
  const { id } = await params;
  const result = await queueModelCache({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    modelId: id,
    nodeId: parsed.body.nodeId,
    approved: parsed.body.approved,
    idempotencyKey: request.headers.get('idempotency-key'),
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  await recordEvidence({
    action: 'ai.model.cache',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
    metadata: {
      nodeId: typeof parsed.body.nodeId === 'string' ? parsed.body.nodeId : 'unknown',
    },
  });
  return Response.json(
    { job: result.job, duplicate: !result.created },
    { status: result.created ? 201 : 200 },
  );
}

import { enqueueJob } from '@/lib/server/nodes';
import { recordEvidence } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit(
    'api:write',
    auth.session.actor.userId,
  );
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 8192);
  if (!parsed.ok) return parsed.response;
  if (
    parsed.body.type !== 'diagnostic.ping' &&
    parsed.body.type !== 'diagnostic.snapshot'
  ) {
    return Response.json(
      { error: 'AI work must be created through the workspace-scoped AI Center.' },
      { status: 400 },
    );
  }
  const result = await enqueueJob({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    type: parsed.body.type,
    payload: parsed.body.payload,
    targetNodeId: parsed.body.targetNodeId,
    idempotencyKey: request.headers.get('idempotency-key'),
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  await recordEvidence({
    action: 'node.job.create',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: result.job.id,
    outcome: 'success',
    request,
    metadata: { kind: parsed.body.type },
  });
  return Response.json(
    { job: result.job, duplicate: !result.created },
    { status: result.created ? 201 : 200 },
  );
}

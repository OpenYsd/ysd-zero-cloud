import { queueAiInference } from '@/lib/server/ai';
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
  const parsed = await readBoundedJson(request, 32 * 1024);
  if (!parsed.ok) return parsed.response;
  const result = await queueAiInference({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    body: parsed.body,
    idempotencyKey: request.headers.get('idempotency-key'),
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  await recordEvidence({
    action: 'ai.job.run',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: result.run.jobId,
    outcome: 'success',
    request,
    metadata: { modelId: result.run.modelId },
  });
  return Response.json(
    { run: result.run, duplicate: !result.created },
    { status: result.created ? 201 : 200 },
  );
}

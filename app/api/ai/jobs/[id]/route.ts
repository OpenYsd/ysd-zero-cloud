import { cancelAiInference } from '@/lib/server/ai';
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
  const result = await cancelAiInference({
    workspaceId: auth.session.workspace.id,
    jobId: id,
    actor: auth.session.user.email,
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  await recordEvidence({
    action: 'ai.job.cancel',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: 'success',
    request,
  });
  return Response.json(result);
}

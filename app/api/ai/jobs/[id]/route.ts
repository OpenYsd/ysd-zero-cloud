import { cancelAiInference } from '@/lib/server/ai';
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
  return Response.json(result);
}

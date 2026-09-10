import { transferDeploymentOwnership } from '@/lib/server/nodes';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

/**
 * Moves one deployment from a lost node to a replacement node.
 *
 * Every identity the caller believes is stated in the body and checked against
 * the database: which node has it now, which revision, which artifact. Nothing
 * is inferred, so an operator acting on a stale screen loses the race instead
 * of moving the wrong deployment.
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return Response.json({ error: 'The transfer request is invalid.' }, { status: 400 });
  }
  const { id } = await params;
  const result = await transferDeploymentOwnership({
    workspaceId: auth.session.workspace.id,
    deploymentId: id,
    sourceNodeId: typeof body.sourceNodeId === 'string' ? body.sourceNodeId : '',
    replacementNodeId: typeof body.replacementNodeId === 'string' ? body.replacementNodeId : '',
    expectedDesiredRevision:
      typeof body.expectedDesiredRevision === 'number' ? body.expectedDesiredRevision : -1,
    expectedArtifactId: typeof body.expectedArtifactId === 'string' ? body.expectedArtifactId : '',
    actor: auth.session.user.email,
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}

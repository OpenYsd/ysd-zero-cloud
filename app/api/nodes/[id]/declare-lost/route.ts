import { declareNodeLost } from '@/lib/server/nodes';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

/**
 * Declares a Compute Node permanently lost.
 *
 * Separate from revoke on purpose, and not a variation of it: revoke stops the
 * work, this preserves the intent so the work can be moved. It is irreversible
 * -- the credential is destroyed the same way revoke destroys it -- so it is an
 * explicit operator action against one node, never something a job or a
 * timeout can decide.
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  const result = await declareNodeLost({
    workspaceId: auth.session.workspace.id,
    nodeId: id,
    actor: auth.session.user.email,
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result);
}

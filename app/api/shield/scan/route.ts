import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { runScan } from '@/lib/server/shield-scan';

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { user, workspace } = auth.session;
  // Explicit rather than relying on the default: this is the one path a human
  // starts, and the scheduler's path must be distinguishable from it in the
  // record forever after.
  return Response.json(await runScan(workspace.id, user.id, user.email, 'manual'));
}

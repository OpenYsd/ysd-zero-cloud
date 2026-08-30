import {
  queueGameServerRequest,
  readGameServersState,
} from '@/lib/server/game-servers';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json(
    await readGameServersState(auth.session.workspace.id),
  );
}

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
  const result = await queueGameServerRequest({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    body: parsed.body,
    idempotencyKey: request.headers.get('idempotency-key'),
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json(result, { status: result.created ? 201 : 200 });
}

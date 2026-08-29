import { createPairing, readNodesState } from '@/lib/server/nodes';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json(await readNodesState(auth.session.workspace.id));
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit(
    'api:write',
    auth.session.actor.userId,
  );
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 4096);
  if (!parsed.ok) return parsed.response;
  const result = await createPairing({
    workspaceId: auth.session.workspace.id,
    name: parsed.body.name,
    actor: auth.session.user.email,
  });
  if (!result.ok) {
    return Response.json({ error: result.error }, { status: result.status });
  }
  return Response.json({ pairing: result.pairing }, { status: 201 });
}

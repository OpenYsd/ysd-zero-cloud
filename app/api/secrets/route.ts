import { listSecrets, putSecret } from '@/lib/server/secrets';
import { recordEvidence } from '@/lib/server/audit';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json({
    secrets: await listSecrets(auth.session.workspace.id, auth.session.actor.projectIds),
  });
}

/** Creates or rotates a secret. The value is sealed before it reaches D1. */
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;

  let body: {
    name?: unknown;
    value?: unknown;
    scope?: unknown;
    environment?: unknown;
    rotationDays?: unknown;
  };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }

  const result = await putSecret({
    workspaceId: auth.session.workspace.id,
    actor: auth.session.user.email,
    name: typeof body.name === 'string' ? body.name : '',
    value: typeof body.value === 'string' ? body.value : '',
    scope: typeof body.scope === 'string' ? body.scope : undefined,
    environment: typeof body.environment === 'string' ? body.environment : undefined,
    rotationDays: typeof body.rotationDays === 'number' ? body.rotationDays : null,
    allowedProjectIds: auth.session.actor.projectIds,
  });

  if (!result.ok) return Response.json({ error: result.error }, { status: result.status });
  await recordEvidence({
    action: 'secret.write',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: result.secret.id,
    outcome: 'success',
    request,
    // Name, value, ciphertext, and fingerprint are all withheld deliberately.
    metadata: {
      environment: result.secret.environment,
      scope: result.secret.scope,
      rotated: !result.created,
    },
  });
  return Response.json({ secret: result.secret }, { status: result.created ? 201 : 200 });
}

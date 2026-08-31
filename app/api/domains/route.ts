import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { createExposureDomain, listExposureDomains } from '@/lib/server/public-exposure';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json({
    domains: await listExposureDomains(auth.session.organization.id, auth.session.workspace.id),
  });
}
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 2_048);
  if (!parsed.ok) return parsed.response;
  const keys = Object.keys(parsed.body);
  if (keys.some((key) => key !== 'hostname')) {
    return Response.json({ error: 'Only an owned hostname may be inventoried.' }, { status: 400 });
  }
  const result = await createExposureDomain({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    hostname: parsed.body.hostname,
  });
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok ? 'exposure.domain.inventory' : 'exposure.domain.inventory.denied',
    resourceType: 'exposure_domain',
    resourceId: result.ok ? result.domain.id : null,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role, zeroCost: true },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { status: 201, headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

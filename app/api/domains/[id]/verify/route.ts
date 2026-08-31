import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { verifyExposureDomain } from '@/lib/server/public-exposure';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!/^dom_[a-f0-9]{24}$/.test(id)) return Response.json({ error: 'Domain not found.' }, { status: 404 });
  const result = await verifyExposureDomain({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    domainId: id,
    actor: auth.session.actor,
  });
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok ? 'exposure.domain.ownership.verify' : 'exposure.domain.ownership.failed',
    resourceType: 'exposure_domain',
    resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

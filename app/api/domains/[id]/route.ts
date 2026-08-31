import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { attachExposureDomain, deleteExposureDomain } from '@/lib/server/public-exposure';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

function validId(value: string): boolean {
  return /^dom_[a-f0-9]{24}$/.test(value);
}
export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!validId(id)) return Response.json({ error: 'Domain not found.' }, { status: 404 });
  const parsed = await readBoundedJson(request, 1_024);
  if (!parsed.ok) return parsed.response;
  if (Object.keys(parsed.body).some((key) => key !== 'exposureId')) {
    return Response.json({ error: 'Only a registered exposure identity may be attached.' }, { status: 400 });
  }
  const exposureId = parsed.body.exposureId === null
    ? null
    : typeof parsed.body.exposureId === 'string' && /^exp_[a-f0-9]{24}$/.test(parsed.body.exposureId)
      ? parsed.body.exposureId
      : undefined;
  if (exposureId === undefined) return Response.json({ error: 'A valid exposure identity or null is required.' }, { status: 400 });
  const result = await attachExposureDomain({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    domainId: id,
    exposureId,
    actor: auth.session.actor,
  });
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok
      ? exposureId === null ? 'exposure.domain.detach' : 'exposure.domain.attach'
      : exposureId === null ? 'exposure.domain.detach.denied' : 'exposure.domain.attach.denied',
    resourceType: 'exposure_domain',
    resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role, attached: exposureId !== null },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!validId(id)) return Response.json({ error: 'Domain not found.' }, { status: 404 });
  const result = await deleteExposureDomain({
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
    action: result.ok ? 'exposure.domain.remove' : 'exposure.domain.remove.denied',
    resourceType: 'exposure_domain',
    resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role },
  }).catch(() => undefined);
  return result.ok
    ? new Response(null, { status: 204, headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { deletePublicExposure, listPublicExposures } from '@/lib/server/public-exposure';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

function validId(value: string): boolean {
  return /^exp_[a-f0-9]{24}$/.test(value);
}
export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  if (!validId(id)) return Response.json({ error: 'Exposure not found.' }, { status: 404 });
  const exposure = (await listPublicExposures({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
  })).find((item) => item.id === id);
  return exposure
    ? Response.json({ exposure })
    : Response.json({ error: 'Exposure not found.' }, { status: 404 });
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
  if (!validId(id)) return Response.json({ error: 'Exposure not found.' }, { status: 404 });
  const result = await deletePublicExposure({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    exposureId: id,
    actor: auth.session.actor,
  });
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok ? 'exposure.route.delete' : 'exposure.delete.denied',
    resourceType: 'public_exposure',
    resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role },
  }).catch(() => undefined);
  return result.ok
    ? new Response(null, { status: 204, headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import {
  listPublicExposures,
  recordExposureSecurityEvent,
  upsertPublicExposure,
} from '@/lib/server/public-exposure';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const exposures = await listPublicExposures({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
  });
  return Response.json({ exposures });
}
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 8_192);
  if (!parsed.ok) return parsed.response;
  const result = await upsertPublicExposure({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    body: parsed.body,
  });
  if (!result.ok && result.securityEvent) {
    await recordExposureSecurityEvent({
      workspaceId: auth.session.workspace.id,
      type: result.securityEvent,
      detail: 'A public exposure mutation attempted to supply an upstream, provider, tunnel, command, billing field, or Zero Mode override.',
    }).catch(() => undefined);
  }
  const context = requestAuditContext(request);
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok
      ? result.exposure.mode === 'private'
        ? 'exposure.disable'
        : result.created
          ? 'exposure.enable'
          : 'exposure.route.change'
      : 'exposure.change.denied',
    resourceType: 'public_exposure',
    resourceId: result.ok ? result.exposure.id : null,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...context,
    metadata: result.ok
      ? {
          role: auth.session.actor.role,
          mode: result.exposure.mode,
          access: result.exposure.accessPolicy,
          preview: result.exposure.preview,
          rateLimit: result.exposure.rateLimitPerMinute,
          zeroCost: true,
        }
      : { role: auth.session.actor.role },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { status: result.created ? 201 : 200, headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

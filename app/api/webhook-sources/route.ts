import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import {
  createWebhookSource,
  listWebhookGatewayState,
} from '@/lib/server/webhook-sources';
import { recordWorkflowSecurityEvent } from '@/lib/server/workflow-events';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  return Response.json(await listWebhookGatewayState({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
  }));
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 4_096);
  if (!parsed.ok) return parsed.response;
  const allowed = new Set(['name', 'description', 'projectId']);
  if (Object.keys(parsed.body).some((key) => !allowed.has(key))) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id,
      type: 'webhook-source-payload-abuse', severity: 'critical',
      detail: 'A source create request included fields outside the reviewed contract.',
    }).catch(() => undefined);
    return Response.json({ error: 'Unknown webhook source fields are forbidden.' }, { status: 400 });
  }
  const result = await createWebhookSource({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    name: parsed.body.name,
    description: parsed.body.description,
    projectId: parsed.body.projectId,
  });
  if (!result.ok && result.securityCode) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id,
      type: result.securityCode, severity: 'critical', detail: result.error,
    }).catch(() => undefined);
  }
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok ? 'webhook.source.create' : 'webhook.source.create.denied',
    resourceType: 'webhook_source',
    resourceId: result.ok ? result.value.source.id : null,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role, zeroCost: true },
  }).catch(() => undefined);
  const responseHeaders = new Headers(limited.headers);
  responseHeaders.set('cache-control', 'no-store');
  return result.ok
    ? Response.json(result.value, { status: 201, headers: responseHeaders })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

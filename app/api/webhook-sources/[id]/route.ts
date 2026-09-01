import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import {
  archiveWebhookSource,
  updateWebhookSource,
} from '@/lib/server/webhook-sources';
import { recordWorkflowSecurityEvent } from '@/lib/server/workflow-events';
import { WEBHOOK_SOURCE_ID } from '@/lib/webhook-gateway';

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!WEBHOOK_SOURCE_ID.test(id)) return Response.json({ error: 'Webhook source not found.' }, { status: 404 });
  const parsed = await readBoundedJson(request, 4_096);
  if (!parsed.ok) return parsed.response;
  const allowed = new Set(['operation', 'name', 'description']);
  if (Object.keys(parsed.body).some((key) => !allowed.has(key)) ||
      typeof parsed.body.operation !== 'string') {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id,
      type: 'webhook-source-payload-abuse', severity: 'critical',
      detail: 'A source mutation included fields outside the reviewed contract.',
    }).catch(() => undefined);
    return Response.json({ error: 'Unknown webhook source mutation fields are forbidden.' }, { status: 400 });
  }
  const result = await updateWebhookSource({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    sourceId: id,
    operation: parsed.body.operation,
    name: parsed.body.name,
    description: parsed.body.description,
  });
  const operation = parsed.body.operation.slice(0, 40);
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok ? `webhook.source.${operation}` : 'webhook.source.change.denied',
    resourceType: 'webhook_source', resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role },
  }).catch(() => undefined);
  const responseHeaders = new Headers(limited.headers);
  responseHeaders.set('cache-control', 'no-store');
  return result.ok
    ? Response.json(result.value, { headers: responseHeaders })
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
  if (!WEBHOOK_SOURCE_ID.test(id)) return Response.json({ error: 'Webhook source not found.' }, { status: 404 });
  const result = await archiveWebhookSource({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    sourceId: id,
  });
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok ? 'webhook.source.archive' : 'webhook.source.archive.denied',
    resourceType: 'webhook_source', resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role },
  }).catch(() => undefined);
  return result.ok
    ? new Response(null, { status: 204, headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

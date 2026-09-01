import { isIncidentId, parseIncidentMutation, INCIDENT_LIMITS } from '@/lib/incidents';
import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { mutateIncident } from '@/lib/server/incidents';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { recordWorkflowSecurityEvent } from '@/lib/server/workflow-events';

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return Response.json({ error: 'Incident mutations require application/json.' }, { status: 415, headers: limited.headers });
  }
  const { id } = await params;
  if (!isIncidentId(id)) return Response.json({ error: 'Incident not found.' }, { status: 404 });
  const parsedBody = await readBoundedJson(request, INCIDENT_LIMITS.requestBytes);
  if (!parsedBody.ok) return parsedBody.response;
  const parsed = parseIncidentMutation(parsedBody.body);
  const result = parsed.ok
    ? await mutateIncident({
        organizationId: auth.session.organization.id,
        workspaceId: auth.session.workspace.id,
        incidentId: id,
        actor: auth.session.actor,
        mutation: parsed.mutation,
      })
    : { ok: false as const, status: 400, error: parsed.error, securityCode: parsed.securityCode };
  const securityCode = result.ok ? null : result.securityCode;
  if (securityCode) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id,
      type: securityCode,
      severity: securityCode.includes('cross-tenant') || securityCode.includes('sensitive') ? 'critical' : 'high',
      detail: 'An incident mutation was rejected by the server-authoritative Operations Center policy.',
    }).catch(() => undefined);
  }
  const operation = parsed.ok ? parsed.mutation.operation : 'invalid';
  const auditOperation = operation === 'severity' ? 'severity_change' : operation;
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    action: result.ok ? `incident.${auditOperation}` : `incident.${auditOperation}.denied`,
    resourceType: 'incident',
    resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 || result.status === 404 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role, zeroCost: true },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

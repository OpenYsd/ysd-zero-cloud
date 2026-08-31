import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { recordWorkflowSecurityEvent } from '@/lib/server/workflow-events';
import { deleteWorkflowVariable, setWorkflowVariable } from '@/lib/server/workflows';

const ID = /^wf_[a-f0-9]{24}$/;

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!ID.test(id)) return Response.json({ error: 'Workflow not found.' }, { status: 404 });
  const parsed = await readBoundedJson(request, 4096);
  if (!parsed.ok) return parsed.response;
  const allowed = new Set(['operation', 'name', 'kind', 'value', 'secretId']);
  if (Object.keys(parsed.body).some((key) => !allowed.has(key))) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id, workflowId: id,
      type: 'workflow-variable-payload-rejected', severity: 'high',
      detail: 'A workflow variable request included fields outside the reviewed metadata contract.',
    });
    return Response.json({ error: 'Unknown variable fields are forbidden.' }, { status: 400 });
  }
  const common = {
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    workflowId: id,
    actor: auth.session.actor,
    name: parsed.body.name,
  };
  const operation = parsed.body.operation === 'delete' ? 'delete' : parsed.body.operation === 'set' ? 'set' : null;
  const result = operation === 'delete'
    ? await deleteWorkflowVariable(common)
    : operation === 'set'
      ? await setWorkflowVariable({
          ...common, kind: parsed.body.kind, value: parsed.body.value,
          secretId: parsed.body.secretId,
        })
      : { ok: false as const, status: 400, error: 'Choose set or delete.' };
  const securityCode = !result.ok && 'securityCode' in result && typeof result.securityCode === 'string'
    ? result.securityCode
    : null;
  if (securityCode) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id, workflowId: id,
      type: securityCode, severity: 'critical', detail: !result.ok ? result.error : 'Workflow variable request rejected.',
    }).catch(() => undefined);
  }
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal, actorId: auth.session.actor.userId,
    action: result.ok ? `workflow.variable.${operation ?? 'unknown'}` : 'workflow.variable.denied',
    resourceType: 'workflow_variable', resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: {
      name: typeof parsed.body.name === 'string' ? parsed.body.name.slice(0, 64) : 'invalid',
      kind: typeof parsed.body.kind === 'string' ? parsed.body.kind : 'none',
    },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import {
  cancelWorkflowExecution,
  retryWorkflowExecution,
} from '@/lib/server/workflows';

const ID = /^wfexec_[a-f0-9]{24}$/;

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!ID.test(id)) return Response.json({ error: 'Execution not found.' }, { status: 404 });
  const parsed = await readBoundedJson(request, 1_024);
  if (!parsed.ok) return parsed.response;
  if (Object.keys(parsed.body).length !== 1 || (parsed.body.operation !== 'cancel' && parsed.body.operation !== 'retry')) {
    return Response.json({ error: 'Choose cancel or retry.' }, { status: 400 });
  }
  const result = parsed.body.operation === 'cancel'
    ? await cancelWorkflowExecution({
        organizationId: auth.session.organization.id,
        workspaceId: auth.session.workspace.id,
        executionId: id,
        actor: auth.session.actor,
      })
    : await retryWorkflowExecution({
        organizationId: auth.session.organization.id,
        workspaceId: auth.session.workspace.id,
        executionId: id,
        actor: auth.session.actor,
      });
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal, actorId: auth.session.actor.userId,
    action: result.ok ? `workflow.execution.${parsed.body.operation}` : 'workflow.execution.change.denied',
    resourceType: 'workflow_execution', resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request), metadata: { role: auth.session.actor.role },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

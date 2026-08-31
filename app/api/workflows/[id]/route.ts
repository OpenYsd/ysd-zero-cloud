import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { recordWorkflowSecurityEvent } from '@/lib/server/workflow-events';
import {
  deleteWorkflow,
  publishWorkflow,
  rollbackWorkflowVersion,
  setWorkflowStatus,
  triggerWorkflowManual,
  updateWorkflowDraft,
} from '@/lib/server/workflows';

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
  const parsed = await readBoundedJson(request, 24_576);
  if (!parsed.ok) return parsed.response;
  const allowed = new Set(['operation', 'name', 'description', 'definition', 'versionId']);
  if (Object.keys(parsed.body).some((key) => !allowed.has(key)) || typeof parsed.body.operation !== 'string') {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id, workflowId: id,
      type: 'workflow-payload-abuse', severity: 'critical',
      detail: 'A workflow mutation included fields outside the reviewed contract.',
    });
    return Response.json({ error: 'Unknown workflow mutation fields are forbidden.' }, { status: 400 });
  }
  const common = {
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    workflowId: id,
    actor: auth.session.actor,
  };
  let result:
    | Awaited<ReturnType<typeof updateWorkflowDraft>>
    | Awaited<ReturnType<typeof publishWorkflow>>
    | Awaited<ReturnType<typeof rollbackWorkflowVersion>>
    | Awaited<ReturnType<typeof setWorkflowStatus>>
    | Awaited<ReturnType<typeof triggerWorkflowManual>>;
  switch (parsed.body.operation) {
    case 'update':
      result = await updateWorkflowDraft({
        ...common, name: parsed.body.name, description: parsed.body.description,
        definition: parsed.body.definition,
      });
      break;
    case 'publish':
      result = typeof parsed.body.versionId === 'string'
        ? await publishWorkflow({ ...common, versionId: parsed.body.versionId })
        : { ok: false, status: 400, error: 'Choose a draft version to publish.' };
      break;
    case 'rollback':
      result = typeof parsed.body.versionId === 'string'
        ? await rollbackWorkflowVersion({ ...common, targetVersionId: parsed.body.versionId })
        : { ok: false, status: 400, error: 'Choose a published version to restore.' };
      break;
    case 'pause':
      result = await setWorkflowStatus({ ...common, status: 'paused' });
      break;
    case 'resume':
      result = await setWorkflowStatus({ ...common, status: 'active' });
      break;
    case 'manual-run':
      result = await triggerWorkflowManual(common);
      break;
    default:
      result = { ok: false, status: 400, error: 'Choose a reviewed workflow operation.' };
  }
  if (!result.ok && 'securityCode' in result && result.securityCode) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id, workflowId: id,
      type: result.securityCode, severity: 'critical', detail: result.error,
    }).catch(() => undefined);
  }
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal, actorId: auth.session.actor.userId,
    action: result.ok ? `workflow.${parsed.body.operation}` : 'workflow.change.denied',
    resourceType: 'workflow', resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request), metadata: { role: auth.session.actor.role },
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
  if (!ID.test(id)) return Response.json({ error: 'Workflow not found.' }, { status: 404 });
  const result = await deleteWorkflow({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    workflowId: id,
    actor: auth.session.actor,
  });
  await recordAudit({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal, actorId: auth.session.actor.userId,
    action: result.ok ? 'workflow.delete' : 'workflow.delete.denied',
    resourceType: 'workflow', resourceId: id,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request), metadata: { role: auth.session.actor.role },
  }).catch(() => undefined);
  return result.ok
    ? new Response(null, { status: 204, headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

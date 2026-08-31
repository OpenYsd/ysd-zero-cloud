import { recordAudit, requestAuditContext } from '@/lib/server/audit';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';
import { recordWorkflowSecurityEvent } from '@/lib/server/workflow-events';
import {
  createWorkflow,
  createWorkflowFromTemplate,
  listWorkflowsState,
} from '@/lib/server/workflows';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const state = await listWorkflowsState({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    userId: auth.session.user.id,
  });
  return Response.json(state);
}
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const parsed = await readBoundedJson(request, 24_576);
  if (!parsed.ok) return parsed.response;
  const allowed = new Set(['name', 'description', 'projectId', 'definition', 'templateId']);
  if (Object.keys(parsed.body).some((key) => !allowed.has(key))) {
    await recordWorkflowSecurityEvent({
      workspaceId: auth.session.workspace.id,
      type: 'workflow-payload-abuse', severity: 'critical',
      detail: 'A workflow create request included fields outside the reviewed contract.',
    });
    return Response.json({ error: 'Unknown workflow fields are forbidden.' }, { status: 400 });
  }
  const result = parsed.body.templateId
    ? await createWorkflowFromTemplate({
        organizationId: auth.session.organization.id,
        workspaceId: auth.session.workspace.id,
        actor: auth.session.actor,
        templateId: parsed.body.templateId,
        name: parsed.body.name,
        projectId: parsed.body.projectId,
      })
    : await createWorkflow({
        organizationId: auth.session.organization.id,
        workspaceId: auth.session.workspace.id,
        actor: auth.session.actor,
        name: parsed.body.name,
        description: parsed.body.description,
        projectId: parsed.body.projectId,
        definition: parsed.body.definition,
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
    action: result.ok ? 'workflow.create' : 'workflow.create.denied',
    resourceType: 'workflow', resourceId: result.ok ? result.workflowId : null,
    outcome: result.ok ? 'success' : result.status === 403 ? 'denied' : 'failed',
    ...requestAuditContext(request),
    metadata: { role: auth.session.actor.role, zeroCost: true },
  }).catch(() => undefined);
  return result.ok
    ? Response.json(result, { status: 201, headers: limited.headers })
    : Response.json({ error: result.error }, { status: result.status, headers: limited.headers });
}

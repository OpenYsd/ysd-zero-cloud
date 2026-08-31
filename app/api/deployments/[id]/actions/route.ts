import { APP_RUNTIME_OPERATIONS, type AppRuntimeOperation } from '@/lib/app-runtime';
import { cancelDeployment, createDeploymentAction } from '@/lib/server/deployments';
import { recordAppRuntimeSecurityEvent } from '@/lib/server/app-runtime-control';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

const ACTIONS = APP_RUNTIME_OPERATIONS.filter((operation) => operation !== 'deploy') as Exclude<AppRuntimeOperation, 'deploy'>[];

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!/^dpl_[a-f0-9]{24}$/.test(id)) return Response.json({ error: 'Deployment not found.' }, { status: 404 });
  const parsed = await readBoundedJson(request, 2_048);
  if (!parsed.ok) return parsed.response;
  const allowedKeys = new Set(['operation', 'targetArtifactId']);
  const unexpectedKeys = Object.keys(parsed.body).filter((key) => !allowedKeys.has(key));
  if (unexpectedKeys.length > 0) {
    const type = unexpectedKeys.some((key) => /tunnel|argo|spectrum|upnp/i.test(key))
      ? 'app-forbidden-tunnel'
      : unexpectedKeys.some((key) => /provider|billing|paid|fallback|gpu|zeroMode/i.test(key))
        ? 'app-forbidden-provider'
        : 'app-unsafe-script';
    await recordAppRuntimeSecurityEvent({
      workspaceId: auth.session.workspace.id,
      nodeId: null,
      type,
      severity: 'critical',
      detail: `Deployment ${id} received fields outside the fixed lifecycle action contract.`,
    });
    return Response.json({ error: 'Provider, command, arguments, and Zero Mode overrides are forbidden.' }, { status: 400 });
  }
  if (parsed.body.operation === 'cancel') {
    const result = await cancelDeployment({
      workspaceId: auth.session.workspace.id,
      deploymentId: id,
      actor: auth.session.user.email,
      allowedProjectIds: auth.session.actor.projectIds,
    });
    return result.ok ? Response.json(result) : Response.json({ error: result.error }, { status: result.status });
  }
  if (typeof parsed.body.operation !== 'string' || !ACTIONS.includes(parsed.body.operation as Exclude<AppRuntimeOperation, 'deploy'>)) {
    return Response.json({ error: 'Choose an allowlisted deployment action.' }, { status: 400 });
  }
  const result = await createDeploymentAction({
    workspaceId: auth.session.workspace.id,
    deploymentId: id,
    actor: auth.session.user.email,
    operation: parsed.body.operation as Exclude<AppRuntimeOperation, 'deploy'>,
    targetArtifactId: typeof parsed.body.targetArtifactId === 'string' ? parsed.body.targetArtifactId : null,
    idempotencyKey: request.headers.get('idempotency-key'),
    allowedProjectIds: auth.session.actor.projectIds,
  });
  return result.ok
    ? Response.json(result, { status: result.duplicate ? 200 : 202 })
    : Response.json({ error: result.error }, { status: result.status });
}

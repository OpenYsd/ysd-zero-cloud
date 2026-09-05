import { recordEvidence } from '@/lib/server/audit';
import { createRelease } from '@/lib/server/deployments';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { listReleases } from '@/lib/server/releases';
import { requireApiSession } from '@/lib/server/session';

const DEPLOYMENT_ID = /^dpl_[a-f0-9]{24}$/;

/**
 * One bounded page of a deployment's release history.
 *
 * GET, so the central route policy resolves it to `deployment.read` -- a
 * member who may look at deployments may read their history, and no new
 * permission is invented for it.
 */
export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  if (!DEPLOYMENT_ID.test(id)) return Response.json({ error: 'Deployment not found.' }, { status: 404 });
  const url = new URL(request.url);
  const history = await listReleases({
    workspaceId: auth.session.workspace.id,
    deploymentId: id,
    allowedProjectIds: auth.session.actor.projectIds,
    limit: url.searchParams.get('limit'),
    cursor: url.searchParams.get('cursor'),
  });
  return history
    ? Response.json({ history })
    : Response.json({ error: 'Deployment not found.' }, { status: 404 });
}

/**
 * Ship a new release of this existing service.
 *
 * The repository is never taken from the request -- only which branch or
 * commit inside the deployment's own repository to build. Anything else in
 * the body is refused rather than ignored, matching how the lifecycle action
 * route treats unexpected fields.
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;
  const { id } = await params;
  if (!DEPLOYMENT_ID.test(id)) return Response.json({ error: 'Deployment not found.' }, { status: 404 });
  const parsed = await readBoundedJson(request, 2_048);
  if (!parsed.ok) return parsed.response;
  const allowed = new Set(['branch', 'commit']);
  if (Object.keys(parsed.body).some((key) => !allowed.has(key))) {
    return Response.json(
      { error: 'A release selects a branch or commit of this deployment’s repository and nothing else.' },
      { status: 400 },
    );
  }
  const branch = typeof parsed.body.branch === 'string' ? parsed.body.branch : null;
  const commit = typeof parsed.body.commit === 'string' ? parsed.body.commit : null;
  if ((parsed.body.branch !== undefined && branch === null) || (parsed.body.commit !== undefined && commit === null)) {
    return Response.json({ error: 'Branch and commit must be strings.' }, { status: 400 });
  }
  const result = await createRelease({
    workspaceId: auth.session.workspace.id,
    deploymentId: id,
    actor: auth.session.user.email,
    branch,
    commit,
    idempotencyKey: request.headers.get('idempotency-key'),
    allowedProjectIds: auth.session.actor.projectIds,
  });
  await recordEvidence({
    action: 'deployment.release',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    outcome: result.ok ? 'success' : 'failed',
    request,
    metadata: result.ok
      ? {
          projectId: result.deployment.projectId,
          nodeId: result.deployment.nodeId,
          artifactId: result.artifactId || null,
          commitSha: result.deployment.commitSha,
        }
      : {},
  });
  return result.ok
    ? Response.json({ action: result.action, deployment: result.deployment, duplicate: result.duplicate }, { status: 202 })
    : Response.json({ error: result.error }, { status: result.status });
}

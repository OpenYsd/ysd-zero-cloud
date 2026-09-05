import { recordEvidence } from '@/lib/server/audit';
import { createDeploymentAction } from '@/lib/server/deployments';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { previewRollback } from '@/lib/server/releases';
import { requireApiSession } from '@/lib/server/session';

const DEPLOYMENT_ID = /^dpl_[a-f0-9]{24}$/;
const ARTIFACT_ID = /^art_[a-f0-9]{24}$/;

/**
 * What restoring a release would do, computed from live state and writing
 * nothing.
 *
 * A GET, so it needs only `deployment.read` and cannot be mistaken for the
 * action itself. It records no evidence: a preview is someone reading a
 * screen, and filing it as an event would put noise between real rollbacks in
 * the audit trail.
 */
export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  if (!DEPLOYMENT_ID.test(id)) return Response.json({ error: 'Deployment not found.' }, { status: 404 });
  const target = new URL(request.url).searchParams.get('targetArtifactId') ?? '';
  if (!ARTIFACT_ID.test(target)) {
    return Response.json({ error: 'Select a release to preview.' }, { status: 400 });
  }
  const preview = await previewRollback({
    workspaceId: auth.session.workspace.id,
    deploymentId: id,
    targetArtifactId: target,
    allowedProjectIds: auth.session.actor.projectIds,
  });
  return preview
    ? Response.json({ preview })
    : Response.json({ error: 'Deployment not found.' }, { status: 404 });
}

/**
 * Restore a previously built, verified release.
 *
 * Everything the preview showed is computed again here from live state --
 * the request carries no verdict the server will honour, only the release the
 * person picked and the release they believed was running.
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
  const allowed = new Set(['targetArtifactId', 'expectedCurrentArtifactId']);
  if (Object.keys(parsed.body).some((key) => !allowed.has(key))) {
    // Notably this refuses an `eligible` or `preflightPassed` flag rather
    // than quietly dropping it, so a caller cannot believe it was honoured.
    return Response.json(
      { error: 'Rollback accepts a target release and the release you saw running, and nothing else.' },
      { status: 400 },
    );
  }
  const target = typeof parsed.body.targetArtifactId === 'string' ? parsed.body.targetArtifactId : '';
  if (!ARTIFACT_ID.test(target)) {
    return Response.json({ error: 'Select a release to restore.' }, { status: 400 });
  }
  const expected = parsed.body.expectedCurrentArtifactId;
  if (expected !== undefined && expected !== null && (typeof expected !== 'string' || !ARTIFACT_ID.test(expected))) {
    return Response.json({ error: 'The expected current release is not a release id.' }, { status: 400 });
  }
  const result = await createDeploymentAction({
    workspaceId: auth.session.workspace.id,
    deploymentId: id,
    actor: auth.session.user.email,
    operation: 'rollback',
    targetArtifactId: target,
    expectedCurrentArtifactId: expected as string | null | undefined,
    idempotencyKey: request.headers.get('idempotency-key'),
    allowedProjectIds: auth.session.actor.projectIds,
  });
  await recordEvidence({
    action: 'deployment.rollback',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: id,
    // A refusal is evidence too. `denied` is reserved for the permission
    // layer, which answers before this handler runs, so the outcome here is
    // success or failed.
    outcome: result.ok ? 'success' : 'failed',
    request,
    metadata: result.ok
      ? {
          projectId: result.deployment.projectId,
          nodeId: result.deployment.nodeId,
          fromArtifactId: result.deployment.currentArtifactId,
          targetArtifactId: target,
        }
      : { targetArtifactId: target, reasonCodes: (result.reasons ?? []).join(',') },
  });
  return result.ok
    ? Response.json({ action: result.action, deployment: result.deployment, duplicate: result.duplicate }, { status: 202 })
    : Response.json({ error: result.error, reasons: result.reasons ?? [] }, { status: result.status });
}

import { failedCheckCodes } from '@/lib/node-preflight';
import { recordEvidence } from '@/lib/server/audit';
import { readNodePreflight } from '@/lib/server/node-onboarding';
import { requireApiSession } from '@/lib/server/session';

/**
 * Whether a node can take a deployment, and why not when it cannot.
 *
 * This is an explanation, not a permission. `planDeployment` re-evaluates the
 * blocking subset when a job is actually queued, so a stale or forged "ready"
 * answer here buys a caller nothing.
 */
export async function GET(
  request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { id } = await context.params;
  const preflight = await readNodePreflight({
    workspaceId: auth.session.workspace.id,
    nodeId: id,
  });
  if (!preflight) {
    return Response.json({ error: 'Compute Node not found.' }, { status: 404 });
  }

  await recordEvidence({
    action: 'node.preflight.run',
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actorType: auth.session.principal,
    actorId: auth.session.actor.userId,
    resourceId: preflight.nodeId,
    outcome: preflight.verdict === 'ready' ? 'success' : 'denied',
    request,
    metadata: {
      verdict: preflight.verdict,
      // Codes from the fixed enum, never the remediation prose and never a
      // string the node supplied.
      failedChecks: failedCheckCodes(preflight).join(',').slice(0, 200),
      agentVersion: preflight.agentVersion ?? 'unknown',
      protocolVersion: preflight.protocolVersion ?? -1,
    },
  });

  return Response.json({ preflight });
}

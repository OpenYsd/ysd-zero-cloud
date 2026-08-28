import { planDeployment } from '@/lib/server/deployments';
import { requireApiSession } from '@/lib/server/session';
import type { DeployTarget } from '@/lib/smart-deploy';

const TARGETS: DeployTarget[] = ['auto', 'cloudflare', 'supabase', 'gpu'];

function isTarget(value: unknown): value is DeployTarget {
  return typeof value === 'string' && (TARGETS as string[]).includes(value);
}

/**
 * Builds and records a deployment plan.
 *
 * Zero Mode is read from the workspace row, never from the request body. A
 * client that asks for the guard to be off is simply ignored: turning it off
 * is a settings change, and settings changes are audited.
 */
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  const { user, workspace } = auth.session;

  let body: { repository?: unknown; target?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }

  const repository = typeof body.repository === 'string' ? body.repository.trim() : '';
  if (!repository) {
    return Response.json({ error: 'repository is required' }, { status: 400 });
  }
  if (repository.length > 200) {
    return Response.json({ error: 'repository is too long' }, { status: 400 });
  }

  const target = isTarget(body.target) ? body.target : 'auto';

  const { plan, deployment } = await planDeployment({
    workspaceId: workspace.id,
    actor: user.email,
    repository,
    target,
    zeroModeEnabled: workspace.zeroMode,
  });

  return Response.json(
    { plan, deployment, zeroMode: workspace.zeroMode },
    { status: plan.protection.allowed ? 200 : 403 },
  );
}

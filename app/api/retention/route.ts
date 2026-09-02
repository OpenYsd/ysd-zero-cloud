import { requireApiSession } from '@/lib/server/session';
import { listDataLifecycleState } from '@/lib/server/retention';
import { collectUsageReadings } from '@/lib/server/usage';

/**
 * Capacity and retention state for the current workspace.
 *
 * Read-only, and deliberately the only shape offered: there is no generic
 * query surface here. `retention.read` is enforced by `permissionForRequest`
 * before this handler runs.
 */
export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const { readings } = await collectUsageReadings({
    workspaceId: auth.session.workspace.id,
    userId: auth.session.actor.userId,
    organizationId: auth.session.organization.id,
    projectIds: auth.session.actor.projectIds,
    includeDatabaseBytes: true,
  });

  const state = await listDataLifecycleState({
    organizationId: auth.session.organization.id,
    workspaceId: auth.session.workspace.id,
    actor: auth.session.actor,
    readings,
    now: Date.now(),
  });
  return Response.json(state);
}

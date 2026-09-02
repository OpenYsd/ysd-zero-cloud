import { canChangeRole, canSuspend, isRole } from '@/lib/roles';
import { recordEvidence } from '@/lib/server/audit';
import { writeLog } from '@/lib/server/logs';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import {
  countOwners,
  getManagedUser,
  listManagedUsers,
  setRole,
  setSuspended,
} from '@/lib/server/roles';
import { requireApiCapability } from '@/lib/server/session';

/**
 * Account administration.
 *
 * Gated on `admin.users.read` / `admin.users.write`, which only owner and
 * admin hold. Note what this endpoint does *not* expose: it returns identity
 * and status for every account, but never anything from another operator's
 * workspace. Administering an account and reading its data are different
 * powers, and only the first one lives here.
 */
export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiCapability(request, 'admin.users.read');
  if (!auth.ok) return auth.response;

  return Response.json({
    users: await listManagedUsers(),
    actor: { userId: auth.session.actor.userId, role: auth.session.actor.role },
    ownerCount: await countOwners(),
  });
}

/**
 * Changes one account's role or suspension state.
 *
 * The decision itself is made by the pure rules in `lib/roles.ts`, which stop
 * self-promotion, acting on an equal or superior, and demoting the last owner.
 */
export async function PATCH(request: Request): Promise<Response> {
  const auth = await requireApiCapability(request, 'admin.users.write');
  if (!auth.ok) return auth.response;

  const { actor, workspace, user } = auth.session;

  const limited = await enforceRateLimit('api:write', actor.userId);
  if (limited.response) return limited.response;

  let body: { userId?: unknown; role?: unknown; suspended?: unknown; reason?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: 'Expected a JSON body.' }, { status: 400 });
  }

  const userId = typeof body.userId === 'string' ? body.userId : '';
  if (!userId) return Response.json({ error: 'userId is required.' }, { status: 400 });

  const target = await getManagedUser(userId);
  if (!target) return Response.json({ error: 'Account not found.' }, { status: 404 });

  const targetRef = { userId: target.id, role: target.role };

  if (typeof body.role === 'string') {
    if (!isRole(body.role)) {
      return Response.json({ error: `Unknown role: ${body.role}` }, { status: 400 });
    }
    const decision = canChangeRole(actor, targetRef, body.role, await countOwners());
    if (!decision.allowed) {
      return Response.json({ error: decision.message }, { status: 403 });
    }
    await setRole(userId, body.role, actor.userId);
    await writeLog({
      workspaceId: workspace.id,
      level: 'WARN',
      source: 'auth',
      message: `Role of ${target.email} changed from ${target.role} to ${body.role}`,
      actor: user.email,
      resource: userId,
    });
  }

  if (typeof body.suspended === 'boolean') {
    const decision = canSuspend(actor, targetRef);
    if (!decision.allowed) {
      return Response.json({ error: decision.message }, { status: 403 });
    }
    const reason = typeof body.reason === 'string' ? body.reason.slice(0, 200) : null;
    await setSuspended(userId, body.suspended, reason, actor.userId);
    await writeLog({
      workspaceId: workspace.id,
      level: 'WARN',
      source: 'auth',
      message: body.suspended
        ? `Suspended ${target.email}${reason ? ` · ${reason}` : ''}`
        : `Restored ${target.email}`,
      actor: user.email,
      resource: userId,
    });
  }

  await recordEvidence({
    action: 'admin.user.update',
    organizationId: auth.session.organization.id,
    workspaceId: workspace.id,
    actorType: auth.session.principal,
    actorId: actor.userId,
    resourceId: userId,
    outcome: 'success',
    request,
    metadata: {
      operation: typeof body.suspended === 'boolean' ? 'suspension' : 'role',
      role: typeof body.role === 'string' ? body.role : target.role,
    },
  });
  return Response.json({ user: await getManagedUser(userId) });
}

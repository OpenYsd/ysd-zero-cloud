import { can, isRole } from '@/lib/roles';
import {
  addMember,
  changeMemberRole,
  listMembers,
  replaceProjectAccess,
  setMemberStatus,
  transferOwnership,
} from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'member.read')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  return Response.json({
    members: await listMembers(auth.session.organization.id, auth.session.workspace.id),
  });
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'member.manage')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  let body: { userId?: unknown; workspaceId?: unknown; role?: unknown };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  const role = typeof body.role === 'string' && isRole(body.role) ? body.role : null;
  if (!role || role === 'owner' || typeof body.userId !== 'string') {
    return Response.json({ error: 'A userId and non-owner role are required.' }, { status: 400 });
  }
  try {
    const added = await addMember({
      organizationId: auth.session.organization.id,
      workspaceId: typeof body.workspaceId === 'string' ? body.workspaceId : auth.session.workspace.id,
      actorId: auth.session.actor.userId,
      userId: body.userId,
      role,
    });
    return added ? Response.json({ added: true }, { status: 201 }) : Response.json({ error: 'User or workspace not found.' }, { status: 404 });
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : 'Member could not be added.' },
      { status: 409 },
    );
  }
}

export async function PATCH(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  let body: {
    userId?: unknown;
    role?: unknown;
    action?: unknown;
    reason?: unknown;
    confirmation?: unknown;
    projectIds?: unknown;
    projectScope?: unknown;
    workspaceId?: unknown;
  };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  if (typeof body.userId !== 'string') return Response.json({ error: 'userId is required.' }, { status: 400 });

  if (body.action === 'transfer-ownership') {
    if (!can(auth.session.actor, 'member.transfer-ownership')) return Response.json({ error: 'Only the owner can transfer ownership.' }, { status: 403 });
    const result = await transferOwnership({
      actor: auth.session.actor,
      organizationId: auth.session.organization.id,
      targetUserId: body.userId,
      confirmation: typeof body.confirmation === 'string' ? body.confirmation : '',
    });
    return result.ok ? Response.json(result) : Response.json({ error: result.error }, { status: 409 });
  }

  if (Array.isArray(body.projectIds) || body.projectScope === 'all') {
    if (!can(auth.session.actor, 'member.manage')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
    const projectIds = body.projectScope === 'all'
      ? null
      : (body.projectIds as unknown[]).filter((item): item is string => typeof item === 'string');
    const updated = await replaceProjectAccess({
      organizationId: auth.session.organization.id,
      workspaceId: typeof body.workspaceId === 'string' ? body.workspaceId : auth.session.workspace.id,
      actorId: auth.session.actor.userId,
      userId: body.userId,
      projectIds,
    });
    return updated ? Response.json({ updated: true }) : Response.json({ error: 'One or more projects were not found.' }, { status: 404 });
  }

  if (typeof body.role === 'string') {
    if (!isRole(body.role) || body.role === 'owner') return Response.json({ error: 'Use ownership transfer for the owner role.' }, { status: 400 });
    const result = await changeMemberRole({
      actor: auth.session.actor,
      organizationId: auth.session.organization.id,
      targetUserId: body.userId,
      role: body.role,
    });
    return result.ok ? Response.json(result) : Response.json({ error: result.error }, { status: 403 });
  }

  if (body.action === 'suspend' || body.action === 'reactivate' || body.action === 'remove') {
    const result = await setMemberStatus({
      actor: auth.session.actor,
      organizationId: auth.session.organization.id,
      targetUserId: body.userId,
      action: body.action,
      reason: typeof body.reason === 'string' ? body.reason : undefined,
    });
    return result.ok ? Response.json(result) : Response.json({ error: result.error }, { status: 403 });
  }
  return Response.json({ error: 'No supported member change was supplied.' }, { status: 400 });
}

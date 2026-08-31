import { can, isRole } from '@/lib/roles';
import { createInvitation, listInvitations } from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'invitation.read')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  return Response.json({ invitations: await listInvitations(auth.session.organization.id), delivery: 'link-only' });
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'invitation.manage')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  let body: { email?: unknown; role?: unknown; workspaceId?: unknown; expiresInHours?: unknown };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  const role = typeof body.role === 'string' && isRole(body.role) ? body.role : null;
  if (!role || role === 'owner' || typeof body.email !== 'string') {
    return Response.json({ error: 'Email and a non-owner role are required.' }, { status: 400 });
  }
  try {
    const created = await createInvitation({
      organizationId: auth.session.organization.id,
      workspaceId: typeof body.workspaceId === 'string' ? body.workspaceId : auth.session.workspace.id,
      actorId: auth.session.actor.userId,
      email: body.email,
      role,
      expiresInHours: typeof body.expiresInHours === 'number' ? body.expiresInHours : undefined,
    });
    const inviteLink = `${new URL(request.url).origin}/invite?token=${encodeURIComponent(created.token)}`;
    return Response.json({ invitation: created.invitation, inviteLink, delivery: 'link-only' }, { status: 201 });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : 'Invitation could not be created.' }, { status: 409 });
  }
}

import { can } from '@/lib/roles';
import { createServiceAccount, listServiceAccounts } from '@/lib/server/service-accounts';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'service-account.read')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  return Response.json({
    accounts: await listServiceAccounts(auth.session.organization.id, auth.session.workspace.id),
  });
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (!can(auth.session.actor, 'service-account.manage')) return Response.json({ error: 'Not permitted.' }, { status: 403 });
  let body: { name?: unknown; projectId?: unknown; scopes?: unknown; expiresAt?: unknown };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  try {
    const created = await createServiceAccount({
      organizationId: auth.session.organization.id,
      workspaceId: auth.session.workspace.id,
      actorId: auth.session.actor.userId,
      name: typeof body.name === 'string' ? body.name : '',
      projectId: typeof body.projectId === 'string' ? body.projectId : null,
      scopes: Array.isArray(body.scopes) ? body.scopes.filter((item): item is string => typeof item === 'string') : [],
      expiresAt: typeof body.expiresAt === 'number' ? body.expiresAt : null,
    });
    // Plaintext is returned exactly once and is never readable again.
    return Response.json(created, { status: 201 });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : 'Service account could not be created.' }, { status: 409 });
  }
}

import { can } from '@/lib/roles';
import { createOrganization, listOrganizations } from '@/lib/server/organizations';
import { requireApiSession } from '@/lib/server/session';

export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (auth.session.principal !== 'user') return Response.json({ error: 'User session required.' }, { status: 403 });
  return Response.json({ organizations: await listOrganizations(auth.session.user.id) });
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (auth.session.principal !== 'user' || !can(auth.session.actor, 'organization.create')) {
    return Response.json({ error: 'Only an organization owner can create another organization.' }, { status: 403 });
  }
  let body: { name?: unknown };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  try {
    const access = await createOrganization({
      userId: auth.session.user.id,
      userName: auth.session.user.name,
      email: auth.session.user.email,
      name: typeof body.name === 'string' ? body.name : undefined,
    });
    return Response.json({ organization: access.organization, workspace: access.workspace }, { status: 201 });
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : 'Organization could not be created.' },
      { status: 409 },
    );
  }
}

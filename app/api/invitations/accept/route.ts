import { getSessionUser } from '@/lib/server/auth';
import { acceptInvitation } from '@/lib/server/organizations';

export async function POST(request: Request): Promise<Response> {
  const user = await getSessionUser(request.headers);
  if (!user) return Response.json({ error: 'Sign in before accepting an invitation.' }, { status: 401 });
  let body: { token?: unknown };
  try { body = (await request.json()) as typeof body; }
  catch { return Response.json({ error: 'Expected JSON.' }, { status: 400 }); }
  if (typeof body.token !== 'string' || body.token.length > 160) return Response.json({ error: 'Invitation token is required.' }, { status: 400 });
  const result = await acceptInvitation({ token: body.token, userId: user.id, email: user.email });
  return result.ok ? Response.json(result) : Response.json({ error: result.error }, { status: result.status });
}

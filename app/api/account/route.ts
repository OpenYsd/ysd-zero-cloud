import { ACCOUNT_LIMITS, parseProfileUpdate } from '@/lib/account';
import { readAccountProfile, updateDisplayName } from '@/lib/server/account';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

/**
 * The signed-in account's own profile.
 *
 * There is no id in either route: both operate on whoever the session says is
 * calling. That is the whole tenancy model here — a request cannot name another
 * account, so there is no cross-user path to guard against.
 */
export async function GET(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;
  if (auth.session.principal !== 'user') {
    return Response.json({ error: 'A user session is required.' }, { status: 403 });
  }
  return Response.json({ account: await readAccountProfile(auth.session) });
}

export async function PATCH(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit('api:write', auth.session.actor.userId);
  if (limited.response) return limited.response;

  if (
    request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !==
    'application/json'
  ) {
    return Response.json(
      { error: 'Profile updates require application/json.' },
      { status: 415, headers: limited.headers },
    );
  }

  const body = await readBoundedJson(request, ACCOUNT_LIMITS.requestBytes);
  if (!body.ok) return body.response;

  const parsed = parseProfileUpdate(body.body);
  if (!parsed.ok) {
    return Response.json(
      { error: parsed.error },
      { status: 400, headers: limited.headers },
    );
  }

  const result = await updateDisplayName({
    session: auth.session,
    displayName: parsed.value.displayName,
    request,
  });
  if (!result.ok) {
    return Response.json(
      { error: result.error },
      { status: result.status, headers: limited.headers },
    );
  }

  return Response.json(
    { account: await readAccountProfile(auth.session) },
    { headers: limited.headers },
  );
}

import { ACCOUNT_LIMITS, parsePasswordChange } from '@/lib/account';
import { changeAccountPassword } from '@/lib/server/account';
import { readBoundedJson } from '@/lib/server/node-request';
import { enforceRateLimit } from '@/lib/server/rate-limit';
import { requireApiSession } from '@/lib/server/session';

/**
 * Changes the signed-in account's password.
 *
 * Rate limited with `auth:reset` — five per hour — rather than the ordinary
 * write budget of 120 a minute. Better Auth's own limiter sits in front of
 * `/api/auth/*` and does not cover this route, which calls its server API
 * directly, so the limit has to be applied here or a wrong-current-password
 * guess would be effectively unbounded.
 *
 * The body is never echoed, never logged, and never reaches audit metadata.
 */
export async function POST(request: Request): Promise<Response> {
  const auth = await requireApiSession(request);
  if (!auth.ok) return auth.response;

  const limited = await enforceRateLimit(
    'auth:reset',
    auth.session.actor.userId,
    'Too many password attempts. Wait before trying again.',
  );
  if (limited.response) return limited.response;

  if (
    request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !==
    'application/json'
  ) {
    return Response.json(
      { error: 'Password changes require application/json.' },
      { status: 415, headers: limited.headers },
    );
  }

  const body = await readBoundedJson(request, ACCOUNT_LIMITS.requestBytes);
  if (!body.ok) return body.response;

  const parsed = parsePasswordChange(body.body);
  if (!parsed.ok) {
    return Response.json(
      { error: parsed.error },
      { status: 400, headers: limited.headers },
    );
  }

  const result = await changeAccountPassword({
    session: auth.session,
    currentPassword: parsed.value.currentPassword,
    newPassword: parsed.value.newPassword,
    request,
  });
  if (!result.ok) {
    return Response.json(
      { error: result.error },
      { status: result.status, headers: limited.headers },
    );
  }

  // Better Auth rotates this browser's session token as part of revoking the
  // others. That cookie arrives on its response, not ours, so it is replayed
  // here — otherwise the browser that just changed its password is the one
  // signed out. Appended rather than assigned, so the rate-limit headers set
  // above survive. The value is never read or logged.
  const headers = new Headers(limited.headers);
  for (const cookie of result.setCookie ?? []) headers.append('Set-Cookie', cookie);

  return Response.json(
    {
      changed: true,
      // Stated plainly so the UI can tell the operator what just happened to
      // their other browsers.
      revokedOtherSessions: result.revokedOtherSessions ?? false,
    },
    { headers },
  );
}

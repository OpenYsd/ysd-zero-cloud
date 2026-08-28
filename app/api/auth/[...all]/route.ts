import { getAuth } from '@/lib/server/auth';
import { clientAddress, enforceRateLimit } from '@/lib/server/rate-limit';
import { checkLockout, noteSignIn } from '@/lib/server/security';
import { verifyTurnstile } from '@/lib/server/turnstile';
import { ensureWorkspace } from '@/lib/server/workspace';
import type { RateLimitName } from '@/lib/rate-limit';

/**
 * Better Auth owns every path under `/api/auth`. Sign-in, sign-up, session
 * lookup, sign-out, and the OAuth callback all arrive here.
 *
 * The abuse controls sit in front of it rather than inside it, in this order:
 *
 *   1. rate limit   — caps how fast one address may call the endpoint
 *   2. Turnstile    — proves a browser is driving, when keys are configured
 *   3. lockout      — refuses an account being guessed at, before any hashing
 *
 * Ordering matters. Each step is cheaper than the one after it, so an attacker
 * is turned away before the expensive work (a challenge round-trip, then a
 * password hash) is ever done.
 */

/** Which endpoints are worth protecting, and under which rule. */
const GUARDED: Record<string, { rule: RateLimitName; challenge: boolean; lockout: boolean }> = {
  'sign-in/email': { rule: 'auth:sign-in', challenge: true, lockout: true },
  'sign-up/email': { rule: 'auth:sign-up', challenge: true, lockout: false },
  'forget-password': { rule: 'auth:reset', challenge: true, lockout: false },
  'reset-password': { rule: 'auth:reset', challenge: false, lockout: false },
};

function guardFor(pathname: string) {
  const path = pathname.replace(/^\/api\/auth\//, '').replace(/\/+$/, '');
  return { path, guard: GUARDED[path] };
}

/**
 * Reads the body once and hands back both a parsed copy and a fresh Request.
 *
 * A Request body can only be consumed once, so the guards and Better Auth
 * cannot both read the original.
 */
async function readBody(request: Request): Promise<{ body: Record<string, unknown>; next: Request }> {
  const raw = await request.text();
  let body: Record<string, unknown> = {};
  try {
    body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
  } catch {
    body = {};
  }
  return { body, next: new Request(request.url, { method: request.method, headers: request.headers, body: raw }) };
}

/** Copies advisory headers onto a response without disturbing its own. */
function mergeHeaders(base: Headers, extra: HeadersInit): Headers {
  const headers = new Headers(base);
  for (const [name, value] of new Headers(extra)) headers.set(name, value);
  return headers;
}

async function handler(request: Request): Promise<Response> {
  const auth = await getAuth();
  const { path, guard } = guardFor(new URL(request.url).pathname);

  if (request.method !== 'POST' || !guard) {
    return auth.handler(request);
  }

  const ip = clientAddress(request);
  const userAgent = request.headers.get('User-Agent');

  const limited = await enforceRateLimit(guard.rule, ip || 'anonymous');
  if (limited.response) return limited.response;

  const { body, next } = await readBody(request);
  const email = typeof body.email === 'string' ? body.email : '';

  if (guard.challenge) {
    const token = typeof body.turnstileToken === 'string' ? body.turnstileToken : '';
    const verdict = await verifyTurnstile(token, ip);
    if (!verdict.ok) {
      return Response.json(
        { message: verdict.message, code: 'CHALLENGE_FAILED' },
        { status: 403, headers: limited.headers },
      );
    }
  }

  if (guard.lockout && email) {
    const lockout = await checkLockout(email, ip);
    if (lockout.locked) {
      const headers = new Headers(limited.headers);
      headers.set('Retry-After', String(lockout.retryAfterSeconds));
      return Response.json(
        { message: lockout.message, code: 'ACCOUNT_LOCKED' },
        { status: 429, headers },
      );
    }
  }

  const handled = await auth.handler(next);

  // Better Auth builds its own response, so the budget headers are attached
  // here rather than lost. A client that can see its remaining allowance can
  // back off before it is refused.
  const response = new Response(handled.body, {
    status: handled.status,
    statusText: handled.statusText,
    headers: mergeHeaders(handled.headers, limited.headers),
  });

  if (path === 'sign-in/email' && email) {
    // The workspace is only resolved on success, so a failed attempt against a
    // non-existent address never creates one.
    let workspaceId: string | undefined;
    if (response.ok) {
      try {
        const session = await auth.api.getSession({ headers: response.headers });
        if (session?.user) {
          const workspace = await ensureWorkspace(
            session.user.id,
            session.user.name,
            session.user.email,
          );
          workspaceId = workspace.id;
        }
      } catch {
        // Auditing must not break the sign-in it is describing.
      }
    }
    await noteSignIn({ email, ip, userAgent, success: response.ok, workspaceId });
  }

  return response;
}

export { handler as GET, handler as POST };

import { fingerprint } from '@/lib/crypto';
import {
  consume,
  rateLimitHeaders,
  rateLimitKey,
  RATE_LIMIT_RULES,
  type RateLimitDecision,
  type RateLimitName,
  type RateLimitState,
} from '@/lib/rate-limit';
import { execute, queryOne } from './db';

/**
 * D1-backed counters for the application's own endpoints.
 *
 * A Worker isolate is thrown away between requests, so an in-memory counter
 * would reset constantly and enforce nothing. The counter therefore lives in
 * the database, which every isolate shares.
 */

/**
 * The caller's address.
 *
 * `CF-Connecting-IP` is set by Cloudflare's edge and cannot be spoofed by the
 * client; `X-Forwarded-For` is only consulted as a fallback for local runs and
 * is never trusted in preference to it.
 */
export function clientAddress(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ??
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    ''
  );
}

/**
 * Hashes the identifier before it becomes a storage key.
 *
 * An address or an email is personal data; a rate-limit table has no business
 * holding either in the clear when a digest works just as well.
 */
async function keyFor(name: RateLimitName, identifier: string): Promise<string> {
  return rateLimitKey(name, await fingerprint(identifier || 'anonymous'));
}

export type LimitOutcome = {
  decision: RateLimitDecision;
  headers: HeadersInit;
  /** A ready-made 429, present only when the request must be refused. */
  response: Response | null;
};

/**
 * Applies a named rule to one identifier.
 *
 * Fails open: if the counter cannot be read or written, the request proceeds.
 * A database blip should degrade rate limiting, not take the site down — the
 * brute-force rules in `lib/brute-force.ts` still stand behind it, and those
 * read history rather than a counter.
 */
export async function enforceRateLimit(
  name: RateLimitName,
  identifier: string,
  message = 'Too many requests. Slow down and try again shortly.',
): Promise<LimitOutcome> {
  const rule = RATE_LIMIT_RULES[name];
  const now = Date.now();

  let state: RateLimitState | null = null;
  let key: string;
  try {
    key = await keyFor(name, identifier);
    state = await queryOne<RateLimitState>(
      'SELECT count, windowStart FROM rate_limit WHERE key = ?',
      key,
    );
  } catch {
    const decision = consume(rule, null, now);
    return { decision, headers: rateLimitHeaders(rule, decision), response: null };
  }

  const decision = consume(rule, state, now);

  try {
    await execute(
      `INSERT INTO rate_limit (key, count, windowStart) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET count = excluded.count, windowStart = excluded.windowStart`,
      key,
      decision.next.count,
      decision.next.windowStart,
    );
  } catch {
    // The decision for this request already stands; losing the write only
    // means the next request starts a fresh window.
  }

  const headers = rateLimitHeaders(rule, decision);
  const response = decision.allowed
    ? null
    : Response.json(
        { error: message, retryAfterSeconds: decision.retryAfterSeconds },
        { status: 429, headers },
      );

  return { decision, headers, response };
}

/**
 * Removes windows that can no longer block anyone.
 *
 * Called opportunistically from the security scan rather than on a schedule:
 * a cron trigger is another moving part, and the table is small.
 */
export async function pruneRateLimits(olderThanMs = 24 * 60 * 60 * 1000): Promise<void> {
  try {
    await execute('DELETE FROM rate_limit WHERE windowStart < ?', Date.now() - olderThanMs);
  } catch {
    // Housekeeping only.
  }
}

/**
 * Fixed-window rate limiting policy.
 *
 * The decision is a pure function of a stored counter and the clock, so the
 * policy can be tested without a database and the same rules apply wherever
 * the counter happens to live.
 *
 * A fixed window is deliberate. A sliding window would be fairer at the
 * boundary, but it costs a row per request; a fixed window costs one row per
 * key per window, which matters when the store is D1 on a free plan.
 */

export type RateLimitRule = {
  /** Requests permitted inside one window. */
  limit: number;
  /** Window length in milliseconds. */
  windowMs: number;
};

export type RateLimitState = {
  count: number;
  windowStart: number;
};

export type RateLimitDecision = {
  allowed: boolean;
  /** Requests left in this window after the current one. */
  remaining: number;
  /** When the window resets, epoch ms. */
  resetAt: number;
  /** Seconds a blocked caller should wait. Zero when allowed. */
  retryAfterSeconds: number;
  /** The state to persist. */
  next: RateLimitState;
};

const MINUTE = 60_000;

/**
 * Named rules for the paths worth protecting.
 *
 * Sign-in and sign-up are the abuse surface: they are unauthenticated, they do
 * real work (password hashing, a database write), and they are what a
 * credential-stuffing run targets. The limits are per IP and are generous
 * enough that a person retrying a typo is never affected.
 */
export const RATE_LIMIT_RULES = {
  'auth:sign-in': { limit: 10, windowMs: 10 * MINUTE },
  'auth:sign-up': { limit: 5, windowMs: 60 * MINUTE },
  'auth:reset': { limit: 5, windowMs: 60 * MINUTE },
  /** Verification re-sends: each one costs a mail and probes for an account. */
  'auth:verify': { limit: 5, windowMs: 60 * MINUTE },
  /** Everything else an anonymous caller can reach. */
  'api:anonymous': { limit: 60, windowMs: MINUTE },
  /** Authenticated writes, per user. */
  'api:write': { limit: 120, windowMs: MINUTE },
  /** One-time node pairing is public but backed by a high-entropy code. */
  'node:pair': { limit: 10, windowMs: 60 * MINUTE },
  /** Signed heartbeats and polls from one authenticated node. */
  'node:agent': { limit: 180, windowMs: MINUTE },
  /** The SQL Editor, which is expensive and owner-only. */
  'sql:query': { limit: 30, windowMs: MINUTE },
  /** One inbound integration source cannot monopolize the shared Worker. */
  'webhook:source': { limit: 60, windowMs: MINUTE },
  /** Aggregate workspace ceiling protects D1 even with many enabled sources. */
  'webhook:workspace': { limit: 240, windowMs: MINUTE },
  /**
   * Repository readiness analysis. Each call costs 3-8 outbound GitHub
   * requests (metadata, commit, tree, plus up to five file reads), and without
   * a configured `GITHUB_TOKEN` those share GitHub's unauthenticated 60/hour
   * budget across every workspace on this Worker. 15/hour per user keeps a
   * single account from being able to exhaust that shared budget alone, while
   * comfortably allowing someone iterating on a repository to fix a blocker
   * and re-check it.
   */
  'deploy:analyze': { limit: 15, windowMs: 60 * MINUTE },
} as const satisfies Record<string, RateLimitRule>;

export type RateLimitName = keyof typeof RATE_LIMIT_RULES;

export function isRateLimitName(value: string): value is RateLimitName {
  return Object.hasOwn(RATE_LIMIT_RULES, value);
}

/**
 * Applies one request against a rule.
 *
 * @param state Stored counter, or null when the key has never been seen.
 * @param now Epoch ms.
 */
export function consume(
  rule: RateLimitRule,
  state: RateLimitState | null,
  now: number,
): RateLimitDecision {
  const expired = state === null || now - state.windowStart >= rule.windowMs;
  const windowStart = expired ? now : state.windowStart;
  const previous = expired ? 0 : state.count;
  const count = previous + 1;
  const resetAt = windowStart + rule.windowMs;

  if (count > rule.limit) {
    return {
      allowed: false,
      remaining: 0,
      resetAt,
      retryAfterSeconds: Math.max(1, Math.ceil((resetAt - now) / 1000)),
      // The counter still advances while blocked, so a caller hammering the
      // endpoint cannot shorten their own window by racing the reset.
      next: { count, windowStart },
    };
  }

  return {
    allowed: true,
    remaining: rule.limit - count,
    resetAt,
    retryAfterSeconds: 0,
    next: { count, windowStart },
  };
}

/**
 * Builds the storage key.
 *
 * The identifier is hashed by the caller when it is personal; this only joins
 * the parts so one rule cannot collide with another.
 */
export function rateLimitKey(name: RateLimitName, identifier: string): string {
  return `${name}|${identifier}`;
}

/** Standard headers so a client can back off intelligently. */
export function rateLimitHeaders(
  rule: RateLimitRule,
  decision: RateLimitDecision,
): HeadersInit {
  const headers: Record<string, string> = {
    'RateLimit-Limit': String(rule.limit),
    'RateLimit-Remaining': String(decision.remaining),
    'RateLimit-Reset': String(
      Math.max(0, Math.ceil((decision.resetAt - Date.now()) / 1000)),
    ),
  };
  if (!decision.allowed)
    headers['Retry-After'] = String(decision.retryAfterSeconds);
  return headers;
}

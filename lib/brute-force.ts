/**
 * Brute-force and suspicious sign-in policy.
 *
 * Rate limiting caps how fast anyone may call an endpoint. This is the
 * narrower question of whether a *particular account* is being guessed at, and
 * it is deliberately separate: a credential-stuffing run spread across many
 * IPs stays under any per-IP limit while still hammering one email.
 *
 * Pure by design — the caller supplies the recent attempt history, so the
 * rules can be tested exhaustively and the same policy is reused by the
 * security scanner.
 */

export type AttemptOutcome = 'success' | 'failure' | 'blocked';

export type AuthAttempt = {
  email: string;
  ip: string;
  userAgent: string | null;
  outcome: AttemptOutcome;
  createdAt: number;
};

const MINUTE = 60_000;

export const BRUTE_FORCE_POLICY = {
  /** Consecutive failures for one email before it is locked. */
  emailFailureThreshold: 5,
  /** How long a locked account stays locked. */
  emailLockoutMs: 15 * MINUTE,
  /** Failures from one IP across any account before it is locked. */
  ipFailureThreshold: 20,
  ipLockoutMs: 15 * MINUTE,
  /** How far back the history is considered. */
  windowMs: 60 * MINUTE,
} as const;

export type LockoutDecision = {
  locked: boolean;
  /** Which rule fired. */
  scope: 'email' | 'ip' | null;
  retryAfterSeconds: number;
  failures: number;
  message: string;
};

const UNLOCKED: LockoutDecision = {
  locked: false,
  scope: null,
  retryAfterSeconds: 0,
  failures: 0,
  message: '',
};

/**
 * Decides whether a sign-in attempt should be refused before the password is
 * ever checked.
 *
 * Only failures *since the last success* count toward the email threshold: a
 * successful sign-in clears the streak, so someone who mistypes twice, gets in,
 * then mistypes again is nowhere near a lockout.
 *
 * @param attempts Recent attempts, any order, already filtered to the window.
 */
export function evaluateLockout(
  attempts: readonly AuthAttempt[],
  email: string,
  ip: string,
  now: number,
): LockoutDecision {
  const inWindow = attempts.filter((a) => now - a.createdAt <= BRUTE_FORCE_POLICY.windowMs);
  const normalizedEmail = email.trim().toLowerCase();

  const forEmail = inWindow
    .filter((a) => a.email.trim().toLowerCase() === normalizedEmail)
    .sort((a, b) => b.createdAt - a.createdAt);

  // Count back to the most recent success; anything older is a resolved streak.
  const streak: AuthAttempt[] = [];
  for (const attempt of forEmail) {
    if (attempt.outcome === 'success') break;
    if (attempt.outcome === 'failure') streak.push(attempt);
  }

  if (streak.length >= BRUTE_FORCE_POLICY.emailFailureThreshold) {
    const newest = streak[0]!.createdAt;
    const until = newest + BRUTE_FORCE_POLICY.emailLockoutMs;
    if (now < until) {
      return {
        locked: true,
        scope: 'email',
        retryAfterSeconds: Math.max(1, Math.ceil((until - now) / 1000)),
        failures: streak.length,
        message: 'Too many failed sign-in attempts for this account. Try again shortly.',
      };
    }
  }

  const forIp = inWindow
    .filter((a) => a.ip === ip && a.outcome === 'failure')
    .sort((a, b) => b.createdAt - a.createdAt);

  if (forIp.length >= BRUTE_FORCE_POLICY.ipFailureThreshold) {
    const until = forIp[0]!.createdAt + BRUTE_FORCE_POLICY.ipLockoutMs;
    if (now < until) {
      return {
        locked: true,
        scope: 'ip',
        retryAfterSeconds: Math.max(1, Math.ceil((until - now) / 1000)),
        failures: forIp.length,
        message: 'Too many failed sign-in attempts from this network. Try again shortly.',
      };
    }
  }

  return UNLOCKED;
}

export type SuspicionCode =
  | 'new-network'
  | 'new-device'
  | 'after-failures'
  | 'credential-stuffing';

export type Suspicion = {
  code: SuspicionCode;
  detail: string;
};

/**
 * Flags a *successful* sign-in that does not look like the account's normal
 * behaviour. These are recorded as audit events rather than blocked: a real
 * operator travels and buys laptops, and refusing them would be worse than
 * telling them.
 *
 * @param history Prior attempts for this email, excluding the one that just
 * succeeded.
 */
export function detectSuspiciousLogin(
  history: readonly AuthAttempt[],
  current: AuthAttempt,
  now: number,
): Suspicion[] {
  const suspicions: Suspicion[] = [];
  const priorSuccesses = history.filter((a) => a.outcome === 'success');

  // A first-ever sign-in has nothing to look unusual against.
  if (priorSuccesses.length > 0) {
    if (!priorSuccesses.some((a) => a.ip === current.ip)) {
      suspicions.push({
        code: 'new-network',
        detail: `First sign-in from ${current.ip || 'an unknown address'}.`,
      });
    }
    if (
      current.userAgent &&
      !priorSuccesses.some((a) => a.userAgent === current.userAgent)
    ) {
      suspicions.push({ code: 'new-device', detail: 'First sign-in from this browser.' });
    }
  }

  const recentFailures = history.filter(
    (a) => a.outcome === 'failure' && now - a.createdAt <= BRUTE_FORCE_POLICY.windowMs,
  );
  if (recentFailures.length >= 3) {
    suspicions.push({
      code: 'after-failures',
      detail: `Succeeded after ${recentFailures.length} recent failures.`,
    });
  }

  // Many distinct addresses failing against one account is the shape of a
  // stuffing run, whoever eventually got in.
  const failingNetworks = new Set(
    history.filter((a) => a.outcome === 'failure').map((a) => a.ip),
  );
  if (failingNetworks.size >= 3) {
    suspicions.push({
      code: 'credential-stuffing',
      detail: `Failures from ${failingNetworks.size} different addresses on this account.`,
    });
  }

  return suspicions;
}

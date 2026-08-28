import {
  BRUTE_FORCE_POLICY,
  detectSuspiciousLogin,
  evaluateLockout,
  type AttemptOutcome,
  type AuthAttempt,
  type LockoutDecision,
} from '@/lib/brute-force';
import { createId } from '@/lib/crypto';
import { count, execute, query } from './db';
import { writeLog } from './logs';

/**
 * Sign-in attempt history, brute-force lockout, and suspicious-login auditing.
 *
 * The policy lives in `lib/brute-force.ts` and is pure; this module supplies
 * the history it reads and records what it concludes.
 */

/** Attempts are kept for a fortnight — long enough to investigate, then gone. */
const RETENTION_MS = 14 * 24 * 60 * 60 * 1000;

export async function recordAttempt(
  email: string,
  ip: string,
  userAgent: string | null,
  outcome: AttemptOutcome,
): Promise<void> {
  try {
    await execute(
      'INSERT INTO auth_attempt (id, email, ip, userAgent, outcome, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
      createId('att'),
      email.trim().toLowerCase(),
      ip,
      userAgent?.slice(0, 256) ?? null,
      outcome,
      Date.now(),
    );
  } catch {
    // Losing one audit row must not fail the sign-in it describes.
  }
}

/** Recent attempts relevant to one email or address. */
async function recentAttempts(email: string, ip: string): Promise<AuthAttempt[]> {
  const since = Date.now() - BRUTE_FORCE_POLICY.windowMs;
  try {
    return await query<AuthAttempt>(
      `SELECT email, ip, userAgent, outcome, createdAt
       FROM auth_attempt
       WHERE createdAt >= ? AND (email = ? OR ip = ?)
       ORDER BY createdAt DESC
       LIMIT 200`,
      since,
      email.trim().toLowerCase(),
      ip,
    );
  } catch {
    return [];
  }
}

/**
 * Whether this sign-in should be refused before the password is checked.
 *
 * Refusals are recorded as `blocked` so a sustained attack is visible in the
 * history rather than looking like the attacker simply gave up.
 */
export async function checkLockout(email: string, ip: string): Promise<LockoutDecision> {
  const attempts = await recentAttempts(email, ip);
  const decision = evaluateLockout(attempts, email, ip, Date.now());

  if (decision.locked) {
    await recordAttempt(email, ip, null, 'blocked');
  }

  return decision;
}

/**
 * Records the outcome of a sign-in and raises audit events for anything that
 * does not look like this account's normal behaviour.
 *
 * @param workspaceId Where the audit line is written. Absent for a failure,
 * since a failed attempt may not correspond to any real account.
 */
export async function noteSignIn(input: {
  email: string;
  ip: string;
  userAgent: string | null;
  success: boolean;
  workspaceId?: string;
}): Promise<void> {
  const { email, ip, userAgent, success, workspaceId } = input;
  const history = await recentAttempts(email, ip);

  await recordAttempt(email, ip, userAgent, success ? 'success' : 'failure');

  if (!success) {
    const failures = history.filter(
      (a) => a.outcome === 'failure' && a.email === email.trim().toLowerCase(),
    ).length;
    if (workspaceId && failures + 1 >= BRUTE_FORCE_POLICY.emailFailureThreshold) {
      await writeLog({
        workspaceId,
        level: 'WARN',
        source: 'auth',
        message: `Repeated failed sign-ins for ${email} · ${failures + 1} in the last hour`,
        actor: email,
        resource: ip || null,
      });
    }
    return;
  }

  if (!workspaceId) return;

  const suspicions = detectSuspiciousLogin(
    history,
    { email, ip, userAgent, outcome: 'success', createdAt: Date.now() },
    Date.now(),
  );

  for (const suspicion of suspicions) {
    await writeLog({
      workspaceId,
      level: 'WARN',
      source: 'auth',
      message: `Suspicious sign-in (${suspicion.code}) · ${suspicion.detail}`,
      actor: email,
      resource: ip || null,
    });
  }

  if (suspicions.length === 0) {
    await writeLog({
      workspaceId,
      source: 'auth',
      message: `Signed in from ${ip || 'an unknown address'}`,
      actor: email,
      resource: ip || null,
    });
  }
}

/**
 * Records an auth-lifecycle event against the account's own workspace.
 *
 * Events are written where the operator will look for them — their own Logs
 * surface — rather than into a global stream only an admin could read. When
 * the address matches no account there is no workspace to write to, and
 * nothing is recorded rather than leaking that the address is unknown.
 */
export async function auditAuthEvent(input: {
  email: string;
  ip: string;
  message: string;
  level?: 'INFO' | 'WARN';
}): Promise<void> {
  try {
    const row = await query<{ id: string }>(
      `SELECT w.id FROM workspace w
       JOIN "user" u ON u.id = w.ownerUserId
       WHERE LOWER(u.email) = ?
       LIMIT 1`,
      input.email.trim().toLowerCase(),
    );
    const workspaceId = row[0]?.id;
    if (!workspaceId) return;

    await writeLog({
      workspaceId,
      level: input.level ?? 'INFO',
      source: 'auth',
      message: input.message,
      actor: input.email,
      resource: input.ip || null,
    });
  } catch {
    // Auditing must never fail the request it describes.
  }
}

/** Counts recent lockouts, for the security scan. */
export async function countRecentBlocks(windowMs = 24 * 60 * 60 * 1000): Promise<number> {
  try {
    return await count(
      "SELECT COUNT(*) AS total FROM auth_attempt WHERE outcome = 'blocked' AND createdAt >= ?",
      Date.now() - windowMs,
    );
  } catch {
    return 0;
  }
}

/** Distinct addresses that failed against any account recently. */
export async function countFailingNetworks(windowMs = 24 * 60 * 60 * 1000): Promise<number> {
  try {
    return await count(
      "SELECT COUNT(DISTINCT ip) AS total FROM auth_attempt WHERE outcome = 'failure' AND createdAt >= ?",
      Date.now() - windowMs,
    );
  } catch {
    return 0;
  }
}

/** Drops attempt rows past the retention window. */
export async function pruneAttempts(): Promise<void> {
  try {
    await execute('DELETE FROM auth_attempt WHERE createdAt < ?', Date.now() - RETENTION_MS);
  } catch {
    // Housekeeping only.
  }
}

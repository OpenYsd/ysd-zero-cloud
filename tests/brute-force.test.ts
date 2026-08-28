import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BRUTE_FORCE_POLICY,
  detectSuspiciousLogin,
  evaluateLockout,
  type AuthAttempt,
} from '../lib/brute-force.ts';

const NOW = 1_800_000_000_000;
const EMAIL = 'operator@example.test';
const IP = '198.51.100.7';

function attempt(over: Partial<AuthAttempt> = {}): AuthAttempt {
  return {
    email: EMAIL,
    ip: IP,
    userAgent: 'browser/1',
    outcome: 'failure',
    createdAt: NOW - 1000,
    ...over,
  };
}

function failures(n: number, over: Partial<AuthAttempt> = {}): AuthAttempt[] {
  return Array.from({ length: n }, (_, i) => attempt({ createdAt: NOW - (i + 1) * 1000, ...over }));
}

void test('a clean history is not locked', () => {
  assert.equal(evaluateLockout([], EMAIL, IP, NOW).locked, false);
});

void test('failures below the threshold do not lock', () => {
  const decision = evaluateLockout(
    failures(BRUTE_FORCE_POLICY.emailFailureThreshold - 1),
    EMAIL,
    IP,
    NOW,
  );
  assert.equal(decision.locked, false);
});

void test('reaching the threshold locks the account and says for how long', () => {
  const decision = evaluateLockout(failures(BRUTE_FORCE_POLICY.emailFailureThreshold), EMAIL, IP, NOW);
  assert.equal(decision.locked, true);
  assert.equal(decision.scope, 'email');
  assert.ok(decision.retryAfterSeconds > 0);
  assert.match(decision.message, /too many failed/i);
});

void test('a successful sign-in clears the failure streak', () => {
  // Failures older than the last success belong to a resolved episode; someone
  // who mistyped, got in, then mistyped again is nowhere near a lockout.
  const history = [
    ...failures(2, { createdAt: NOW - 1000 }),
    attempt({ outcome: 'success', createdAt: NOW - 5000 }),
    ...failures(BRUTE_FORCE_POLICY.emailFailureThreshold, { createdAt: NOW - 10_000 }),
  ];
  assert.equal(evaluateLockout(history, EMAIL, IP, NOW).locked, false);
});

void test('a lockout expires once the window passes', () => {
  const history = failures(BRUTE_FORCE_POLICY.emailFailureThreshold);
  const later = NOW + BRUTE_FORCE_POLICY.emailLockoutMs + 1000;
  assert.equal(evaluateLockout(history, EMAIL, IP, NOW).locked, true);
  assert.equal(evaluateLockout(history, EMAIL, IP, later).locked, false);
});

void test('failures against other accounts do not lock this one', () => {
  const history = failures(BRUTE_FORCE_POLICY.emailFailureThreshold, {
    email: 'someone-else@example.test',
    ip: '203.0.113.9',
  });
  assert.equal(evaluateLockout(history, EMAIL, IP, NOW).locked, false);
});

void test('email matching ignores case and surrounding space', () => {
  const history = failures(BRUTE_FORCE_POLICY.emailFailureThreshold, {
    email: `  ${EMAIL.toUpperCase()}  `,
  });
  assert.equal(evaluateLockout(history, EMAIL, IP, NOW).locked, true);
});

void test('one address failing across many accounts is locked by the IP rule', () => {
  // Spreading guesses across accounts stays under the per-email threshold,
  // which is exactly what the address rule exists to catch.
  const history = Array.from({ length: BRUTE_FORCE_POLICY.ipFailureThreshold }, (_, i) =>
    attempt({ email: `victim${i}@example.test`, createdAt: NOW - (i + 1) * 1000 }),
  );
  const decision = evaluateLockout(history, 'fresh@example.test', IP, NOW);
  assert.equal(decision.locked, true);
  assert.equal(decision.scope, 'ip');
});

void test('attempts outside the window are ignored entirely', () => {
  const stale = failures(BRUTE_FORCE_POLICY.emailFailureThreshold, {
    createdAt: NOW - BRUTE_FORCE_POLICY.windowMs - 60_000,
  });
  assert.equal(evaluateLockout(stale, EMAIL, IP, NOW).locked, false);
});

void test('a first-ever sign-in raises no suspicion', () => {
  const suspicions = detectSuspiciousLogin([], attempt({ outcome: 'success' }), NOW);
  assert.deepEqual(suspicions, []);
});

void test('a familiar address and browser raise no suspicion', () => {
  const history = [attempt({ outcome: 'success', createdAt: NOW - 86_400_000 })];
  const suspicions = detectSuspiciousLogin(history, attempt({ outcome: 'success' }), NOW);
  assert.deepEqual(suspicions, []);
});

void test('a new address and a new browser are each flagged', () => {
  const history = [attempt({ outcome: 'success', createdAt: NOW - 86_400_000 })];
  const codes = detectSuspiciousLogin(
    history,
    attempt({ outcome: 'success', ip: '203.0.113.55', userAgent: 'browser/2' }),
    NOW,
  ).map((s) => s.code);
  assert.ok(codes.includes('new-network'));
  assert.ok(codes.includes('new-device'));
});

void test('succeeding right after a run of failures is flagged', () => {
  const history = [
    attempt({ outcome: 'success', createdAt: NOW - 86_400_000 }),
    ...failures(3),
  ];
  const codes = detectSuspiciousLogin(history, attempt({ outcome: 'success' }), NOW).map((s) => s.code);
  assert.ok(codes.includes('after-failures'));
});

void test('failures from several addresses look like credential stuffing', () => {
  const history = [
    attempt({ outcome: 'success', createdAt: NOW - 86_400_000 }),
    attempt({ ip: '203.0.113.1' }),
    attempt({ ip: '203.0.113.2' }),
    attempt({ ip: '203.0.113.3' }),
  ];
  const codes = detectSuspiciousLogin(history, attempt({ outcome: 'success' }), NOW).map((s) => s.code);
  assert.ok(codes.includes('credential-stuffing'));
});

void test('every suspicion carries a detail a person can read', () => {
  const history = [
    attempt({ outcome: 'success', createdAt: NOW - 86_400_000 }),
    ...failures(4, { ip: '203.0.113.4' }),
  ];
  const suspicions = detectSuspiciousLogin(
    history,
    attempt({ outcome: 'success', ip: '203.0.113.99', userAgent: 'browser/9' }),
    NOW,
  );
  assert.ok(suspicions.length > 0);
  for (const suspicion of suspicions) assert.ok(suspicion.detail.length > 5, suspicion.code);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  consume,
  isRateLimitName,
  rateLimitHeaders,
  rateLimitKey,
  RATE_LIMIT_RULES,
} from '../lib/rate-limit.ts';

const RULE = { limit: 3, windowMs: 60_000 };
const T0 = 1_000_000;

void test('a first request opens a window and is allowed', () => {
  const decision = consume(RULE, null, T0);
  assert.equal(decision.allowed, true);
  assert.equal(decision.remaining, 2);
  assert.deepEqual(decision.next, { count: 1, windowStart: T0 });
});

void test('requests are allowed up to the limit and refused past it', () => {
  let state = null as { count: number; windowStart: number } | null;
  for (let i = 1; i <= RULE.limit; i += 1) {
    const decision = consume(RULE, state, T0);
    assert.equal(decision.allowed, true, `request ${i} should be allowed`);
    state = decision.next;
  }
  const refused = consume(RULE, state, T0);
  assert.equal(refused.allowed, false);
  assert.equal(refused.remaining, 0);
  assert.ok(refused.retryAfterSeconds > 0);
});

void test('the window resets once it has elapsed', () => {
  const exhausted = { count: 99, windowStart: T0 };
  const decision = consume(RULE, exhausted, T0 + RULE.windowMs);
  assert.equal(decision.allowed, true);
  assert.deepEqual(decision.next, { count: 1, windowStart: T0 + RULE.windowMs });
});

void test('a window one millisecond from expiry still blocks', () => {
  const exhausted = { count: 99, windowStart: T0 };
  const decision = consume(RULE, exhausted, T0 + RULE.windowMs - 1);
  assert.equal(decision.allowed, false);
});

void test('hammering a blocked key does not shorten its window', () => {
  // The counter keeps climbing while blocked, so the reset stays anchored to
  // the original window start rather than sliding forward.
  let state = { count: RULE.limit, windowStart: T0 };
  const first = consume(RULE, state, T0 + 1000);
  state = first.next;
  const second = consume(RULE, state, T0 + 2000);
  assert.equal(second.allowed, false);
  assert.equal(second.next.windowStart, T0);
  assert.ok(second.next.count > first.next.count);
});

void test('retry-after counts down as the window drains', () => {
  const state = { count: 99, windowStart: T0 };
  const early = consume(RULE, state, T0 + 1000);
  const late = consume(RULE, state, T0 + 50_000);
  assert.ok(early.retryAfterSeconds > late.retryAfterSeconds);
  assert.ok(late.retryAfterSeconds >= 1);
});

void test('every catalogued rule is a positive budget over a positive window', () => {
  for (const [name, rule] of Object.entries(RATE_LIMIT_RULES)) {
    assert.ok(rule.limit > 0, `${name} has no budget`);
    assert.ok(rule.windowMs > 0, `${name} has no window`);
    assert.equal(isRateLimitName(name), true);
  }
});

void test('unauthenticated auth endpoints are tighter than general API traffic', () => {
  // Sign-in does real work and is the credential-stuffing target, so its
  // budget must be well below the ordinary API allowance.
  assert.ok(RATE_LIMIT_RULES['auth:sign-in'].limit < RATE_LIMIT_RULES['api:anonymous'].limit);
  assert.ok(RATE_LIMIT_RULES['auth:sign-up'].limit <= RATE_LIMIT_RULES['auth:sign-in'].limit);
});

void test('the rule name guard rejects anything uncatalogued', () => {
  assert.equal(isRateLimitName('auth:sign-in'), true);
  assert.equal(isRateLimitName('auth:whatever'), false);
  assert.equal(isRateLimitName('__proto__'), false);
});

void test('keys separate rules so one cannot spend another budget', () => {
  assert.notEqual(rateLimitKey('auth:sign-in', 'abc'), rateLimitKey('auth:sign-up', 'abc'));
  assert.equal(rateLimitKey('auth:sign-in', 'abc'), rateLimitKey('auth:sign-in', 'abc'));
});

void test('headers advertise the budget, and Retry-After only when blocked', () => {
  const allowed = rateLimitHeaders(RULE, consume(RULE, null, Date.now())) as Record<string, string>;
  assert.equal(allowed['RateLimit-Limit'], '3');
  assert.equal('Retry-After' in allowed, false);

  const blocked = rateLimitHeaders(
    RULE,
    consume(RULE, { count: 99, windowStart: Date.now() }, Date.now()),
  ) as Record<string, string>;
  assert.ok('Retry-After' in blocked);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  interpretSiteVerify,
  isTurnstileConfigured,
  readTurnstileConfig,
} from '../lib/turnstile.ts';

void test('both keys are required before the challenge counts as configured', () => {
  assert.equal(isTurnstileConfigured({}), false);
  assert.equal(isTurnstileConfigured({ TURNSTILE_SITE_KEY: 'site' }), false);
  assert.equal(isTurnstileConfigured({ TURNSTILE_SECRET_KEY: 'secret' }), false);
  assert.equal(
    isTurnstileConfigured({ TURNSTILE_SITE_KEY: 'site', TURNSTILE_SECRET_KEY: 'secret' }),
    true,
  );
});

void test('blank keys do not count as configuration', () => {
  assert.equal(
    isTurnstileConfigured({ TURNSTILE_SITE_KEY: '   ', TURNSTILE_SECRET_KEY: 'secret' }),
    false,
  );
});

void test('the config is returned trimmed', () => {
  const config = readTurnstileConfig({
    TURNSTILE_SITE_KEY: '  site  ',
    TURNSTILE_SECRET_KEY: '  secret  ',
  });
  assert.deepEqual(config, { siteKey: 'site', secretKey: 'secret' });
});

void test('a successful verification passes', () => {
  assert.equal(interpretSiteVerify({ success: true }, 200).ok, true);
});

void test('an unreachable verifier fails closed', () => {
  // Treating an outage as a pass would turn a dependency blip into an open
  // door on the two unauthenticated endpoints.
  const verdict = interpretSiteVerify(null, 0);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'unreachable');
});

void test('a non-200 response fails closed', () => {
  const verdict = interpretSiteVerify({ success: true }, 500);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'http-500');
});

void test('a replayed or expired token is reported as such', () => {
  const verdict = interpretSiteVerify(
    { success: false, 'error-codes': ['timeout-or-duplicate'] },
    200,
  );
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'timeout-or-duplicate');
  assert.match(verdict.message, /expired/i);
});

void test('a missing token asks the person to complete the challenge', () => {
  const verdict = interpretSiteVerify(
    { success: false, 'error-codes': ['missing-input-response'] },
    200,
  );
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'missing-token');
});

void test('an unrecognised rejection still fails and names the codes', () => {
  const verdict = interpretSiteVerify(
    { success: false, 'error-codes': ['invalid-input-secret'] },
    200,
  );
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'invalid-input-secret');
});

void test('a rejection with no codes still fails', () => {
  const verdict = interpretSiteVerify({ success: false }, 200);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'rejected');
});

void test('every failure carries a message safe to show a person', () => {
  const verdicts = [
    interpretSiteVerify(null, 0),
    interpretSiteVerify({ success: false, 'error-codes': ['invalid-input-secret'] }, 200),
    interpretSiteVerify({ success: false }, 200),
  ];
  for (const verdict of verdicts) {
    assert.equal(verdict.ok, false);
    assert.ok(verdict.message.length > 10);
    // The operator's secret key must never reach a client-facing message.
    assert.doesNotMatch(verdict.message, /secret/i);
  }
});

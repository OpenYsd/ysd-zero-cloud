import assert from 'node:assert/strict';
import test from 'node:test';
import {
  emailVerificationStatus,
  readEmailProvider,
  verificationMessage,
} from '../lib/email.ts';

void test('email verification requires both an API key and an explicit sender', () => {
  assert.equal(readEmailProvider({}), null);
  assert.equal(readEmailProvider({ RESEND_API_KEY: 'key' }), null);
  assert.equal(
    readEmailProvider({ YSD_EMAIL_FROM: 'noreply@example.com' }),
    null,
  );
});

void test('a complete Resend configuration is trimmed and accepted', () => {
  assert.deepEqual(
    readEmailProvider({
      RESEND_API_KEY: '  key  ',
      YSD_EMAIL_FROM: '  YSD Zero Cloud <noreply@example.com>  ',
    }),
    {
      id: 'resend',
      apiKey: 'key',
      from: 'YSD Zero Cloud <noreply@example.com>',
    },
  );
});

void test('the no-domain production gate wins over stale provider credentials', () => {
  const env = {
    YSD_EMAIL_VERIFICATION_MODE: 'disabled-no-domain',
    RESEND_API_KEY: 'stale-key',
    YSD_EMAIL_FROM: 'noreply@example.com',
  };

  assert.equal(readEmailProvider(env), null);
  assert.deepEqual(emailVerificationStatus(env), {
    state: 'unavailable-no-domain',
    provider: null,
  });
});

void test('enabled mode still requires a complete provider configuration', () => {
  assert.deepEqual(
    emailVerificationStatus({ YSD_EMAIL_VERIFICATION_MODE: 'enabled' }),
    { state: 'not-configured', provider: null },
  );
});

void test('the verification message carries the link and expiry without a credential', () => {
  const message = verificationMessage(
    'Tariq',
    'https://cloud.example/verify?token=public-test',
  );
  assert.match(message.subject, /confirm/i);
  assert.match(message.text, /24 hours/i);
  assert.match(message.text, /https:\/\/cloud\.example\/verify/);
  assert.doesNotMatch(message.text, /api key|secret/i);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { createId, decryptSecret, encryptSecret, fingerprint } from '../lib/crypto.ts';

const KEY = 'a-master-key-with-plenty-of-entropy-0123456789';

void test('a sealed value round-trips with the right key', async () => {
  const sealed = await encryptSecret('postgres://user:pass@host/db', KEY);
  assert.equal(await decryptSecret(sealed, KEY), 'postgres://user:pass@host/db');
});

void test('the envelope never contains the plaintext', async () => {
  const sealed = await encryptSecret('super-secret-token', KEY);
  assert.ok(!sealed.includes('super-secret-token'));
  assert.match(sealed, /^v1\./);
  assert.equal(sealed.split('.').length, 4);
});

void test('the same value seals differently every time', async () => {
  const first = await encryptSecret('same-value', KEY);
  const second = await encryptSecret('same-value', KEY);
  assert.notEqual(first, second, 'a fresh salt and IV must be used per record');
});

void test('a wrong key cannot open the envelope', async () => {
  const sealed = await encryptSecret('value', KEY);
  await assert.rejects(() => decryptSecret(sealed, 'a-different-master-key-entirely'));
});

void test('a tampered envelope is rejected rather than decoded', async () => {
  const sealed = await encryptSecret('value', KEY);
  const parts = sealed.split('.');
  // Flip a character in the ciphertext; AES-GCM must fail the auth tag.
  const cipher = parts[3]!;
  parts[3] = `${cipher.slice(0, -2)}${cipher.slice(-2) === 'AA' ? 'AB' : 'AA'}`;
  await assert.rejects(() => decryptSecret(parts.join('.'), KEY));
});

void test('a malformed envelope is rejected', async () => {
  await assert.rejects(() => decryptSecret('not-an-envelope', KEY));
  await assert.rejects(() => decryptSecret('v2.a.b.c', KEY));
});

void test('encryption requires a master secret', async () => {
  await assert.rejects(() => encryptSecret('value', ''));
});

void test('fingerprints match for equal values and differ otherwise', async () => {
  assert.equal(await fingerprint('shared'), await fingerprint('shared'));
  assert.notEqual(await fingerprint('shared'), await fingerprint('different'));
});

void test('a fingerprint does not reveal the value', async () => {
  const print = await fingerprint('leak-me');
  assert.ok(!print.includes('leak-me'));
  assert.equal(print.length, 22);
});

void test('ids are prefixed and unique', () => {
  const first = createId('sec');
  const second = createId('sec');
  assert.match(first, /^sec_[0-9a-f]{24}$/);
  assert.notEqual(first, second);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { duration, logTime, money, relativeTime } from '../lib/format.ts';

const NOW = Date.UTC(2026, 7, 28, 18, 30, 0);
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

void test('relative time steps through the units an operator reads', () => {
  assert.equal(relativeTime(NOW, NOW), 'now');
  assert.equal(relativeTime(NOW - 30_000, NOW), 'now');
  assert.equal(relativeTime(NOW - 3 * MINUTE, NOW), '3m ago');
  assert.equal(relativeTime(NOW - 5 * HOUR, NOW), '5h ago');
  assert.equal(relativeTime(NOW - 4 * DAY, NOW), '4d ago');
  assert.equal(relativeTime(NOW - 90 * DAY, NOW), '3mo ago');
});

void test('a timestamp in the future reads as scheduled rather than negative', () => {
  assert.equal(relativeTime(NOW + HOUR, NOW), 'scheduled');
});

void test('log timestamps are zero-padded to the millisecond', () => {
  assert.equal(logTime(Date.UTC(2026, 7, 28, 6, 5, 4, 3)), '06:05:04.003');
});

void test('durations pick a readable unit', () => {
  assert.equal(duration(420), '420ms');
  assert.equal(duration(1500), '1.5s');
  assert.equal(duration(90_000), '90s');
  assert.equal(duration(null), '—');
  assert.equal(duration(undefined), '—');
});

void test('money always renders two decimals', () => {
  assert.equal(money(0), '$0.00');
  assert.equal(money(18), '$18.00');
});

void test('an unrepresentable cost says so instead of printing a wrong number', () => {
  assert.equal(money(Number.NaN), 'over limit');
});

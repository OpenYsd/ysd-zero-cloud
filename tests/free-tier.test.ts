import assert from 'node:assert/strict';
import test from 'node:test';
import {
  formatBytes,
  formatUsage,
  FREE_TIER_LIMITS,
  projectedMonthlyCost,
  readUsage,
} from '../lib/free-tier.ts';

void test('every catalogued limit is a real, positive allowance', () => {
  assert.ok(FREE_TIER_LIMITS.length > 0);
  for (const entry of FREE_TIER_LIMITS) {
    assert.ok(entry.limit > 0, `${entry.id} has no allowance`);
    assert.ok(entry.label.length > 0);
    assert.ok(entry.provider.length > 0);
  }
});

void test('a usage reading is produced for every limit, even with no input', () => {
  const readings = readUsage({});
  assert.equal(readings.length, FREE_TIER_LIMITS.length);
  assert.ok(readings.every((reading) => reading.used === 0 && reading.percent === 0));
});

void test('percentages and states track consumption', () => {
  const [projects] = readUsage({ projects: 5 });
  assert.equal(projects?.used, 5);
  assert.equal(projects?.percent, 20);
  assert.equal(projects?.state, 'healthy');

  assert.equal(readUsage({ projects: 18 })[0]?.state, 'watch');
  assert.equal(readUsage({ projects: 24 })[0]?.state, 'critical');
});

void test('a percentage never exceeds 100 even when the limit is passed', () => {
  const [projects] = readUsage({ projects: 900 });
  assert.equal(projects?.percent, 100);
  assert.equal(projects?.used, 900);
});

void test('negative input is clamped rather than trusted', () => {
  assert.equal(readUsage({ projects: -12 })[0]?.used, 0);
});

void test('a workspace inside every allowance costs exactly zero', () => {
  assert.equal(projectedMonthlyCost(readUsage({ projects: 3, deployments: 40 })), 0);
});

void test('exceeding an allowance refuses to report a number rather than inventing a charge', () => {
  const cost = projectedMonthlyCost(readUsage({ projects: 10_000 }));
  assert.ok(Number.isNaN(cost), 'an over-limit workspace must not be given a fabricated price');
});

void test('byte formatting steps through units', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(1024), '1 KB');
  assert.equal(formatBytes(1536), '1.5 KB');
  assert.equal(formatBytes(500 * 1024 * 1024), '500 MB');
  assert.equal(formatBytes(-1), '—');
});

void test('usage strings render counts and bytes differently', () => {
  assert.equal(formatUsage({ used: 1200, limit: 20_000, unit: 'count' }), '1,200 / 20,000');
  assert.equal(formatUsage({ used: 1024, limit: 2048, unit: 'bytes' }), '1 KB / 2 KB');
});

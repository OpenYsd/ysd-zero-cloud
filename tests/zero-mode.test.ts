import assert from 'node:assert/strict';
import test from 'node:test';
import { enforceZeroMode, type PlannedResource } from '../lib/zero-mode.ts';

const freeWorker: PlannedResource = {
  name: 'Cloudflare Worker',
  provider: 'Cloudflare',
  kind: 'compute',
  estimatedMonthlyCost: 0,
  freeTierEligible: true,
};

void test('Zero Mode allows a fully free deployment plan', () => {
  const decision = enforceZeroMode([freeWorker], true);
  assert.equal(decision.allowed, true);
  assert.equal(decision.estimatedMonthlyCost, 0);
  assert.deepEqual(decision.blockedResources, []);
});

void test('Zero Mode blocks any billable resource', () => {
  const decision = enforceZeroMode(
    [freeWorker, { ...freeWorker, name: 'GPU worker', provider: 'GPU', kind: 'ai', estimatedMonthlyCost: 18, freeTierEligible: false }],
    true,
  );
  assert.equal(decision.allowed, false);
  assert.equal(decision.estimatedMonthlyCost, 18);
  assert.equal(decision.blockedResources[0]?.name, 'GPU worker');
});

void test('cost estimates remain visible when Zero Mode is paused', () => {
  const decision = enforceZeroMode([{ ...freeWorker, estimatedMonthlyCost: 12, freeTierEligible: false }], false);
  assert.equal(decision.allowed, true);
  assert.equal(decision.estimatedMonthlyCost, 12);
});

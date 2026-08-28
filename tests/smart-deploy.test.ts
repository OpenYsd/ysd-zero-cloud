import assert from 'node:assert/strict';
import test from 'node:test';
import { createSmartDeployPlan } from '../lib/smart-deploy.ts';

void test('Smart Deploy auto-selects a zero-cost Cloudflare plan', () => {
  const plan = createSmartDeployPlan('OpenYsd/ysd-zero-cloud', 'auto', true);
  assert.equal(plan.framework, 'Next.js');
  assert.equal(plan.resources[0]?.provider, 'Cloudflare');
  assert.equal(plan.protection.allowed, true);
  assert.equal(plan.steps.length, 4);
});

void test('Smart Deploy detects Node.js API repositories', () => {
  const plan = createSmartDeployPlan('OpenYsd/shield-api', 'cloudflare', true);
  assert.equal(plan.framework, 'Node.js');
});

void test('Smart Deploy rejects a paid GPU plan under Zero Mode', () => {
  const plan = createSmartDeployPlan('OpenYsd/ai-worker', 'gpu', true);
  assert.equal(plan.protection.allowed, false);
  assert.equal(plan.protection.estimatedMonthlyCost, 18);
});

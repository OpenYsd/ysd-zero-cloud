import assert from 'node:assert/strict';
import test from 'node:test';
import { createSmartDeployPlan, detectFramework } from '../lib/smart-deploy.ts';

void test('Smart Deploy auto-selects a zero-cost Cloudflare plan', () => {
  const plan = createSmartDeployPlan('OpenYsd/ysd-zero-cloud', 'auto', true);
  assert.equal(plan.framework, 'Next.js');
  assert.equal(plan.resources[0]?.provider, 'Cloudflare');
  assert.equal(plan.protection.allowed, true);
  assert.equal(plan.protection.estimatedMonthlyCost, 0);
  assert.ok(plan.steps.includes('Inspect repository'));
  assert.ok(plan.steps.includes('Run health checks'));
});

void test('Smart Deploy detects Node.js API repositories by name', () => {
  const plan = createSmartDeployPlan('OpenYsd/shield-api', 'cloudflare', true);
  assert.equal(plan.framework, 'Node.js');
  assert.equal(plan.confidence, 'inferred');
});

void test('Smart Deploy rejects a paid GPU plan under Zero Mode', () => {
  const plan = createSmartDeployPlan('OpenYsd/ai-worker', 'gpu', true);
  assert.equal(plan.protection.allowed, false);
  assert.equal(plan.protection.estimatedMonthlyCost, 18);
  assert.equal(plan.protection.blockedResources.length, 1);
});

void test('a paid plan is still described when Zero Mode is paused', () => {
  const plan = createSmartDeployPlan('OpenYsd/ai-worker', 'gpu', false);
  assert.equal(plan.protection.allowed, true);
  assert.equal(plan.protection.estimatedMonthlyCost, 18);
});

void test('every resource in an allowed plan is free-tier eligible and free', () => {
  for (const target of ['auto', 'cloudflare', 'supabase'] as const) {
    const plan = createSmartDeployPlan('OpenYsd/ysd-zero-cloud', target, true);
    assert.equal(plan.protection.allowed, true, `${target} should be allowed`);
    for (const resource of plan.resources) {
      assert.equal(resource.estimatedMonthlyCost, 0, `${resource.name} must be free`);
      assert.equal(resource.freeTierEligible, true, `${resource.name} must be free-tier eligible`);
    }
  }
});

void test('repository signals beat the name-based guess', () => {
  const plan = createSmartDeployPlan('OpenYsd/some-api', 'auto', true, {
    dependencies: ['vite', 'react'],
    files: ['vite.config.ts', 'index.html'],
  });
  assert.equal(plan.framework, 'Vite');
  assert.equal(plan.confidence, 'inspected');
});

void test('framework detection reads real manifests', () => {
  assert.equal(detectFramework('anything', { dependencies: ['next'] }), 'Next.js');
  assert.equal(detectFramework('anything', { dependencies: ['vinext'] }), 'Next.js');
  assert.equal(detectFramework('anything', { dependencies: ['hono'] }), 'Node.js');
  assert.equal(detectFramework('anything', { dependencies: ['express'] }), 'Node.js');
  assert.equal(detectFramework('anything', { files: ['vite.config.js'] }), 'Vite');
  assert.equal(detectFramework('anything', { files: ['index.html'], dependencies: [] }), 'Static');
});

void test('a Next.js plan provisions a database alongside the worker', () => {
  const plan = createSmartDeployPlan('OpenYsd/app', 'cloudflare', true, { dependencies: ['next'] });
  const kinds = plan.resources.map((resource) => resource.kind);
  assert.ok(kinds.includes('compute'));
  assert.ok(kinds.includes('database'));
});

void test('plan ids are stable and safe to use as identifiers', () => {
  const plan = createSmartDeployPlan('OpenYsd/ysd-zero-cloud', 'auto', true);
  assert.equal(plan.id, 'plan_openysd_ysd_zero_cloud');
  assert.equal(plan.id, createSmartDeployPlan('OpenYsd/ysd-zero-cloud', 'auto', true).id);
});

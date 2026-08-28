import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectDeploymentConfig } from '../lib/deploy-guard.ts';

const DATABASE_ID = '4175f8f4-34ff-4234-bbf4-72cc2602c520';

function input() {
  return {
    freeTierVerified: true,
    estimatedMonthlyCost: 0,
    expectedD1DatabaseId: DATABASE_ID,
  };
}

function config() {
  return {
    d1_databases: [{ binding: 'DB', database_id: DATABASE_ID }],
    queues: { producers: [], consumers: [] },
    durable_objects: { bindings: [] },
    r2_buckets: [],
  };
}

void test('the expected Worker and D1-only deployment is allowed', () => {
  assert.deepEqual(inspectDeploymentConfig(config(), input()), {
    allowed: true,
    reasons: [],
  });
});

void test('an unverified plan is blocked even when its estimate says zero', () => {
  const decision = inspectDeploymentConfig(config(), {
    ...input(),
    freeTierVerified: false,
  });
  assert.equal(decision.allowed, false);
  assert.match(decision.reasons.join(' '), /not verified/i);
});

void test('any non-zero estimate is blocked', () => {
  const decision = inspectDeploymentConfig(config(), {
    ...input(),
    estimatedMonthlyCost: 0.01,
  });
  assert.equal(decision.allowed, false);
  assert.match(decision.reasons.join(' '), /exactly \$0\.00/i);
});

void test('paid or unrequested bindings fail closed', () => {
  for (const extra of [
    { r2_buckets: [{ binding: 'FILES', bucket_name: 'files' }] },
    {
      queues: {
        producers: [{ binding: 'QUEUE', queue: 'jobs' }],
        consumers: [],
      },
    },
    { ai: { binding: 'AI' } },
    { limits: { cpu_ms: 30_000 } },
    { send_email: [{ name: 'EMAIL' }] },
  ]) {
    const decision = inspectDeploymentConfig(
      { ...config(), ...extra },
      input(),
    );
    assert.equal(decision.allowed, false, JSON.stringify(extra));
  }
});

void test('a different D1 database is blocked', () => {
  const decision = inspectDeploymentConfig(
    { ...config(), d1_databases: [{ binding: 'DB', database_id: 'other' }] },
    input(),
  );
  assert.equal(decision.allowed, false);
  assert.match(decision.reasons.join(' '), /unexpected D1/i);
});

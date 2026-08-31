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
    vars: {
      YSD_PUBLIC_TRANSPORT_MODE: 'unavailable-zero-mode',
      YSD_CLOUDFLARE_PLAN: 'workers-free',
      YSD_BILLING_STATE: 'no-payment-method',
      YSD_OWNED_ZONE_COUNT: '0',
      YSD_TUNNEL_COUNT: '0',
    },
    queues: { producers: [], consumers: [] },
    durable_objects: { bindings: [] },
    r2_buckets: [],
    triggers: { crons: ['* * * * *'] },
  };
}

void test('the expected Worker, D1, and single free scheduler deployment is allowed', () => {
  assert.deepEqual(inspectDeploymentConfig(config(), input()), {
    allowed: true,
    reasons: [],
  });
});

void test('the scheduler is pinned to one reviewed global tick', () => {
  for (const triggers of [
    undefined,
    { crons: [] },
    { crons: ['*/5 * * * *'] },
    { crons: ['* * * * *', '*/5 * * * *'] },
    { crons: ['* * * * *'], extra: true },
  ]) {
    const decision = inspectDeploymentConfig(
      { ...config(), triggers },
      input(),
    );
    assert.equal(decision.allowed, false);
    assert.match(decision.reasons.join(' '), /exactly one reviewed/i);
  }
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
    { routes: [{ pattern: 'app.example.com', custom_domain: true }] },
    { services: [{ binding: 'ORIGIN', service: 'paid-provider' }] },
  ]) {
    const decision = inspectDeploymentConfig(
      { ...config(), ...extra },
      input(),
    );
    assert.equal(decision.allowed, false, JSON.stringify(extra));
  }
});

void test('request flags cannot bypass the attested no-zone and no-tunnel state', () => {
  for (const vars of [
    { ...config().vars, YSD_PUBLIC_TRANSPORT_MODE: 'cloudflare-tunnel' },
    { ...config().vars, YSD_CLOUDFLARE_PLAN: 'paid' },
    { ...config().vars, YSD_BILLING_STATE: 'active' },
    { ...config().vars, YSD_OWNED_ZONE_COUNT: '1' },
    { ...config().vars, YSD_TUNNEL_COUNT: '1' },
  ]) {
    const decision = inspectDeploymentConfig({ ...config(), vars }, input());
    assert.equal(decision.allowed, false);
    assert.match(decision.reasons.join(' '), /public transport/i);
  }
});

void test('one explicitly-attested private R2 binding is allowed', () => {
  const decision = inspectDeploymentConfig(
    {
      ...config(),
      r2_buckets: [
        { binding: 'STORAGE', bucket_name: 'ysd-zero-cloud-storage' },
      ],
    },
    { ...input(), expectedR2BucketName: 'ysd-zero-cloud-storage' },
  );
  assert.deepEqual(decision, { allowed: true, reasons: [] });
});

void test('R2 fails closed without the exact bucket attestation', () => {
  for (const expectedR2BucketName of ['', 'other-bucket']) {
    const decision = inspectDeploymentConfig(
      {
        ...config(),
        r2_buckets: [
          { binding: 'STORAGE', bucket_name: 'ysd-zero-cloud-storage' },
        ],
      },
      { ...input(), expectedR2BucketName },
    );
    assert.equal(decision.allowed, false);
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

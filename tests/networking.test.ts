import assert from 'node:assert/strict';
import test from 'node:test';
import { buildNetworkState } from '../lib/networking.ts';

void test('the workers.dev-only profile exposes no paid or public storage route', () => {
  const state = buildNetworkState({
    origin: 'https://ysd-zero-cloud.example.workers.dev',
    mode: 'workers-dev-only',
    storageAvailable: true,
  });

  assert.equal(state.tls, true);
  assert.equal(state.workerDomain, true);
  assert.equal(state.customDomains, 0);
  assert.equal(state.tunnels, 0);
  assert.equal(state.publicStorageEndpoints, 0);
  assert.equal(
    state.routes.find((route) => route.id === 'r2')?.exposure,
    'internal',
  );
});

void test('workspace routes remain session-scoped', () => {
  const state = buildNetworkState({
    origin: 'https://cloud.example.com',
    mode: 'custom',
    storageAvailable: false,
  });
  assert.equal(
    state.routes.find((route) => route.id === 'workspace-api')?.exposure,
    'session',
  );
  assert.equal(
    state.routes.find((route) => route.id === 'r2')?.address,
    'binding unavailable',
  );
});

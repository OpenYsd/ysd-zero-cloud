import assert from 'node:assert/strict';
import test from 'node:test';

import {
  availabilityFromVerificationFailure,
  deriveLegacyRuntimeTruth,
  observedStateFromRuntime,
  planRuntimeReconciliation,
  selectRetainedArtifacts,
  shouldSpawnCrashReplacement,
} from '../lib/runtime-recovery.ts';

const CURRENT = 'art_111111111111111111111111';
const PREVIOUS = 'art_222222222222222222222222';

void test('fresh Agent startup detects a desired runtime missing from the managed summary', () => {
  const plans = planRuntimeReconciliation({
    agentVersion: '0.5.0',
    managedDeploymentIds: [],
    deployments: [{
      deploymentId: 'dpl_aaaaaaaaaaaaaaaaaaaaaaaa',
      desiredState: 'running',
      desiredRevision: 4,
      currentArtifactId: CURRENT,
      busy: false,
      recoveryStatus: null,
      recoveryRevision: null,
    }],
  });
  assert.deepEqual(plans.map((plan) => plan.deploymentId), ['dpl_aaaaaaaaaaaaaaaaaaaaaaaa']);
});

void test('Desired Running and runtime missing produces one revision-scoped reconciliation plan', () => {
  const input = {
    agentVersion: '0.5.0',
    managedDeploymentIds: [] as string[],
    deployments: [{
      deploymentId: 'dpl_bbbbbbbbbbbbbbbbbbbbbbbb',
      desiredState: 'running' as const,
      desiredRevision: 9,
      currentArtifactId: CURRENT,
      busy: false,
      recoveryStatus: 'blocked' as const,
      recoveryRevision: 8,
    }],
  };
  assert.equal(planRuntimeReconciliation(input).length, 1);
  assert.equal(planRuntimeReconciliation(input)[0]?.expectedDesiredRevision, 9);
  input.deployments[0]!.recoveryRevision = 9;
  assert.equal(planRuntimeReconciliation(input).length, 0, 'the same revision must not storm every heartbeat');
});

void test('a new Agent generation retries a prior success but not a blocked or failed condition', () => {
  const deployment = {
    deploymentId: 'dpl_cccccccccccccccccccccccc',
    desiredState: 'running' as const,
    desiredRevision: 3,
    currentArtifactId: CURRENT,
    busy: false,
    recoveryStatus: 'succeeded' as const,
    recoveryRevision: 3,
    recoveryGeneration: 'generation_aaaaaaaa',
  };
  const input = {
    agentVersion: '0.5.0', managedDeploymentIds: [] as string[],
    deployments: [deployment], runtimeGeneration: 'generation_bbbbbbbb',
  };
  assert.equal(planRuntimeReconciliation(input).length, 1, 'a later reboot is a new missing-runtime event');
  assert.equal(planRuntimeReconciliation({
    ...input, deployments: [{ ...deployment, recoveryStatus: 'blocked' as const }],
  }).length, 0, 'blocked recovery waits for remediation or a new desired revision');
  assert.equal(planRuntimeReconciliation({
    ...input, deployments: [{ ...deployment, recoveryStatus: 'failed' as const }],
  }).length, 0, 'failed recovery waits for remediation or a new desired revision');
});

void test('an intentional Stop invalidates a delayed crash replacement', () => {
  assert.equal(shouldSpawnCrashReplacement({
    scheduledRevision: 7,
    currentRevision: 8,
    desiredRunning: false,
    intentionalStop: true,
    sameRuntime: true,
  }), false);
});

void test('a replacement process is not Healthy until its health check succeeds', () => {
  assert.equal(observedStateFromRuntime({ processRunning: true, health: 'unknown', crashLoop: false }), 'unknown');
  assert.equal(observedStateFromRuntime({ processRunning: true, health: 'unhealthy', crashLoop: false }), 'unhealthy');
  assert.equal(observedStateFromRuntime({ processRunning: true, health: 'healthy', crashLoop: false }), 'healthy');
});

void test('retention protects current and previous verified artifacts within an exact cap of five', () => {
  const selected = selectRetainedArtifacts({
    currentArtifactId: CURRENT,
    previousVerifiedArtifactId: PREVIOUS,
    cap: 5,
    artifacts: [
      { id: 'junk', modifiedAt: 100, verified: false },
      { id: 'art_333333333333333333333333', modifiedAt: 90, verified: true },
      { id: 'art_444444444444444444444444', modifiedAt: 80, verified: true },
      { id: 'art_555555555555555555555555', modifiedAt: 70, verified: true },
      { id: 'art_666666666666666666666666', modifiedAt: 60, verified: true },
      { id: PREVIOUS, modifiedAt: 20, verified: true },
      { id: CURRENT, modifiedAt: 10, verified: true },
    ],
  });
  assert.equal(selected.size, 5);
  assert.equal(selected.has(CURRENT), true);
  assert.equal(selected.has(PREVIOUS), true);
  assert.equal(selected.has('junk'), false);
});

void test('physical absence is distinct from verified historical metadata', () => {
  assert.equal(availabilityFromVerificationFailure({ code: 'ENOENT', integrityFailure: false }), 'missing');
  assert.equal(availabilityFromVerificationFailure({ code: null, integrityFailure: true }), 'corrupted');
});

void test('legacy lifecycle state backfills desired intent separately from unproven observation', () => {
  assert.deepEqual(deriveLegacyRuntimeTruth('healthy'), {
    desiredState: 'running', desiredRevision: 1, observedState: 'unknown',
  });
  assert.deepEqual(deriveLegacyRuntimeTruth('stopped'), {
    desiredState: 'stopped', desiredRevision: 1, observedState: 'stopped',
  });
  assert.deepEqual(deriveLegacyRuntimeTruth('node_revoked'), {
    desiredState: 'stopped', desiredRevision: 1, observedState: 'unknown',
  });
});

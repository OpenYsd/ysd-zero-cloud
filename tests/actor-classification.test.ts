import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { classifyActivityActor } from '../lib/audit-actions.ts';

/**
 * 0.15.1: who an activity mirror is attributed to.
 *
 * `writeLog` mirrors every telemetry line into `audit_event` as
 * `activity.<source>`. Until this fix it decided the actor kind from the actor
 * STRING -- "any non-null actor is a person" -- so the Phase 15 Shield sweep,
 * the first system caller to pass a readable actor, filed its own activity as
 * `actorType='user'` with `actorId='system:shield-scheduler'`.
 */

function source(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
}

function code(path: string): string {
  return source(path)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/(^|\s)\/\/.*$/, '$1'))
    .join('\n');
}

void test('platform automation is classified as system when it declares itself', () => {
  assert.deepEqual(
    classifyActivityActor({ actor: 'system:shield-scheduler', trusted: 'system' }),
    { actorType: 'system', actorId: 'system:shield-scheduler' },
  );
});

void test('the readable automation actor survives classification', () => {
  // "system" alone would lose which automation did it. The id is the useful
  // half and must not be flattened.
  const { actorId } = classifyActivityActor({ actor: 'system:shield-scheduler', trusted: 'system' });
  assert.equal(actorId, 'system:shield-scheduler');
});

void test('a normal signed-in user stays a user', () => {
  assert.deepEqual(
    classifyActivityActor({ actor: 'person@example.test' }),
    { actorType: 'user', actorId: 'person@example.test' },
  );
});

void test('a caller with no actor at all is still the system', () => {
  assert.deepEqual(
    classifyActivityActor({}),
    { actorType: 'system', actorId: 'system' },
  );
  assert.deepEqual(
    classifyActivityActor({ actor: null }),
    { actorType: 'system', actorId: 'system' },
  );
});

void test('service accounts keep their own kind and shed the synthetic suffix', () => {
  assert.deepEqual(
    classifyActivityActor({ actor: 'sa_123.service.ysd.invalid' }),
    { actorType: 'service_account', actorId: 'sa_123' },
  );
});

void test('a user cannot dress their own activity up as the platform', () => {
  // The actor string at almost every call site is the signed-in user's email
  // address, and this app applies no email format validation of its own -- so
  // an address shaped like an automation id cannot be ruled out. Classifying
  // on the string alone would hand any self-registered account the `system`
  // label, which is exactly what this fix must not do.
  for (const impersonation of [
    'system:shield-scheduler',
    'system:shield-scheduler@example.test',
    'system:anything',
    'system@example.test',
    'agent:node_0000000000000000000000',
    'sa_123.service.ysd.invalid.example.test',
  ]) {
    const { actorType } = classifyActivityActor({ actor: impersonation });
    assert.equal(
      actorType,
      'user',
      `"${impersonation}" was classified ${actorType} without a trusted declaration`,
    );
  }
});

void test('the actor string alone can never produce a system classification', () => {
  // The property, stated directly rather than by example: without `trusted`,
  // no input string yields `system` unless there was no actor at all.
  for (const actor of ['a', 'system:', 'SYSTEM:x', 'system', ' system:x', 'x@y.z']) {
    assert.equal(classifyActivityActor({ actor }).actorType, 'user', actor);
  }
});

void test('the mirror reads its actor kind from the helper, not from a string test', () => {
  const logs = code('lib/server/logs.ts');

  assert.match(logs, /classifyActivityActor\(\{/);
  assert.match(logs, /trusted: input\.actorType/);

  // The exact shape of the defect: a ternary on the actor string deciding the
  // actor kind. It must not come back.
  assert.doesNotMatch(logs, /actorType:\s*[^,\n]*input\.actor\s*\?\s*'user'/);
  assert.doesNotMatch(logs, /\?\s*'user'\s*:\s*'system'/);
});

void test('only the scheduled Shield path declares itself as system', () => {
  const scan = code('lib/server/shield-scan.ts');

  // Both writeLog calls in the scan path are gated on the trigger, so a manual
  // scan by a real person is still recorded as that person.
  assert.equal(
    (scan.match(/actorType: trigger === 'scheduled' \? 'system' : undefined/g) ?? []).length,
    2,
  );
  assert.doesNotMatch(scan, /actorType: 'system'(?!.*trigger)/);

  // `trigger` is a literal in server code on both paths into runScan: the
  // route hard-codes it, and the scheduler is not a request surface.
  const route = code('app/api/shield/scan/route.ts');
  assert.match(route, /runScan\([^)]*'manual'\)/);
  assert.doesNotMatch(route, /body|searchParams|json\(\)/);

  const scheduler = code('lib/server/shield-schedule.ts');
  assert.match(scheduler, /'scheduled',/);
  assert.doesNotMatch(scheduler, /request/i);
});

void test('the fix changes attribution only, and nothing else about the record', () => {
  const logs = code('lib/server/logs.ts');

  // Same action name, same resource shape, same metadata, same tenancy.
  assert.match(logs, /action: `activity\.\$\{input\.source\}`/);
  assert.match(logs, /resourceType: input\.source/);
  assert.match(logs, /resourceId: input\.resource \?\? null/);
  assert.match(logs, /metadata: \{ level: input\.level \?\? 'INFO' \}/);
  assert.match(logs, /organizationId: workspace\.organizationId/);
  assert.match(logs, /workspaceId: input\.workspaceId/);

  // Tenancy still comes from the workspace row, never from the caller.
  assert.doesNotMatch(logs, /organizationId: input\./);

  // No secret-shaped value was introduced into the mirrored metadata.
  for (const forbidden of ['token', 'secret', 'password', 'cookie', 'header', 'ipAddress']) {
    assert.doesNotMatch(
      logs.slice(logs.indexOf('recordAudit({')),
      new RegExp(forbidden, 'i'),
      `the activity mirror must not carry a "${forbidden}"-shaped value`,
    );
  }
});

void test('0.15.1 adds no migration and no schema change', () => {
  const db = code('lib/server/db.ts');
  // The ledger still ends at 0019. A classification fix needs no column.
  assert.match(db, /\{ name: '0019_shield_posture', sql: shieldPostureSchema \}/);
  assert.doesNotMatch(db, /0020/);
});

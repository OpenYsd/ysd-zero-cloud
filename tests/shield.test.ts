import assert from 'node:assert/strict';
import test from 'node:test';
import { runShieldRules, type ShieldSnapshot } from '../lib/shield.ts';

const NOW = Date.UTC(2026, 7, 28, 12, 0, 0);
const DAY = 24 * 60 * 60 * 1000;

function snapshot(overrides: Partial<ShieldSnapshot> = {}): ShieldSnapshot {
  return {
    zeroModeEnabled: true,
    billableResources: 0,
    secrets: [],
    users: { total: 1, unverified: 0 },
    sessions: { total: 1, expired: 0 },
    tables: [{ name: 'project', hasPrimaryKey: true, rows: 4 }],
    integrations: [{ id: 'cloudflare-d1', status: 'configured' }],
    publicProjects: [],
    now: NOW,
    ...overrides,
  };
}

void test('a clean workspace scores 100 and reports nothing', () => {
  const report = runShieldRules(snapshot());
  assert.equal(report.score, 100);
  assert.equal(report.grade, 'strong');
  assert.deepEqual(report.findings, []);
  assert.ok(report.checks.every((check) => check.state === 'passed'));
});

void test('pausing Zero Mode is reported as a high-severity finding', () => {
  const report = runShieldRules(snapshot({ zeroModeEnabled: false }));
  const finding = report.findings.find((entry) => entry.code === 'zero-mode-disabled');
  assert.ok(finding, 'expected a zero-mode finding');
  assert.equal(finding.severity, 'high');
  assert.equal(report.checks.find((check) => check.id === 'cost-guard')?.state, 'failed');
  assert.ok(report.score < 100);
});

void test('a recorded billable resource is flagged even with the guard on', () => {
  const report = runShieldRules(snapshot({ billableResources: 2 }));
  const finding = report.findings.find((entry) => entry.code === 'billable-resources-planned');
  assert.ok(finding);
  assert.match(finding.detail, /2 planned resources/);
});

void test('a secret past its rotation window is flagged, and worse when long overdue', () => {
  const mild = runShieldRules(
    snapshot({
      secrets: [
        {
          name: 'API_KEY',
          environment: 'Production',
          rotationDays: 30,
          updatedAt: NOW - 40 * DAY,
          fingerprint: 'aaa',
        },
      ],
    }),
  );
  assert.equal(mild.findings[0]?.severity, 'medium');

  const severe = runShieldRules(
    snapshot({
      secrets: [
        {
          name: 'API_KEY',
          environment: 'Production',
          rotationDays: 30,
          updatedAt: NOW - 200 * DAY,
          fingerprint: 'aaa',
        },
      ],
    }),
  );
  assert.equal(severe.findings[0]?.severity, 'high');
});

void test('a secret inside its rotation window is not flagged', () => {
  const report = runShieldRules(
    snapshot({
      secrets: [
        {
          name: 'API_KEY',
          environment: 'Production',
          rotationDays: 90,
          updatedAt: NOW - 10 * DAY,
          fingerprint: 'aaa',
        },
      ],
    }),
  );
  assert.deepEqual(report.findings, []);
});

void test('a secret with no rotation policy is left alone', () => {
  const report = runShieldRules(
    snapshot({
      secrets: [
        {
          name: 'API_KEY',
          environment: 'Production',
          rotationDays: null,
          updatedAt: NOW - 5000 * DAY,
          fingerprint: 'aaa',
        },
      ],
    }),
  );
  assert.deepEqual(report.findings, []);
});

void test('one value shared across environments is reported once', () => {
  const report = runShieldRules(
    snapshot({
      secrets: [
        { name: 'API_KEY', environment: 'Production', rotationDays: null, updatedAt: NOW, fingerprint: 'same' },
        { name: 'API_KEY', environment: 'Preview', rotationDays: null, updatedAt: NOW, fingerprint: 'same' },
      ],
    }),
  );
  const reused = report.findings.filter((entry) => entry.code.startsWith('secret-reused:'));
  assert.equal(reused.length, 1);
  assert.match(reused[0]!.detail, /Preview\/API_KEY, Production\/API_KEY/);
});

void test('distinct values across environments are not reported', () => {
  const report = runShieldRules(
    snapshot({
      secrets: [
        { name: 'API_KEY', environment: 'Production', rotationDays: null, updatedAt: NOW, fingerprint: 'one' },
        { name: 'API_KEY', environment: 'Preview', rotationDays: null, updatedAt: NOW, fingerprint: 'two' },
      ],
    }),
  );
  assert.deepEqual(report.findings, []);
});

void test('a populated table without a primary key is flagged', () => {
  const report = runShieldRules(
    snapshot({ tables: [{ name: 'audit', hasPrimaryKey: false, rows: 120 }] }),
  );
  const finding = report.findings.find((entry) => entry.code === 'table-no-primary-key:audit');
  assert.ok(finding);
  assert.equal(finding.severity, 'medium');
});

void test('an empty table without a primary key is not worth reporting', () => {
  const report = runShieldRules(
    snapshot({ tables: [{ name: 'audit', hasPrimaryKey: false, rows: 0 }] }),
  );
  assert.deepEqual(report.findings, []);
});

void test('unverified accounts and stale sessions are low-severity', () => {
  const report = runShieldRules(
    snapshot({ users: { total: 3, unverified: 2 }, sessions: { total: 5, expired: 3 } }),
  );
  const codes = report.findings.map((finding) => finding.code);
  assert.ok(codes.includes('unverified-accounts'));
  assert.ok(codes.includes('expired-sessions'));
  assert.ok(report.findings.every((finding) => finding.severity === 'low'));
});

void test('a public project is surfaced by name', () => {
  const report = runShieldRules(snapshot({ publicProjects: ['docs'] }));
  const finding = report.findings.find((entry) => entry.code === 'public-project:docs');
  assert.ok(finding);
  assert.equal(finding.resource, 'docs');
});

void test('the score floors at zero rather than going negative', () => {
  const report = runShieldRules(
    snapshot({
      zeroModeEnabled: false,
      billableResources: 5,
      users: { total: 10, unverified: 9 },
      sessions: { total: 10, expired: 8 },
      tables: Array.from({ length: 12 }, (_, index) => ({
        name: `t${index}`,
        hasPrimaryKey: false,
        rows: 10,
      })),
    }),
  );
  assert.equal(report.score, 0);
  assert.equal(report.grade, 'at-risk');
});

void test('every finding carries a remediation an operator can act on', () => {
  const report = runShieldRules(
    snapshot({ zeroModeEnabled: false, publicProjects: ['docs'], billableResources: 1 }),
  );
  assert.ok(report.findings.length > 0);
  for (const finding of report.findings) {
    assert.ok(finding.remediation.length > 10, `missing remediation for ${finding.code}`);
    assert.ok(finding.code.length > 0);
  }
});

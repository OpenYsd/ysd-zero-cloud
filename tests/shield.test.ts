import assert from 'node:assert/strict';
import test from 'node:test';
import { runShieldRules, type ShieldSnapshot } from '../lib/shield.ts';

const NOW = Date.UTC(2026, 7, 28, 12, 0, 0);
const DAY = 24 * 60 * 60 * 1000;

/** A fully-protected instance, so each test changes only what it is about. */
const PROTECTED: ShieldSnapshot['protections'] = {
  turnstileConfigured: true,
  emailProviderConfigured: true,
  emailVerificationRequired: true,
  rateLimitEnabled: true,
  recentBlocks: 0,
  failingNetworks: 0,
  owners: 1,
  admins: 0,
  suspended: 0,
  unverifiedPrivileged: 0,
  securityHeaders: {
    present: [
      'content-security-policy',
      'strict-transport-security',
      'x-content-type-options',
      'x-frame-options',
      'referrer-policy',
    ],
    missing: [],
    observed: true,
  },
  orphanRoles: 0,
  suspendedPrivileged: 0,
  unscopedTables: [],
  sqlEditorRestricted: true,
};

function snapshot(overrides: Partial<ShieldSnapshot> = {}): ShieldSnapshot {
  return {
    zeroModeEnabled: true,
    protections: { ...PROTECTED, ...overrides.protections },
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

void test('a missing bot challenge is a high-severity finding', () => {
  const report = runShieldRules(snapshot({ protections: { ...PROTECTED, turnstileConfigured: false } }));
  const finding = report.findings.find((f) => f.code === 'turnstile-not-configured');
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
  assert.equal(report.checks.find((c) => c.id === 'hardening')?.state, 'failed');
});

void test('disabled rate limiting is critical', () => {
  const report = runShieldRules(snapshot({ protections: { ...PROTECTED, rateLimitEnabled: false } }));
  const finding = report.findings.find((f) => f.code === 'rate-limit-disabled');
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
});

void test('no mail provider is reported, and optional verification only when one exists', () => {
  const noMail = runShieldRules(
    snapshot({
      protections: {
        ...PROTECTED,
        emailProviderConfigured: false,
        emailVerificationRequired: false,
      },
    }),
  );
  const codes = noMail.findings.map((f) => f.code);
  assert.ok(codes.includes('email-not-configured'));
  // Without a provider, "verification is optional" is not a separate failing —
  // it is the only possible state.
  assert.ok(!codes.includes('email-verification-optional'));

  const mailButOptional = runShieldRules(
    snapshot({ protections: { ...PROTECTED, emailVerificationRequired: false } }),
  );
  assert.ok(mailButOptional.findings.some((f) => f.code === 'email-verification-optional'));
});

void test('an instance with no owner is flagged', () => {
  const report = runShieldRules(snapshot({ protections: { ...PROTECTED, owners: 0 } }));
  const finding = report.findings.find((f) => f.code === 'no-owner');
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
});

void test('privileged accounts without a verified address are flagged', () => {
  const report = runShieldRules(
    snapshot({ protections: { ...PROTECTED, unverifiedPrivileged: 2 } }),
  );
  const finding = report.findings.find((f) => f.code === 'unverified-privileged-accounts');
  assert.ok(finding);
  assert.match(finding.detail, /2 owner or admin/);
});

void test('lockouts escalate when many networks are involved', () => {
  const isolated = runShieldRules(
    snapshot({ protections: { ...PROTECTED, recentBlocks: 2, failingNetworks: 1 } }),
  );
  assert.equal(isolated.findings.find((f) => f.code === 'brute-force-observed')?.severity, 'low');

  const distributed = runShieldRules(
    snapshot({ protections: { ...PROTECTED, recentBlocks: 9, failingNetworks: 5 } }),
  );
  assert.equal(distributed.findings.find((f) => f.code === 'brute-force-observed')?.severity, 'high');
});

void test('a fully protected instance passes the hardening check', () => {
  const report = runShieldRules(snapshot());
  assert.equal(report.checks.find((c) => c.id === 'hardening')?.state, 'passed');
});

void test('missing security headers are reported, and CSP weighs heavier', () => {
  const cspGone = runShieldRules(
    snapshot({
      protections: {
        ...PROTECTED,
        securityHeaders: { present: [], missing: ['content-security-policy'], observed: true },
      },
    }),
  );
  assert.equal(
    cspGone.findings.find((f) => f.code === 'security-headers-missing')?.severity,
    'medium',
  );

  const minorGone = runShieldRules(
    snapshot({
      protections: {
        ...PROTECTED,
        securityHeaders: { present: [], missing: ['referrer-policy'], observed: true },
      },
    }),
  );
  assert.equal(
    minorGone.findings.find((f) => f.code === 'security-headers-missing')?.severity,
    'low',
  );
});

void test('an unrestricted SQL Editor is the most severe finding available', () => {
  const report = runShieldRules(
    snapshot({ protections: { ...PROTECTED, sqlEditorRestricted: false } }),
  );
  const finding = report.findings.find((f) => f.code === 'sql-editor-unrestricted');
  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
});

void test('orphaned role rows and suspended privileged accounts are flagged', () => {
  const report = runShieldRules(
    snapshot({ protections: { ...PROTECTED, orphanRoles: 2, suspendedPrivileged: 1 } }),
  );
  const codes = report.findings.map((f) => f.code);
  assert.ok(codes.includes('orphan-role-rows'));
  assert.ok(codes.includes('suspended-privileged-accounts'));
});

void test('a table the scoping rules do not classify is reported', () => {
  const report = runShieldRules(
    snapshot({ protections: { ...PROTECTED, unscopedTables: ['audit_trail'] } }),
  );
  const finding = report.findings.find((f) => f.code === 'unscoped-tables');
  assert.ok(finding);
  assert.match(finding.detail, /audit_trail/);
});

void test('a fully hardened instance still scores 100', () => {
  // The score must only reach 100 when every check genuinely passes, so this
  // guards against a future check that can never be satisfied.
  const report = runShieldRules(snapshot());
  assert.equal(report.score, 100);
  assert.deepEqual(report.findings, []);
});

void test('an unobservable header probe is not reported as a failure', () => {
  // A Worker cannot reliably fetch its own origin, so "could not observe" must
  // never be presented as "the headers are absent".
  const report = runShieldRules(
    snapshot({
      protections: {
        ...PROTECTED,
        securityHeaders: { present: [], missing: [], observed: false },
      },
    }),
  );
  assert.ok(!report.findings.some((f) => f.code === 'security-headers-missing'));
});

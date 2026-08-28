/**
 * YSD Shield: the security posture rules.
 *
 * Every check is a pure function of a snapshot taken from the workspace
 * database, so the same rules run in a scan, in a test, and in a preview
 * without touching D1 twice.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type ShieldFinding = {
  /** Stable across scans so a finding can be tracked rather than duplicated. */
  code: string;
  title: string;
  detail: string;
  resource: string;
  severity: Severity;
  /** What the operator should do about it. */
  remediation: string;
};

export type ShieldCheck = {
  id: string;
  name: string;
  detail: string;
  state: 'passed' | 'review' | 'failed';
};

export type ShieldSnapshot = {
  zeroModeEnabled: boolean;
  /** Planned resources recorded with a projected charge above zero. */
  billableResources: number;
  secrets: {
    name: string;
    environment: string;
    rotationDays: number | null;
    updatedAt: number;
    fingerprint: string;
  }[];
  users: { total: number; unverified: number };
  sessions: { total: number; expired: number };
  tables: { name: string; hasPrimaryKey: boolean; rows: number }[];
  integrations: { id: string; status: 'mock' | 'configured' }[];
  /** Projects reachable without authentication. */
  publicProjects: string[];
  now: number;
};

export type ShieldReport = {
  score: number;
  grade: 'strong' | 'fair' | 'at-risk';
  headline: string;
  checks: ShieldCheck[];
  findings: ShieldFinding[];
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 30,
  high: 16,
  medium: 8,
  low: 3,
};

const DAY_MS = 24 * 60 * 60 * 1000;

/** Tables that must never be world-readable, regardless of their contents. */
const CREDENTIAL_TABLES = new Set(['account', 'session', 'verification']);

function checkZeroMode(snapshot: ShieldSnapshot): { check: ShieldCheck; findings: ShieldFinding[] } {
  const findings: ShieldFinding[] = [];
  if (!snapshot.zeroModeEnabled) {
    findings.push({
      code: 'zero-mode-disabled',
      title: 'Zero Mode is paused',
      detail: 'Deployment plans can provision billable resources while the cost guard is off.',
      resource: 'workspace',
      severity: 'high',
      remediation: 'Re-enable Zero Mode in Settings so billable plans are rejected before they run.',
    });
  }
  if (snapshot.billableResources > 0) {
    findings.push({
      code: 'billable-resources-planned',
      title: 'Billable resources appear in recorded plans',
      detail: `${snapshot.billableResources} planned resource${snapshot.billableResources === 1 ? '' : 's'} carried a projected charge.`,
      resource: 'deployments',
      severity: 'medium',
      remediation: 'Replace the paid target with a free-tier equivalent, or delete the plan.',
    });
  }
  return {
    check: {
      id: 'cost-guard',
      name: 'Cost guard',
      detail: snapshot.zeroModeEnabled
        ? 'Zero Mode is enforcing free-tier-only plans'
        : 'Zero Mode is paused',
      state: findings.length === 0 ? 'passed' : snapshot.zeroModeEnabled ? 'review' : 'failed',
    },
    findings,
  };
}

function checkSecrets(snapshot: ShieldSnapshot): { check: ShieldCheck; findings: ShieldFinding[] } {
  const findings: ShieldFinding[] = [];

  for (const secret of snapshot.secrets) {
    if (secret.rotationDays === null) continue;
    const ageDays = Math.floor((snapshot.now - secret.updatedAt) / DAY_MS);
    if (ageDays > secret.rotationDays) {
      findings.push({
        code: `secret-overdue:${secret.name}:${secret.environment}`,
        title: `${secret.name} is past its rotation window`,
        detail: `Last updated ${ageDays} days ago against a ${secret.rotationDays} day policy.`,
        resource: `${secret.environment}/${secret.name}`,
        severity: ageDays > secret.rotationDays * 2 ? 'high' : 'medium',
        remediation: 'Rotate the value and update every workload that reads it.',
      });
    }
  }

  // Identical ciphertext fingerprints mean one credential is doing duty in
  // several environments; a leak in the weakest one compromises them all.
  const byFingerprint = new Map<string, string[]>();
  for (const secret of snapshot.secrets) {
    const scope = `${secret.environment}/${secret.name}`;
    byFingerprint.set(secret.fingerprint, [...(byFingerprint.get(secret.fingerprint) ?? []), scope]);
  }
  for (const [, scopes] of byFingerprint) {
    if (scopes.length < 2) continue;
    findings.push({
      code: `secret-reused:${scopes.slice().sort().join('|')}`,
      title: 'One secret value is shared across environments',
      detail: `The same value is stored for ${scopes.slice().sort().join(', ')}.`,
      resource: scopes[0]!,
      severity: 'medium',
      remediation: 'Give each environment its own value so a leak stays contained.',
    });
  }

  return {
    check: {
      id: 'secrets',
      name: 'Secrets exposure',
      detail:
        snapshot.secrets.length === 0
          ? 'No secrets stored yet'
          : `${snapshot.secrets.length} encrypted secret${snapshot.secrets.length === 1 ? '' : 's'} checked`,
      state: findings.length === 0 ? 'passed' : 'review',
    },
    findings,
  };
}

function checkIdentity(snapshot: ShieldSnapshot): { check: ShieldCheck; findings: ShieldFinding[] } {
  const findings: ShieldFinding[] = [];

  if (snapshot.users.unverified > 0) {
    findings.push({
      code: 'unverified-accounts',
      title: 'Accounts without a verified email',
      detail: `${snapshot.users.unverified} of ${snapshot.users.total} accounts have not confirmed their address.`,
      resource: 'identity',
      severity: 'low',
      remediation: 'Enable email verification before inviting collaborators outside your team.',
    });
  }

  if (snapshot.sessions.expired > 0) {
    findings.push({
      code: 'expired-sessions',
      title: 'Expired sessions are still stored',
      detail: `${snapshot.sessions.expired} expired session row${snapshot.sessions.expired === 1 ? '' : 's'} remain in the database.`,
      resource: 'identity',
      severity: 'low',
      remediation: 'Run a scan to clear them, or shorten the session lifetime.',
    });
  }

  return {
    check: {
      id: 'identity',
      name: 'Identity and sessions',
      detail: `${snapshot.users.total} account${snapshot.users.total === 1 ? '' : 's'} · ${snapshot.sessions.total} active session${snapshot.sessions.total === 1 ? '' : 's'}`,
      state: findings.length === 0 ? 'passed' : 'review',
    },
    findings,
  };
}

function checkDatabase(snapshot: ShieldSnapshot): { check: ShieldCheck; findings: ShieldFinding[] } {
  const findings: ShieldFinding[] = [];

  for (const table of snapshot.tables) {
    if (table.hasPrimaryKey || table.rows === 0) continue;
    findings.push({
      code: `table-no-primary-key:${table.name}`,
      title: `${table.name} has no primary key`,
      detail: `${table.rows.toLocaleString('en-US')} rows cannot be addressed or de-duplicated reliably.`,
      resource: table.name,
      severity: 'medium',
      remediation: 'Add a primary key so updates and deletes target exactly one row.',
    });
  }

  const credentialTables = snapshot.tables.filter((table) => CREDENTIAL_TABLES.has(table.name));

  return {
    check: {
      id: 'database',
      name: 'Database policies',
      detail: `${snapshot.tables.length} table${snapshot.tables.length === 1 ? '' : 's'} inspected · ${credentialTables.length} holding credentials`,
      state: findings.length === 0 ? 'passed' : 'review',
    },
    findings,
  };
}

function checkSurface(snapshot: ShieldSnapshot): { check: ShieldCheck; findings: ShieldFinding[] } {
  const findings: ShieldFinding[] = [];

  for (const project of snapshot.publicProjects) {
    findings.push({
      code: `public-project:${project}`,
      title: `${project} is reachable without authentication`,
      detail: 'Anyone with the URL can load this project.',
      resource: project,
      severity: 'low',
      remediation: 'Confirm this is intentional, or move the project behind the workspace session.',
    });
  }

  const configured = snapshot.integrations.filter((entry) => entry.status === 'configured');

  return {
    check: {
      id: 'surface',
      name: 'Network surface',
      detail: `${snapshot.publicProjects.length} public project${snapshot.publicProjects.length === 1 ? '' : 's'} · ${configured.length} live integration${configured.length === 1 ? '' : 's'}`,
      state: findings.length === 0 ? 'passed' : 'review',
    },
    findings,
  };
}

/** Runs every rule against a snapshot and scores the result. */
export function runShieldRules(snapshot: ShieldSnapshot): ShieldReport {
  const results = [
    checkZeroMode(snapshot),
    checkSecrets(snapshot),
    checkIdentity(snapshot),
    checkDatabase(snapshot),
    checkSurface(snapshot),
  ];

  const checks = results.map((result) => result.check);
  const findings = results.flatMap((result) => result.findings);

  const penalty = findings.reduce((total, finding) => total + SEVERITY_WEIGHT[finding.severity], 0);
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const grade = score >= 85 ? 'strong' : score >= 60 ? 'fair' : 'at-risk';

  return {
    score,
    grade,
    headline:
      findings.length === 0
        ? 'Every check passed. Nothing needs attention.'
        : `${findings.length} finding${findings.length === 1 ? '' : 's'} to review before the next release.`,
    checks,
    findings,
  };
}

export function severityRank(severity: Severity): number {
  return SEVERITY_WEIGHT[severity];
}

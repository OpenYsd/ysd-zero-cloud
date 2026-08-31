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

/** State of the abuse and identity protections, for the hardening checks. */
export type ProtectionSnapshot = {
  turnstileConfigured: boolean;
  emailProviderConfigured: boolean;
  emailVerificationRequired: boolean;
  /** Distinguishes a deliberate no-domain gate from an incomplete setup. */
  emailVerificationState?:
    | 'enabled'
    | 'unavailable-no-domain'
    | 'not-configured';
  rateLimitEnabled: boolean;
  /** Lockouts triggered in the last day. */
  recentBlocks: number;
  /** Distinct addresses that failed a sign-in in the last day. */
  failingNetworks: number;
  owners: number;
  admins: number;
  suspended: number;
  /** Accounts holding admin or owner without a verified address. */
  unverifiedPrivileged: number;
  /**
   * Security response headers.
   *
   * `observed` distinguishes "the origin answered and these were absent" from
   * "the origin could not be reached", so an unreachable probe is reported as
   * unverified rather than as a failure that is not real.
   */
  securityHeaders: { present: string[]; missing: string[]; observed: boolean };
  /** Role rows whose account no longer exists. */
  orphanRoles: number;
  /** Owner or admin accounts that are currently suspended. */
  suspendedPrivileged: number;
  /** Tables holding tenant data that the scoping rules do not classify. */
  unscopedTables: string[];
  /** True while the SQL Editor is restricted to a single owner. */
  sqlEditorRestricted: boolean;
};

export type ShieldSnapshot = {
  zeroModeEnabled: boolean;
  protections: ProtectionSnapshot;
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
  collaboration?: {
    ownerInvariant: boolean;
    tenantIsolationViolations: number;
    tenantIsolationGuarded: boolean;
    auditAppendOnly: boolean;
    staleAdmins: number;
    expiredInvitations: number;
    unboundedServiceTokens: number;
    privilegeEscalationBlocked: boolean;
  };
  storage?: {
    available: boolean;
    private: boolean;
    bytesUsed: number;
    limitBytes: number;
    objectCount: number;
  };
  network?: {
    tls: boolean;
    customDomains: number;
    tunnels: number;
    publicStorageEndpoints: number;
  };
  nodes?: {
    total: number;
    stale: number;
    offline: number;
    revoked: number;
    outdated: number;
    unsignedJobs: number;
    staleLeases: number;
    anomalousEvents: number;
    revokedActivity: number;
  };
  ai?: {
    totalAiNodes: number;
    eligibleOnlineNodes: number;
    staleNodes: number;
    offlineNodes: number;
    outdatedNodes: number;
    unsupportedRuntime: number;
    invalidModelHash: number;
    oversizedModels: number;
    insufficientDisk: number;
    unsignedJobs: number;
    forgedClaims: number;
    replayedJobs: number;
    expiredLeases: number;
    repeatedFailures: number;
    suspiciousVolume: number;
    resourceExhaustion: number;
    unexpectedOutbound: number;
    forbiddenProvider: number;
    revokedActivity: number;
    modelPathAbuse: number;
    payloadAbuse: number;
  };
  gameServers?: {
    total: number;
    eligibleOnlineNodes: number;
    staleNodes: number;
    revokedNodes: number;
    unexpectedExposure: number;
    onlineModeDisabled: number;
    whitelistDisabled: number;
    outdatedVersions: number;
    unverifiedBinaries: number;
    excessiveRam: number;
    crashLoops: number;
    unsafeConfig: number;
    corruptedBackups: number;
    unsignedJobs: number;
    expiredLeases: number;
    suspiciousVolume: number;
    forgedClaims: number;
    replayedJobs: number;
    revokedActivity: number;
    resourceExhaustion: number;
    zeroModeBypass: number;
    payloadAbuse: number;
  };
  appRuntime?: {
    unsafeScripts: number;
    lifecycleHooks: number;
    unsafeRegistry: number;
    pathAbuse: number;
    unsignedArtifacts: number;
    checksumMismatch: number;
    exposedBind: number;
    crashLoops: number;
    staleNodes: number;
    revokedActivity: number;
    resourceExhaustion: number;
    envLeak: number;
    unexpectedOutbound: number;
    forbiddenProvider: number;
    suspiciousVolume: number;
  };
  publicExposure?: {
    unavailableUnderZeroMode: boolean;
    unexpectedPublic: number;
    staleRoutes: number;
    offlineOrRevokedRoutes: number;
    unverifiedDomains: number;
    tlsUnavailable: number;
    originLeakIndicators: number;
    openProxyAttempts: number;
    excessivePublicRoutes: number;
    rateLimitDisabled: number;
    suspiciousDomainChurn: number;
    lowPrivilegeChanges: number;
    tunnelCredentialAnomaly: number;
    unexpectedConnectorTarget: number;
    orphanRoutes: number;
    crossOrgDomainConflict: number;
    zeroModeBypass: number;
  };
  workflows?: {
    privilegedLowOwner: number;
    excessiveRetry: number;
    potentialCycles: number;
    noTimeout: number;
    highConcurrency: number;
    stale: number;
    repeatedFailures: number;
    suspiciousVolume: number;
    orphanReferences: number;
    crossOrgAttempts: number;
    secretExposure: number;
    zeroModeBypass: number;
  };
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

function checkZeroMode(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const findings: ShieldFinding[] = [];
  if (!snapshot.zeroModeEnabled) {
    findings.push({
      code: 'zero-mode-disabled',
      title: 'Zero Mode is paused',
      detail:
        'Deployment plans can provision billable resources while the cost guard is off.',
      resource: 'workspace',
      severity: 'high',
      remediation:
        'Re-enable Zero Mode in Settings so billable plans are rejected before they run.',
    });
  }
  if (snapshot.billableResources > 0) {
    findings.push({
      code: 'billable-resources-planned',
      title: 'Billable resources appear in recorded plans',
      detail: `${snapshot.billableResources} planned resource${snapshot.billableResources === 1 ? '' : 's'} carried a projected charge.`,
      resource: 'deployments',
      severity: 'medium',
      remediation:
        'Replace the paid target with a free-tier equivalent, or delete the plan.',
    });
  }
  return {
    check: {
      id: 'cost-guard',
      name: 'Cost guard',
      detail: snapshot.zeroModeEnabled
        ? 'Zero Mode is enforcing free-tier-only plans'
        : 'Zero Mode is paused',
      state:
        findings.length === 0
          ? 'passed'
          : snapshot.zeroModeEnabled
            ? 'review'
            : 'failed',
    },
    findings,
  };
}

function checkSecrets(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
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
        remediation:
          'Rotate the value and update every workload that reads it.',
      });
    }
  }

  // Identical ciphertext fingerprints mean one credential is doing duty in
  // several environments; a leak in the weakest one compromises them all.
  const byFingerprint = new Map<string, string[]>();
  for (const secret of snapshot.secrets) {
    const scope = `${secret.environment}/${secret.name}`;
    byFingerprint.set(secret.fingerprint, [
      ...(byFingerprint.get(secret.fingerprint) ?? []),
      scope,
    ]);
  }
  for (const [, scopes] of byFingerprint) {
    if (scopes.length < 2) continue;
    findings.push({
      code: `secret-reused:${scopes.slice().sort().join('|')}`,
      title: 'One secret value is shared across environments',
      detail: `The same value is stored for ${scopes.slice().sort().join(', ')}.`,
      resource: scopes[0]!,
      severity: 'medium',
      remediation:
        'Give each environment its own value so a leak stays contained.',
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

function checkIdentity(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const findings: ShieldFinding[] = [];
  const emailUnavailable =
    snapshot.protections.emailVerificationState === 'unavailable-no-domain';

  if (snapshot.users.unverified > 0 && !emailUnavailable) {
    findings.push({
      code: 'unverified-accounts',
      title: 'Accounts without a verified email',
      detail: `${snapshot.users.unverified} of ${snapshot.users.total} accounts have not confirmed their address.`,
      resource: 'identity',
      severity: 'low',
      remediation:
        'Enable email verification before inviting collaborators outside your team.',
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

function checkDatabase(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const findings: ShieldFinding[] = [];

  for (const table of snapshot.tables) {
    if (table.hasPrimaryKey || table.rows === 0) continue;
    findings.push({
      code: `table-no-primary-key:${table.name}`,
      title: `${table.name} has no primary key`,
      detail: `${table.rows.toLocaleString('en-US')} rows cannot be addressed or de-duplicated reliably.`,
      resource: table.name,
      severity: 'medium',
      remediation:
        'Add a primary key so updates and deletes target exactly one row.',
    });
  }

  const credentialTables = snapshot.tables.filter((table) =>
    CREDENTIAL_TABLES.has(table.name),
  );

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

function checkStorage(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const findings: ShieldFinding[] = [];
  const storage = snapshot.storage;

  if (!storage) {
    return {
      check: {
        id: 'storage',
        name: 'Object storage',
        detail: 'Storage state was not sampled',
        state: 'passed',
      },
      findings,
    };
  }

  if (!storage.available) {
    findings.push({
      code: 'r2-account-not-enabled',
      title: 'R2 unavailable: account activation required',
      detail:
        'The private storage implementation and quota ledger are ready, but Cloudflare currently refuses R2 bucket access for this account.',
      resource: 'storage',
      severity: 'low',
      remediation:
        'No code fix or paid upgrade is required. Keep uploads disabled unless R2 can be enabled from Cloudflare at a confirmed cost of $0.',
    });
  }

  if (!storage.private) {
    findings.push({
      code: 'r2-public-access-enabled',
      title: 'Object storage has a public endpoint',
      detail:
        'Objects can bypass the workspace session and D1 authorization index.',
      resource: 'storage',
      severity: 'critical',
      remediation:
        'Disable r2.dev and bucket custom domains; serve objects only through the authenticated Worker route.',
    });
  }

  if (storage.bytesUsed > storage.limitBytes) {
    findings.push({
      code: 'r2-workspace-quota-exceeded',
      title: 'Workspace storage exceeded its Zero Mode guard',
      detail: `${storage.bytesUsed.toLocaleString('en-US')} bytes are recorded against a ${storage.limitBytes.toLocaleString('en-US')} byte ceiling.`,
      resource: 'storage',
      severity: 'high',
      remediation:
        'Delete objects until usage is below the hard limit; do not raise the ceiling into billable capacity.',
    });
  }

  return {
    check: {
      id: 'storage',
      name: 'Private object storage',
      detail: storage.available
        ? `${storage.objectCount} object${storage.objectCount === 1 ? '' : 's'} · ${storage.bytesUsed.toLocaleString('en-US')} bytes · private binding`
        : 'R2 binding unavailable · uploads disabled · no public endpoint',
      state: findings.some(
        (finding) =>
          finding.severity === 'critical' || finding.severity === 'high',
      )
        ? 'failed'
        : findings.length > 0
          ? 'review'
          : 'passed',
    },
    findings,
  };
}

/**
 * The abuse controls in front of the unauthenticated endpoints.
 *
 * A protection that is merely *available* is not a protection; these check
 * that each one is actually configured and doing something.
 */
function checkHardening(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const findings: ShieldFinding[] = [];
  const p = snapshot.protections;
  const emailState =
    p.emailVerificationState ??
    (p.emailProviderConfigured ? 'enabled' : 'not-configured');

  if (!p.turnstileConfigured) {
    findings.push({
      code: 'turnstile-not-configured',
      title: 'Sign-up and sign-in have no bot challenge',
      detail:
        'Turnstile keys are not set, so automated sign-up and credential stuffing are unimpeded.',
      resource: 'identity',
      severity: 'high',
      remediation:
        'Create a free Turnstile widget and set TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY.',
    });
  }

  if (emailState === 'unavailable-no-domain') {
    findings.push({
      code: 'email-verification-unavailable-no-domain',
      title: 'Email verification unavailable: no owned sending domain',
      detail:
        'Production delivery is configuration-gated off because this Cloudflare account has no owned sending domain. Authentication remains usable, but addresses are not asserted as verified.',
      resource: 'identity',
      severity: 'low',
      remediation:
        'No code fix is required. Keep verification disabled until an owned domain is available; then verify the domain and deliberately change YSD_EMAIL_VERIFICATION_MODE to enabled.',
    });
  } else if (!p.emailProviderConfigured) {
    findings.push({
      code: 'email-not-configured',
      title: 'Addresses cannot be verified',
      detail:
        'No mail provider is configured, so verification links cannot be delivered and every account stays unverified.',
      resource: 'identity',
      severity: 'medium',
      remediation:
        'Set RESEND_API_KEY to enable verification, or accept unverified addresses deliberately.',
    });
  } else if (!p.emailVerificationRequired) {
    findings.push({
      code: 'email-verification-optional',
      title: 'Email verification is not required',
      detail:
        'Mail is configured but sign-in does not require a verified address.',
      resource: 'identity',
      severity: 'low',
      remediation:
        'Remove YSD_REQUIRE_EMAIL_VERIFICATION=false to require verification.',
    });
  }

  if (!p.rateLimitEnabled) {
    findings.push({
      code: 'rate-limit-disabled',
      title: 'Authentication endpoints are not rate limited',
      detail: 'Sign-in and sign-up accept unlimited attempts.',
      resource: 'identity',
      severity: 'critical',
      remediation: 'Re-enable the rate limiter in lib/server/auth-options.ts.',
    });
  }

  if (p.owners === 0) {
    findings.push({
      code: 'no-owner',
      title: 'The instance has no owner',
      detail: 'Nobody can administer accounts or reach the SQL Editor.',
      resource: 'identity',
      severity: 'high',
      remediation:
        'Set YSD_OWNER_EMAIL to an account that exists, then sign in with it.',
    });
  }

  if (p.unverifiedPrivileged > 0 && emailState !== 'unavailable-no-domain') {
    findings.push({
      code: 'unverified-privileged-accounts',
      title: 'Privileged accounts have unverified addresses',
      detail: `${p.unverifiedPrivileged} owner or admin account${p.unverifiedPrivileged === 1 ? '' : 's'} cannot be reached at a confirmed address.`,
      resource: 'identity',
      severity: 'medium',
      remediation:
        'Verify the address, or move the privilege to an account you can prove you control.',
    });
  }

  if (p.recentBlocks > 0) {
    findings.push({
      code: 'brute-force-observed',
      title: 'Sign-in lockouts triggered recently',
      detail: `${p.recentBlocks} attempt${p.recentBlocks === 1 ? ' was' : 's were'} refused by the brute-force guard in the last day.`,
      resource: 'identity',
      severity: p.failingNetworks >= 3 ? 'high' : 'low',
      remediation:
        'Review the auth entries in Logs. The guard held, but repeated attempts are worth understanding.',
    });
  }

  if (p.securityHeaders.observed && p.securityHeaders.missing.length > 0) {
    findings.push({
      code: 'security-headers-missing',
      title: 'Security response headers are missing',
      detail: `Not served: ${p.securityHeaders.missing.join(', ')}.`,
      resource: 'edge',
      severity: p.securityHeaders.missing.includes('content-security-policy')
        ? 'medium'
        : 'low',
      remediation: 'Set them in middleware.ts so every response carries them.',
    });
  }

  if (p.orphanRoles > 0) {
    findings.push({
      code: 'orphan-role-rows',
      title: 'Role rows without an account',
      detail: `${p.orphanRoles} role assignment${p.orphanRoles === 1 ? '' : 's'} point at an account that no longer exists.`,
      resource: 'identity',
      severity: 'medium',
      remediation:
        'Delete the orphaned rows; a recreated account could otherwise inherit a stale role.',
    });
  }

  if (p.suspendedPrivileged > 0) {
    findings.push({
      code: 'suspended-privileged-accounts',
      title: 'A privileged account is suspended',
      detail: `${p.suspendedPrivileged} owner or admin account${p.suspendedPrivileged === 1 ? ' is' : 's are'} suspended and cannot act.`,
      resource: 'identity',
      severity: 'medium',
      remediation:
        'Restore the account, or move its role to someone who can use it.',
    });
  }

  if (!p.sqlEditorRestricted) {
    findings.push({
      code: 'sql-editor-unrestricted',
      title: 'The SQL Editor is not owner-restricted',
      detail:
        'A raw statement cannot be scoped to one workspace, so this would expose every tenant.',
      resource: 'database',
      severity: 'critical',
      remediation:
        'Restore the owner-only capability check on the query route.',
    });
  }

  if (p.unscopedTables.length > 0) {
    findings.push({
      code: 'unscoped-tables',
      title: 'Tables are not covered by the tenant scoping rules',
      detail: `${p.unscopedTables.join(', ')} would be invisible in Studio because no scoping rule classifies them.`,
      resource: 'database',
      severity: 'low',
      remediation:
        'Add them to lib/tenancy.ts so their rows are scoped rather than hidden.',
    });
  }

  const configured = [p.turnstileConfigured, p.rateLimitEnabled].filter(
    Boolean,
  ).length;
  const emailDetail =
    emailState === 'unavailable-no-domain'
      ? 'email gated: no owned domain'
      : emailState === 'enabled'
        ? 'email verification active'
        : 'email delivery not configured';

  return {
    check: {
      id: 'hardening',
      name: 'Abuse protections',
      detail: `${configured} of 2 active abuse controls configured · ${emailDetail} · ${p.owners} owner${p.owners === 1 ? '' : 's'}, ${p.admins} admin${p.admins === 1 ? '' : 's'}, ${p.suspended} suspended`,
      state: findings.some(
        (f) => f.severity === 'critical' || f.severity === 'high',
      )
        ? 'failed'
        : findings.length > 0
          ? 'review'
          : 'passed',
    },
    findings,
  };
}

function checkSurface(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const findings: ShieldFinding[] = [];

  for (const project of snapshot.publicProjects) {
    findings.push({
      code: `public-project:${project}`,
      title: `${project} is reachable without authentication`,
      detail: 'Anyone with the URL can load this project.',
      resource: project,
      severity: 'low',
      remediation:
        'Confirm this is intentional, or move the project behind the workspace session.',
    });
  }

  if (snapshot.network && !snapshot.network.tls) {
    findings.push({
      code: 'edge-tls-disabled',
      title: 'The production origin is not using TLS',
      detail:
        'Credentials and session cookies would cross the network without transport encryption.',
      resource: 'edge',
      severity: 'critical',
      remediation:
        'Use the Cloudflare-managed HTTPS workers.dev origin or an owned HTTPS custom domain.',
    });
  }

  if ((snapshot.network?.publicStorageEndpoints ?? 0) > 0) {
    findings.push({
      code: 'public-storage-route',
      title: 'A public object-storage route bypasses workspace authorization',
      detail: `${snapshot.network!.publicStorageEndpoints} public storage endpoint${snapshot.network!.publicStorageEndpoints === 1 ? '' : 's'} are configured.`,
      resource: 'edge',
      severity: 'high',
      remediation:
        'Remove public bucket routes and use the session-scoped /api/storage endpoint.',
    });
  }

  const configured = snapshot.integrations.filter(
    (entry) => entry.status === 'configured',
  );

  return {
    check: {
      id: 'surface',
      name: 'Network surface',
      detail: `${snapshot.publicProjects.length} public project${snapshot.publicProjects.length === 1 ? '' : 's'} · ${configured.length} live integration${configured.length === 1 ? '' : 's'} · ${snapshot.network?.customDomains ?? 0} custom domain${snapshot.network?.customDomains === 1 ? '' : 's'} · ${snapshot.network?.tunnels ?? 0} tunnel${snapshot.network?.tunnels === 1 ? '' : 's'}`,
      state: findings.length === 0 ? 'passed' : 'review',
    },
    findings,
  };
}

function checkCollaboration(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const state = snapshot.collaboration;
  const findings: ShieldFinding[] = [];
  if (!state) {
    return {
      check: {
        id: 'organization-isolation',
        name: 'Organization isolation',
        detail: 'Organization controls were not sampled',
        state: 'review',
      },
      findings,
    };
  }
  if (!state.ownerInvariant) findings.push({
    code: 'organization-owner-invariant',
    title: 'Organization ownership is inconsistent',
    detail: 'The designated owner is not the one active owner membership expected by the organization record.',
    resource: 'organization/members',
    severity: 'critical',
    remediation: 'Restore one active designated owner before allowing any further member changes.',
  });
  if (state.tenantIsolationViolations > 0) findings.push({
    code: 'organization-tenant-key-mismatch',
    title: 'Cross-organization tenant keys disagree',
    detail: `${state.tenantIsolationViolations} row${state.tenantIsolationViolations === 1 ? '' : 's'} carry an organization, workspace, or project relationship that does not match.`,
    resource: 'organization/isolation',
    severity: 'critical',
    remediation: 'Quarantine the affected rows, restore the tenant consistency triggers, and audit the creating request.',
  });
  if (!state.tenantIsolationGuarded) findings.push({
    code: 'organization-tenant-guards-missing',
    title: 'Tenant consistency guards are incomplete',
    detail: 'One or more D1 triggers that prevent cross-organization key changes are missing.',
    resource: 'organization/isolation',
    severity: 'critical',
    remediation: 'Reapply the organization migration before accepting collaboration writes.',
  });
  if (!state.auditAppendOnly) findings.push({
    code: 'audit-not-append-only',
    title: 'Audit history is not protected from mutation',
    detail: 'One or both D1 triggers that reject audit updates and deletes are missing.',
    resource: 'audit_event',
    severity: 'critical',
    remediation: 'Reapply the organization migration before trusting the audit trail.',
  });
  if (!state.privilegeEscalationBlocked) findings.push({
    code: 'organization-privilege-escalation',
    title: 'An administrator can reach owner-only capabilities',
    detail: 'The server permission matrix no longer separates administration from ownership transfer.',
    resource: 'organization/permissions',
    severity: 'critical',
    remediation: 'Restore the server-authoritative role matrix and confirmed ownership-transfer path.',
  });
  if (state.staleAdmins > 0) findings.push({
    code: 'stale-organization-admins',
    title: 'Organization administrators are stale',
    detail: `${state.staleAdmins} administrator${state.staleAdmins === 1 ? ' has' : 's have'} had no activity for at least 90 days.`,
    resource: 'organization/members',
    severity: 'medium',
    remediation: 'Confirm the access is still needed, then downgrade, suspend, or remove stale administrators.',
  });
  if (state.expiredInvitations > 0) findings.push({
    code: 'expired-organization-invitations',
    title: 'Expired invitations await reconciliation',
    detail: `${state.expiredInvitations} pending invitation${state.expiredInvitations === 1 ? ' is' : 's are'} past expiry.`,
    resource: 'organization/invitations',
    severity: 'low',
    remediation: 'Open Invitations or run another scan to mark the links expired.',
  });
  if (state.unboundedServiceTokens > 0) findings.push({
    code: 'unbounded-service-tokens',
    title: 'Service tokens have no bounded expiry',
    detail: `${state.unboundedServiceTokens} active token${state.unboundedServiceTokens === 1 ? ' has' : 's have'} no expiry or an expiry more than 180 days away.`,
    resource: 'organization/service-accounts',
    severity: 'medium',
    remediation: 'Replace them with short-lived project-scoped tokens and revoke the old credentials.',
  });
  return {
    check: {
      id: 'organization-isolation',
      name: 'Organization isolation',
      detail: 'Owner invariant · tenant-key triggers · append-only audit · scoped automation',
      state: findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high')
        ? 'failed'
        : findings.length > 0 ? 'review' : 'passed',
    },
    findings,
  };
}

function checkNodes(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const nodes = snapshot.nodes;
  const findings: ShieldFinding[] = [];
  if (!nodes) {
    return {
      check: {
        id: 'compute-nodes',
        name: 'Compute Nodes',
        detail: 'Node security state was not sampled',
        state: 'passed',
      },
      findings,
    };
  }

  if (nodes.outdated > 0) {
    findings.push({
      code: 'outdated-node-agents',
      title: 'Node agents are below the minimum version',
      detail: `${nodes.outdated} node agent${nodes.outdated === 1 ? ' is' : 's are'} below the supported security baseline.`,
      resource: 'nodes',
      severity: 'medium',
      remediation:
        'Stop the old process, update the checked-out agent, and restart it with the encrypted credential.',
    });
  }
  if (nodes.stale > 0) {
    findings.push({
      code: 'stale-node-heartbeats',
      title: 'Compute node heartbeats are stale',
      detail: `${nodes.stale} node${nodes.stale === 1 ? ' has' : 's have'} missed the online heartbeat window.`,
      resource: 'nodes',
      severity: 'medium',
      remediation:
        'Check the outbound HTTPS connection and local agent process before dispatching work.',
    });
  }
  if (nodes.offline > 0) {
    findings.push({
      code: 'offline-compute-nodes',
      title: 'Compute nodes are offline',
      detail: `${nodes.offline} active node${nodes.offline === 1 ? ' is' : 's are'} not reporting. Queued work remains in D1 and is not lost.`,
      resource: 'nodes',
      severity: 'low',
      remediation:
        'Restart the local agent, or revoke the node if the machine should no longer connect.',
    });
  }
  if (nodes.revoked > 0) {
    findings.push({
      code: 'revoked-nodes-retained',
      title: 'Revoked nodes are retained in audit history',
      detail: `${nodes.revoked} revoked node record${nodes.revoked === 1 ? ' is' : 's are'} retained with its credential erased.`,
      resource: 'nodes',
      severity: 'low',
      remediation:
        'No credential remains usable. Keep the row for audit history, or add a deliberate retention policy later.',
    });
  }
  if (nodes.unsignedJobs > 0) {
    findings.push({
      code: 'unsigned-node-jobs',
      title: 'Node jobs are missing signed claims',
      detail: `${nodes.unsignedJobs} claimed or completed job${nodes.unsignedJobs === 1 ? ' has' : 's have'} no control-plane signature.`,
      resource: 'node-jobs',
      severity: 'critical',
      remediation:
        'Stop the affected nodes, revoke their credentials, and investigate the job rows before re-pairing.',
    });
  }
  if (nodes.staleLeases > 0) {
    findings.push({
      code: 'stale-node-leases',
      title: 'Node job leases expired without recovery',
      detail: `${nodes.staleLeases} lease${nodes.staleLeases === 1 ? ' is' : 's are'} past timeout while still marked active.`,
      resource: 'node-jobs',
      severity: 'high',
      remediation:
        'Open Nodes to trigger recovery, then inspect agent connectivity and completion errors.',
    });
  }
  if (nodes.anomalousEvents > 0) {
    findings.push({
      code: 'anomalous-node-activity',
      title: 'Anomalous node activity was blocked',
      detail: `${nodes.anomalousEvents} high-severity node security event${nodes.anomalousEvents === 1 ? ' was' : 's were'} recorded in the last day.`,
      resource: 'nodes',
      severity: 'high',
      remediation:
        'Review the Nodes security events and revoke any credential whose machine or local passphrase may be compromised.',
    });
  }
  if (nodes.revokedActivity > 0) {
    findings.push({
      code: 'revoked-node-activity',
      title: 'A revoked node tried to reconnect',
      detail: `${nodes.revokedActivity} request${nodes.revokedActivity === 1 ? ' used' : 's used'} a revoked node identifier in the last day.`,
      resource: 'nodes',
      severity: 'high',
      remediation:
        'Confirm the old agent process is stopped. The credential remains rejected and cannot claim work.',
    });
  }

  return {
    check: {
      id: 'compute-nodes',
      name: 'Compute Nodes',
      detail: `${nodes.total} paired · ${nodes.stale} stale · ${nodes.offline} offline · ${nodes.revoked} revoked · signed outbound-only claims`,
      state: findings.some(
        (finding) =>
          finding.severity === 'critical' || finding.severity === 'high',
      )
        ? 'failed'
        : findings.length > 0
          ? 'review'
          : 'passed',
    },
    findings,
  };
}

function checkAiCompute(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const ai = snapshot.ai;
  const findings: ShieldFinding[] = [];
  if (!ai) {
    return {
      check: {
        id: 'ai-compute',
        name: 'YSD AI Compute',
        detail: 'AI security state was not sampled',
        state: 'passed',
      },
      findings,
    };
  }

  if (ai.totalAiNodes === 0) {
    findings.push({
      code: 'ai-no-local-node',
      title: 'No local AI node is connected',
      detail:
        'The control plane is ready, but no user-owned node currently reports an allowlisted local AI runtime.',
      resource: 'ai',
      severity: 'low',
      remediation:
        'Pair an outbound-only node and start Ollama or llama.cpp locally when AI execution is needed.',
    });
  } else if (ai.eligibleOnlineNodes === 0) {
    findings.push({
      code: 'ai-no-eligible-node',
      title: 'No AI node is eligible for scheduling',
      detail: `${ai.totalAiNodes} AI-capable node${ai.totalAiNodes === 1 ? ' is' : 's are'} known, but none is online with a supported agent and runtime.`,
      resource: 'ai/nodes',
      severity: 'medium',
      remediation:
        'Update the agent, restore its outbound connection, and confirm the local runtime health before submitting inference.',
    });
  }

  const readinessIssues = ai.staleNodes + ai.offlineNodes + ai.outdatedNodes;
  if (readinessIssues > 0) {
    findings.push({
      code: 'ai-node-readiness',
      title: 'AI nodes need attention',
      detail: `${ai.staleNodes} stale · ${ai.offlineNodes} offline · ${ai.outdatedNodes} below the minimum agent version.`,
      resource: 'ai/nodes',
      severity: ai.outdatedNodes > 0 || ai.staleNodes > 0 ? 'medium' : 'low',
      remediation:
        'Use the current agent version and restore signed outbound heartbeats; revoke machines that should stay disconnected.',
    });
  }

  const integrityFailures =
    ai.unsignedJobs + ai.forgedClaims + ai.replayedJobs + ai.invalidModelHash;
  if (integrityFailures > 0) {
    findings.push({
      code: 'ai-integrity-failure',
      title: 'AI job or model integrity checks failed',
      detail: `${ai.unsignedJobs} unsigned · ${ai.forgedClaims} forged · ${ai.replayedJobs} replayed · ${ai.invalidModelHash} invalid model hash.`,
      resource: 'ai/security',
      severity: 'critical',
      remediation:
        'Revoke affected node credentials, stop inference, inspect the audit events, and re-pair only after the local machine is trusted.',
    });
  }

  const boundaryViolations =
    ai.unexpectedOutbound +
    ai.forbiddenProvider +
    ai.modelPathAbuse +
    ai.payloadAbuse;
  if (boundaryViolations > 0) {
    findings.push({
      code: 'ai-execution-boundary-violation',
      title: 'AI execution boundary abuse was blocked',
      detail: `${ai.unexpectedOutbound} unexpected outbound · ${ai.forbiddenProvider} forbidden provider · ${ai.modelPathAbuse} model path · ${ai.payloadAbuse} malicious payload event.`,
      resource: 'ai/security',
      severity: 'critical',
      remediation:
        'Review the initiating account and node audit events. Keep local-only origins and the reviewed model catalog unchanged.',
    });
  }

  if (ai.revokedActivity > 0) {
    findings.push({
      code: 'ai-revoked-node-activity',
      title: 'A revoked node attempted AI activity',
      detail: `${ai.revokedActivity} revoked-node event${ai.revokedActivity === 1 ? ' was' : 's were'} blocked in the last day.`,
      resource: 'ai/nodes',
      severity: 'high',
      remediation:
        'Confirm the old agent process is stopped and inspect the machine. Its erased credential remains unusable.',
    });
  }

  const operationalIssues =
    ai.unsupportedRuntime +
    ai.oversizedModels +
    ai.insufficientDisk +
    ai.expiredLeases +
    ai.repeatedFailures +
    ai.suspiciousVolume +
    ai.resourceExhaustion;
  if (operationalIssues > 0) {
    findings.push({
      code: 'ai-operational-anomaly',
      title: 'AI workload anomalies need review',
      detail: `${ai.unsupportedRuntime} runtime · ${ai.oversizedModels} oversized model · ${ai.insufficientDisk} disk · ${ai.expiredLeases} stale lease · ${ai.repeatedFailures} repeated failure · ${ai.suspiciousVolume} suspicious volume · ${ai.resourceExhaustion} resource event.`,
      resource: 'ai/operations',
      severity:
        ai.oversizedModels > 0 ||
        ai.expiredLeases > 0 ||
        ai.suspiciousVolume > 0
          ? 'high'
          : 'medium',
      remediation:
        'Inspect AI jobs and node metrics, restore safe capacity, and keep model size, lease, rate, and runtime guards enforced.',
    });
  }

  return {
    check: {
      id: 'ai-compute',
      name: 'YSD AI Compute',
      detail: `${ai.eligibleOnlineNodes} eligible local node${ai.eligibleOnlineNodes === 1 ? '' : 's'} · signed jobs · allowlisted runtimes · $0 platform compute`,
      state: findings.some(
        (finding) =>
          finding.severity === 'critical' || finding.severity === 'high',
      )
        ? 'failed'
        : findings.length > 0
          ? 'review'
          : 'passed',
    },
    findings,
  };
}

function checkGameServers(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const game = snapshot.gameServers;
  const findings: ShieldFinding[] = [];
  if (!game) {
    return {
      check: {
        id: 'game-servers',
        name: 'YSD Game Servers',
        detail: 'Game Server security state was not sampled',
        state: 'passed',
      },
      findings,
    };
  }

  if (game.total > 0 && game.eligibleOnlineNodes === 0) {
    findings.push({
      code: 'game-no-eligible-node',
      title: 'Game Servers have no eligible local node',
      detail: `${game.total} server${game.total === 1 ? ' is' : 's are'} recorded, but no current outbound-only node is online with Java capacity.`,
      resource: 'game-servers/nodes',
      severity: 'medium',
      remediation:
        'Restore the assigned node with the current agent and supported Java runtime, or leave the local server stopped.',
    });
  }
  if (game.staleNodes + game.revokedNodes > 0) {
    findings.push({
      code: 'game-node-readiness',
      title: 'Game Server nodes need attention',
      detail: `${game.staleNodes} stale · ${game.revokedNodes} revoked. Revoked local processes are not remotely controlled.`,
      resource: 'game-servers/nodes',
      severity: game.revokedNodes > 0 ? 'high' : 'medium',
      remediation:
        'Confirm revoked agents are stopped locally and restore signed heartbeats only on machines that should remain trusted.',
    });
  }
  if (game.unexpectedExposure > 0) {
    findings.push({
      code: 'game-unexpected-network-exposure',
      title: 'Unexpected Game Server network exposure',
      detail: `${game.unexpectedExposure} server${game.unexpectedExposure === 1 ? ' no longer binds' : 's no longer bind'} only to the private localhost policy.`,
      resource: 'game-servers/network',
      severity: 'critical',
      remediation:
        'Stop the server, restore server-ip=127.0.0.1 and RCON disabled, and inspect any manual router or firewall changes.',
    });
  }
  if (game.onlineModeDisabled > 0) {
    findings.push({
      code: 'game-online-mode-disabled',
      title: 'Minecraft identity verification is disabled',
      detail: `${game.onlineModeDisabled} server${game.onlineModeDisabled === 1 ? ' has' : 's have'} online-mode disabled.`,
      resource: 'game-servers/config',
      severity: 'high',
      remediation:
        'Enable online-mode unless a deliberate, reviewed local-only test requires otherwise.',
    });
  }
  if (game.whitelistDisabled > 0) {
    findings.push({
      code: 'game-whitelist-disabled',
      title: 'Minecraft whitelist is disabled',
      detail: `${game.whitelistDisabled} server${game.whitelistDisabled === 1 ? ' accepts' : 's accept'} any authenticated player that can reach its locally configured network.`,
      resource: 'game-servers/config',
      severity: 'low',
      remediation:
        'Enable and enforce the whitelist for private communities, then add players through the bounded interface.',
    });
  }

  const integrity =
    game.unverifiedBinaries +
    game.corruptedBackups +
    game.unsignedJobs +
    game.forgedClaims +
    game.replayedJobs;
  if (integrity > 0) {
    findings.push({
      code: 'game-integrity-failure',
      title: 'Game Server job, binary, or backup integrity failed',
      detail: `${game.unverifiedBinaries} unverified binary · ${game.corruptedBackups} corrupted backup · ${game.unsignedJobs} unsigned · ${game.forgedClaims} forged · ${game.replayedJobs} replayed.`,
      resource: 'game-servers/security',
      severity: 'critical',
      remediation:
        'Stop affected servers, revoke suspect node credentials, refuse damaged backups, and reprovision only from verified Mojang metadata.',
    });
  }
  if (game.zeroModeBypass + game.payloadAbuse > 0) {
    findings.push({
      code: 'game-execution-boundary-violation',
      title: 'Game Server execution boundary abuse was blocked',
      detail: `${game.zeroModeBypass} Zero Mode/provider bypass · ${game.payloadAbuse} command, path, URL, tunnel, or malformed action event.`,
      resource: 'game-servers/security',
      severity: 'critical',
      remediation:
        'Review the initiating account and node audit trail. Keep fixed Java arguments, private exposure, and local-node provider enforcement unchanged.',
    });
  }
  if (game.revokedActivity > 0) {
    findings.push({
      code: 'game-revoked-node-activity',
      title: 'A revoked node had Game Server activity',
      detail: `${game.revokedActivity} revoked-node event${game.revokedActivity === 1 ? ' was' : 's were'} blocked or recorded in the last day.`,
      resource: 'game-servers/nodes',
      severity: 'high',
      remediation:
        'Confirm the old agent and any local Java process are handled directly on that machine. Its erased credential remains unusable.',
    });
  }

  const operations =
    game.outdatedVersions +
    game.excessiveRam +
    game.crashLoops +
    game.unsafeConfig +
    game.expiredLeases +
    game.suspiciousVolume +
    game.resourceExhaustion;
  if (operations > 0) {
    findings.push({
      code: 'game-operational-anomaly',
      title: 'Game Server workload anomalies need review',
      detail: `${game.outdatedVersions} outdated · ${game.excessiveRam} excessive RAM · ${game.crashLoops} crash loop · ${game.unsafeConfig} unsafe config · ${game.expiredLeases} stale lease · ${game.suspiciousVolume} suspicious volume · ${game.resourceExhaustion} resource event.`,
      resource: 'game-servers/operations',
      severity:
        game.excessiveRam > 0 ||
        game.crashLoops > 0 ||
        game.unsafeConfig > 0 ||
        game.expiredLeases > 0 ||
        game.suspiciousVolume > 0
          ? 'high'
          : 'medium',
      remediation:
        'Inspect lifecycle history and node capacity, update the allowlisted release, and keep crash-loop, lease, RAM, disk, and config guards enforced.',
    });
  }

  return {
    check: {
      id: 'game-servers',
      name: 'YSD Game Servers',
      detail: `${game.total} local Vanilla server${game.total === 1 ? '' : 's'} · private default · verified downloads · signed bounded actions · $0 platform hosting`,
      state: findings.some(
        (finding) =>
          finding.severity === 'critical' || finding.severity === 'high',
      )
        ? 'failed'
        : findings.length > 0
          ? 'review'
          : 'passed',
    },
    findings,
  };
}

function checkAppRuntime(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const app = snapshot.appRuntime;
  const findings: ShieldFinding[] = [];
  if (!app) {
    return {
      check: {
        id: 'app-runtime',
        name: 'YSD App Runtime',
        detail: 'App Runtime security state was not sampled',
        state: 'passed',
      },
      findings,
    };
  }

  const executionBoundary =
    app.unsafeScripts + app.lifecycleHooks + app.unsafeRegistry + app.pathAbuse;
  if (executionBoundary > 0) {
    findings.push({
      code: 'app-execution-boundary-violation',
      title: 'Unsafe App Runtime input was blocked',
      detail: `${app.unsafeScripts} arbitrary script · ${app.lifecycleHooks} lifecycle hook · ${app.unsafeRegistry} registry config · ${app.pathAbuse} path or symlink event.`,
      resource: 'deployments/security',
      severity: 'critical',
      remediation:
        'Keep the fixed package-manager and Node entrypoint contract, inspect the source and actor, and do not retry a rejected repository unchanged.',
    });
  }

  if (app.unsignedArtifacts + app.checksumMismatch > 0) {
    findings.push({
      code: 'app-artifact-integrity-failure',
      title: 'App artifact integrity could not be verified',
      detail: `${app.unsignedArtifacts} unverified artifact · ${app.checksumMismatch} checksum failure.`,
      resource: 'deployments/artifacts',
      severity: 'critical',
      remediation:
        'Stop the affected deployment and rebuild from the pinned GitHub commit. Roll back only to an artifact whose manifest and checksum verify locally.',
    });
  }

  if (app.exposedBind + app.unexpectedOutbound + app.forbiddenProvider > 0) {
    findings.push({
      code: 'app-network-boundary-violation',
      title: 'App Runtime network boundary needs attention',
      detail: `${app.exposedBind} wildcard bind · ${app.unexpectedOutbound} unexpected outbound attempt · ${app.forbiddenProvider} provider or tunnel bypass.`,
      resource: 'deployments/network',
      severity: 'critical',
      remediation:
        'Stop the app, retain localhost-only permissions and Private exposure, and do not create a tunnel, provider fallback, or public route automatically.',
    });
  }

  if (app.envLeak > 0) {
    findings.push({
      code: 'app-environment-leak',
      title: 'A possible deployment secret leak was detected',
      detail: `${app.envLeak} environment leak indicator${app.envLeak === 1 ? ' was' : 's were'} recorded.`,
      resource: 'deployments/logs',
      severity: 'critical',
      remediation:
        'Stop the deployment, rotate the affected scoped secret, and inspect only redacted bounded logs and the local node.',
    });
  }

  if (app.revokedActivity > 0) {
    findings.push({
      code: 'app-revoked-node-activity',
      title: 'A revoked node attempted App Runtime activity',
      detail: `${app.revokedActivity} revoked-node event${app.revokedActivity === 1 ? ' was' : 's were'} blocked or recorded.`,
      resource: 'deployments/nodes',
      severity: 'high',
      remediation:
        'Confirm the old agent and its managed app processes stopped locally. Keep its erased credential revoked.',
    });
  }

  const operational =
    app.crashLoops + app.staleNodes + app.resourceExhaustion + app.suspiciousVolume;
  if (operational > 0) {
    findings.push({
      code: 'app-operational-anomaly',
      title: 'App Runtime workload anomalies need review',
      detail: `${app.crashLoops} crash loop · ${app.staleNodes} stale/revoked node · ${app.resourceExhaustion} resource event · ${app.suspiciousVolume} suspicious deploy volume.`,
      resource: 'deployments/operations',
      severity:
        app.crashLoops > 0 || app.resourceExhaustion > 0 || app.suspiciousVolume > 0
          ? 'high'
          : 'medium',
      remediation:
        'Inspect the selected node, capacity, lease history, and bounded restart policy before issuing another deployment action.',
    });
  }

  return {
    check: {
      id: 'app-runtime',
      name: 'YSD App Runtime',
      detail: 'Pinned GitHub sources · fixed Node.js contract · private user-owned compute · $0 platform runtime',
      state: findings.some(
        (finding) => finding.severity === 'critical' || finding.severity === 'high',
      )
        ? 'failed'
        : findings.length > 0
          ? 'review'
          : 'passed',
    },
    findings,
  };
}

function checkPublicExposure(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const state = snapshot.publicExposure;
  const findings: ShieldFinding[] = [];
  if (!state) {
    return {
      check: {
        id: 'public-exposure',
        name: 'Public App Exposure',
        detail: 'Public route security state was not sampled',
        state: 'review',
      },
      findings,
    };
  }
  if (state.unexpectedPublic > 0) {
    findings.push({
      code: 'exposure-unexpected-public-route',
      title: 'Unexpected public exposure is active',
      detail: `${state.unexpectedPublic} active route${state.unexpectedPublic === 1 ? '' : 's'} lack the fixed reviewed connector identity.`,
      resource: 'networking/routes',
      severity: 'critical',
      remediation: 'Disable the route and keep public transport gated until the Cloudflare connector, zone, and cost attestation are reviewed together.',
    });
  }
  if (state.staleRoutes + state.offlineOrRevokedRoutes > 0) {
    findings.push({
      code: 'exposure-unhealthy-route',
      title: 'A public route targets unhealthy compute',
      detail: `${state.staleRoutes} stale or failed route · ${state.offlineOrRevokedRoutes} offline or revoked node route.`,
      resource: 'networking/health',
      severity: 'critical',
      remediation: 'Fail the route closed, verify the deployment artifact and node heartbeat, and never fall back across projects or organizations.',
    });
  }
  if (state.unverifiedDomains + state.tlsUnavailable > 0) {
    findings.push({
      code: 'exposure-domain-or-tls-unverified',
      title: 'Custom domain ownership or TLS is unavailable',
      detail: `${state.unverifiedDomains} unverified attached domain · ${state.tlsUnavailable} active route without Cloudflare TLS.`,
      resource: 'networking/domains',
      severity: 'critical',
      remediation: 'Detach the domain until DNS ownership is verified and Cloudflare has issued TLS for an owned zone.',
    });
  }
  if (state.originLeakIndicators + state.openProxyAttempts > 0) {
    findings.push({
      code: 'exposure-ssrf-or-origin-leak',
      title: 'Gateway origin or open-proxy abuse was detected',
      detail: `${state.originLeakIndicators} origin/IP leak indicator · ${state.openProxyAttempts} upstream or SSRF attempt.`,
      resource: 'networking/gateway',
      severity: 'critical',
      remediation: 'Keep target selection derived only from deployment identity; reject every user URL, IP, localhost, metadata, and internal-network target.',
    });
  }
  if (state.excessivePublicRoutes + state.rateLimitDisabled > 0) {
    findings.push({
      code: 'exposure-abuse-controls',
      title: 'Public route abuse controls need attention',
      detail: `${state.excessivePublicRoutes} route${state.excessivePublicRoutes === 1 ? '' : 's'} above the workspace ceiling · ${state.rateLimitDisabled} route${state.rateLimitDisabled === 1 ? '' : 's'} without rate limiting.`,
      resource: 'networking/rate-limits',
      severity: 'high',
      remediation: 'Disable excess routes and restore the D1-backed per-route rate limit before public traffic is allowed.',
    });
  }
  if (state.suspiciousDomainChurn + state.lowPrivilegeChanges > 0) {
    findings.push({
      code: 'exposure-suspicious-change',
      title: 'Suspicious domain or low-privilege exposure changes were recorded',
      detail: `${state.suspiciousDomainChurn} recent domain mutation${state.suspiciousDomainChurn === 1 ? '' : 's'} · ${state.lowPrivilegeChanges} low-privilege exposure change${state.lowPrivilegeChanges === 1 ? '' : 's'}.`,
      resource: 'audit/exposure',
      severity: 'high',
      remediation: 'Review the actor and audit sequence. Owners/admins manage production exposure; developers may bind only enabled Preview deployments.',
    });
  }
  if (state.tunnelCredentialAnomaly + state.unexpectedConnectorTarget > 0) {
    findings.push({
      code: 'exposure-connector-anomaly',
      title: 'Tunnel connector contract anomaly was blocked',
      detail: `${state.tunnelCredentialAnomaly} credential anomaly · ${state.unexpectedConnectorTarget} unexpected connector target.`,
      resource: 'networking/connector',
      severity: 'critical',
      remediation: 'Revoke the connector credential locally, keep the fixed executable/API contract disabled, and inspect the node without accepting user commands or endpoints.',
    });
  }
  if (state.orphanRoutes + state.crossOrgDomainConflict > 0) {
    findings.push({
      code: 'exposure-tenant-integrity',
      title: 'Exposure tenant integrity failed',
      detail: `${state.orphanRoutes} orphan route · ${state.crossOrgDomainConflict} cross-organization domain conflict.`,
      resource: 'networking/tenancy',
      severity: 'critical',
      remediation: 'Remove the orphan/conflict and restore the D1 tenant triggers before enabling any route.',
    });
  }
  if (state.zeroModeBypass > 0) {
    findings.push({
      code: 'exposure-zero-mode-bypass',
      title: 'A paid provider or Zero Mode bypass was attempted',
      detail: `${state.zeroModeBypass} paid-provider, billing, or zeroMode=false attempt${state.zeroModeBypass === 1 ? ' was' : 's were'} blocked.`,
      resource: 'networking/zero-mode',
      severity: 'critical',
      remediation: 'Keep the deployment guard pinned to Workers Free, one D1 database, no zones, no tunnels, and exactly $0.00/month.',
    });
  }
  return {
    check: {
      id: 'public-exposure',
      name: 'Public App Exposure',
      detail: state.unavailableUnderZeroMode
        ? 'Unavailable under Zero Mode · path Gateway reserved · no owned zone or Tunnel created'
        : 'Reviewed outbound connector · exact deployment routes · Cloudflare TLS',
      state: findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high')
        ? 'failed'
        : findings.length > 0
          ? 'review'
          : 'passed',
    },
    findings,
  };
}

function checkWorkflows(snapshot: ShieldSnapshot): {
  check: ShieldCheck;
  findings: ShieldFinding[];
} {
  const state = snapshot.workflows;
  const findings: ShieldFinding[] = [];
  if (!state) {
    return {
      check: {
        id: 'workflows', name: 'YSD Workflows',
        detail: 'No workflow security state was present in this snapshot', state: 'passed',
      },
      findings,
    };
  }
  const add = (
    count: number,
    code: string,
    title: string,
    detail: string,
    severity: Severity,
    remediation: string,
  ) => {
    if (count <= 0) return;
    findings.push({ code, title, detail, resource: 'workflows/security', severity, remediation });
  };
  add(state.privilegedLowOwner, 'workflow-privileged-low-owner', 'Privileged workflow has a low-privilege owner', `${state.privilegedLowOwner} workflow configuration${state.privilegedLowOwner === 1 ? '' : 's'} require an owner/admin review.`, 'critical', 'Pause the workflow and republish it through an owner or admin after reviewing every privileged action.');
  add(state.excessiveRetry, 'workflow-excessive-retry', 'Workflow retry policy is excessive', `${state.excessiveRetry} workflow${state.excessiveRetry === 1 ? '' : 's'} exceed the bounded retry policy.`, 'high', 'Lower attempts and backoff to the Zero Mode limits before publishing.');
  add(state.potentialCycles, 'workflow-potential-cycle', 'A workflow event cycle is possible', `${state.potentialCycles} workflow${state.potentialCycles === 1 ? '' : 's'} may re-trigger their own event chain.`, 'critical', 'Remove the cyclic action or keep the workflow paused; causation and chain-depth guards are a final safety net, not a design tool.');
  add(state.noTimeout, 'workflow-timeout-policy', 'Workflow timeout policy is missing or unsafe', `${state.noTimeout} workflow${state.noTimeout === 1 ? '' : 's'} have an invalid timeout.`, 'high', 'Set a bounded timeout between 5 and 300 seconds.');
  add(state.highConcurrency, 'workflow-concurrency-policy', 'Workflow concurrency is too high', `${state.highConcurrency} workflow${state.highConcurrency === 1 ? '' : 's'} exceed the Worker/D1 concurrency ceiling.`, 'high', 'Reduce workflow and workspace concurrency before resuming automation.');
  add(state.stale, 'workflow-stale', 'Stale workflows need review', `${state.stale} workflow${state.stale === 1 ? '' : 's'} have not been maintained for 90 days.`, 'low', 'Pause or archive abandoned workflows and confirm resource references for the rest.');
  add(state.repeatedFailures, 'workflow-repeated-failures', 'Workflows are failing repeatedly', `${state.repeatedFailures} workflow${state.repeatedFailures === 1 ? '' : 's'} reached the repeated-failure threshold.`, 'high', 'Review the dead-letter execution, fix the bounded action, and retry manually only after the cause is resolved.');
  add(state.suspiciousVolume, 'workflow-suspicious-volume', 'Suspicious workflow trigger volume was recorded', `${state.suspiciousVolume} event${state.suspiciousVolume === 1 ? '' : 's'} exceeded the hourly safety threshold.`, 'high', 'Pause noisy workflows and inspect their correlation and causation identifiers.');
  add(state.orphanReferences, 'workflow-orphan-reference', 'A workflow resource reference is orphaned', `${state.orphanReferences} active workflow${state.orphanReferences === 1 ? '' : 's'} reference a missing immutable version or resource.`, 'critical', 'Pause the workflow and restore a same-tenant immutable version or archive it.');
  add(state.crossOrgAttempts, 'workflow-cross-org-attempt', 'A cross-tenant workflow reference was blocked', `${state.crossOrgAttempts} forged or cross-scope event attempt${state.crossOrgAttempts === 1 ? ' was' : 's were'} recorded.`, 'critical', 'Inspect the actor and correlation chain; keep all workflow and resource identifiers server-derived.');
  add(state.secretExposure, 'workflow-secret-exposure', 'Workflow configuration attempted to expose a secret', `${state.secretExposure} secret or sensitive-payload attempt${state.secretExposure === 1 ? ' was' : 's were'} rejected.`, 'critical', 'Keep secret values in the existing write-only store and expose only non-sensitive metadata to workflows.');
  add(state.zeroModeBypass, 'workflow-zero-mode-bypass', 'A workflow attempted to bypass Zero Mode', `${state.zeroModeBypass} paid-provider or Zero Mode override attempt${state.zeroModeBypass === 1 ? ' was' : 's were'} rejected.`, 'critical', 'Keep the workflow on the existing Worker and D1; remove every provider, billing, URL, or zeroMode override field.');
  return {
    check: {
      id: 'workflows', name: 'YSD Workflows',
      detail: 'Immutable versions · D1 leases · bounded retries · trusted events · Zero Mode actions',
      state: findings.some((finding) => finding.severity === 'critical' || finding.severity === 'high')
        ? 'failed'
        : findings.length > 0 ? 'review' : 'passed',
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
    checkCollaboration(snapshot),
    checkDatabase(snapshot),
    checkStorage(snapshot),
    checkNodes(snapshot),
    checkAiCompute(snapshot),
    checkGameServers(snapshot),
    checkAppRuntime(snapshot),
    checkPublicExposure(snapshot),
    checkWorkflows(snapshot),
    checkSurface(snapshot),
    checkHardening(snapshot),
  ];

  const checks = results.map((result) => result.check);
  const findings = results.flatMap((result) => result.findings);

  const penalty = findings.reduce(
    (total, finding) => total + SEVERITY_WEIGHT[finding.severity],
    0,
  );
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

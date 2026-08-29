import { createId } from '@/lib/crypto';
import { getIntegrationCatalog } from '@/lib/integrations';
import { runtimeEnv } from './env';
import {
  runShieldRules,
  type ShieldFinding,
  type ShieldReport,
  type ShieldSnapshot,
} from '@/lib/shield';
import { count, execute, query, queryOne } from './db';
import { emailVerificationRequired } from './auth';
import { countBillableResources } from './deployments';
import { emailVerificationStatus, isEmailConfigured } from './email';
import { pruneRateLimits } from './rate-limit';
import { countByRole, countOwners, countSuspended } from './roles';
import {
  countFailingNetworks,
  countRecentBlocks,
  pruneAttempts,
} from './security';
import { turnstileConfigured } from './turnstile';
import { can } from '@/lib/roles';
import { configuredSecurityHeaders } from '@/lib/security-headers';
import { DENY_ALL, isSchemaOnlyTable, scopeForTable } from '@/lib/tenancy';
import { listTableColumns } from './studio';
import { writeLog } from './logs';
import { secretsForShield } from './secrets';
import { listTables } from './studio';
import { getWorkspace } from './workspace';
import { STORAGE_LIMITS } from '@/lib/storage';
import { readNetworkState } from './networking';
import { storageShieldState } from './storage';

/**
 * YSD Shield: gathering the snapshot and persisting the result.
 *
 * The rules themselves live in `lib/shield.ts` and are pure. This module only
 * reads the workspace, hands the snapshot over, and reconciles the findings
 * against what a previous scan already recorded so an operator sees an issue
 * age rather than reappear as new every time.
 */

export type StoredFinding = ShieldFinding & {
  id: string;
  status: 'open' | 'resolved';
  firstSeenAt: number;
  lastSeenAt: number;
};

export type ScanRecord = {
  id: string;
  score: number;
  grade: ShieldReport['grade'];
  headline: string;
  findingCount: number;
  durationMs: number;
  createdAt: number;
};

async function collectSnapshot(
  workspaceId: string,
  userId: string,
): Promise<ShieldSnapshot> {
  const workspace = await getWorkspace(workspaceId);
  const now = Date.now();
  const emailStatus = emailVerificationStatus();

  const [
    secrets,
    tables,
    billableResources,
    users,
    unverified,
    sessions,
    expiredSessions,
    publicProjects,
    owners,
    admins,
    suspended,
    unverifiedPrivileged,
    recentBlocks,
    failingNetworks,
    orphanRoles,
    suspendedPrivileged,
    columnsByTable,
    storage,
  ] = await Promise.all([
    secretsForShield(workspaceId),
    listTables({ workspaceId, userId }),
    countBillableResources(workspaceId),
    count('SELECT COUNT(*) AS total FROM "user"'),
    count('SELECT COUNT(*) AS total FROM "user" WHERE emailVerified = 0'),
    count('SELECT COUNT(*) AS total FROM "session"'),
    countExpiredSessions(now),
    query<{ name: string }>(
      "SELECT name FROM project WHERE workspaceId = ? AND visibility = 'public'",
      workspaceId,
    ),
    countOwners(),
    countByRole('admin'),
    countSuspended(),
    count(
      `SELECT COUNT(*) AS total FROM user_role r
         JOIN "user" u ON u.id = r.userId
         WHERE r.role IN ('owner', 'admin') AND u.emailVerified = 0`,
    ),
    countRecentBlocks(),
    countFailingNetworks(),
    count(
      `SELECT COUNT(*) AS total FROM user_role r
         LEFT JOIN "user" u ON u.id = r.userId
         WHERE u.id IS NULL`,
    ),
    count(
      `SELECT COUNT(*) AS total FROM user_role
         WHERE role IN ('owner','admin') AND suspendedAt IS NOT NULL`,
    ),
    listTableColumns(),
    storageShieldState(workspaceId),
  ]);

  const network = readNetworkState();

  return {
    zeroModeEnabled: workspace?.zeroMode ?? true,
    protections: {
      turnstileConfigured: turnstileConfigured(),
      emailProviderConfigured: isEmailConfigured(),
      emailVerificationRequired: emailVerificationRequired(),
      emailVerificationState: emailStatus.state,
      // Enabled unconditionally in `lib/server/auth-options.ts`; reported so a
      // future change that switches it off cannot pass unnoticed.
      rateLimitEnabled: true,
      recentBlocks,
      failingNetworks,
      owners,
      admins,
      suspended,
      unverifiedPrivileged,
      // Read from the module that produces the headers rather than from a
      // request: a Worker fetching its own origin is not routed back through
      // middleware and cannot observe them. Delivery is proven from outside by
      // security-acceptance.py.
      securityHeaders: { ...configuredSecurityHeaders(), observed: true },
      orphanRoles,
      suspendedPrivileged,
      // Any table holding rows that the scoping rules do not classify would be
      // hidden in Studio rather than scoped, which is worth surfacing.
      unscopedTables: tables
        .filter((table) => !isSchemaOnlyTable(table.name) && table.rows > 0)
        .filter(
          (table) =>
            scopeForTable(table.name, columnsByTable[table.name] ?? [], {
              workspaceId: 'probe',
              userId: 'probe',
            }).sql === DENY_ALL.sql,
        )
        .map((table) => table.name),
      // A live assertion that an admin still cannot reach the SQL Editor, so
      // removing that gate shows up here as a critical finding.
      sqlEditorRestricted: !can(
        { userId: 'probe', role: 'admin', suspended: false },
        'sql-editor.run',
      ),
    },
    billableResources,
    secrets,
    users: { total: users, unverified },
    sessions: { total: sessions, expired: expiredSessions },
    tables: tables
      .filter((table) => table.name !== 'ysd_migration')
      .map((table) => ({
        name: table.name,
        hasPrimaryKey: table.hasPrimaryKey,
        rows: table.rows,
      })),
    integrations: getIntegrationCatalog(runtimeEnv).map((entry) => ({
      id: entry.id,
      status:
        entry.status === 'configured' || entry.status === 'bound'
          ? 'configured'
          : 'mock',
    })),
    publicProjects: publicProjects.map((row) => row.name),
    storage: {
      available: storage.available,
      private: storage.private,
      bytesUsed: storage.usage.bytesUsed,
      limitBytes: STORAGE_LIMITS.workspaceBytes,
      objectCount: storage.usage.objectCount,
    },
    network: {
      tls: network.tls,
      customDomains: network.customDomains,
      tunnels: network.tunnels,
      publicStorageEndpoints: network.publicStorageEndpoints,
    },
    now,
  };
}

/**
 * Counts sessions whose expiry has passed.
 *
 * Better Auth's SQLite dialect writes `expiresAt` as an ISO 8601 string, which
 * compares correctly against another ISO string but not against epoch
 * milliseconds — casting the text to an integer yields the leading year and
 * makes every live session look expired. The comparison is therefore chosen by
 * the stored type, so the count stays right if that storage ever changes.
 */
async function countExpiredSessions(now: number): Promise<number> {
  try {
    return await count(
      `SELECT COUNT(*) AS total FROM "session"
       WHERE (typeof(expiresAt) = 'text' AND expiresAt < ?)
          OR (typeof(expiresAt) IN ('integer', 'real') AND expiresAt < ?)`,
      new Date(now).toISOString(),
      now,
    );
  } catch {
    return 0;
  }
}

async function reconcileFindings(
  workspaceId: string,
  findings: ShieldFinding[],
  now: number,
): Promise<void> {
  const codes = new Set(findings.map((finding) => finding.code));

  for (const finding of findings) {
    const existing = await queryOne<{ id: string; firstSeenAt: number }>(
      'SELECT id, firstSeenAt FROM shield_finding WHERE workspaceId = ? AND code = ?',
      workspaceId,
      finding.code,
    );

    if (existing) {
      await execute(
        `UPDATE shield_finding
         SET title = ?, detail = ?, resource = ?, severity = ?, remediation = ?, status = 'open', lastSeenAt = ?
         WHERE id = ?`,
        finding.title,
        finding.detail,
        finding.resource,
        finding.severity,
        finding.remediation,
        now,
        existing.id,
      );
      continue;
    }

    await execute(
      `INSERT INTO shield_finding (id, workspaceId, code, title, detail, resource, severity, remediation, status, firstSeenAt, lastSeenAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
      createId('fnd'),
      workspaceId,
      finding.code,
      finding.title,
      finding.detail,
      finding.resource,
      finding.severity,
      finding.remediation,
      now,
      now,
    );
  }

  // Anything the rules no longer report has been fixed. It stays in the table
  // as history rather than disappearing.
  const open = await query<{ id: string; code: string }>(
    "SELECT id, code FROM shield_finding WHERE workspaceId = ? AND status = 'open'",
    workspaceId,
  );
  for (const row of open) {
    if (codes.has(row.code)) continue;
    await execute(
      "UPDATE shield_finding SET status = 'resolved', lastSeenAt = ? WHERE id = ?",
      now,
      row.id,
    );
  }
}

export type ScanOutcome = ShieldReport & { scan: ScanRecord };

export async function runScan(
  workspaceId: string,
  userId: string,
  actor: string,
): Promise<ScanOutcome> {
  const startedAt = Date.now();
  const snapshot = await collectSnapshot(workspaceId, userId);
  const report = runShieldRules(snapshot);

  // The scan is the one regular sweep this app has, so it doubles as the
  // moment stale counters and expired attempt rows are cleared.
  await Promise.all([pruneRateLimits(), pruneAttempts()]);
  const now = Date.now();

  await reconcileFindings(workspaceId, report.findings, now);

  const scan: ScanRecord = {
    id: createId('scan'),
    score: report.score,
    grade: report.grade,
    headline: report.headline,
    findingCount: report.findings.length,
    durationMs: now - startedAt,
    createdAt: now,
  };

  await execute(
    `INSERT INTO shield_scan (id, workspaceId, score, grade, headline, checks, findingCount, durationMs, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    scan.id,
    workspaceId,
    scan.score,
    scan.grade,
    scan.headline,
    JSON.stringify(report.checks),
    scan.findingCount,
    scan.durationMs,
    scan.createdAt,
  );

  await writeLog({
    workspaceId,
    level: report.findings.length === 0 ? 'INFO' : 'WARN',
    source: 'shield',
    message: `Scan complete · score ${report.score} · ${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}`,
    actor,
    resource: scan.id,
  });

  return { ...report, scan };
}

export type ShieldState = {
  scan: ScanRecord | null;
  checks: ShieldReport['checks'];
  findings: StoredFinding[];
};

/** The last recorded scan, for rendering the Shield page without re-scanning. */
export async function readShieldState(
  workspaceId: string,
): Promise<ShieldState> {
  const row = await queryOne<{
    id: string;
    score: number;
    grade: ShieldReport['grade'];
    headline: string;
    checks: string;
    findingCount: number;
    durationMs: number;
    createdAt: number;
  }>(
    'SELECT * FROM shield_scan WHERE workspaceId = ? ORDER BY createdAt DESC LIMIT 1',
    workspaceId,
  );

  const findings = await query<StoredFinding>(
    `SELECT id, code, title, detail, resource, severity, remediation, status, firstSeenAt, lastSeenAt
     FROM shield_finding WHERE workspaceId = ? ORDER BY status ASC, lastSeenAt DESC`,
    workspaceId,
  );

  if (!row) return { scan: null, checks: [], findings };

  return {
    scan: {
      id: row.id,
      score: row.score,
      grade: row.grade,
      headline: row.headline,
      findingCount: row.findingCount,
      durationMs: row.durationMs,
      createdAt: row.createdAt,
    },
    checks: JSON.parse(row.checks) as ShieldReport['checks'],
    findings,
  };
}

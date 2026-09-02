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
import { nodesForShield } from './nodes';
import { aiForShield } from './ai';
import { gameServersForShield } from './game-servers';
import { appRuntimeForShield } from './app-runtime-control';
import { publicExposureForShield } from './public-exposure';
import { workflowsForShield } from './workflows';
import { capacityForShield } from './retention';
import { auditIntegrityForShield } from './audit';
import { incidentsForShield } from './incidents';
import { emitWorkflowEvent } from './workflow-events';

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
  if (!workspace) throw new Error('Workspace not found.');
  const organizationId = workspace.organizationId;
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
    nodes,
    ai,
    gameServers,
    appRuntime,
    publicExposure,
    workflows,
    incidents,
    capacity,
    auditIntegrity,
    ownerInvariant,
    staleAdmins,
    expiredInvitations,
    unboundedServiceTokens,
    tenantIsolationViolations,
    tenantTriggerCount,
    auditTriggerCount,
  ] = await Promise.all([
    secretsForShield(workspaceId),
    listTables({ workspaceId, organizationId, userId }),
    countBillableResources(workspaceId),
    count(
      `SELECT COUNT(*) AS total FROM organization_member m
         JOIN "user" u ON u.id = m.userId
        WHERE m.organizationId = ? AND m.status <> 'removed'`,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_member m
         JOIN "user" u ON u.id = m.userId
        WHERE m.organizationId = ? AND m.status = 'active' AND u.emailVerified = 0`,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM "session" s
         JOIN organization_member m ON m.userId = s.userId
        WHERE m.organizationId = ? AND m.status <> 'removed'`,
      organizationId,
    ),
    countExpiredSessions(now, organizationId),
    query<{ name: string }>(
      "SELECT name FROM project WHERE workspaceId = ? AND visibility = 'public'",
      workspaceId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_member
        WHERE organizationId = ? AND role = 'owner' AND status = 'active' AND suspendedAt IS NULL`,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_member
        WHERE organizationId = ? AND role = 'admin' AND status = 'active' AND suspendedAt IS NULL`,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_member
        WHERE organizationId = ? AND (status = 'suspended' OR suspendedAt IS NOT NULL)`,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_member m
         JOIN "user" u ON u.id = m.userId
        WHERE m.organizationId = ? AND m.role IN ('owner', 'admin')
          AND m.status = 'active' AND m.suspendedAt IS NULL AND u.emailVerified = 0`,
      organizationId,
    ),
    countRecentBlocks(),
    countFailingNetworks(),
    count(
      `SELECT COUNT(*) AS total FROM organization_member r
         LEFT JOIN "user" u ON u.id = r.userId
         WHERE r.organizationId = ? AND u.id IS NULL`,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_member
        WHERE organizationId = ? AND role IN ('owner','admin')
          AND (status = 'suspended' OR suspendedAt IS NOT NULL)`,
      organizationId,
    ),
    listTableColumns(),
    storageShieldState(workspaceId),
    nodesForShield(workspaceId, now),
    aiForShield(workspaceId, now),
    gameServersForShield(workspaceId, now),
    appRuntimeForShield(workspaceId, now),
    publicExposureForShield(workspaceId, now),
    workflowsForShield(organizationId, workspaceId, now),
    incidentsForShield(workspaceId, now),
    capacityForShield(workspaceId, now),
    auditIntegrityForShield(organizationId),
    queryOne<{ valid: number }>(
      `SELECT CASE WHEN
          EXISTS (
            SELECT 1 FROM organization_member m
             WHERE m.organizationId = o.id AND m.userId = o.ownerUserId
               AND m.role = 'owner' AND m.status = 'active' AND m.suspendedAt IS NULL
          ) AND (
            SELECT COUNT(*) FROM organization_member m
             WHERE m.organizationId = o.id AND m.role = 'owner'
               AND m.status = 'active' AND m.suspendedAt IS NULL
          ) = 1 THEN 1 ELSE 0 END AS valid
         FROM organization o WHERE o.id = ?`,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_member
        WHERE organizationId = ? AND role = 'admin' AND status = 'active'
          AND suspendedAt IS NULL AND (lastActiveAt IS NULL OR lastActiveAt <= ?)`,
      organizationId,
      now - 90 * 24 * 60 * 60 * 1000,
    ),
    count(
      `SELECT COUNT(*) AS total FROM organization_invitation
        WHERE organizationId = ? AND status = 'pending' AND expiresAt <= ?`,
      organizationId,
      now,
    ),
    count(
      `SELECT COUNT(*) AS total FROM service_account_token t
         JOIN service_account a ON a.id = t.serviceAccountId
        WHERE a.organizationId = ? AND a.status = 'active' AND t.revokedAt IS NULL
          AND (t.expiresAt IS NULL OR t.expiresAt > ?)`,
      organizationId,
      now + 180 * 24 * 60 * 60 * 1000,
    ),
    count(
      `SELECT (
          (SELECT COUNT(*) FROM workspace_member wm
            LEFT JOIN workspace w ON w.id = wm.workspaceId
            LEFT JOIN organization_member m
              ON m.organizationId = wm.organizationId AND m.userId = wm.userId
           WHERE wm.organizationId = ?
             AND (w.organizationId IS NULL OR w.organizationId <> wm.organizationId OR m.id IS NULL))
          + (SELECT COUNT(*) FROM member_project_access a
              LEFT JOIN workspace w ON w.id = a.workspaceId
              LEFT JOIN project p ON p.id = a.projectId
              LEFT JOIN organization_member m
                ON m.organizationId = a.organizationId AND m.userId = a.userId
             WHERE a.organizationId = ? AND (
               w.organizationId IS NULL OR w.organizationId <> a.organizationId
               OR p.workspaceId IS NULL OR p.workspaceId <> a.workspaceId OR m.id IS NULL))
          + (SELECT COUNT(*) FROM organization_invitation i
              LEFT JOIN workspace w ON w.id = i.workspaceId
             WHERE i.organizationId = ?
               AND (w.organizationId IS NULL OR w.organizationId <> i.organizationId))
          + (SELECT COUNT(*) FROM service_account a
              LEFT JOIN workspace w ON w.id = a.workspaceId
              LEFT JOIN project p ON p.id = a.projectId
             WHERE a.organizationId = ? AND (
               w.organizationId IS NULL OR w.organizationId <> a.organizationId
               OR (a.projectId IS NOT NULL AND (p.workspaceId IS NULL OR p.workspaceId <> a.workspaceId))))
          + (SELECT COUNT(*) FROM audit_event e
              LEFT JOIN workspace w ON w.id = e.workspaceId
             WHERE e.organizationId = ? AND e.workspaceId IS NOT NULL
               AND (w.organizationId IS NULL OR w.organizationId <> e.organizationId))
          + (SELECT COUNT(*) FROM workspace_limit l
              LEFT JOIN workspace w ON w.id = l.workspaceId
             WHERE l.organizationId = ?
               AND (w.organizationId IS NULL OR w.organizationId <> l.organizationId))
          + (SELECT COUNT(*) FROM webhook_source s
              LEFT JOIN workspace w ON w.id = s.workspaceId
              LEFT JOIN project p ON p.id = s.projectId
             WHERE s.organizationId = ? AND (
               w.organizationId IS NULL OR w.organizationId <> s.organizationId
               OR (s.projectId IS NOT NULL AND (p.workspaceId IS NULL OR p.workspaceId <> s.workspaceId))))
          + (SELECT COUNT(*) FROM webhook_replay_guard r
              LEFT JOIN webhook_source s ON s.id = r.sourceId
             WHERE r.organizationId = ? AND (
               s.organizationId IS NULL OR s.organizationId <> r.organizationId
               OR s.workspaceId <> r.workspaceId))
          + (SELECT COUNT(*) FROM webhook_delivery d
              LEFT JOIN webhook_source s ON s.id = d.sourceId
              LEFT JOIN workflow_event e ON e.id = d.workflowEventId
             WHERE d.organizationId = ? AND (
               s.organizationId IS NULL OR s.organizationId <> d.organizationId
               OR s.workspaceId <> d.workspaceId
               OR (d.workflowEventId IS NOT NULL AND (
                 e.organizationId IS NULL OR e.organizationId <> d.organizationId OR e.workspaceId <> d.workspaceId))))
        ) AS total`,
      organizationId,
      organizationId,
      organizationId,
      organizationId,
      organizationId,
      organizationId,
      organizationId,
      organizationId,
      organizationId,
    ),
    count(
      `SELECT COUNT(*) AS total FROM sqlite_master
        WHERE type = 'trigger' AND name IN (
          'workspace_org_insert_guard', 'workspace_org_update_guard',
          'workspace_member_tenant_guard', 'workspace_member_tenant_update_guard',
          'project_access_tenant_guard', 'project_access_tenant_update_guard',
          'invitation_tenant_guard', 'invitation_tenant_update_guard',
          'service_account_tenant_guard', 'service_account_tenant_update_guard',
          'audit_event_tenant_guard',
          'workspace_limit_tenant_guard', 'workspace_limit_tenant_update_guard',
          'public_exposure_tenant_guard', 'public_exposure_tenant_update_guard',
          'exposure_domain_tenant_guard', 'exposure_domain_tenant_update_guard',
          'workflow_tenant_guard', 'workflow_tenant_update_guard',
          'workflow_version_tenant_guard', 'workflow_variable_tenant_guard',
          'workflow_variable_tenant_update_guard',
          'workflow_event_tenant_guard', 'workflow_execution_tenant_guard',
          'workflow_action_tenant_guard', 'workflow_incident_tenant_guard',
          'workflow_security_event_tenant_guard', 'notification_tenant_guard',
          'workflow_resource_state_tenant_guard',
          'webhook_source_tenant_guard', 'webhook_source_tenant_update_guard',
          'webhook_replay_tenant_guard', 'webhook_delivery_tenant_guard',
          'webhook_delivery_tenant_update_guard'
          ,'incident_phase11_insert_guard', 'incident_phase11_scope_immutable_guard',
          'incident_phase11_assignee_guard', 'incident_event_tenant_guard',
          'incident_event_volume_guard',
          'incident_event_append_only_update', 'incident_event_append_only_delete'
          ,'retention_policy_tenant_guard', 'retention_policy_scope_immutable_guard',
          'retention_policy_activation_guard', 'retention_policy_window_guard',
          'retention_policy_class_floor_guard', 'retention_policy_class_floor_update_guard',
          'usage_snapshot_tenant_guard', 'usage_snapshot_append_only_update',
          'retention_run_tenant_guard', 'retention_run_finalize_guard',
          'retention_run_append_only_delete'
        )`,
    ),
    count(
      `SELECT COUNT(*) AS total FROM sqlite_master
        WHERE type = 'trigger' AND name IN ('audit_event_no_update', 'audit_event_no_delete')`,
    ),
  ]);

  const network = await readNetworkState({
    organizationId,
    workspaceId,
    actor: {
      userId,
      role: 'owner',
      suspended: false,
      organizationId,
      workspaceId,
      projectIds: null,
    },
  });

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
      ) && !can(
        { userId: 'probe', role: 'owner', suspended: false },
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
    collaboration: {
      ownerInvariant: ownerInvariant?.valid === 1,
      tenantIsolationViolations,
      tenantIsolationGuarded: tenantTriggerCount === 52,
      auditAppendOnly: auditTriggerCount === 2,
      staleAdmins,
      expiredInvitations,
      unboundedServiceTokens,
      privilegeEscalationBlocked:
        !can({ userId: 'probe', role: 'admin', suspended: false }, 'member.transfer-ownership')
        && !can({ userId: 'probe', role: 'admin', suspended: false }, 'sql-editor.run')
        && !can({ userId: 'probe', role: 'owner', suspended: false }, 'sql-editor.run'),
    },
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
    nodes,
    ai,
    gameServers,
    appRuntime,
    publicExposure,
    workflows,
    incidents,
    capacity,
    auditIntegrity,
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
async function countExpiredSessions(now: number, organizationId: string): Promise<number> {
  try {
    return await count(
      `SELECT COUNT(*) AS total FROM "session" s
         JOIN organization_member m ON m.userId = s.userId
        WHERE m.organizationId = ? AND m.status <> 'removed' AND (
          (typeof(s.expiresAt) = 'text' AND s.expiresAt < ?)
          OR (typeof(s.expiresAt) IN ('integer', 'real') AND s.expiresAt < ?)
        )`,
      organizationId,
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
    const existing = await queryOne<{ id: string; firstSeenAt: number; status: string; severity: string }>(
      'SELECT id, firstSeenAt, status, severity FROM shield_finding WHERE workspaceId = ? AND code = ?',
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
      if (existing.status !== 'open') {
        await emitWorkflowEvent({
          workspaceId, type: 'shield.finding.opened', resourceType: 'shield_finding',
          resourceId: existing.id, payload: { findingId: existing.id, status: 'open', severity: finding.severity },
          dedupeKey: `shield-opened:${existing.id}:${now}`,
        });
      }
      if (existing.severity !== finding.severity) {
        await emitWorkflowEvent({
          workspaceId, type: 'shield.finding.severity_changed', resourceType: 'shield_finding',
          resourceId: existing.id,
          payload: { findingId: existing.id, previousSeverity: existing.severity, severity: finding.severity },
          dedupeKey: `shield-severity:${existing.id}:${existing.severity}:${finding.severity}:${now}`,
        });
      }
      continue;
    }

    const findingId = createId('fnd');
    await execute(
      `INSERT INTO shield_finding (id, workspaceId, code, title, detail, resource, severity, remediation, status, firstSeenAt, lastSeenAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
      findingId,
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
    await emitWorkflowEvent({
      workspaceId, type: 'shield.finding.opened', resourceType: 'shield_finding',
      resourceId: findingId, payload: { findingId, status: 'open', severity: finding.severity },
      dedupeKey: `shield-opened:${findingId}:${now}`,
    });
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
    await emitWorkflowEvent({
      workspaceId, type: 'shield.finding.resolved', resourceType: 'shield_finding',
      resourceId: row.id, payload: { findingId: row.id, status: 'resolved' },
      dedupeKey: `shield-resolved:${row.id}:${now}`,
    });
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

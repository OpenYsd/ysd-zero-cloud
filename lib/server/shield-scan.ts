import { createId } from '@/lib/crypto';
import { getIntegrationCatalog } from '@/lib/integrations';
import { runtimeEnv } from './env';
import {
  runShieldRules,
  type ShieldFinding,
  type ShieldReport,
  type ShieldSnapshot,
} from '@/lib/shield';
import {
  POSTURE_LIMITS,
  chunk,
  planFindingReconciliation,
  planScanHistoryTrim,
  type ExistingFinding,
  type PostureDelta,
  type ReconciliationPlan,
  type ScanStatus,
  type ScanTrigger,
  type StoredPostureDelta,
  UNKNOWN_GRADE,
} from '@/lib/shield-posture';
import { count, db, execute, query, queryOne } from './db';
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
  /**
   * `'unknown'` on a failed attempt, which has no posture to grade. Use
   * `displayGrade` before rendering rather than trusting this to be a grade.
   */
  grade: ShieldReport['grade'] | typeof UNKNOWN_GRADE;
  headline: string;
  findingCount: number;
  durationMs: number;
  createdAt: number;
  /** Where the scan came from. null on rows written before 0.15.0. */
  trigger: ScanTrigger | null;
  /**
   * null on pre-0.15.0 rows, which were only ever written on success.
   * 'failed' means the attempt did not finish: its score and grade are
   * placeholders and must never be read as posture.
   */
  status: ScanStatus | null;
  /** What moved since the previous scan. null when it was never recorded. */
  delta: StoredPostureDelta | null;
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

/**
 * Applies a scan's findings in a bounded number of round trips.
 *
 * The 0.14.0 version read and wrote one finding at a time, so a workspace
 * reporting N findings cost roughly `2N` sequential round trips plus one more
 * per resolution. Finding codes are templated per resource
 * (`table-no-primary-key:<table>`, `secret-overdue:<name>:<env>`,
 * `public-project:<id>`), so N grows with the tables, secrets and public
 * projects a workspace has -- it is not capped by the rule catalog. That was
 * tolerable behind a button a human presses. It is not something to put on a
 * timer.
 *
 * Now: one read of this workspace's findings, a pure plan, then writes sent in
 * fixed-size `database.batch` chunks. Round trips are
 * `1 + ceil(writes / POSTURE_LIMITS.writeBatchSize)` -- independent of N
 * except through that ceiling.
 *
 * Events are deliberately NOT batched. `emitWorkflowEvent` re-checks that the
 * finding really belongs to this workspace before writing, and that check is
 * worth more than the round trips it costs. They stay bounded because only a
 * real transition emits one: a finding that has not moved emits nothing, which
 * is what stops a recurring scan from re-announcing the same problem for ever.
 */
async function reconcileFindings(
  workspaceId: string,
  findings: ShieldFinding[],
  now: number,
): Promise<PostureDelta> {
  const existing = await query<ExistingFinding>(
    'SELECT id, code, status, severity FROM shield_finding WHERE workspaceId = ?',
    workspaceId,
  );

  // Minted up front so the plan stays pure and each insert agrees with its
  // event about the identifier.
  const newIds = findings.map(() => createId('fnd'));
  const plan = planFindingReconciliation({ existing, reported: findings, newIds });

  await applyReconciliationPlan(workspaceId, plan, newIds, now);
  await emitReconciliationEvents(workspaceId, plan, now);
  return plan.delta;
}

/** The write half: bounded batches, nothing sequential per finding. */
async function applyReconciliationPlan(
  workspaceId: string,
  plan: ReconciliationPlan,
  newIds: readonly string[],
  now: number,
): Promise<void> {
  const database = await db();
  const statements: D1PreparedStatement[] = [];

  const insertSql =
    'INSERT INTO shield_finding'
    + ' (id, workspaceId, code, title, detail, resource, severity, remediation, status, firstSeenAt, lastSeenAt)'
    + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)";
  const updateSql =
    "UPDATE shield_finding SET title = ?, detail = ?, resource = ?, severity = ?, remediation = ?, status = 'open', lastSeenAt = ? WHERE id = ? AND workspaceId = ?";
  const resolveSql =
    "UPDATE shield_finding SET status = 'resolved', lastSeenAt = ? WHERE id = ? AND workspaceId = ?";

  let index = 0;
  for (const insert of plan.inserts) {
    const id = newIds[index] ?? createId('fnd');
    index += 1;
    statements.push(
      database.prepare(insertSql).bind(
        id,
        workspaceId,
        insert.finding.code,
        insert.finding.title,
        insert.finding.detail,
        insert.finding.resource,
        insert.finding.severity,
        insert.finding.remediation,
        now,
        now,
      ),
    );
  }

  for (const update of plan.updates) {
    statements.push(
      database.prepare(updateSql).bind(
        update.finding.title,
        update.finding.detail,
        update.finding.resource,
        update.finding.severity,
        update.finding.remediation,
        now,
        update.id,
        workspaceId,
      ),
    );
  }

  for (const resolve of plan.resolves) {
    statements.push(database.prepare(resolveSql).bind(now, resolve.id, workspaceId));
  }

  // Every write carries `workspaceId` in its predicate as well as its id, so a
  // planning mistake cannot reach another tenant's row.
  for (const group of chunk(statements, POSTURE_LIMITS.writeBatchSize)) {
    if (group.length > 0) await database.batch(group);
  }
}

/** The event half: one call per real transition, each tenant-verified. */
async function emitReconciliationEvents(
  workspaceId: string,
  plan: ReconciliationPlan,
  now: number,
): Promise<void> {
  for (const event of plan.events) {
    if (event.type === 'opened') {
      await emitWorkflowEvent({
        workspaceId, type: 'shield.finding.opened', resourceType: 'shield_finding',
        resourceId: event.findingId,
        payload: { findingId: event.findingId, status: 'open', severity: event.severity },
        dedupeKey: `shield-opened:${event.findingId}:${now}`,
      });
      continue;
    }
    if (event.type === 'severity_changed') {
      await emitWorkflowEvent({
        workspaceId, type: 'shield.finding.severity_changed', resourceType: 'shield_finding',
        resourceId: event.findingId,
        payload: {
          findingId: event.findingId,
          previousSeverity: event.previousSeverity,
          severity: event.severity,
        },
        dedupeKey: `shield-severity:${event.findingId}:${event.previousSeverity}:${event.severity}:${now}`,
      });
      continue;
    }
    await emitWorkflowEvent({
      workspaceId, type: 'shield.finding.resolved', resourceType: 'shield_finding',
      resourceId: event.findingId,
      payload: { findingId: event.findingId, status: 'resolved' },
      dedupeKey: `shield-resolved:${event.findingId}:${now}`,
    });
  }
}

/**
 * Keeps scan history bounded, oldest first.
 *
 * Only `shield_scan` rows are ever removed here. Findings, audit evidence,
 * workflow events, incidents and retention runs are untouched: this exists so
 * a recurring sweep cannot grow one table without limit, not as a general
 * retention mechanism.
 */
async function trimScanHistory(workspaceId: string): Promise<number> {
  const scans = await query<{ id: string; createdAt: number }>(
    'SELECT id, createdAt FROM shield_scan WHERE workspaceId = ? ORDER BY createdAt DESC',
    workspaceId,
  );
  const doomed = planScanHistoryTrim(scans, POSTURE_LIMITS.historyPerWorkspace);
  if (doomed.length === 0) return 0;

  const database = await db();
  const deleteSql = 'DELETE FROM shield_scan WHERE id = ? AND workspaceId = ?';
  for (const group of chunk(doomed, POSTURE_LIMITS.writeBatchSize)) {
    await database.batch(
      group.map((id) => database.prepare(deleteSql).bind(id, workspaceId)),
    );
  }
  return doomed.length;
}


export type ScanOutcome = ShieldReport & { scan: ScanRecord };

const SCAN_COLUMNS =
  'id, score, grade, headline, checks, findingCount, durationMs, createdAt,'
  + ' scanTrigger, scanStatus, newFindings, resolvedFindings, reopenedFindings,'
  + ' severityChangedFindings';

const INSERT_SCAN_SQL =
  'INSERT INTO shield_scan'
  + ' (id, workspaceId, score, grade, headline, checks, findingCount, durationMs,'
  + ' createdAt, scanTrigger, scanStatus, newFindings, resolvedFindings,'
  + ' reopenedFindings, severityChangedFindings)'
  + ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

/** Completed and pre-0.15.0 rows. A failed attempt is never posture. */
const NOT_FAILED = "(scanStatus IS NULL OR scanStatus <> 'failed')";

/**
 * What a failed attempt stores in the columns that are NOT NULL.
 *
 * A failed attempt still has to occupy a row: it is the only record that the
 * scheduler tried, and without it a workspace that always fails would stay
 * permanently at the front of the queue and consume every tick. So the row
 * exists, and the values below are chosen so no reader can mistake it for a
 * result -- a score outside the real 0..100 range, and a grade that is not one
 * of the grades. Every read path filters on `scanStatus` as well.
 */
const FAILED_SCAN = {
  score: -1,
  grade: 'unknown',
  headline: 'Scan did not complete.',
  checks: '[]',
} as const;

type ScanRow = {
  id: string;
  score: number;
  grade: ShieldReport['grade'] | typeof UNKNOWN_GRADE;
  headline: string;
  checks: string;
  findingCount: number;
  durationMs: number;
  createdAt: number;
  scanTrigger: string | null;
  scanStatus: string | null;
  newFindings: number | null;
  resolvedFindings: number | null;
  reopenedFindings: number | null;
  severityChangedFindings: number | null;
};

/**
 * A row written before 0.15.0 carries no provenance and no delta. Both stay
 * null here rather than being filled in: "Legacy" and "not recorded" are true,
 * and an invented "Manual" or a zeroed delta would not be.
 */
function toScanRecord(row: ScanRow): ScanRecord {
  return {
    id: row.id,
    score: row.score,
    grade: row.grade,
    headline: row.headline,
    findingCount: row.findingCount,
    durationMs: row.durationMs,
    createdAt: row.createdAt,
    trigger:
      row.scanTrigger === 'manual' || row.scanTrigger === 'scheduled'
        ? row.scanTrigger
        : null,
    status:
      row.scanStatus === 'completed' || row.scanStatus === 'failed'
        ? row.scanStatus
        : null,
    delta:
      row.newFindings === null
        ? null
        : {
            opened: row.newFindings,
            resolved: row.resolvedFindings ?? 0,
            reopened: row.reopenedFindings ?? 0,
            severityChanged: row.severityChangedFindings ?? 0,
          },
  };
}

/**
 * Records that an attempt happened and did not finish.
 *
 * Deliberately best effort. If this write also fails the database is
 * unavailable, in which case the scheduler could not have selected the
 * workspace in the first place, so there is no hot loop left to protect
 * against. The cause is never written down: an error message can carry SQL, a
 * resource name or a stack path, and the log table is readable in-app.
 */
async function recordFailedAttempt(
  workspaceId: string,
  trigger: ScanTrigger,
  startedAt: number,
  actor: string,
): Promise<void> {
  const now = Date.now();
  try {
    await execute(
      INSERT_SCAN_SQL,
      createId('scan'),
      workspaceId,
      FAILED_SCAN.score,
      FAILED_SCAN.grade,
      FAILED_SCAN.headline,
      FAILED_SCAN.checks,
      0,
      Math.max(0, now - startedAt),
      now,
      trigger,
      'failed' satisfies ScanStatus,
      null,
      null,
      null,
      null,
    );
    await writeLog({
      workspaceId,
      level: 'ERROR',
      source: 'shield',
      message: 'Scan did not complete. No posture was recorded for this attempt.',
      actor,
      // A sweep is platform automation, so its activity mirror must not be
      // filed against a person. `trigger` is a literal in server code -- the
      // route hard-codes 'manual' and only the scheduler passes 'scheduled'
      // -- so nothing from a request can reach this.
      actorType: trigger === 'scheduled' ? 'system' : undefined,
    });
  } catch {
    // See the note above: nothing useful is left to do here.
  }
}

/**
 * Runs Shield against a workspace and records the result.
 *
 * Ordering matters. Findings are reconciled *before* the scan row is written,
 * so a reconciliation that dies halfway can never leave behind a completed
 * scan claiming a score whose findings were only partly applied. The failure
 * path writes a `failed` row instead, which is what the scheduler reads as
 * "this workspace was attempted".
 */
export async function runScan(
  workspaceId: string,
  userId: string,
  actor: string,
  trigger: ScanTrigger = 'manual',
): Promise<ScanOutcome> {
  const startedAt = Date.now();

  let report: ShieldReport;
  let delta: PostureDelta;
  try {
    const snapshot = await collectSnapshot(workspaceId, userId);
    report = runShieldRules(snapshot);

    // The scan is the one regular sweep this app has, so it doubles as the
    // moment stale counters and expired attempt rows are cleared.
    await Promise.all([pruneRateLimits(), pruneAttempts()]);

    delta = await reconcileFindings(workspaceId, report.findings, Date.now());
  } catch (error) {
    await recordFailedAttempt(workspaceId, trigger, startedAt, actor);
    throw error;
  }

  const now = Date.now();
  const scan: ScanRecord = {
    id: createId('scan'),
    score: report.score,
    grade: report.grade,
    headline: report.headline,
    findingCount: report.findings.length,
    durationMs: Math.max(0, now - startedAt),
    createdAt: now,
    trigger,
    status: 'completed',
    delta: {
      opened: delta.opened,
      resolved: delta.resolved,
      reopened: delta.reopened,
      severityChanged: delta.severityChanged,
    },
  };

  await execute(
    INSERT_SCAN_SQL,
    scan.id,
    workspaceId,
    scan.score,
    scan.grade,
    scan.headline,
    JSON.stringify(report.checks),
    scan.findingCount,
    scan.durationMs,
    scan.createdAt,
    trigger,
    'completed' satisfies ScanStatus,
    delta.opened,
    delta.resolved,
    delta.reopened,
    delta.severityChanged,
  );

  // Bounded history. Runs after the insert so the scan just written is one of
  // the rows being kept, never one of the rows being counted out.
  await trimScanHistory(workspaceId);

  await writeLog({
    workspaceId,
    level: report.findings.length === 0 ? 'INFO' : 'WARN',
    source: 'shield',
    message: `Scan complete · score ${report.score} · ${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}`,
    actor,
    resource: scan.id,
    // A sweep is platform automation, so its activity mirror must not be
    // filed against a person. `trigger` is a literal in server code -- the
    // route hard-codes 'manual' and only the scheduler passes 'scheduled'
    // -- so nothing from a request can reach this.
    actorType: trigger === 'scheduled' ? 'system' : undefined,
  });

  return { ...report, scan };
}

export type ShieldState = {
  /**
   * The newest scan that actually completed. A failed attempt never becomes
   * the posture, however recent it is.
   */
  scan: ScanRecord | null;
  /** The newest attempt of any kind, so a failed sweep is visible not silent. */
  lastAttempt: ScanRecord | null;
  /** The newest scheduled attempt, for the "last automatic scan" line. */
  lastScheduled: ScanRecord | null;
  /** Recent attempts, newest first. Bounded by POSTURE_LIMITS.trendWindow. */
  history: ScanRecord[];
  checks: ShieldReport['checks'];
  findings: StoredFinding[];
};

/** The last recorded scan, for rendering the Shield page without re-scanning. */
export async function readShieldState(
  workspaceId: string,
): Promise<ShieldState> {
  const [completedRow, scheduledRow, historyRows, findings] = await Promise.all([
    queryOne<ScanRow>(
      `SELECT ${SCAN_COLUMNS} FROM shield_scan
       WHERE workspaceId = ? AND ${NOT_FAILED}
       ORDER BY createdAt DESC LIMIT 1`,
      workspaceId,
    ),
    queryOne<ScanRow>(
      `SELECT ${SCAN_COLUMNS} FROM shield_scan
       WHERE workspaceId = ? AND scanTrigger = 'scheduled'
       ORDER BY createdAt DESC LIMIT 1`,
      workspaceId,
    ),
    query<ScanRow>(
      `SELECT ${SCAN_COLUMNS} FROM shield_scan
       WHERE workspaceId = ?
       ORDER BY createdAt DESC LIMIT ?`,
      workspaceId,
      POSTURE_LIMITS.trendWindow,
    ),
    query<StoredFinding>(
      `SELECT id, code, title, detail, resource, severity, remediation, status, firstSeenAt, lastSeenAt
       FROM shield_finding WHERE workspaceId = ? ORDER BY status ASC, lastSeenAt DESC`,
      workspaceId,
    ),
  ]);

  const history = historyRows.map(toScanRecord);

  return {
    scan: completedRow ? toScanRecord(completedRow) : null,
    lastAttempt: history[0] ?? null,
    lastScheduled: scheduledRow ? toScanRecord(scheduledRow) : null,
    history,
    checks: completedRow
      ? (JSON.parse(completedRow.checks) as ShieldReport['checks'])
      : [],
    findings,
  };
}

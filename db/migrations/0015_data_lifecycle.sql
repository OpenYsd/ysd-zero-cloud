-- Phase 12: YSD Data Lifecycle & Capacity Guard.
--
-- Three tables, no new binding. Everything here is D1 state advanced by the
-- single existing free-plan Cron Trigger.
--
-- The safety posture of this migration is deliberately conservative:
--
--   * It deletes nothing. Applying it changes no existing row.
--   * Every policy it can hold is DISABLED until an owner or admin reviews a
--     dry-run and activates it explicitly.
--   * `dataClass` is a closed CHECK list. A table name never travels from a
--     request into SQL; the server maps an allowlisted class to a fixed
--     statement. See `lib/server/retention.ts`.
--   * `audit_event`, `incident_event`, and `workflow_version` are absent from
--     the class list on purpose. Each carries a BEFORE DELETE trigger that
--     raises ABORT (0010, 0014, and 0012 respectively). Phase 12 keeps those
--     append-only guarantees intact rather than weakening them to reclaim
--     rows, so those tables are never pruned automatically.

CREATE TABLE IF NOT EXISTS retention_policy (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  dataClass TEXT NOT NULL CHECK (dataClass IN (
    'platform-logs',
    'workflow-events',
    'workflow-executions',
    'workflow-security-events',
    'webhook-deliveries',
    'read-notifications',
    'resolved-shield-findings'
  )),
  -- Disabled by default. Nothing is ever deleted until a human activates it.
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  -- Absolute floor shared by every class. Per-class floors are higher and are
  -- enforced by the server registry; this CHECK is the last line of defence.
  retentionDays INTEGER NOT NULL CHECK (retentionDays BETWEEN 7 AND 3650),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
  lastDryRunAt INTEGER,
  lastDryRunRevision INTEGER,
  lastDryRunRetentionDays INTEGER,
  lastDryRunCandidateRows INTEGER,
  lastPrunedAt INTEGER,
  lastRunStatus TEXT CHECK (lastRunStatus IS NULL OR lastRunStatus IN (
    'completed', 'partial', 'failed', 'skipped'
  )),
  consecutiveFailures INTEGER NOT NULL DEFAULT 0 CHECK (consecutiveFailures >= 0),
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  UNIQUE (workspaceId, dataClass)
);

CREATE INDEX IF NOT EXISTS retention_policy_workspace_idx
  ON retention_policy (workspaceId, dataClass);
CREATE INDEX IF NOT EXISTS retention_policy_due_idx
  ON retention_policy (enabled, lastPrunedAt);

-- Usage history. Append-once rows; the metrics blob holds only trusted
-- counter ids from `lib/free-tier.ts`. No secret, ciphertext, fingerprint, or
-- free-text value is ever written here.
CREATE TABLE IF NOT EXISTS usage_snapshot (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  -- Floor of capturedAt over the snapshot cadence. The UNIQUE constraint below
  -- is what makes a repeated tick in the same window a no-op.
  slot INTEGER NOT NULL,
  capturedAt INTEGER NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('cron', 'manual')),
  metrics TEXT NOT NULL DEFAULT '{}',
  overLimitCount INTEGER NOT NULL DEFAULT 0 CHECK (overLimitCount >= 0),
  UNIQUE (workspaceId, slot)
);

CREATE INDEX IF NOT EXISTS usage_snapshot_history_idx
  ON usage_snapshot (workspaceId, capturedAt DESC);

-- Operational evidence for every dry-run and every prune. Write-once, then a
-- single finalisation update. Never deleted, including by retention itself.
CREATE TABLE IF NOT EXISTS retention_run (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  policyId TEXT REFERENCES retention_policy (id) ON DELETE RESTRICT,
  dataClass TEXT NOT NULL CHECK (dataClass IN (
    'platform-logs',
    'workflow-events',
    'workflow-executions',
    'workflow-security-events',
    'webhook-deliveries',
    'read-notifications',
    'resolved-shield-findings'
  )),
  mode TEXT NOT NULL CHECK (mode IN ('dry-run', 'prune')),
  actorType TEXT NOT NULL CHECK (actorType IN ('user', 'system')),
  actorId TEXT NOT NULL,
  retentionDays INTEGER NOT NULL CHECK (retentionDays >= 7),
  cutoff INTEGER NOT NULL,
  candidateRows INTEGER NOT NULL DEFAULT 0 CHECK (candidateRows >= 0),
  deletedRows INTEGER NOT NULL DEFAULT 0 CHECK (deletedRows >= 0),
  status TEXT NOT NULL CHECK (status IN ('completed', 'partial', 'failed', 'skipped')),
  -- An allowlisted code, never a raw driver message.
  failureCode TEXT,
  startedAt INTEGER NOT NULL,
  finishedAt INTEGER
);

CREATE INDEX IF NOT EXISTS retention_run_workspace_idx
  ON retention_run (workspaceId, dataClass, startedAt DESC);
CREATE INDEX IF NOT EXISTS retention_run_policy_idx
  ON retention_run (policyId, mode, startedAt DESC);

-- Tenant isolation: a policy may only be attached to a live workspace that
-- really belongs to the named organization.
CREATE TRIGGER IF NOT EXISTS retention_policy_tenant_guard
BEFORE INSERT ON retention_policy
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
     AND w.archivedAt IS NULL
)
BEGIN SELECT RAISE(ABORT, 'retention policy tenant mismatch'); END;

-- Scope is fixed at creation. A policy can never be re-pointed at another
-- workspace, organization, or data class.
CREATE TRIGGER IF NOT EXISTS retention_policy_scope_immutable_guard
BEFORE UPDATE OF organizationId, workspaceId, dataClass, createdAt ON retention_policy
WHEN NEW.organizationId <> OLD.organizationId
  OR NEW.workspaceId <> OLD.workspaceId
  OR NEW.dataClass <> OLD.dataClass
  OR NEW.createdAt <> OLD.createdAt
BEGIN SELECT RAISE(ABORT, 'retention policy scope is immutable'); END;

-- Activation requires evidence. Turning a policy on is refused unless a
-- dry-run was recorded against the revision being activated and against the
-- exact retentionDays now in force. Freshness is enforced in the server layer,
-- which owns the clock; existence and exact match are enforced here.
CREATE TRIGGER IF NOT EXISTS retention_policy_activation_guard
BEFORE UPDATE OF enabled ON retention_policy
WHEN NEW.enabled = 1 AND OLD.enabled = 0
  AND (
    NEW.lastDryRunAt IS NULL
    OR NEW.lastDryRunRetentionDays IS NOT NEW.retentionDays
    OR NEW.lastDryRunRevision IS NOT OLD.revision
  )
BEGIN SELECT RAISE(ABORT, 'retention activation requires a matching dry-run'); END;

-- Changing the window invalidates the review. The policy must be disabled
-- first, which forces a fresh dry-run before it can delete again.
CREATE TRIGGER IF NOT EXISTS retention_policy_window_guard
BEFORE UPDATE OF retentionDays ON retention_policy
WHEN NEW.retentionDays <> OLD.retentionDays AND NEW.enabled = 1
BEGIN SELECT RAISE(ABORT, 'changing retention days requires disabling the policy first'); END;

-- Per-class floors are enforced at the database edge as well as in the API.
-- A compromised or stale application path therefore cannot weaken security
-- evidence retention below the reviewed window for its class.
CREATE TRIGGER IF NOT EXISTS retention_policy_class_floor_guard
BEFORE INSERT ON retention_policy
WHEN (NEW.dataClass = 'platform-logs' AND NEW.retentionDays < 7)
  OR (NEW.dataClass IN ('workflow-events','workflow-executions','webhook-deliveries') AND NEW.retentionDays < 14)
  OR (NEW.dataClass IN ('workflow-security-events','resolved-shield-findings') AND NEW.retentionDays < 90)
  OR (NEW.dataClass = 'read-notifications' AND NEW.retentionDays < 7)
BEGIN SELECT RAISE(ABORT, 'retention window is below the reviewed class floor'); END;

CREATE TRIGGER IF NOT EXISTS retention_policy_class_floor_update_guard
BEFORE UPDATE OF retentionDays, dataClass ON retention_policy
WHEN (NEW.dataClass = 'platform-logs' AND NEW.retentionDays < 7)
  OR (NEW.dataClass IN ('workflow-events','workflow-executions','webhook-deliveries') AND NEW.retentionDays < 14)
  OR (NEW.dataClass IN ('workflow-security-events','resolved-shield-findings') AND NEW.retentionDays < 90)
  OR (NEW.dataClass = 'read-notifications' AND NEW.retentionDays < 7)
BEGIN SELECT RAISE(ABORT, 'retention window is below the reviewed class floor'); END;

-- Snapshots are tenant-checked and immutable once captured.
CREATE TRIGGER IF NOT EXISTS usage_snapshot_tenant_guard
BEFORE INSERT ON usage_snapshot
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
BEGIN SELECT RAISE(ABORT, 'usage snapshot tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS usage_snapshot_append_only_update
BEFORE UPDATE ON usage_snapshot
BEGIN SELECT RAISE(ABORT, 'usage snapshot is immutable'); END;

-- Retention evidence is tenant-checked, write-once, finalise-once, and
-- undeletable. A run row outlives the policy that produced it.
CREATE TRIGGER IF NOT EXISTS retention_run_tenant_guard
BEFORE INSERT ON retention_run
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
OR (NEW.policyId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM retention_policy p
   WHERE p.id = NEW.policyId AND p.workspaceId = NEW.workspaceId
     AND p.organizationId = NEW.organizationId AND p.dataClass = NEW.dataClass
))
BEGIN SELECT RAISE(ABORT, 'retention run tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS retention_run_finalize_guard
BEFORE UPDATE ON retention_run
WHEN OLD.finishedAt IS NOT NULL
  OR NEW.id <> OLD.id
  OR NEW.organizationId <> OLD.organizationId
  OR NEW.workspaceId <> OLD.workspaceId
  OR NEW.dataClass <> OLD.dataClass
  OR NEW.mode <> OLD.mode
  OR NEW.cutoff <> OLD.cutoff
  OR NEW.retentionDays <> OLD.retentionDays
  OR NEW.startedAt <> OLD.startedAt
BEGIN SELECT RAISE(ABORT, 'retention_run is append-only once finished'); END;

CREATE TRIGGER IF NOT EXISTS retention_run_append_only_delete
BEFORE DELETE ON retention_run
BEGIN SELECT RAISE(ABORT, 'retention_run evidence cannot be deleted'); END;

-- Retention-scan indexes. Every prune statement is (workspace, time) bounded,
-- so each class gets a covering index rather than a table scan.
CREATE INDEX IF NOT EXISTS workflow_event_retention_idx
  ON workflow_event (workspaceId, createdAt);
CREATE INDEX IF NOT EXISTS workflow_execution_event_retention_ref_idx
  ON workflow_execution (eventId);
CREATE INDEX IF NOT EXISTS workflow_execution_retention_idx
  ON workflow_execution (workspaceId, state, createdAt);
CREATE INDEX IF NOT EXISTS workflow_incident_execution_retention_ref_idx
  ON workflow_incident (executionId) WHERE executionId IS NOT NULL;
CREATE INDEX IF NOT EXISTS workflow_security_event_retention_idx
  ON workflow_security_event (workspaceId, createdAt);
CREATE INDEX IF NOT EXISTS webhook_delivery_retention_idx
  ON webhook_delivery (workspaceId, receivedAt);
CREATE INDEX IF NOT EXISTS internal_notification_retention_idx
  ON internal_notification (workspaceId, readAt, createdAt);
CREATE INDEX IF NOT EXISTS shield_finding_retention_idx
  ON shield_finding (workspaceId, status, lastSeenAt);

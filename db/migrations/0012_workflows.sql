-- Phase 9: YSD Workflows & Automation Engine.
--
-- The engine is deliberately implemented on the existing Worker and D1
-- database. Definitions contain only reviewed JSON contracts: no shell, eval,
-- arbitrary script, provider endpoint, URL, or paid integration is stored.

ALTER TABLE compute_node ADD COLUMN assignmentsDisabledAt INTEGER;
ALTER TABLE compute_node ADD COLUMN assignmentsDisabledBy TEXT;
ALTER TABLE shield_finding ADD COLUMN acknowledgedAt INTEGER;
ALTER TABLE shield_finding ADD COLUMN acknowledgedBy TEXT;

CREATE TABLE IF NOT EXISTS workflow (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'paused')),
  activeVersionId TEXT,
  latestVersion INTEGER NOT NULL DEFAULT 0,
  ownerUserId TEXT NOT NULL,
  failureStreak INTEGER NOT NULL DEFAULT 0,
  lastTriggeredAt INTEGER,
  lastSucceededAt INTEGER,
  lastFailedAt INTEGER,
  lastScheduledAt INTEGER,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  deletedAt INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS workflow_workspace_name_uidx
  ON workflow (workspaceId, name) WHERE deletedAt IS NULL;
CREATE INDEX IF NOT EXISTS workflow_trigger_scan_idx
  ON workflow (workspaceId, status, updatedAt DESC) WHERE deletedAt IS NULL;
CREATE INDEX IF NOT EXISTS workflow_org_idx
  ON workflow (organizationId, workspaceId, projectId, updatedAt DESC);

-- Workflow causation travels with the existing D1-backed node job. This lets
-- asynchronous App Runtime and Game Server completions retain one correlation
-- chain without creating a second queue.
ALTER TABLE node_job ADD COLUMN workflowId TEXT;
ALTER TABLE node_job ADD COLUMN workflowExecutionId TEXT;
ALTER TABLE node_job ADD COLUMN workflowCorrelationId TEXT;
ALTER TABLE node_job ADD COLUMN workflowChainDepth INTEGER CHECK (workflowChainDepth IS NULL OR workflowChainDepth BETWEEN 1 AND 5);

CREATE TABLE IF NOT EXISTS workflow_version (
  id TEXT PRIMARY KEY,
  workflowId TEXT NOT NULL REFERENCES workflow (id) ON DELETE CASCADE,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('draft', 'published', 'rollback')),
  triggerType TEXT NOT NULL,
  definition TEXT NOT NULL,
  definitionHash TEXT NOT NULL,
  sourceVersionId TEXT REFERENCES workflow_version (id) ON DELETE SET NULL,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  publishedAt INTEGER,
  UNIQUE (workflowId, version)
);

CREATE INDEX IF NOT EXISTS workflow_version_history_idx
  ON workflow_version (workflowId, version DESC);

-- Versions are append-only. Publish and rollback create a new snapshot and
-- switch workflow.activeVersionId; an execution never changes version midway.
CREATE TRIGGER IF NOT EXISTS workflow_version_no_update
BEFORE UPDATE ON workflow_version
BEGIN
  SELECT RAISE(ABORT, 'workflow_version is append-only');
END;
CREATE TRIGGER IF NOT EXISTS workflow_version_no_delete
BEFORE DELETE ON workflow_version
BEGIN
  SELECT RAISE(ABORT, 'workflow_version is append-only');
END;

CREATE TABLE IF NOT EXISTS workflow_variable (
  id TEXT PRIMARY KEY,
  workflowId TEXT NOT NULL REFERENCES workflow (id) ON DELETE CASCADE,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('text', 'number', 'boolean', 'secret')),
  value TEXT,
  secretId TEXT REFERENCES secret (id) ON DELETE SET NULL,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  UNIQUE (workflowId, name),
  CHECK ((kind = 'secret' AND value IS NULL AND secretId IS NOT NULL)
      OR (kind <> 'secret' AND secretId IS NULL))
);

CREATE TABLE IF NOT EXISTS workflow_event (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  resourceType TEXT NOT NULL,
  resourceId TEXT,
  payload TEXT NOT NULL DEFAULT '{}',
  source TEXT NOT NULL CHECK (source IN ('system', 'manual', 'schedule')),
  trusted INTEGER NOT NULL DEFAULT 1 CHECK (trusted = 1),
  dedupeKey TEXT NOT NULL,
  correlationId TEXT NOT NULL,
  causationId TEXT,
  sourceWorkflowId TEXT REFERENCES workflow (id) ON DELETE SET NULL,
  chainDepth INTEGER NOT NULL DEFAULT 0 CHECK (chainDepth BETWEEN 0 AND 5),
  createdAt INTEGER NOT NULL,
  processedAt INTEGER,
  rejectedAt INTEGER,
  rejectionReason TEXT,
  UNIQUE (organizationId, dedupeKey)
);

CREATE INDEX IF NOT EXISTS workflow_event_dispatch_idx
  ON workflow_event (processedAt, rejectedAt, createdAt ASC);
CREATE INDEX IF NOT EXISTS workflow_event_workspace_idx
  ON workflow_event (organizationId, workspaceId, type, createdAt DESC);
CREATE INDEX IF NOT EXISTS workflow_event_correlation_idx
  ON workflow_event (correlationId, chainDepth, createdAt ASC);

CREATE TABLE IF NOT EXISTS workflow_execution (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  workflowId TEXT NOT NULL REFERENCES workflow (id) ON DELETE CASCADE,
  versionId TEXT NOT NULL REFERENCES workflow_version (id) ON DELETE RESTRICT,
  eventId TEXT NOT NULL REFERENCES workflow_event (id) ON DELETE RESTRICT,
  state TEXT NOT NULL CHECK (state IN (
    'queued','running','waiting','succeeded','failed','cancelled','timed_out','skipped'
  )),
  idempotencyKey TEXT NOT NULL,
  correlationId TEXT NOT NULL,
  causationId TEXT,
  chainDepth INTEGER NOT NULL DEFAULT 0 CHECK (chainDepth BETWEEN 0 AND 5),
  actionIndex INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  maxAttempts INTEGER NOT NULL,
  nextAttemptAt INTEGER,
  timeoutAt INTEGER NOT NULL,
  leaseToken TEXT,
  leaseExpiresAt INTEGER,
  cancelRequestedAt INTEGER,
  cancelRequestedBy TEXT,
  lastError TEXT,
  startedAt INTEGER,
  finishedAt INTEGER,
  deadLetterAt INTEGER,
  manualRetryOf TEXT REFERENCES workflow_execution (id) ON DELETE SET NULL,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  UNIQUE (workflowId, versionId, eventId),
  UNIQUE (workspaceId, idempotencyKey)
);

CREATE INDEX IF NOT EXISTS workflow_execution_queue_idx
  ON workflow_execution (state, nextAttemptAt, leaseExpiresAt, createdAt ASC);
CREATE INDEX IF NOT EXISTS workflow_execution_history_idx
  ON workflow_execution (workspaceId, workflowId, createdAt DESC);
CREATE INDEX IF NOT EXISTS workflow_execution_correlation_idx
  ON workflow_execution (correlationId, chainDepth, createdAt ASC);

CREATE TABLE IF NOT EXISTS workflow_action_execution (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  workflowId TEXT NOT NULL REFERENCES workflow (id) ON DELETE CASCADE,
  executionId TEXT NOT NULL REFERENCES workflow_execution (id) ON DELETE CASCADE,
  actionIndex INTEGER NOT NULL,
  attempt INTEGER NOT NULL,
  actionType TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('running','succeeded','failed','skipped')),
  idempotencyKey TEXT NOT NULL,
  resourceType TEXT,
  resourceId TEXT,
  error TEXT,
  startedAt INTEGER NOT NULL,
  finishedAt INTEGER,
  UNIQUE (executionId, actionIndex, attempt),
  UNIQUE (workspaceId, idempotencyKey)
);

CREATE INDEX IF NOT EXISTS workflow_action_history_idx
  ON workflow_action_execution (executionId, actionIndex, attempt DESC);

CREATE TABLE IF NOT EXISTS workflow_incident (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  workflowId TEXT REFERENCES workflow (id) ON DELETE SET NULL,
  executionId TEXT REFERENCES workflow_execution (id) ON DELETE SET NULL,
  resourceType TEXT NOT NULL,
  resourceId TEXT,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  resolvedAt INTEGER
);

CREATE INDEX IF NOT EXISTS workflow_incident_workspace_idx
  ON workflow_incident (workspaceId, status, severity, createdAt DESC);

CREATE TABLE IF NOT EXISTS workflow_security_event (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  workflowId TEXT REFERENCES workflow (id) ON DELETE SET NULL,
  executionId TEXT REFERENCES workflow_execution (id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  detail TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS workflow_security_event_workspace_idx
  ON workflow_security_event (workspaceId, type, createdAt DESC);

CREATE TABLE IF NOT EXISTS internal_notification (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  userId TEXT REFERENCES "user" (id) ON DELETE CASCADE,
  workflowId TEXT REFERENCES workflow (id) ON DELETE SET NULL,
  executionId TEXT REFERENCES workflow_execution (id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  resourceType TEXT NOT NULL,
  resourceId TEXT,
  href TEXT,
  dedupeKey TEXT NOT NULL,
  readAt INTEGER,
  createdAt INTEGER NOT NULL,
  UNIQUE (workspaceId, dedupeKey)
);

CREATE INDEX IF NOT EXISTS internal_notification_inbox_idx
  ON internal_notification (workspaceId, userId, readAt, createdAt DESC);

CREATE TABLE IF NOT EXISTS workflow_resource_state (
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  resourceType TEXT NOT NULL,
  resourceId TEXT NOT NULL,
  state TEXT NOT NULL,
  updatedAt INTEGER NOT NULL,
  PRIMARY KEY (workspaceId, resourceType, resourceId)
);

-- Database-edge tenant guards make programming mistakes fail closed.
CREATE TRIGGER IF NOT EXISTS workflow_tenant_guard
BEFORE INSERT ON workflow
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
))
BEGIN SELECT RAISE(ABORT, 'workflow tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, projectId ON workflow
WHEN NEW.organizationId <> OLD.organizationId OR NEW.workspaceId <> OLD.workspaceId
  OR NOT EXISTS (
    SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
  ) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
  ))
BEGIN SELECT RAISE(ABORT, 'workflow tenant is immutable'); END;

CREATE TRIGGER IF NOT EXISTS workflow_version_tenant_guard
BEFORE INSERT ON workflow_version
WHEN NOT EXISTS (
  SELECT 1 FROM workflow w WHERE w.id = NEW.workflowId
    AND w.organizationId = NEW.organizationId AND w.workspaceId = NEW.workspaceId
    AND COALESCE(w.projectId, '') = COALESCE(NEW.projectId, '') AND w.deletedAt IS NULL
)
BEGIN SELECT RAISE(ABORT, 'workflow version tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_variable_tenant_guard
BEFORE INSERT ON workflow_variable
WHEN NOT EXISTS (
  SELECT 1 FROM workflow w WHERE w.id = NEW.workflowId
    AND w.organizationId = NEW.organizationId AND w.workspaceId = NEW.workspaceId
    AND COALESCE(w.projectId, '') = COALESCE(NEW.projectId, '') AND w.deletedAt IS NULL
) OR (NEW.secretId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM secret s WHERE s.id = NEW.secretId AND s.workspaceId = NEW.workspaceId
    AND (NEW.projectId IS NULL OR s.scope IN ('Workspace', 'Project:' || NEW.projectId))
))
BEGIN SELECT RAISE(ABORT, 'workflow variable tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_variable_tenant_update_guard
BEFORE UPDATE ON workflow_variable
WHEN NOT EXISTS (
  SELECT 1 FROM workflow w WHERE w.id = NEW.workflowId
    AND w.organizationId = NEW.organizationId AND w.workspaceId = NEW.workspaceId
    AND COALESCE(w.projectId, '') = COALESCE(NEW.projectId, '') AND w.deletedAt IS NULL
) OR (NEW.secretId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM secret s WHERE s.id = NEW.secretId AND s.workspaceId = NEW.workspaceId
    AND (NEW.projectId IS NULL OR s.scope IN ('Workspace', 'Project:' || NEW.projectId))
))
BEGIN SELECT RAISE(ABORT, 'workflow variable tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_event_tenant_guard
BEFORE INSERT ON workflow_event
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
)) OR (NEW.sourceWorkflowId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM workflow w WHERE w.id = NEW.sourceWorkflowId
    AND w.organizationId = NEW.organizationId AND w.workspaceId = NEW.workspaceId
))
BEGIN SELECT RAISE(ABORT, 'workflow event tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_execution_tenant_guard
BEFORE INSERT ON workflow_execution
WHEN NOT EXISTS (
  SELECT 1 FROM workflow w
  JOIN workflow_version v ON v.workflowId = w.id
  JOIN workflow_event e ON e.id = NEW.eventId
  WHERE w.id = NEW.workflowId AND v.id = NEW.versionId
    AND w.organizationId = NEW.organizationId AND w.workspaceId = NEW.workspaceId
    AND e.organizationId = NEW.organizationId AND e.workspaceId = NEW.workspaceId
    AND COALESCE(w.projectId, '') = COALESCE(NEW.projectId, '')
)
BEGIN SELECT RAISE(ABORT, 'workflow execution tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_action_tenant_guard
BEFORE INSERT ON workflow_action_execution
WHEN NOT EXISTS (
  SELECT 1 FROM workflow_execution e WHERE e.id = NEW.executionId
    AND e.workflowId = NEW.workflowId AND e.organizationId = NEW.organizationId
    AND e.workspaceId = NEW.workspaceId
)
BEGIN SELECT RAISE(ABORT, 'workflow action tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_incident_tenant_guard
BEFORE INSERT ON workflow_incident
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
))
BEGIN SELECT RAISE(ABORT, 'workflow incident tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_security_event_tenant_guard
BEFORE INSERT ON workflow_security_event
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.workflowId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM workflow w WHERE w.id = NEW.workflowId
    AND w.organizationId = NEW.organizationId AND w.workspaceId = NEW.workspaceId
))
BEGIN SELECT RAISE(ABORT, 'workflow security event tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS notification_tenant_guard
BEFORE INSERT ON internal_notification
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
))
BEGIN SELECT RAISE(ABORT, 'notification tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS workflow_resource_state_tenant_guard
BEFORE INSERT ON workflow_resource_state
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
BEGIN SELECT RAISE(ABORT, 'workflow resource state tenant mismatch'); END;

-- Phase 10: YSD External Event Gateway + Webhook Sources.
--
-- Webhook ingress remains on the existing Worker and D1 database. Secrets are
-- encrypted before storage; deliveries retain only bounded, non-sensitive
-- metadata and never persist the signed body, signature, or nonce value.

CREATE TABLE IF NOT EXISTS webhook_source (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled','disabled','archived')),
  secretCiphertext TEXT NOT NULL,
  secretFingerprint TEXT NOT NULL,
  secretVersion INTEGER NOT NULL DEFAULT 1 CHECK (secretVersion BETWEEN 1 AND 1000000),
  receivedCount INTEGER NOT NULL DEFAULT 0 CHECK (receivedCount >= 0),
  acceptedCount INTEGER NOT NULL DEFAULT 0 CHECK (acceptedCount >= 0),
  rejectedCount INTEGER NOT NULL DEFAULT 0 CHECK (rejectedCount >= 0),
  deduplicatedCount INTEGER NOT NULL DEFAULT 0 CHECK (deduplicatedCount >= 0),
  workflowExecutionsCreated INTEGER NOT NULL DEFAULT 0 CHECK (workflowExecutionsCreated >= 0),
  lastReceivedAt INTEGER,
  lastAcceptedAt INTEGER,
  lastRejectedAt INTEGER,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  rotatedAt INTEGER,
  archivedAt INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS webhook_source_workspace_name_uidx
  ON webhook_source (workspaceId, name) WHERE archivedAt IS NULL;
CREATE INDEX IF NOT EXISTS webhook_source_workspace_idx
  ON webhook_source (organizationId, workspaceId, projectId, status, updatedAt DESC);

-- Replay protection stores digests only. Both an external event id and a
-- nonce are single-use per source inside the retained history.
CREATE TABLE IF NOT EXISTS webhook_replay_guard (
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  sourceId TEXT NOT NULL REFERENCES webhook_source (id) ON DELETE CASCADE,
  externalEventId TEXT NOT NULL,
  nonceHash TEXT NOT NULL,
  receivedAt INTEGER NOT NULL,
  PRIMARY KEY (sourceId, externalEventId),
  UNIQUE (sourceId, nonceHash)
);

CREATE INDEX IF NOT EXISTS webhook_replay_received_idx
  ON webhook_replay_guard (workspaceId, receivedAt DESC);

CREATE TABLE IF NOT EXISTS webhook_delivery (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  sourceId TEXT NOT NULL REFERENCES webhook_source (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE SET NULL,
  externalEventId TEXT,
  eventType TEXT,
  subject TEXT,
  status TEXT NOT NULL CHECK (status IN ('accepted','rejected','deduplicated')),
  reasonCode TEXT,
  workflowEventId TEXT REFERENCES workflow_event (id) ON DELETE SET NULL,
  correlationId TEXT,
  workflowExecutionsCreated INTEGER NOT NULL DEFAULT 0 CHECK (workflowExecutionsCreated >= 0),
  receivedAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS webhook_delivery_source_idx
  ON webhook_delivery (sourceId, receivedAt DESC);
CREATE INDEX IF NOT EXISTS webhook_delivery_event_idx
  ON webhook_delivery (workflowEventId, status);
CREATE INDEX IF NOT EXISTS webhook_delivery_workspace_idx
  ON webhook_delivery (organizationId, workspaceId, status, receivedAt DESC);

-- Database-edge tenant checks make cross-workspace programming mistakes fail
-- closed even if an application query is accidentally widened later.
CREATE TRIGGER IF NOT EXISTS webhook_source_tenant_guard
BEFORE INSERT ON webhook_source
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
))
BEGIN SELECT RAISE(ABORT, 'webhook source tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS webhook_source_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, projectId ON webhook_source
WHEN NEW.organizationId <> OLD.organizationId OR NEW.workspaceId <> OLD.workspaceId
  OR COALESCE(NEW.projectId, '') <> COALESCE(OLD.projectId, '')
  OR NOT EXISTS (
    SELECT 1 FROM workspace w WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
  ) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
  ))
BEGIN SELECT RAISE(ABORT, 'webhook source tenant is immutable'); END;

CREATE TRIGGER IF NOT EXISTS webhook_replay_tenant_guard
BEFORE INSERT ON webhook_replay_guard
WHEN NOT EXISTS (
  SELECT 1 FROM webhook_source s WHERE s.id = NEW.sourceId
    AND s.organizationId = NEW.organizationId AND s.workspaceId = NEW.workspaceId
)
BEGIN SELECT RAISE(ABORT, 'webhook replay tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS webhook_delivery_tenant_guard
BEFORE INSERT ON webhook_delivery
WHEN NOT EXISTS (
  SELECT 1 FROM webhook_source s WHERE s.id = NEW.sourceId
    AND s.organizationId = NEW.organizationId AND s.workspaceId = NEW.workspaceId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
)) OR (NEW.workflowEventId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM workflow_event e WHERE e.id = NEW.workflowEventId
    AND e.organizationId = NEW.organizationId AND e.workspaceId = NEW.workspaceId
))
BEGIN SELECT RAISE(ABORT, 'webhook delivery tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS webhook_delivery_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, sourceId, projectId, workflowEventId ON webhook_delivery
WHEN NEW.organizationId <> OLD.organizationId OR NEW.workspaceId <> OLD.workspaceId
  OR NEW.sourceId <> OLD.sourceId
  OR COALESCE(NEW.projectId, '') <> COALESCE(OLD.projectId, '')
  OR COALESCE(NEW.workflowEventId, '') <> COALESCE(OLD.workflowEventId, '')
  OR NOT EXISTS (
    SELECT 1 FROM webhook_source s WHERE s.id = NEW.sourceId
      AND s.organizationId = NEW.organizationId AND s.workspaceId = NEW.workspaceId
  )
BEGIN SELECT RAISE(ABORT, 'webhook delivery tenant is immutable'); END;

CREATE TRIGGER IF NOT EXISTS webhook_replay_no_update
BEFORE UPDATE ON webhook_replay_guard
BEGIN SELECT RAISE(ABORT, 'webhook replay guard is append-only'); END;

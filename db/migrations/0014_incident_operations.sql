-- Phase 11: YSD Operations Center & Incident Response.
-- This migration expands the Phase 9 incident marker in place so existing
-- evidence remains addressable. Timeline rows are append-only by design.

ALTER TABLE workflow_incident ADD COLUMN correlationId TEXT;
ALTER TABLE workflow_incident ADD COLUMN dedupeKey TEXT;
ALTER TABLE workflow_incident ADD COLUMN occurrenceCount INTEGER NOT NULL DEFAULT 1 CHECK (occurrenceCount BETWEEN 1 AND 1000000);
ALTER TABLE workflow_incident ADD COLUMN lastSeenAt INTEGER;
ALTER TABLE workflow_incident ADD COLUMN assignedTo TEXT REFERENCES "user" (id) ON DELETE SET NULL;
ALTER TABLE workflow_incident ADD COLUMN acknowledgedAt INTEGER;
ALTER TABLE workflow_incident ADD COLUMN acknowledgedBy TEXT REFERENCES "user" (id) ON DELETE SET NULL;
ALTER TABLE workflow_incident ADD COLUMN resolvedBy TEXT REFERENCES "user" (id) ON DELETE SET NULL;
ALTER TABLE workflow_incident ADD COLUMN resolution TEXT;
ALTER TABLE workflow_incident ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 2147483647);

UPDATE workflow_incident
   SET correlationId = COALESCE(correlationId, 'incident:' || id),
       dedupeKey = COALESCE(dedupeKey, 'legacy:' || id),
       lastSeenAt = COALESCE(lastSeenAt, updatedAt, createdAt),
       occurrenceCount = MAX(1, occurrenceCount),
       acknowledgedAt = CASE
         WHEN status = 'acknowledged' THEN COALESCE(acknowledgedAt, updatedAt)
         ELSE acknowledgedAt
       END;

CREATE UNIQUE INDEX IF NOT EXISTS workflow_incident_active_dedupe_idx
  ON workflow_incident (workspaceId, dedupeKey)
  WHERE status <> 'resolved';
CREATE INDEX IF NOT EXISTS workflow_incident_inbox_idx
  ON workflow_incident (workspaceId, status, severity, lastSeenAt DESC);
CREATE INDEX IF NOT EXISTS workflow_incident_assignee_idx
  ON workflow_incident (workspaceId, assignedTo, status, lastSeenAt DESC);
CREATE INDEX IF NOT EXISTS workflow_incident_project_idx
  ON workflow_incident (workspaceId, projectId, status, lastSeenAt DESC);
CREATE INDEX IF NOT EXISTS workflow_incident_resource_idx
  ON workflow_incident (workspaceId, resourceType, status, lastSeenAt DESC);
CREATE INDEX IF NOT EXISTS workflow_incident_correlation_idx
  ON workflow_incident (workspaceId, correlationId, createdAt DESC);

CREATE TABLE IF NOT EXISTS incident_event (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE SET NULL,
  incidentId TEXT NOT NULL REFERENCES workflow_incident (id) ON DELETE RESTRICT,
  type TEXT NOT NULL CHECK (type IN (
    'incident.created','incident.occurrence','incident.assigned','incident.unassigned',
    'incident.acknowledged','incident.severity_changed','incident.note_added',
    'incident.resolved','incident.reopened'
  )),
  actorType TEXT NOT NULL CHECK (actorType IN ('user','system','workflow')),
  actorId TEXT NOT NULL,
  correlationId TEXT NOT NULL,
  fromStatus TEXT CHECK (fromStatus IS NULL OR fromStatus IN ('open','acknowledged','resolved')),
  toStatus TEXT CHECK (toStatus IS NULL OR toStatus IN ('open','acknowledged','resolved')),
  message TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  idempotencyKey TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  UNIQUE (workspaceId, idempotencyKey)
);

CREATE INDEX IF NOT EXISTS incident_event_timeline_idx
  ON incident_event (workspaceId, incidentId, createdAt DESC);
CREATE INDEX IF NOT EXISTS incident_event_correlation_idx
  ON incident_event (workspaceId, correlationId, createdAt ASC);
CREATE INDEX IF NOT EXISTS incident_event_type_idx
  ON incident_event (workspaceId, type, createdAt DESC);

INSERT OR IGNORE INTO incident_event
  (id, organizationId, workspaceId, projectId, incidentId, type, actorType,
   actorId, correlationId, fromStatus, toStatus, message, metadata,
   idempotencyKey, createdAt)
SELECT 'incevt_legacy_' || id, organizationId, workspaceId, projectId, id,
       'incident.created',
       CASE WHEN createdBy LIKE 'workflow:%' THEN 'workflow' ELSE 'system' END,
       createdBy, correlationId, NULL, 'open', NULL,
       json_object('backfilled', 1), 'legacy-created:' || id, createdAt
  FROM workflow_incident;

CREATE TRIGGER IF NOT EXISTS incident_phase11_insert_guard
BEFORE INSERT ON workflow_incident
WHEN NEW.correlationId IS NULL OR NEW.dedupeKey IS NULL OR NEW.lastSeenAt IS NULL
  OR NOT EXISTS (
    SELECT 1 FROM workspace w
     WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
       AND w.archivedAt IS NULL
  )
  OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM project p
     WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
  ))
  OR (NEW.workflowId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM workflow w
     WHERE w.id = NEW.workflowId AND w.organizationId = NEW.organizationId
       AND w.workspaceId = NEW.workspaceId
       AND COALESCE(w.projectId, '') = COALESCE(NEW.projectId, '')
  ))
  OR (NEW.executionId IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM workflow_execution e
     WHERE e.id = NEW.executionId AND e.organizationId = NEW.organizationId
       AND e.workspaceId = NEW.workspaceId
       AND COALESCE(e.projectId, '') = COALESCE(NEW.projectId, '')
  ))
  OR (NEW.assignedTo IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM organization_member m
     WHERE m.organizationId = NEW.organizationId AND m.userId = NEW.assignedTo
       AND m.status = 'active' AND m.suspendedAt IS NULL
  ))
BEGIN SELECT RAISE(ABORT, 'incident tenant or assignee mismatch'); END;

CREATE TRIGGER IF NOT EXISTS incident_phase11_scope_immutable_guard
BEFORE UPDATE OF organizationId, workspaceId, projectId, workflowId, executionId,
  correlationId, dedupeKey, createdAt ON workflow_incident
WHEN NEW.organizationId <> OLD.organizationId OR NEW.workspaceId <> OLD.workspaceId
  OR COALESCE(NEW.projectId, '') <> COALESCE(OLD.projectId, '')
  OR COALESCE(NEW.workflowId, '') <> COALESCE(OLD.workflowId, '')
  OR COALESCE(NEW.executionId, '') <> COALESCE(OLD.executionId, '')
  OR NEW.correlationId <> OLD.correlationId OR NEW.dedupeKey <> OLD.dedupeKey
  OR NEW.createdAt <> OLD.createdAt
BEGIN SELECT RAISE(ABORT, 'incident scope is immutable'); END;

CREATE TRIGGER IF NOT EXISTS incident_phase11_assignee_guard
BEFORE UPDATE OF assignedTo ON workflow_incident
WHEN NEW.assignedTo IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM organization_member m
   WHERE m.organizationId = NEW.organizationId AND m.userId = NEW.assignedTo
     AND m.status = 'active' AND m.suspendedAt IS NULL
)
BEGIN SELECT RAISE(ABORT, 'incident assignee is not an active organization member'); END;

CREATE TRIGGER IF NOT EXISTS incident_event_tenant_guard
BEFORE INSERT ON incident_event
WHEN NOT EXISTS (
  SELECT 1 FROM workflow_incident i
   WHERE i.id = NEW.incidentId AND i.organizationId = NEW.organizationId
     AND i.workspaceId = NEW.workspaceId
     AND COALESCE(i.projectId, '') = COALESCE(NEW.projectId, '')
     AND i.correlationId = NEW.correlationId
)
BEGIN SELECT RAISE(ABORT, 'incident event tenant mismatch'); END;

CREATE TRIGGER IF NOT EXISTS incident_event_volume_guard
BEFORE INSERT ON incident_event
WHEN (SELECT COUNT(*) FROM incident_event WHERE workspaceId = NEW.workspaceId AND incidentId = NEW.incidentId) >= 10000
BEGIN SELECT RAISE(ABORT, 'incident timeline safety limit reached'); END;

CREATE TRIGGER IF NOT EXISTS incident_event_append_only_update
BEFORE UPDATE ON incident_event
BEGIN SELECT RAISE(ABORT, 'incident timeline is append-only'); END;

CREATE TRIGGER IF NOT EXISTS incident_event_append_only_delete
BEFORE DELETE ON incident_event
BEGIN SELECT RAISE(ABORT, 'incident timeline is append-only'); END;

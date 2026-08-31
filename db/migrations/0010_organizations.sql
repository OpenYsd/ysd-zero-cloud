-- Phase 7: Organizations and team collaboration.
--
-- Existing workspace and resource identifiers are preserved. Every legacy
-- workspace is attached to a deterministic default organization owned by its
-- existing owner. Resource rows continue to reference workspace directly;
-- workspace.organizationId gives every resource one unambiguous organization
-- without duplicating a second tenant key that could drift.

CREATE TABLE IF NOT EXISTS organization (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  ownerUserId TEXT NOT NULL REFERENCES "user" (id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
  adminCanRevokeSessions INTEGER NOT NULL DEFAULT 1,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  archivedAt INTEGER
);

ALTER TABLE workspace ADD COLUMN organizationId TEXT REFERENCES organization (id) ON DELETE RESTRICT;
ALTER TABLE workspace ADD COLUMN archivedAt INTEGER;

INSERT OR IGNORE INTO organization
  (id, name, slug, ownerUserId, status, adminCanRevokeSessions, createdAt, updatedAt, archivedAt)
SELECT
  'org_legacy_' || id,
  CASE WHEN trim(name) = '' THEN 'YSD Workspace' ELSE name END,
  'legacy-' || lower(replace(id, '_', '-')),
  ownerUserId,
  'active',
  1,
  createdAt,
  updatedAt,
  NULL
FROM workspace;

UPDATE workspace
SET organizationId = 'org_legacy_' || id
WHERE organizationId IS NULL;

DROP INDEX IF EXISTS workspace_owner_uidx;
CREATE INDEX IF NOT EXISTS workspace_organization_idx
  ON workspace (organizationId, archivedAt, createdAt);
CREATE UNIQUE INDEX IF NOT EXISTS workspace_org_name_uidx
  ON workspace (organizationId, name) WHERE archivedAt IS NULL;

CREATE TABLE IF NOT EXISTS organization_member (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  userId TEXT NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'viewer')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'removed')),
  suspendedAt INTEGER,
  suspendedReason TEXT,
  acceptedAt INTEGER NOT NULL,
  lastActiveAt INTEGER,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  UNIQUE (organizationId, userId)
);

CREATE INDEX IF NOT EXISTS organization_member_user_idx
  ON organization_member (userId, status, updatedAt DESC);
CREATE INDEX IF NOT EXISTS organization_member_role_idx
  ON organization_member (organizationId, role, status);

INSERT OR IGNORE INTO organization_member
  (id, organizationId, userId, role, status, suspendedAt, suspendedReason,
   acceptedAt, lastActiveAt, createdBy, createdAt, updatedAt)
SELECT
  'member_legacy_' || w.id,
  w.organizationId,
  w.ownerUserId,
  'owner',
  'active',
  NULL,
  NULL,
  w.createdAt,
  NULL,
  'migration',
  w.createdAt,
  w.updatedAt
FROM workspace w
WHERE w.organizationId IS NOT NULL;

CREATE TABLE IF NOT EXISTS workspace_member (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  userId TEXT NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
  projectScope TEXT NOT NULL DEFAULT 'all' CHECK (projectScope IN ('all', 'restricted')),
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  UNIQUE (workspaceId, userId)
);

CREATE INDEX IF NOT EXISTS workspace_member_user_idx
  ON workspace_member (organizationId, userId, workspaceId);

INSERT OR IGNORE INTO workspace_member
  (id, organizationId, workspaceId, userId, createdBy, createdAt)
SELECT
  'wmem_legacy_' || w.id,
  w.organizationId,
  w.id,
  w.ownerUserId,
  'migration',
  w.createdAt
FROM workspace w
WHERE w.organizationId IS NOT NULL;

CREATE TABLE IF NOT EXISTS member_project_access (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  userId TEXT NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
  projectId TEXT NOT NULL REFERENCES project (id) ON DELETE CASCADE,
  grantedBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  UNIQUE (workspaceId, userId, projectId)
);

CREATE INDEX IF NOT EXISTS member_project_access_user_idx
  ON member_project_access (organizationId, workspaceId, userId);

CREATE TABLE IF NOT EXISTS organization_invitation (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'developer', 'viewer')),
  tokenHash TEXT NOT NULL UNIQUE,
  tokenPrefix TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
  expiresAt INTEGER NOT NULL,
  usedAt INTEGER,
  usedBy TEXT REFERENCES "user" (id) ON DELETE SET NULL,
  revokedAt INTEGER,
  revokedBy TEXT REFERENCES "user" (id) ON DELETE SET NULL,
  createdBy TEXT NOT NULL REFERENCES "user" (id) ON DELETE RESTRICT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS organization_invitation_pending_uidx
  ON organization_invitation (organizationId, workspaceId, email)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS organization_invitation_lookup_idx
  ON organization_invitation (organizationId, status, expiresAt);

CREATE TABLE IF NOT EXISTS service_account (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  createdBy TEXT NOT NULL REFERENCES "user" (id) ON DELETE RESTRICT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  revokedAt INTEGER,
  revokedBy TEXT REFERENCES "user" (id) ON DELETE SET NULL,
  UNIQUE (workspaceId, name)
);

CREATE INDEX IF NOT EXISTS service_account_org_idx
  ON service_account (organizationId, workspaceId, status);

CREATE TABLE IF NOT EXISTS service_account_token (
  id TEXT PRIMARY KEY,
  serviceAccountId TEXT NOT NULL REFERENCES service_account (id) ON DELETE CASCADE,
  tokenPrefix TEXT NOT NULL UNIQUE,
  tokenHash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  expiresAt INTEGER,
  lastUsedAt INTEGER,
  createdAt INTEGER NOT NULL,
  revokedAt INTEGER,
  revokedBy TEXT REFERENCES "user" (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS service_account_token_active_idx
  ON service_account_token (serviceAccountId, revokedAt, expiresAt);

CREATE TABLE IF NOT EXISTS audit_event (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE RESTRICT,
  workspaceId TEXT REFERENCES workspace (id) ON DELETE SET NULL,
  actorType TEXT NOT NULL CHECK (actorType IN ('user', 'service_account', 'system')),
  actorId TEXT NOT NULL,
  action TEXT NOT NULL,
  resourceType TEXT NOT NULL,
  resourceId TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failed')),
  ipAddress TEXT,
  userAgent TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_event_org_idx
  ON audit_event (organizationId, createdAt DESC);
CREATE INDEX IF NOT EXISTS audit_event_workspace_idx
  ON audit_event (organizationId, workspaceId, createdAt DESC);
CREATE INDEX IF NOT EXISTS audit_event_action_idx
  ON audit_event (organizationId, action, outcome, createdAt DESC);

-- Audit history is immutable even to application bugs or a future route that
-- accidentally receives broad write access. Corrections are new events.
CREATE TRIGGER IF NOT EXISTS audit_event_no_update
BEFORE UPDATE ON audit_event
BEGIN
  SELECT RAISE(ABORT, 'audit_event is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_event_no_delete
BEFORE DELETE ON audit_event
BEGIN
  SELECT RAISE(ABORT, 'audit_event is append-only');
END;

CREATE TABLE IF NOT EXISTS organization_limit (
  organizationId TEXT PRIMARY KEY REFERENCES organization (id) ON DELETE CASCADE,
  members INTEGER NOT NULL DEFAULT 25,
  workspaces INTEGER NOT NULL DEFAULT 8,
  projects INTEGER NOT NULL DEFAULT 100,
  nodes INTEGER NOT NULL DEFAULT 25,
  deployments INTEGER NOT NULL DEFAULT 2000,
  gameServers INTEGER NOT NULL DEFAULT 25,
  aiJobs INTEGER NOT NULL DEFAULT 2000,
  storageMetadata INTEGER NOT NULL DEFAULT 5000,
  updatedAt INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_limit (
  workspaceId TEXT PRIMARY KEY REFERENCES workspace (id) ON DELETE CASCADE,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  members INTEGER NOT NULL DEFAULT 25,
  projects INTEGER NOT NULL DEFAULT 25,
  nodes INTEGER NOT NULL DEFAULT 10,
  deployments INTEGER NOT NULL DEFAULT 1000,
  gameServers INTEGER NOT NULL DEFAULT 10,
  aiJobs INTEGER NOT NULL DEFAULT 1000,
  storageMetadata INTEGER NOT NULL DEFAULT 1000,
  updatedAt INTEGER NOT NULL
);

-- Denormalized organization/workspace keys make queries cheap, but they must
-- never be allowed to disagree. These triggers turn a programming mistake
-- into a failed write instead of a cross-tenant row.
CREATE TRIGGER IF NOT EXISTS workspace_org_insert_guard
BEFORE INSERT ON workspace
WHEN NEW.organizationId IS NULL OR NOT EXISTS (
  SELECT 1 FROM organization o WHERE o.id = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'workspace organization mismatch');
END;

CREATE TRIGGER IF NOT EXISTS workspace_org_update_guard
BEFORE UPDATE OF organizationId ON workspace
WHEN NEW.organizationId IS NULL OR NEW.organizationId <> OLD.organizationId OR NOT EXISTS (
  SELECT 1 FROM organization o WHERE o.id = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'workspace organization is immutable');
END;

CREATE TRIGGER IF NOT EXISTS workspace_member_tenant_guard
BEFORE INSERT ON workspace_member
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR NOT EXISTS (
  SELECT 1 FROM organization_member m
   WHERE m.organizationId = NEW.organizationId AND m.userId = NEW.userId
)
BEGIN
  SELECT RAISE(ABORT, 'workspace member tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS workspace_member_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, userId ON workspace_member
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR NOT EXISTS (
  SELECT 1 FROM organization_member m
   WHERE m.organizationId = NEW.organizationId AND m.userId = NEW.userId
)
BEGIN
  SELECT RAISE(ABORT, 'workspace member tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS project_access_tenant_guard
BEFORE INSERT ON member_project_access
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR NOT EXISTS (
  SELECT 1 FROM project p
   WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
) OR NOT EXISTS (
  SELECT 1 FROM organization_member m
   WHERE m.organizationId = NEW.organizationId AND m.userId = NEW.userId
)
BEGIN
  SELECT RAISE(ABORT, 'project access tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS project_access_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, userId, projectId ON member_project_access
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR NOT EXISTS (
  SELECT 1 FROM project p
   WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
) OR NOT EXISTS (
  SELECT 1 FROM organization_member m
   WHERE m.organizationId = NEW.organizationId AND m.userId = NEW.userId
)
BEGIN
  SELECT RAISE(ABORT, 'project access tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS invitation_tenant_guard
BEFORE INSERT ON organization_invitation
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'invitation tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS invitation_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId ON organization_invitation
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'invitation tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS service_account_tenant_guard
BEFORE INSERT ON service_account
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p
   WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
))
BEGIN
  SELECT RAISE(ABORT, 'service account tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS service_account_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, projectId ON service_account
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.projectId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM project p
   WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
))
BEGIN
  SELECT RAISE(ABORT, 'service account tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS audit_event_tenant_guard
BEFORE INSERT ON audit_event
WHEN NEW.workspaceId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'audit event tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS workspace_limit_tenant_guard
BEFORE INSERT ON workspace_limit
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'workspace limit tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS workspace_limit_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId ON workspace_limit
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'workspace limit tenant mismatch');
END;

-- The designated organization owner must remain an active owner. The
-- transfer flow first promotes the target, then changes ownerUserId, then
-- demotes the previous owner in one D1 batch.
CREATE TRIGGER IF NOT EXISTS organization_owner_target_guard
BEFORE UPDATE OF ownerUserId ON organization
WHEN NEW.ownerUserId <> OLD.ownerUserId AND NOT EXISTS (
  SELECT 1 FROM organization_member m
   WHERE m.organizationId = OLD.id AND m.userId = NEW.ownerUserId
     AND m.role = 'owner' AND m.status = 'active' AND m.suspendedAt IS NULL
)
BEGIN
  SELECT RAISE(ABORT, 'new owner must be an active owner member');
END;

CREATE TRIGGER IF NOT EXISTS organization_last_owner_update_guard
BEFORE UPDATE OF role, status, suspendedAt ON organization_member
WHEN OLD.role = 'owner' AND OLD.status = 'active' AND OLD.suspendedAt IS NULL
 AND (NEW.role <> 'owner' OR NEW.status <> 'active' OR NEW.suspendedAt IS NOT NULL)
 AND (
   OLD.userId = (SELECT ownerUserId FROM organization WHERE id = OLD.organizationId)
   OR (SELECT COUNT(*) FROM organization_member
        WHERE organizationId = OLD.organizationId AND role = 'owner'
          AND status = 'active' AND suspendedAt IS NULL) <= 1
 )
BEGIN
  SELECT RAISE(ABORT, 'organization must retain its designated owner');
END;

CREATE TRIGGER IF NOT EXISTS organization_last_owner_delete_guard
BEFORE DELETE ON organization_member
WHEN OLD.role = 'owner' AND OLD.status = 'active' AND OLD.suspendedAt IS NULL
 AND (
   OLD.userId = (SELECT ownerUserId FROM organization WHERE id = OLD.organizationId)
   OR (SELECT COUNT(*) FROM organization_member
        WHERE organizationId = OLD.organizationId AND role = 'owner'
          AND status = 'active' AND suspendedAt IS NULL) <= 1
 )
BEGIN
  SELECT RAISE(ABORT, 'organization must retain its designated owner');
END;

INSERT OR IGNORE INTO organization_limit (organizationId, updatedAt)
SELECT id, updatedAt FROM organization;

INSERT OR IGNORE INTO workspace_limit (workspaceId, organizationId, updatedAt)
SELECT id, organizationId, updatedAt FROM workspace WHERE organizationId IS NOT NULL;

-- The old instance-level member role had ordinary workspace mutation rights.
-- Map it to developer so migration never silently downgrades an account.
UPDATE user_role SET role = 'developer' WHERE role = 'member';

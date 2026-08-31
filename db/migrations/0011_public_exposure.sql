-- Phase 8: Public App Exposure & Domains.
--
-- The Worker remains the only Internet-facing service. These tables hold
-- bounded route, policy, health, and ownership metadata; they never hold an
-- origin URL, a node IP address, a shell command, or a Tunnel credential.

CREATE TABLE IF NOT EXISTS public_exposure (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT NOT NULL REFERENCES project (id) ON DELETE CASCADE,
  deploymentId TEXT NOT NULL REFERENCES deployment (id) ON DELETE CASCADE,
  routeId TEXT NOT NULL UNIQUE,
  routePath TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL DEFAULT 'private'
    CHECK (mode IN ('private', 'public', 'custom-domain')),
  status TEXT NOT NULL DEFAULT 'disabled'
    CHECK (status IN (
      'disabled', 'pending', 'unavailable_zero_mode', 'active', 'degraded',
      'expired', 'revoked', 'failed', 'deleted'
    )),
  accessPolicy TEXT NOT NULL DEFAULT 'public'
    CHECK (accessPolicy IN ('public', 'authenticated')),
  transport TEXT NOT NULL DEFAULT 'none'
    CHECK (transport IN ('none', 'cloudflare_tunnel')),
  transportState TEXT NOT NULL DEFAULT 'unavailable_zero_mode'
    CHECK (transportState IN (
      'unavailable_zero_mode', 'disconnected', 'ready', 'revoked', 'failed'
    )),
  assignedHostname TEXT,
  targetNodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  targetArtifactId TEXT REFERENCES app_artifact (id) ON DELETE SET NULL,
  healthState TEXT NOT NULL DEFAULT 'unknown'
    CHECK (healthState IN ('unknown', 'healthy', 'stale', 'offline', 'revoked', 'failed')),
  tlsState TEXT NOT NULL DEFAULT 'unavailable'
    CHECK (tlsState IN ('unavailable', 'pending', 'cloudflare')),
  verificationState TEXT NOT NULL DEFAULT 'not_required'
    CHECK (verificationState IN ('not_required', 'pending', 'verified', 'failed')),
  fallbackPolicy TEXT NOT NULL DEFAULT 'none'
    CHECK (fallbackPolicy IN ('none', 'previous_healthy')),
  rateLimitEnabled INTEGER NOT NULL DEFAULT 1 CHECK (rateLimitEnabled IN (0, 1)),
  rateLimitPerMinute INTEGER NOT NULL DEFAULT 60
    CHECK (rateLimitPerMinute BETWEEN 5 AND 600),
  ipAllowlist TEXT NOT NULL DEFAULT '[]',
  isPreview INTEGER NOT NULL DEFAULT 0 CHECK (isPreview IN (0, 1)),
  expiresAt INTEGER,
  lastRequestAt INTEGER,
  lastError TEXT,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  deletedAt INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS public_exposure_deployment_uidx
  ON public_exposure (deploymentId, isPreview)
  WHERE deletedAt IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS public_exposure_hostname_uidx
  ON public_exposure (assignedHostname)
  WHERE assignedHostname IS NOT NULL AND deletedAt IS NULL;
CREATE INDEX IF NOT EXISTS public_exposure_workspace_idx
  ON public_exposure (organizationId, workspaceId, projectId, updatedAt DESC);
CREATE INDEX IF NOT EXISTS public_exposure_gateway_idx
  ON public_exposure (routeId, status, deletedAt);

CREATE TABLE IF NOT EXISTS exposure_domain (
  id TEXT PRIMARY KEY,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  dnsRecordName TEXT NOT NULL,
  tokenHash TEXT NOT NULL UNIQUE,
  tokenPrefix TEXT NOT NULL,
  ownershipState TEXT NOT NULL DEFAULT 'pending'
    CHECK (ownershipState IN ('pending', 'verified', 'failed')),
  providerState TEXT NOT NULL DEFAULT 'no_owned_zone'
    CHECK (providerState IN ('no_owned_zone', 'ready', 'unavailable_zero_mode')),
  attachState TEXT NOT NULL DEFAULT 'detached'
    CHECK (attachState IN ('detached', 'pending', 'attached')),
  tlsState TEXT NOT NULL DEFAULT 'unavailable'
    CHECK (tlsState IN ('unavailable', 'pending', 'cloudflare')),
  exposureId TEXT REFERENCES public_exposure (id) ON DELETE SET NULL,
  verifiedAt INTEGER,
  attachedAt INTEGER,
  detachedAt INTEGER,
  lastError TEXT,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  deletedAt INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS exposure_domain_hostname_uidx
  ON exposure_domain (hostname) WHERE deletedAt IS NULL;
CREATE INDEX IF NOT EXISTS exposure_domain_workspace_idx
  ON exposure_domain (organizationId, workspaceId, updatedAt DESC);
CREATE INDEX IF NOT EXISTS exposure_domain_target_idx
  ON exposure_domain (exposureId, attachState) WHERE deletedAt IS NULL;

-- Every denormalized tenant and target key is checked at the database edge.
-- A programming error becomes a failed write instead of a cross-organization
-- route or domain assignment.
CREATE TRIGGER IF NOT EXISTS public_exposure_tenant_guard
BEFORE INSERT ON public_exposure
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR NOT EXISTS (
  SELECT 1 FROM project p
   WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
) OR NOT EXISTS (
  SELECT 1 FROM deployment d
   WHERE d.id = NEW.deploymentId AND d.workspaceId = NEW.workspaceId
     AND d.projectId = NEW.projectId AND d.nodeId = NEW.targetNodeId
) OR NOT EXISTS (
  SELECT 1 FROM compute_node n
   WHERE n.id = NEW.targetNodeId AND n.workspaceId = NEW.workspaceId
) OR (NEW.targetArtifactId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM app_artifact a
   WHERE a.id = NEW.targetArtifactId AND a.workspaceId = NEW.workspaceId
     AND a.projectId = NEW.projectId AND a.deploymentId = NEW.deploymentId
     AND a.nodeId = NEW.targetNodeId AND a.deletedAt IS NULL
))
BEGIN
  SELECT RAISE(ABORT, 'public exposure tenant or target mismatch');
END;
CREATE TRIGGER IF NOT EXISTS public_exposure_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, projectId, deploymentId,
  targetNodeId, targetArtifactId ON public_exposure
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR NOT EXISTS (
  SELECT 1 FROM project p
   WHERE p.id = NEW.projectId AND p.workspaceId = NEW.workspaceId
) OR NOT EXISTS (
  SELECT 1 FROM deployment d
   WHERE d.id = NEW.deploymentId AND d.workspaceId = NEW.workspaceId
     AND d.projectId = NEW.projectId AND d.nodeId = NEW.targetNodeId
) OR NOT EXISTS (
  SELECT 1 FROM compute_node n
   WHERE n.id = NEW.targetNodeId AND n.workspaceId = NEW.workspaceId
) OR (NEW.targetArtifactId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM app_artifact a
   WHERE a.id = NEW.targetArtifactId AND a.workspaceId = NEW.workspaceId
     AND a.projectId = NEW.projectId AND a.deploymentId = NEW.deploymentId
     AND a.nodeId = NEW.targetNodeId AND a.deletedAt IS NULL
))
BEGIN
  SELECT RAISE(ABORT, 'public exposure tenant or target mismatch');
END;

CREATE TRIGGER IF NOT EXISTS exposure_domain_tenant_guard
BEFORE INSERT ON exposure_domain
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.exposureId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM public_exposure e
   WHERE e.id = NEW.exposureId AND e.organizationId = NEW.organizationId
     AND e.workspaceId = NEW.workspaceId AND e.deletedAt IS NULL
))
BEGIN
  SELECT RAISE(ABORT, 'exposure domain tenant mismatch');
END;

CREATE TRIGGER IF NOT EXISTS exposure_domain_tenant_update_guard
BEFORE UPDATE OF organizationId, workspaceId, exposureId ON exposure_domain
WHEN NOT EXISTS (
  SELECT 1 FROM workspace w
   WHERE w.id = NEW.workspaceId AND w.organizationId = NEW.organizationId
) OR (NEW.exposureId IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM public_exposure e
   WHERE e.id = NEW.exposureId AND e.organizationId = NEW.organizationId
     AND e.workspaceId = NEW.workspaceId AND e.deletedAt IS NULL
))
BEGIN
  SELECT RAISE(ABORT, 'exposure domain tenant mismatch');
END;

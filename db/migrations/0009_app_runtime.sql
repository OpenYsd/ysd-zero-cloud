-- Phase 6: Node.js App Runtime on user-owned Compute Nodes.
--
-- Source archives, dependency caches, artifacts, application processes, and
-- full logs stay local. D1 stores bounded control-plane metadata only.

ALTER TABLE deployment ADD COLUMN branch TEXT NOT NULL DEFAULT 'main';
ALTER TABLE deployment ADD COLUMN environment TEXT NOT NULL DEFAULT 'Production';
ALTER TABLE deployment ADD COLUMN nodeId TEXT;
ALTER TABLE deployment ADD COLUMN jobId TEXT;
ALTER TABLE deployment ADD COLUMN currentArtifactId TEXT;
ALTER TABLE deployment ADD COLUMN localPort INTEGER;
ALTER TABLE deployment ADD COLUMN localAddress TEXT;
ALTER TABLE deployment ADD COLUMN exposure TEXT NOT NULL DEFAULT 'private';
ALTER TABLE deployment ADD COLUMN observedBind TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE deployment ADD COLUMN healthPath TEXT NOT NULL DEFAULT '/';
ALTER TABLE deployment ADD COLUMN buildDurationMs INTEGER;
ALTER TABLE deployment ADD COLUMN startedAt INTEGER;
ALTER TABLE deployment ADD COLUMN updatedAt INTEGER;
ALTER TABLE deployment ADD COLUMN lastError TEXT;
ALTER TABLE deployment ADD COLUMN restartCount INTEGER NOT NULL DEFAULT 0;
ALTER TABLE deployment ADD COLUMN crashLoop INTEGER NOT NULL DEFAULT 0;
ALTER TABLE deployment ADD COLUMN deletedAt INTEGER;

CREATE UNIQUE INDEX IF NOT EXISTS deployment_node_port_uidx
  ON deployment (nodeId, localPort)
  WHERE nodeId IS NOT NULL AND localPort IS NOT NULL AND deletedAt IS NULL
    AND state <> 'blocked';
CREATE INDEX IF NOT EXISTS deployment_node_state_idx
  ON deployment (workspaceId, nodeId, state, createdAt DESC);

CREATE TABLE IF NOT EXISTS app_deployment_action (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  deploymentId TEXT NOT NULL REFERENCES deployment (id) ON DELETE CASCADE,
  projectId TEXT NOT NULL REFERENCES project (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  jobId TEXT NOT NULL UNIQUE REFERENCES node_job (id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  idempotencyKey TEXT,
  requestedBy TEXT NOT NULL,
  error TEXT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  completedAt INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS app_deployment_action_idempotency_uidx
  ON app_deployment_action (workspaceId, idempotencyKey)
  WHERE idempotencyKey IS NOT NULL;
CREATE INDEX IF NOT EXISTS app_deployment_action_workspace_idx
  ON app_deployment_action (workspaceId, deploymentId, createdAt DESC);

CREATE TABLE IF NOT EXISTS app_artifact (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  deploymentId TEXT NOT NULL REFERENCES deployment (id) ON DELETE CASCADE,
  projectId TEXT NOT NULL REFERENCES project (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  commitSha TEXT NOT NULL,
  version INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'building',
  manifest TEXT NOT NULL,
  checksum TEXT,
  sizeBytes INTEGER NOT NULL DEFAULT 0,
  createdAt INTEGER NOT NULL,
  verifiedAt INTEGER,
  activatedAt INTEGER,
  deletedAt INTEGER,
  UNIQUE (projectId, nodeId, version)
);

CREATE INDEX IF NOT EXISTS app_artifact_workspace_idx
  ON app_artifact (workspaceId, projectId, createdAt DESC);

CREATE TABLE IF NOT EXISTS app_deployment_log (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  deploymentId TEXT NOT NULL REFERENCES deployment (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  level TEXT NOT NULL,
  phase TEXT NOT NULL,
  message TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS app_deployment_log_workspace_idx
  ON app_deployment_log (workspaceId, deploymentId, createdAt DESC);

CREATE TABLE IF NOT EXISTS app_deployment_metric (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  deploymentId TEXT NOT NULL REFERENCES deployment (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  cpuLoadPercent REAL,
  memoryUsedBytes INTEGER,
  uptimeSeconds INTEGER NOT NULL DEFAULT 0,
  restartCount INTEGER NOT NULL DEFAULT 0,
  recordedAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS app_deployment_metric_workspace_idx
  ON app_deployment_metric (workspaceId, deploymentId, recordedAt DESC);

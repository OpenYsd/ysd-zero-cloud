-- Phase 3: outbound-only user-owned compute nodes.
--
-- Cloudflare remains the control plane. Every row is workspace-scoped and all
-- compute happens on a paired machine owned by the operator. Pairing secrets
-- and node credentials are never stored in plaintext.

CREATE TABLE IF NOT EXISTS node_pairing (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  codeHash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  createdBy TEXT NOT NULL,
  nodeId TEXT,
  expiresAt INTEGER NOT NULL,
  consumedAt INTEGER,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS node_pairing_workspace_idx
  ON node_pairing (workspaceId, createdAt DESC);

CREATE TABLE IF NOT EXISTS compute_node (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  pairingId TEXT NOT NULL UNIQUE REFERENCES node_pairing (id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  agentVersion TEXT NOT NULL,
  protocolVersion INTEGER NOT NULL,
  platform TEXT NOT NULL,
  architecture TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  tokenCiphertext TEXT NOT NULL,
  tokenHash TEXT NOT NULL UNIQUE,
  pairedAt INTEGER NOT NULL,
  lastHeartbeatAt INTEGER,
  revokedAt INTEGER,
  revokedBy TEXT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS compute_node_workspace_idx
  ON compute_node (workspaceId, createdAt DESC);
CREATE INDEX IF NOT EXISTS compute_node_heartbeat_idx
  ON compute_node (workspaceId, lastHeartbeatAt DESC);

CREATE TABLE IF NOT EXISTS node_request_nonce (
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE CASCADE,
  nonce TEXT NOT NULL,
  requestTimestamp INTEGER NOT NULL,
  createdAt INTEGER NOT NULL,
  PRIMARY KEY (nodeId, nonce)
);

CREATE INDEX IF NOT EXISTS node_request_nonce_workspace_idx
  ON node_request_nonce (workspaceId, createdAt DESC);

CREATE INDEX IF NOT EXISTS node_request_nonce_created_idx
  ON node_request_nonce (createdAt);

CREATE TABLE IF NOT EXISTS node_job (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,
  payloadHash TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 0,
  idempotencyKey TEXT,
  targetNodeId TEXT REFERENCES compute_node (id) ON DELETE SET NULL,
  assignedNodeId TEXT REFERENCES compute_node (id) ON DELETE SET NULL,
  leaseId TEXT,
  leaseExpiresAt INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  maxAttempts INTEGER NOT NULL DEFAULT 3,
  claimSignature TEXT,
  result TEXT,
  lastError TEXT,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  completedAt INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS node_job_idempotency_uidx
  ON node_job (workspaceId, idempotencyKey)
  WHERE idempotencyKey IS NOT NULL;
CREATE INDEX IF NOT EXISTS node_job_queue_idx
  ON node_job (workspaceId, state, priority DESC, createdAt ASC);
CREATE INDEX IF NOT EXISTS node_job_node_idx
  ON node_job (workspaceId, assignedNodeId, updatedAt DESC);

CREATE TABLE IF NOT EXISTS node_metric (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE CASCADE,
  cpuLoadPercent REAL NOT NULL,
  memoryUsedBytes INTEGER NOT NULL,
  memoryTotalBytes INTEGER NOT NULL,
  runningJobs INTEGER NOT NULL,
  recordedAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS node_metric_node_idx
  ON node_metric (workspaceId, nodeId, recordedAt DESC);

CREATE TABLE IF NOT EXISTS node_job_event (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  nodeId TEXT REFERENCES compute_node (id) ON DELETE SET NULL,
  jobId TEXT REFERENCES node_job (id) ON DELETE SET NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS node_job_event_workspace_idx
  ON node_job_event (workspaceId, createdAt DESC);

CREATE TABLE IF NOT EXISTS node_security_event (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  nodeId TEXT REFERENCES compute_node (id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  detail TEXT NOT NULL,
  networkFingerprint TEXT,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS node_security_event_workspace_idx
  ON node_security_event (workspaceId, createdAt DESC);

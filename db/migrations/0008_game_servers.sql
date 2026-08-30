-- Phase 5: Minecraft Java control-plane metadata for user-owned nodes.
--
-- Server binaries, worlds, backups, RCON material, and full logs remain local
-- to the node. D1 stores bounded operational metadata and signed action links.

CREATE TABLE IF NOT EXISTS game_server (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  game TEXT NOT NULL DEFAULT 'minecraft-java',
  serverType TEXT NOT NULL DEFAULT 'vanilla',
  version TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'provisioning',
  desiredStatus TEXT NOT NULL DEFAULT 'stopped',
  ramMb INTEGER NOT NULL,
  cpuCores INTEGER NOT NULL,
  diskQuotaBytes INTEGER NOT NULL,
  port INTEGER NOT NULL,
  exposurePolicy TEXT NOT NULL DEFAULT 'private',
  observedExposure TEXT NOT NULL DEFAULT 'private',
  playerCount INTEGER NOT NULL DEFAULT 0,
  playersJson TEXT NOT NULL DEFAULT '[]',
  worldsJson TEXT NOT NULL DEFAULT '["world","world_nether","world_the_end"]',
  cpuLoadPercent REAL,
  memoryUsedBytes INTEGER,
  uptimeSeconds INTEGER NOT NULL DEFAULT 0,
  onlineMode INTEGER NOT NULL DEFAULT 1,
  whitelistEnabled INTEGER NOT NULL DEFAULT 1,
  config TEXT NOT NULL,
  binaryHash TEXT,
  binaryVerified INTEGER NOT NULL DEFAULT 0,
  crashCount INTEGER NOT NULL DEFAULT 0,
  crashLoop INTEGER NOT NULL DEFAULT 0,
  lastError TEXT,
  lastStatusAt INTEGER,
  createdBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  deletedAt INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS game_server_node_port_uidx
  ON game_server (nodeId, port) WHERE deletedAt IS NULL;
CREATE INDEX IF NOT EXISTS game_server_workspace_idx
  ON game_server (workspaceId, createdAt DESC);
CREATE INDEX IF NOT EXISTS game_server_node_idx
  ON game_server (workspaceId, nodeId, status);

CREATE TABLE IF NOT EXISTS game_server_action (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  serverId TEXT NOT NULL REFERENCES game_server (id) ON DELETE CASCADE,
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

CREATE UNIQUE INDEX IF NOT EXISTS game_server_action_idempotency_uidx
  ON game_server_action (workspaceId, idempotencyKey)
  WHERE idempotencyKey IS NOT NULL;
CREATE INDEX IF NOT EXISTS game_server_action_workspace_idx
  ON game_server_action (workspaceId, serverId, createdAt DESC);

CREATE TABLE IF NOT EXISTS game_server_backup (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  serverId TEXT NOT NULL REFERENCES game_server (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'creating',
  sizeBytes INTEGER NOT NULL DEFAULT 0,
  checksum TEXT,
  fileCount INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  createdAt INTEGER NOT NULL,
  verifiedAt INTEGER,
  restoredAt INTEGER,
  deletedAt INTEGER,
  updatedAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS game_server_backup_workspace_idx
  ON game_server_backup (workspaceId, serverId, createdAt DESC);

CREATE TABLE IF NOT EXISTS game_server_log (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  serverId TEXT NOT NULL REFERENCES game_server (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE RESTRICT,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS game_server_log_workspace_idx
  ON game_server_log (workspaceId, serverId, createdAt DESC);

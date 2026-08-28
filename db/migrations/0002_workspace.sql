-- YSD Zero Cloud workspace schema.
--
-- Timestamps are stored as integer epoch milliseconds so D1 can sort and range
-- them without a date function, and so the Node test runner and workerd agree
-- on the value.

CREATE TABLE IF NOT EXISTS workspace (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  ownerUserId TEXT NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
  zeroMode INTEGER NOT NULL DEFAULT 1,
  autoScan INTEGER NOT NULL DEFAULT 1,
  sleepIdleServers INTEGER NOT NULL DEFAULT 1,
  previewDeployments INTEGER NOT NULL DEFAULT 0,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS workspace_owner_uidx ON workspace (ownerUserId);

CREATE TABLE IF NOT EXISTS project (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  repository TEXT,
  framework TEXT NOT NULL DEFAULT 'Next.js',
  environment TEXT NOT NULL DEFAULT 'Production',
  region TEXT NOT NULL DEFAULT 'Global Edge',
  status TEXT NOT NULL DEFAULT 'idle',
  visibility TEXT NOT NULL DEFAULT 'private',
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS project_name_uidx ON project (workspaceId, name);
CREATE INDEX IF NOT EXISTS project_workspace_idx ON project (workspaceId);

CREATE TABLE IF NOT EXISTS deployment (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  projectId TEXT REFERENCES project (id) ON DELETE SET NULL,
  repository TEXT NOT NULL,
  target TEXT NOT NULL,
  framework TEXT NOT NULL,
  commitSha TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued',
  durationMs INTEGER,
  estimatedMonthlyCost REAL NOT NULL DEFAULT 0,
  zeroModeEnabled INTEGER NOT NULL DEFAULT 1,
  plan TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  finishedAt INTEGER
);

CREATE INDEX IF NOT EXISTS deployment_workspace_idx ON deployment (workspaceId, createdAt DESC);

CREATE TABLE IF NOT EXISTS log_event (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  level TEXT NOT NULL DEFAULT 'INFO',
  source TEXT NOT NULL,
  message TEXT NOT NULL,
  actor TEXT,
  resource TEXT,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS log_event_workspace_idx ON log_event (workspaceId, createdAt DESC);
CREATE INDEX IF NOT EXISTS log_event_source_idx ON log_event (workspaceId, source);

CREATE TABLE IF NOT EXISTS secret (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'Workspace',
  environment TEXT NOT NULL DEFAULT 'Production',
  ciphertext TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  rotationDays INTEGER,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS secret_name_uidx ON secret (workspaceId, environment, name);

CREATE TABLE IF NOT EXISTS shield_scan (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  score INTEGER NOT NULL,
  grade TEXT NOT NULL,
  headline TEXT NOT NULL,
  checks TEXT NOT NULL,
  findingCount INTEGER NOT NULL DEFAULT 0,
  durationMs INTEGER NOT NULL DEFAULT 0,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS shield_scan_workspace_idx ON shield_scan (workspaceId, createdAt DESC);

CREATE TABLE IF NOT EXISTS shield_finding (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  resource TEXT NOT NULL,
  severity TEXT NOT NULL,
  remediation TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  firstSeenAt INTEGER NOT NULL,
  lastSeenAt INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS shield_finding_code_uidx ON shield_finding (workspaceId, code);
CREATE INDEX IF NOT EXISTS shield_finding_status_idx ON shield_finding (workspaceId, status);

-- Phase 4: AI control-plane metadata for user-owned Compute Nodes.
--
-- Models and inference records are workspace-scoped. Model bytes, prompts,
-- inference, and GPU work never run on or upload to Cloudflare.

CREATE TABLE IF NOT EXISTS ai_model (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  catalogId TEXT NOT NULL,
  displayName TEXT NOT NULL,
  runtime TEXT NOT NULL,
  family TEXT NOT NULL,
  runtimeModel TEXT NOT NULL,
  source TEXT NOT NULL,
  sizeBytes INTEGER NOT NULL,
  expectedMemoryBytes INTEGER NOT NULL,
  requiredVramBytes INTEGER NOT NULL,
  checksum TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL DEFAULT 'available',
  lastVerifiedAt INTEGER,
  lastUsedAt INTEGER,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL,
  UNIQUE (workspaceId, catalogId)
);

CREATE INDEX IF NOT EXISTS ai_model_workspace_idx
  ON ai_model (workspaceId, enabled, createdAt ASC);

CREATE TABLE IF NOT EXISTS ai_model_cache (
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  nodeId TEXT NOT NULL REFERENCES compute_node (id) ON DELETE CASCADE,
  modelId TEXT NOT NULL REFERENCES ai_model (id) ON DELETE CASCADE,
  state TEXT NOT NULL,
  sizeBytes INTEGER NOT NULL DEFAULT 0,
  checksum TEXT,
  error TEXT,
  lastVerifiedAt INTEGER,
  lastUsedAt INTEGER,
  updatedAt INTEGER NOT NULL,
  PRIMARY KEY (nodeId, modelId)
);

CREATE INDEX IF NOT EXISTS ai_model_cache_workspace_idx
  ON ai_model_cache (workspaceId, modelId, state, updatedAt DESC);

CREATE TABLE IF NOT EXISTS ai_inference (
  jobId TEXT PRIMARY KEY REFERENCES node_job (id) ON DELETE CASCADE,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  modelId TEXT NOT NULL REFERENCES ai_model (id) ON DELETE RESTRICT,
  requestedNodeId TEXT REFERENCES compute_node (id) ON DELETE SET NULL,
  selectedNodeId TEXT REFERENCES compute_node (id) ON DELETE SET NULL,
  provider TEXT NOT NULL DEFAULT 'local-node',
  zeroMode INTEGER NOT NULL DEFAULT 1,
  promptCharacters INTEGER NOT NULL,
  systemPromptCharacters INTEGER NOT NULL,
  maxTokens INTEGER NOT NULL,
  temperature REAL NOT NULL,
  responseFormat TEXT NOT NULL,
  inputTokensEstimate INTEGER,
  outputTokensEstimate INTEGER,
  latencyMs INTEGER,
  cancelRequestedAt INTEGER,
  cancelledBy TEXT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS ai_inference_workspace_idx
  ON ai_inference (workspaceId, createdAt DESC);
CREATE INDEX IF NOT EXISTS ai_inference_node_idx
  ON ai_inference (workspaceId, selectedNodeId, createdAt DESC);

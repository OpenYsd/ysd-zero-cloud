-- Private R2 object metadata and the application-side free-tier meters.
--
-- The R2 bucket itself is never public. D1 is the authorization index and the
-- quota ledger, so an object cannot be addressed without a signed-in workspace
-- session and usage stops well below Cloudflare's account-level free tier.

CREATE TABLE IF NOT EXISTS storage_object (
  id TEXT PRIMARY KEY,
  workspaceId TEXT NOT NULL REFERENCES workspace (id) ON DELETE CASCADE,
  r2Key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  contentType TEXT NOT NULL,
  size INTEGER NOT NULL CHECK (size >= 0),
  etag TEXT NOT NULL,
  uploadedBy TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS storage_object_workspace_idx
  ON storage_object (workspaceId, createdAt DESC);

-- One row per workspace plus one `global` row. `workspaceId` is null only for
-- the global account guard; Studio's tenancy predicate therefore cannot show
-- that row to an ordinary workspace.
CREATE TABLE IF NOT EXISTS storage_meter (
  scope TEXT PRIMARY KEY,
  workspaceId TEXT REFERENCES workspace (id) ON DELETE CASCADE,
  bytesUsed INTEGER NOT NULL DEFAULT 0 CHECK (bytesUsed >= 0),
  bytesReserved INTEGER NOT NULL DEFAULT 0 CHECK (bytesReserved >= 0),
  objectCount INTEGER NOT NULL DEFAULT 0 CHECK (objectCount >= 0),
  period TEXT NOT NULL,
  classAWrites INTEGER NOT NULL DEFAULT 0 CHECK (classAWrites >= 0),
  classBReads INTEGER NOT NULL DEFAULT 0 CHECK (classBReads >= 0),
  updatedAt INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS storage_meter_workspace_idx
  ON storage_meter (workspaceId);

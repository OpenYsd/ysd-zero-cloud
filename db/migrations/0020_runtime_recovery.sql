-- Phase 18: same-node runtime recovery.
--
-- The legacy `deployment.state` mixed the operator's intent with the last
-- runtime observation. These additive columns separate those facts. Existing
-- Workers ignore every new nullable column, so 0020 can be applied before the
-- 0.18.0 Worker. No recovery job is created by this migration.

ALTER TABLE deployment ADD COLUMN desiredState TEXT;
ALTER TABLE deployment ADD COLUMN desiredRevision INTEGER;
ALTER TABLE deployment ADD COLUMN observedState TEXT;
ALTER TABLE deployment ADD COLUMN lastReconciledAt INTEGER;
ALTER TABLE deployment ADD COLUMN recoveryStatus TEXT;
ALTER TABLE deployment ADD COLUMN recoveryReasonCode TEXT;
ALTER TABLE deployment ADD COLUMN recoveryRevision INTEGER;
ALTER TABLE deployment ADD COLUMN recoveryGeneration TEXT;

ALTER TABLE app_artifact ADD COLUMN availabilityState TEXT;
ALTER TABLE app_artifact ADD COLUMN lastVerifiedOnNodeAt INTEGER;

-- Conservative deterministic compatibility backfill. Historical healthy and
-- in-progress states prove that the last committed intent was to run, but they
-- do not prove that a runtime is healthy now. Terminal stopped/revoked/deleted
-- states can never become desired Running during migration.
UPDATE deployment
SET desiredState = CASE
      WHEN state IN ('planned','blocked','stopping','stopped','deleting','deleted','cancelled','node_revoked')
        THEN 'stopped'
      ELSE 'running'
    END,
    desiredRevision = 1,
    observedState = CASE WHEN state IN ('stopped','deleted') THEN 'stopped' ELSE 'unknown' END
WHERE desiredState IS NULL AND desiredRevision IS NULL AND observedState IS NULL;

UPDATE app_artifact
SET availabilityState = 'unknown'
WHERE availabilityState IS NULL;

CREATE INDEX IF NOT EXISTS deployment_node_desired_idx
  ON deployment (workspaceId, nodeId, desiredState, deletedAt, updatedAt DESC);

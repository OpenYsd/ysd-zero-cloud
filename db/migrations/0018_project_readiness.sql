-- Phase 14: Repository Readiness & Deploy Planning.
--
-- Stores the latest repository readiness result on the project it belongs to.
--
-- Why columns on `project` rather than a new table:
--
--   * Only the latest result is ever shown. A per-analysis history table would
--     grow without bound, would need a retention policy, and would make the
--     Projects list a join or an N+1 -- the exact pattern the P0 pass removed
--     from Studio and Usage.
--   * One row per project means the list stays a single bounded SELECT, and the
--     summary columns can be read without parsing the stored report at all.
--   * The rows are cascade-deleted with the project, so there is nothing to
--     prune and nothing to leak after a project is removed.
--
-- Why analysis does NOT write to `deployment`:
--
--   Readiness is not a deployment. Recording it as one would corrupt deployment
--   history, `countDeployments`, and the dashboard, and it would imply that
--   something ran. Nothing runs: analysis reads a public GitHub repository and
--   stores a verdict. A Compute Node is still mandatory for every build,
--   execution, and runtime action.
--
-- Safety properties of this migration:
--
--   * Additive only. Six nullable columns, no DROP, no DELETE, no UPDATE.
--   * No backfill. NULL means "never analyzed", which the UI renders as a real
--     state rather than guessing.
--   * No index. Readiness is always reached through `id`/`workspaceId`, which
--     are already indexed, so an extra index would only add write cost.
--   * No trigger. `project` is mutable by design; append-only semantics belong
--     to evidence, which keeps flowing through `audit_event` and stays covered
--     by the Phase 13 triggers.
--   * The tenant guards on `project` are untouched and keep applying.
--   * The previous Worker tolerates added nullable columns, exactly as 0017
--     demonstrated, so this can be applied before the new code is deployed.
--
-- The legacy orphan `projects` table (no source references) is deliberately not
-- touched.

ALTER TABLE project ADD COLUMN readinessAnalyzedAt INTEGER;
ALTER TABLE project ADD COLUMN readinessCommit TEXT;
ALTER TABLE project ADD COLUMN readinessFramework TEXT;
ALTER TABLE project ADD COLUMN readinessBlockedCount INTEGER;
ALTER TABLE project ADD COLUMN readinessReport TEXT;
ALTER TABLE project ADD COLUMN readinessSourceBranch TEXT;

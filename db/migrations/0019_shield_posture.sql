-- Phase 15: Shield Continuous Posture.
--
-- `workspace.autoScan` has been stored, defaulted on, and shown in Settings
-- since Phase 10, and nothing has ever read it to run a scan. Shield only ever
-- ran when a human pressed the button. This migration adds the columns a
-- scheduled sweep needs to be honest about what it did.
--
-- scanTrigger   'manual' | 'scheduled'. NULL on every row written before
--               0.15.0, which the UI labels "Legacy" rather than guessing.
--               Named scanTrigger, not trigger, because TRIGGER is a SQL
--               keyword and the unquoted column would be a tooling hazard.
--
-- scanStatus    'completed' | 'failed'. A scheduled scan that dies partway
--               must not leave a row that reads like a success, and the
--               scheduler needs to know an attempt happened so a workspace
--               that always fails cannot sit at the front of the queue and
--               consume every tick. NULL means a pre-0.15.0 row, which was
--               only ever written on success.
--
-- The four delta counters are persisted rather than recomputed. The delta for
-- the newest scan could be derived from shield_finding timestamps, but the
-- delta for a scan two weeks ago could not -- that history is gone the moment
-- a finding moves again. Storing four integers turns the trend into one
-- bounded SELECT over an index that already exists.
--
-- Safety properties:
--
--   * Additive only. Six nullable columns, no DROP, no DELETE, no UPDATE.
--   * No backfill. NULL is a real, displayable state ("Legacy", "unknown").
--   * No new table. shield_scan and shield_finding already carry the whole
--     lifecycle: status, firstSeenAt, lastSeenAt, acknowledgedAt,
--     acknowledgedBy, and UNIQUE (workspaceId, code).
--   * No new index. shield_scan_workspace_idx (workspaceId, createdAt DESC)
--     already serves the trend read, the newest-scan read, and the
--     least-recently-attempted ordering the scheduler needs.
--   * No trigger. Shield rows are mutable operational state by design;
--     immutability belongs to audit_event, which keeps its Phase 13 triggers.
--   * The previous Worker tolerates added nullable columns, as 0017 and 0018
--     both demonstrated, so this can be applied before the new code ships.
--
-- Scan history becomes bounded in application code (trimmed oldest-first per
-- workspace) rather than by a schema rule, because the cap is a product
-- decision and D1 has no scheduled vacuum to enforce one.

ALTER TABLE shield_scan ADD COLUMN scanTrigger TEXT;
ALTER TABLE shield_scan ADD COLUMN scanStatus TEXT;
ALTER TABLE shield_scan ADD COLUMN newFindings INTEGER;
ALTER TABLE shield_scan ADD COLUMN resolvedFindings INTEGER;
ALTER TABLE shield_scan ADD COLUMN reopenedFindings INTEGER;
ALTER TABLE shield_scan ADD COLUMN severityChangedFindings INTEGER;

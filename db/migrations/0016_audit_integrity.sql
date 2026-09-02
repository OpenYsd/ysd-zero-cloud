-- Phase 13: Audit Completeness & Evidence Integrity.
--
-- Goal: make an audit gap detectable. `audit_event` is already append-only at
-- the database (0010: `audit_event_no_update`, `audit_event_no_delete`), but
-- append-only proves no row was *changed* — it cannot prove no row was removed
-- beneath the triggers at the storage layer, because nothing records how many
-- rows there should be.
--
-- Design note, and why this is a side table rather than a column.
--
-- The obvious shape is `ALTER TABLE audit_event ADD COLUMN sequence`, then
-- backfill with an UPDATE. That is impossible here, and deliberately so:
-- `audit_event_no_update` aborts every UPDATE on the table. Dropping that
-- trigger to run a backfill would weaken the exact guarantee this phase
-- exists to strengthen, and would leave the table unprotected if the migration
-- failed midway. SQLite also cannot assign to NEW in a BEFORE INSERT trigger,
-- so the value cannot be filled in on the way past either.
--
-- `audit_sequence` therefore holds the numbering beside the evidence. Nothing
-- ever updates `audit_event`, its triggers are untouched, and the numbering is
-- assigned entirely by the database: the application never supplies, sees, or
-- can influence a sequence value.
--
-- Two tables also detect more than one would. A removed `audit_event` row
-- leaves an orphaned `audit_sequence` row; a removed `audit_sequence` row
-- leaves a gap in the run of integers. Either is a mismatch Shield can see.

CREATE TABLE IF NOT EXISTS audit_sequence (
  auditId TEXT PRIMARY KEY REFERENCES audit_event (id) ON DELETE RESTRICT,
  organizationId TEXT NOT NULL REFERENCES organization (id) ON DELETE RESTRICT,
  -- Monotonic from 1 within one organization, with no gaps while intact.
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  createdAt INTEGER NOT NULL,
  UNIQUE (organizationId, sequence)
);

CREATE INDEX IF NOT EXISTS audit_sequence_org_idx
  ON audit_sequence (organizationId, sequence DESC);
CREATE INDEX IF NOT EXISTS audit_sequence_created_idx
  ON audit_sequence (organizationId, createdAt DESC);

-- Backfill existing history deterministically.
--
-- Ordering is `createdAt` with `id` as a stable tie-breaker, so two rows
-- written in the same millisecond always number the same way no matter when
-- the migration runs. The NOT EXISTS guard makes this replayable: the lazy
-- migration runner may execute this file again on a cold isolate, and a second
-- pass must add nothing.
INSERT INTO audit_sequence (auditId, organizationId, sequence, createdAt)
SELECT e.id,
       e.organizationId,
       ROW_NUMBER() OVER (
         PARTITION BY e.organizationId ORDER BY e.createdAt ASC, e.id ASC
       ),
       e.createdAt
  FROM audit_event e
 WHERE NOT EXISTS (
   SELECT 1 FROM audit_sequence s WHERE s.auditId = e.id
 );

-- Assignment. The next number is read and written inside the same statement
-- that inserts the audit row, so the pair commits together or not at all.
-- D1 serialises writers on one database, and the UNIQUE (organizationId,
-- sequence) constraint above is the backstop if that ever stopped holding:
-- a duplicate aborts the insert rather than silently reusing a number.
CREATE TRIGGER IF NOT EXISTS audit_sequence_assign
AFTER INSERT ON audit_event
BEGIN
  INSERT INTO audit_sequence (auditId, organizationId, sequence, createdAt)
  VALUES (
    NEW.id,
    NEW.organizationId,
    COALESCE(
      (SELECT MAX(sequence) FROM audit_sequence WHERE organizationId = NEW.organizationId),
      0
    ) + 1,
    NEW.createdAt
  );
END;

-- A sequence row may only ever describe a real audit row in its own
-- organization. This is what stops a forged numbering being attributed to
-- another tenant.
CREATE TRIGGER IF NOT EXISTS audit_sequence_tenant_guard
BEFORE INSERT ON audit_sequence
WHEN NOT EXISTS (
  SELECT 1 FROM audit_event e
   WHERE e.id = NEW.auditId AND e.organizationId = NEW.organizationId
)
BEGIN
  SELECT RAISE(ABORT, 'audit sequence tenant mismatch');
END;

-- The numbering inherits the evidence guarantees of the table it describes.
CREATE TRIGGER IF NOT EXISTS audit_sequence_no_update
BEFORE UPDATE ON audit_sequence
BEGIN
  SELECT RAISE(ABORT, 'audit_sequence is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_sequence_no_delete
BEFORE DELETE ON audit_sequence
BEGIN
  SELECT RAISE(ABORT, 'audit_sequence is append-only');
END;

-- Phase 13 raises audit write volume, so the read paths the Audit surface and
-- the export use get a covering index for the new ordering.
CREATE INDEX IF NOT EXISTS audit_event_org_created_idx
  ON audit_event (organizationId, createdAt DESC, id);

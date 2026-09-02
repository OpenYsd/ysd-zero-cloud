import {
  EVIDENCE_LIMITS,
  evidenceAction,
  narrowEvidenceMetadata,
  type EvidenceActionName,
} from '@/lib/audit-actions';
import { createId, sha256Hex } from '@/lib/crypto';
import type { AuditEvent } from '@/lib/domain';
import { execute, query } from './db';

type SafeMetadata = Record<string, string | number | boolean | null>;

const FORBIDDEN_METADATA_KEY = /secret|token|password|prompt|result|payload|content/i;

function safeMetadata(value: SafeMetadata | undefined): SafeMetadata {
  if (!value) return {};
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !FORBIDDEN_METADATA_KEY.test(key))
      .slice(0, 20)
      .map(([key, item]) => [
        key.slice(0, 64),
        typeof item === 'string' ? item.slice(0, 240) : item,
      ]),
  );
}

export function requestAuditContext(request: Request): {
  ipAddress: string | null;
  userAgent: string | null;
} {
  return {
    // Cloudflare supplies this header; forwarded/client-provided alternatives
    // are deliberately ignored because they are forgeable.
    ipAddress: request.headers.get('cf-connecting-ip')?.slice(0, 64) ?? null,
    userAgent: request.headers.get('user-agent')?.slice(0, 240) ?? null,
  };
}

export async function recordAudit(input: {
  organizationId: string;
  workspaceId?: string | null;
  actorType: AuditEvent['actorType'];
  actorId: string;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  outcome: AuditEvent['outcome'];
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: SafeMetadata;
}): Promise<void> {
  await execute(
    `INSERT INTO audit_event
       (id, organizationId, workspaceId, actorType, actorId, action,
        resourceType, resourceId, outcome, ipAddress, userAgent, metadata, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    createId('audit'),
    input.organizationId,
    input.workspaceId ?? null,
    input.actorType,
    input.actorId,
    input.action.slice(0, 120),
    input.resourceType.slice(0, 80),
    input.resourceId?.slice(0, 160) ?? null,
    input.outcome,
    input.ipAddress?.slice(0, 64) ?? null,
    input.userAgent?.slice(0, 240) ?? null,
    JSON.stringify(safeMetadata(input.metadata)),
    Date.now(),
  );
}

/**
 * Writes one evidence-class record.
 *
 * Differences from `recordAudit`, all deliberate:
 *
 *   * The action must exist in the Phase 13 catalog. A typo throws here rather
 *     than silently producing an un-queryable action name.
 *   * `resourceType` comes from the catalog, never the caller, so the two can
 *     never drift for the same action.
 *   * Metadata is narrowed to the keys that action declares, on top of the
 *     global forbidden-key filter.
 *   * Failure is not swallowed for a `critical` action. If the evidence cannot
 *     be written, the caller is told, because an unprovable privileged action
 *     should surface rather than quietly succeed. Non-critical evidence stays
 *     best-effort so telemetry-grade records cannot break a request.
 */
export async function recordEvidence(input: {
  action: EvidenceActionName;
  organizationId: string;
  workspaceId?: string | null;
  actorType: AuditEvent['actorType'];
  actorId: string;
  resourceId?: string | null;
  outcome: AuditEvent['outcome'];
  request?: Request;
  metadata?: SafeMetadata;
}): Promise<void> {
  const entry = evidenceAction(input.action);
  if (!entry) {
    throw new Error(`Unreviewed evidence action: ${input.action}`);
  }

  const metadata = narrowEvidenceMetadata(entry.action, input.metadata);

  const context = input.request ? requestAuditContext(input.request) : {};

  try {
    await recordAudit({
      organizationId: input.organizationId,
      workspaceId: input.workspaceId ?? null,
      actorType: input.actorType,
      actorId: input.actorId,
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: input.resourceId ?? null,
      outcome: input.outcome,
      ...context,
      metadata,
    });
  } catch (error) {
    if (entry.critical) throw error;
  }
}

/**
 * A statement fingerprint for the SQL Editor.
 *
 * The raw statement is never stored: it can embed literal credentials, and it
 * is exactly the kind of free text an audit trail must not accumulate. A
 * truncated digest still lets an operator see that the same statement ran
 * twice without revealing what it said.
 */
export async function statementFingerprint(statement: string): Promise<string> {
  return (await sha256Hex(statement)).slice(0, EVIDENCE_LIMITS.hashLength);
}

type AuditRow = Omit<AuditEvent, 'metadata'> & { metadata: string };

export async function listAuditEvents(
  organizationId: string,
  filter: {
    workspaceId?: string;
    actorId?: string;
    action?: string;
    outcome?: AuditEvent['outcome'];
    from?: number;
    to?: number;
    limit?: number;
  } = {},
): Promise<AuditEvent[]> {
  const conditions = ['organizationId = ?'];
  const params: unknown[] = [organizationId];
  for (const [column, value] of [
    ['workspaceId', filter.workspaceId],
    ['actorId', filter.actorId],
    ['action', filter.action],
    ['outcome', filter.outcome],
  ] as const) {
    if (value) {
      conditions.push(`${column} = ?`);
      params.push(value);
    }
  }
  if (filter.from) {
    conditions.push('createdAt >= ?');
    params.push(filter.from);
  }
  if (filter.to) {
    conditions.push('createdAt <= ?');
    params.push(filter.to);
  }
  params.push(Math.min(1000, Math.max(1, filter.limit ?? 200)));
  const rows = await query<AuditRow>(
    `SELECT e.id, e.workspaceId, e.actorType, e.actorId, e.action, e.resourceType,
            e.resourceId, e.outcome, e.ipAddress, e.userAgent, e.metadata, e.createdAt,
            s.sequence AS sequence
       FROM audit_event e
       LEFT JOIN audit_sequence s ON s.auditId = e.id
      WHERE ${conditions.map((clause) => `e.${clause}`).join(' AND ')}
      ORDER BY e.createdAt DESC, e.id DESC LIMIT ?`,
    ...params,
  );
  return rows.map((row) => {
    let metadata: SafeMetadata = {};
    try {
      metadata = JSON.parse(row.metadata) as SafeMetadata;
    } catch {
      metadata = {};
    }
    return { ...row, metadata };
  });
}

export type AuditIntegrityState = {
  /** Audit rows that never received a number. */
  unnumbered: number;
  /** Numbering rows whose audit row is gone. */
  orphanNumbering: number;
  /** True when the run of sequence values has a hole. */
  sequenceGap: boolean;
  /** Highest number issued, for the Audit surface. */
  latestSequence: number;
};

/**
 * Evidence integrity for Shield.
 *
 * Append-only triggers prove no row was altered. They cannot prove no row was
 * removed underneath them, because nothing else knows how many rows there
 * should be. Comparing `audit_event` against `audit_sequence` does: a missing
 * audit row leaves orphaned numbering, and missing numbering leaves a hole in
 * the run of integers. Either means the evidence trail is no longer complete.
 */
export async function auditIntegrityForShield(
  organizationId: string,
): Promise<AuditIntegrityState> {
  const [unnumbered, orphan, extent] = await Promise.all([
    query<{ total: number }>(
      `SELECT COUNT(*) AS total FROM audit_event e
        WHERE e.organizationId = ?
          AND NOT EXISTS (SELECT 1 FROM audit_sequence s WHERE s.auditId = e.id)`,
      organizationId,
    ),
    query<{ total: number }>(
      `SELECT COUNT(*) AS total FROM audit_sequence s
        WHERE s.organizationId = ?
          AND NOT EXISTS (SELECT 1 FROM audit_event e WHERE e.id = s.auditId)`,
      organizationId,
    ),
    query<{ total: number; highest: number }>(
      `SELECT COUNT(*) AS total, COALESCE(MAX(sequence), 0) AS highest
         FROM audit_sequence WHERE organizationId = ?`,
      organizationId,
    ),
  ]);
  const counted = extent[0]?.total ?? 0;
  const highest = extent[0]?.highest ?? 0;
  return {
    unnumbered: unnumbered[0]?.total ?? 0,
    orphanNumbering: orphan[0]?.total ?? 0,
    // Numbering starts at 1 and never skips, so the highest value must equal
    // how many rows exist.
    sequenceGap: highest !== counted,
    latestSequence: highest,
  };
}

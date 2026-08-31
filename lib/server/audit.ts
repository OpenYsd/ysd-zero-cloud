import { createId } from '@/lib/crypto';
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
    `SELECT id, workspaceId, actorType, actorId, action, resourceType,
            resourceId, outcome, ipAddress, userAgent, metadata, createdAt
       FROM audit_event WHERE ${conditions.join(' AND ')}
       ORDER BY createdAt DESC LIMIT ?`,
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

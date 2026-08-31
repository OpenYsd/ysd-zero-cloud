import { createId, createOpaqueToken, sha256Hex } from '@/lib/crypto';
import type { ServiceAccount } from '@/lib/domain';
import {
  isServiceTokenScope,
  PROJECT_SERVICE_TOKEN_SCOPES,
  type Permission,
  type ServiceTokenScope,
} from '@/lib/roles';
import { recordAudit } from './audit';
import { db, execute, query, queryOne } from './db';

type ServiceAccountRow = Omit<ServiceAccount, 'scopes'> & { scopes: string | null };

function parseScopes(value: string | null): ServiceTokenScope[] {
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is ServiceTokenScope =>
      typeof item === 'string' && isServiceTokenScope(item),
    );
  } catch {
    return [];
  }
}

export async function listServiceAccounts(
  organizationId: string,
  workspaceId: string,
): Promise<ServiceAccount[]> {
  const rows = await query<ServiceAccountRow>(
    `SELECT a.id, a.name, a.workspaceId, a.projectId, p.name AS projectName,
            a.status, t.scopes, t.tokenPrefix, t.expiresAt, t.lastUsedAt, a.createdAt
       FROM service_account a
       LEFT JOIN project p ON p.id = a.projectId AND p.workspaceId = a.workspaceId
       LEFT JOIN service_account_token t ON t.serviceAccountId = a.id
         AND t.revokedAt IS NULL
      WHERE a.organizationId = ? AND a.workspaceId = ?
      ORDER BY a.createdAt DESC`,
    organizationId,
    workspaceId,
  );
  return rows.map((row) => ({ ...row, scopes: parseScopes(row.scopes) }));
}

export async function createServiceAccount(input: {
  organizationId: string;
  workspaceId: string;
  projectId?: string | null;
  actorId: string;
  name: string;
  scopes: string[];
  expiresAt?: number | null;
}): Promise<{ account: ServiceAccount; token: string }> {
  const name = input.name.trim().replace(/\s+/g, ' ').slice(0, 80);
  if (!name) throw new Error('A service account name is required.');
  const scopes = [...new Set(input.scopes)];
  if (scopes.length === 0 || scopes.length > 12 || !scopes.every(isServiceTokenScope)) {
    throw new Error('Choose one or more allowlisted service-token scopes.');
  }
  if (input.projectId) {
    const project = await queryOne<{ id: string }>(
      'SELECT id FROM project WHERE id = ? AND workspaceId = ?',
      input.projectId,
      input.workspaceId,
    );
    if (!project) throw new Error('Project not found.');
    const projectScopes = new Set<string>(PROJECT_SERVICE_TOKEN_SCOPES);
    if (scopes.some((scope) => !projectScopes.has(scope))) {
      throw new Error('A project-bound token may only use project, deployment, and project-secret scopes.');
    }
  }
  const now = Date.now();
  const expiresAt = input.expiresAt ?? now + 30 * 24 * 60 * 60 * 1000;
  if (expiresAt <= now) {
    throw new Error('Token expiry must be in the future.');
  }
  if (expiresAt > now + 180 * 24 * 60 * 60 * 1000) {
    throw new Error('Service tokens are limited to a 180-day lifetime.');
  }
  const token = createOpaqueToken('ysd_sa');
  const accountId = createId('svc');
  const tokenId = createId('sat');
  const prefix = token.slice(0, 18);
  const database = await db();
  await database.batch([
    database.prepare(
      `INSERT INTO service_account
         (id, organizationId, workspaceId, projectId, name, status, createdBy,
          createdAt, updatedAt, revokedAt, revokedBy)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, NULL, NULL)`,
    ).bind(accountId, input.organizationId, input.workspaceId, input.projectId ?? null, name, input.actorId, now, now),
    database.prepare(
      `INSERT INTO service_account_token
         (id, serviceAccountId, tokenPrefix, tokenHash, scopes, expiresAt,
          lastUsedAt, createdAt, revokedAt, revokedBy)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL)`,
    ).bind(tokenId, accountId, prefix, await sha256Hex(token), JSON.stringify(scopes), expiresAt, now),
  ]);
  await recordAudit({
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    actorType: 'user',
    actorId: input.actorId,
    action: 'service-account.create',
    resourceType: 'service-account',
    resourceId: accountId,
    outcome: 'success',
    metadata: {
      name,
      projectBound: Boolean(input.projectId),
      scopeCount: scopes.length,
      expiresAt,
    },
  });
  return {
    account: {
      id: accountId,
      name,
      workspaceId: input.workspaceId,
      projectId: input.projectId ?? null,
      projectName: null,
      status: 'active',
      scopes,
      tokenPrefix: prefix,
      expiresAt,
      lastUsedAt: null,
      createdAt: now,
    },
    token,
  };
}

export async function revokeServiceAccount(input: {
  organizationId: string;
  workspaceId: string;
  accountId: string;
  actorId: string;
}): Promise<boolean> {
  const now = Date.now();
  const account = await queryOne<{ id: string }>(
    `SELECT id FROM service_account
      WHERE id = ? AND organizationId = ? AND workspaceId = ? AND status = 'active'`,
    input.accountId, input.organizationId, input.workspaceId,
  );
  if (!account) return false;
  const database = await db();
  await database.batch([
    database.prepare(
      `UPDATE service_account SET status = 'revoked', revokedAt = ?, revokedBy = ?, updatedAt = ?
        WHERE id = ? AND organizationId = ? AND workspaceId = ?`,
    ).bind(now, input.actorId, now, input.accountId, input.organizationId, input.workspaceId),
    database.prepare(
      `UPDATE service_account_token SET revokedAt = ?, revokedBy = ?
        WHERE serviceAccountId = ? AND revokedAt IS NULL`,
    ).bind(now, input.actorId, input.accountId),
  ]);
  await recordAudit({
    organizationId: input.organizationId, workspaceId: input.workspaceId,
    actorType: 'user', actorId: input.actorId, action: 'service-account.revoke',
    resourceType: 'service-account', resourceId: input.accountId, outcome: 'success',
  });
  return true;
}

export type ServiceTokenPrincipal = {
  serviceAccountId: string;
  name: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  scopes: Permission[];
};

export async function authenticateServiceToken(
  request: Request,
): Promise<ServiceTokenPrincipal | null> {
  const authorization = request.headers.get('authorization') ?? '';
  const match = /^Bearer (ysd_sa_[A-Za-z0-9_-]{32,})$/.exec(authorization);
  if (!match) return null;
  const token = match[1]!;
  const row = await queryOne<{
    tokenId: string;
    serviceAccountId: string;
    name: string;
    organizationId: string;
    workspaceId: string;
    projectId: string | null;
    scopes: string;
    expiresAt: number | null;
  }>(
    `SELECT t.id AS tokenId, a.id AS serviceAccountId, a.name,
            a.organizationId, a.workspaceId, a.projectId, t.scopes, t.expiresAt
       FROM service_account_token t
       JOIN service_account a ON a.id = t.serviceAccountId
       JOIN organization o ON o.id = a.organizationId
       JOIN workspace w ON w.id = a.workspaceId
      WHERE t.tokenHash = ? AND t.revokedAt IS NULL AND a.status = 'active'
        AND o.status = 'active' AND w.archivedAt IS NULL`,
    await sha256Hex(token),
  );
  if (!row || (row.expiresAt !== null && row.expiresAt <= Date.now())) return null;
  const scopes = parseScopes(row.scopes);
  if (scopes.length === 0) return null;
  await execute('UPDATE service_account_token SET lastUsedAt = ? WHERE id = ?', Date.now(), row.tokenId);
  return {
    serviceAccountId: row.serviceAccountId,
    name: row.name,
    organizationId: row.organizationId,
    workspaceId: row.workspaceId,
    projectId: row.projectId,
    scopes,
  };
}

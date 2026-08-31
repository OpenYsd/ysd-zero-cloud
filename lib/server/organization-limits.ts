import { queryOne } from './db';

export const LIMIT_KEYS = [
  'members',
  'workspaces',
  'projects',
  'nodes',
  'deployments',
  'gameServers',
  'aiJobs',
  'storageMetadata',
] as const;

export type LimitKey = (typeof LIMIT_KEYS)[number];

export type LimitReading = {
  key: LimitKey;
  used: number;
  limit: number;
  remaining: number;
};

export type CollaborationLimits = {
  organizationId: string;
  workspaceId: string;
  organization: LimitReading[];
  workspace: LimitReading[];
  measuredAt: number;
};

const ORGANIZATION_USAGE_SQL: Record<LimitKey, string> = {
  members: `SELECT COUNT(*) AS used FROM organization_member
             WHERE organizationId = ? AND status <> 'removed'`,
  workspaces: `SELECT COUNT(*) AS used FROM workspace
                WHERE organizationId = ? AND archivedAt IS NULL`,
  projects: `SELECT COUNT(*) AS used FROM project p JOIN workspace w ON w.id = p.workspaceId
              WHERE w.organizationId = ? AND w.archivedAt IS NULL`,
  nodes: `SELECT COUNT(*) AS used FROM compute_node n JOIN workspace w ON w.id = n.workspaceId
           WHERE w.organizationId = ? AND n.revokedAt IS NULL`,
  deployments: `SELECT COUNT(*) AS used FROM deployment d JOIN workspace w ON w.id = d.workspaceId
                  WHERE w.organizationId = ?`,
  gameServers: `SELECT COUNT(*) AS used FROM game_server g JOIN workspace w ON w.id = g.workspaceId
                  WHERE w.organizationId = ? AND g.deletedAt IS NULL`,
  aiJobs: `SELECT COUNT(*) AS used FROM ai_inference a JOIN workspace w ON w.id = a.workspaceId
            WHERE w.organizationId = ?`,
  storageMetadata: `SELECT COUNT(*) AS used FROM storage_object s JOIN workspace w ON w.id = s.workspaceId
                     WHERE w.organizationId = ?`,
};

const WORKSPACE_USAGE_SQL: Omit<Record<LimitKey, string>, 'workspaces'> = {
  members: `SELECT COUNT(*) AS used FROM workspace_member wm
             JOIN organization_member om
               ON om.organizationId = wm.organizationId AND om.userId = wm.userId
            WHERE wm.workspaceId = ? AND om.status <> 'removed'`,
  projects: 'SELECT COUNT(*) AS used FROM project WHERE workspaceId = ?',
  nodes: 'SELECT COUNT(*) AS used FROM compute_node WHERE workspaceId = ? AND revokedAt IS NULL',
  deployments: 'SELECT COUNT(*) AS used FROM deployment WHERE workspaceId = ?',
  gameServers: `SELECT COUNT(*) AS used FROM game_server
                 WHERE workspaceId = ? AND deletedAt IS NULL`,
  aiJobs: 'SELECT COUNT(*) AS used FROM ai_inference WHERE workspaceId = ?',
  storageMetadata: 'SELECT COUNT(*) AS used FROM storage_object WHERE workspaceId = ?',
};

async function usage(sql: string, id: string): Promise<number> {
  return (await queryOne<{ used: number }>(sql, id))?.used ?? 0;
}

function reading(key: LimitKey, used: number, limit: number): LimitReading {
  return { key, used, limit, remaining: Math.max(0, limit - used) };
}

export async function readCollaborationLimits(
  organizationId: string,
  workspaceId: string,
): Promise<CollaborationLimits> {
  const [organizationLimits, workspaceLimits] = await Promise.all([
    queryOne<Record<LimitKey, number>>(
      `SELECT members, workspaces, projects, nodes, deployments, gameServers,
              aiJobs, storageMetadata
         FROM organization_limit WHERE organizationId = ?`,
      organizationId,
    ),
    queryOne<Omit<Record<LimitKey, number>, 'workspaces'>>(
      `SELECT members, projects, nodes, deployments, gameServers, aiJobs,
              storageMetadata
         FROM workspace_limit WHERE workspaceId = ? AND organizationId = ?`,
      workspaceId,
      organizationId,
    ),
  ]);
  if (!organizationLimits || !workspaceLimits) {
    throw new Error('Organization limits are not initialized.');
  }

  const organization = await Promise.all(LIMIT_KEYS.map(async (key) =>
    reading(key, await usage(ORGANIZATION_USAGE_SQL[key], organizationId), organizationLimits[key]),
  ));
  const workspaceKeys = LIMIT_KEYS.filter((key): key is Exclude<LimitKey, 'workspaces'> => key !== 'workspaces');
  const workspace = await Promise.all(workspaceKeys.map(async (key) =>
    reading(key, await usage(WORKSPACE_USAGE_SQL[key], workspaceId), workspaceLimits[key]),
  ));

  return { organizationId, workspaceId, organization, workspace, measuredAt: Date.now() };
}

export async function assertResourceCapacity(
  workspaceId: string,
  key: Exclude<LimitKey, 'members' | 'workspaces'>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const workspace = await queryOne<{ organizationId: string }>(
    'SELECT organizationId FROM workspace WHERE id = ? AND archivedAt IS NULL',
    workspaceId,
  );
  if (!workspace?.organizationId) return { ok: false, error: 'Workspace not found.' };
  const limits = await readCollaborationLimits(workspace.organizationId, workspaceId);
  const organization = limits.organization.find((item) => item.key === key)!;
  const local = limits.workspace.find((item) => item.key === key)!;
  if (organization.used >= organization.limit) {
    return { ok: false, error: `The organization ${key} limit has been reached.` };
  }
  if (local.used >= local.limit) {
    return { ok: false, error: `The workspace ${key} limit has been reached.` };
  }
  return { ok: true };
}

export async function assertMemberCapacity(
  organizationId: string,
  workspaceId: string,
  options: {
    reservePendingInvitation?: boolean;
    organizationMemberExists?: boolean;
    workspaceMemberExists?: boolean;
  } = {},
): Promise<{ ok: true } | { ok: false; error: string }> {
  const limits = await readCollaborationLimits(organizationId, workspaceId);
  const organization = limits.organization.find((item) => item.key === 'members')!;
  const local = limits.workspace.find((item) => item.key === 'members')!;
  let organizationUsed = organization.used;
  let workspaceUsed = local.used;
  if (options.reservePendingInvitation) {
    organizationUsed += (await queryOne<{ used: number }>(
      `SELECT COUNT(*) AS used FROM organization_invitation
        WHERE organizationId = ? AND status = 'pending' AND expiresAt > ?`,
      organizationId,
      Date.now(),
    ))?.used ?? 0;
    workspaceUsed += (await queryOne<{ used: number }>(
      `SELECT COUNT(*) AS used FROM organization_invitation
        WHERE workspaceId = ? AND status = 'pending' AND expiresAt > ?`,
      workspaceId,
      Date.now(),
    ))?.used ?? 0;
  }
  if (!options.organizationMemberExists && organizationUsed >= organization.limit) {
    return { ok: false, error: 'The organization member limit has been reached.' };
  }
  if (!options.workspaceMemberExists && workspaceUsed >= local.limit) {
    return { ok: false, error: 'The workspace member limit has been reached.' };
  }
  return { ok: true };
}

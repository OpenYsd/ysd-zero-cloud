import { createId } from '@/lib/crypto';
import { isWorkspaceSetting, type Workspace, type WorkspaceSetting } from '@/lib/domain';
import { execute, queryOne } from './db';

/**
 * Every operator owns exactly one workspace, created the first time they are
 * seen. Workspace settings are the source of truth for Zero Mode: the client
 * toggle only asks for a change, it never decides one.
 */

export { isWorkspaceSetting };
export type { Workspace, WorkspaceSetting };

type WorkspaceRow = {
  id: string;
  name: string;
  ownerUserId: string;
  zeroMode: number;
  autoScan: number;
  sleepIdleServers: number;
  previewDeployments: number;
  createdAt: number;
  updatedAt: number;
};

function toWorkspace(row: WorkspaceRow): Workspace {
  return {
    id: row.id,
    name: row.name,
    ownerUserId: row.ownerUserId,
    zeroMode: row.zeroMode === 1,
    autoScan: row.autoScan === 1,
    sleepIdleServers: row.sleepIdleServers === 1,
    previewDeployments: row.previewDeployments === 1,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function workspaceName(userName: string, email: string): string {
  const base = userName.trim() || email.split('@')[0] || 'Workspace';
  return `${base}'s workspace`;
}

/**
 * Finds the caller's workspace, creating it on first sight.
 *
 * The insert is `OR IGNORE` against the unique owner index so two requests
 * arriving together cannot produce two workspaces for one operator.
 */
export async function ensureWorkspace(
  userId: string,
  userName: string,
  email: string,
): Promise<Workspace> {
  const existing = await queryOne<WorkspaceRow>(
    'SELECT * FROM workspace WHERE ownerUserId = ?',
    userId,
  );
  if (existing) return toWorkspace(existing);

  const now = Date.now();
  await execute(
    `INSERT OR IGNORE INTO workspace (id, name, ownerUserId, zeroMode, autoScan, sleepIdleServers, previewDeployments, createdAt, updatedAt)
     VALUES (?, ?, ?, 1, 1, 1, 0, ?, ?)`,
    createId('ws'),
    workspaceName(userName, email),
    userId,
    now,
    now,
  );

  const created = await queryOne<WorkspaceRow>(
    'SELECT * FROM workspace WHERE ownerUserId = ?',
    userId,
  );
  if (!created) throw new Error('Workspace could not be created.');
  return toWorkspace(created);
}

export async function getWorkspace(workspaceId: string): Promise<Workspace | null> {
  const row = await queryOne<WorkspaceRow>('SELECT * FROM workspace WHERE id = ?', workspaceId);
  return row ? toWorkspace(row) : null;
}

/** Applies one boolean setting. The column name is validated, never interpolated blind. */
export async function updateWorkspaceSetting(
  workspaceId: string,
  setting: WorkspaceSetting,
  value: boolean,
): Promise<Workspace | null> {
  if (!isWorkspaceSetting(setting)) throw new Error(`Unknown workspace setting: ${String(setting)}`);
  await execute(
    `UPDATE workspace SET ${setting} = ?, updatedAt = ? WHERE id = ?`,
    value ? 1 : 0,
    Date.now(),
    workspaceId,
  );
  return getWorkspace(workspaceId);
}

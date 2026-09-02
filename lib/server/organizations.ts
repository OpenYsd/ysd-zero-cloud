import { createId, createOpaqueToken, sha256Hex } from '@/lib/crypto';
import { selectMembership, selectWorkspace } from '@/lib/context-fallback';
import type {
  Organization,
  OrganizationInvitation,
  OrganizationMember,
  OrganizationSummary,
  Workspace,
} from '@/lib/domain';
import {
  canChangeRole,
  canSuspend,
  normalizeRole,
  type Actor,
  type Role,
} from '@/lib/roles';
import { recordAudit } from './audit';
import { count, db, execute, query, queryOne } from './db';
import { assertMemberCapacity } from './organization-limits';
import { emitWorkflowEvent } from './workflow-events';

type OrganizationRow = Omit<Organization, 'adminCanRevokeSessions'> & {
  adminCanRevokeSessions: number;
};

type WorkspaceRow = Omit<Workspace, 'zeroMode' | 'autoScan' | 'sleepIdleServers' | 'previewDeployments'> & {
  zeroMode: number;
  autoScan: number;
  sleepIdleServers: number;
  previewDeployments: number;
};

type MembershipRow = {
  id: string;
  organizationId: string;
  userId: string;
  role: string;
  status: string;
  suspendedAt: number | null;
};

export type OrganizationAccess = {
  organization: Organization;
  workspace: Workspace;
  membership: MembershipRow & { role: Role };
  projectIds: string[] | null;
  /**
   * True when a stored `ysd_organization` / `ysd_workspace` preference could
   * not be honoured and a valid membership was chosen instead. Callers that
   * own a response use this to rewrite the stale cookie; resolution itself
   * stays pure.
   */
  repairedContext: boolean;
};

const MAX_ORGANIZATIONS_PER_USER = 8;

async function emitMemberWorkflowEvents(input: {
  organizationId: string;
  type: 'organization.member.invited' | 'organization.member.removed' | 'organization.member.role_changed';
  resourceId: string;
  payload: Record<string, string>;
  dedupeKey: string;
}): Promise<void> {
  const workspaces = await query<{ id: string }>(
    'SELECT id FROM workspace WHERE organizationId = ? AND archivedAt IS NULL',
    input.organizationId,
  );
  await Promise.all(workspaces.map(async (workspace) => {
    const result = await emitWorkflowEvent({
      workspaceId: workspace.id,
      type: input.type,
      resourceType: input.type === 'organization.member.invited' ? 'invitation' : 'member',
      resourceId: input.resourceId,
      payload: input.payload,
      dedupeKey: `${input.dedupeKey}:${workspace.id}`,
    });
    if (!result.ok) console.error('workflow.organization_event_rejected', result.error);
  }));
}

function toOrganization(row: OrganizationRow): Organization {
  return { ...row, adminCanRevokeSessions: row.adminCanRevokeSessions === 1 };
}

function toWorkspace(row: WorkspaceRow): Workspace {
  return {
    ...row,
    zeroMode: row.zeroMode === 1,
    autoScan: row.autoScan === 1,
    sleepIdleServers: row.sleepIdleServers === 1,
    previewDeployments: row.previewDeployments === 1,
  };
}

function safeName(value: string, fallback: string): string {
  return value.trim().replace(/\s+/g, ' ').slice(0, 80) || fallback;
}

function baseSlug(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'ysd-workspace';
}

async function uniqueSlug(name: string): Promise<string> {
  const base = baseSlug(name);
  const existing = await queryOne<{ id: string }>('SELECT id FROM organization WHERE slug = ?', base);
  return existing ? `${base}-${createId('o').slice(-6)}` : base;
}

export async function getOrganization(id: string): Promise<Organization | null> {
  const row = await queryOne<OrganizationRow>(
    `SELECT id, name, slug, ownerUserId, status, adminCanRevokeSessions,
            createdAt, updatedAt, archivedAt
       FROM organization WHERE id = ?`,
    id,
  );
  return row ? toOrganization(row) : null;
}

export async function getOrganizationWorkspace(id: string): Promise<Workspace | null> {
  const row = await queryOne<WorkspaceRow>(
    `SELECT id, organizationId, name, ownerUserId, zeroMode, autoScan,
            sleepIdleServers, previewDeployments, createdAt, updatedAt, archivedAt
       FROM workspace WHERE id = ?`,
    id,
  );
  return row ? toWorkspace(row) : null;
}

export async function createOrganization(input: {
  userId: string;
  userName: string;
  email: string;
  name?: string;
}): Promise<OrganizationAccess> {
  const organizationCount = await count(
    `SELECT COUNT(*) AS total FROM organization_member m
       JOIN organization o ON o.id = m.organizationId
      WHERE m.userId = ? AND m.status <> 'removed' AND o.status = 'active'`,
    input.userId,
  );
  if (organizationCount >= MAX_ORGANIZATIONS_PER_USER) {
    throw new Error(`An account may belong to at most ${MAX_ORGANIZATIONS_PER_USER} active organizations.`);
  }
  const now = Date.now();
  const name = safeName(input.name ?? '', 'YSD Workspace');
  const organization: Organization = {
    id: createId('org'),
    name,
    slug: await uniqueSlug(name),
    ownerUserId: input.userId,
    status: 'active',
    adminCanRevokeSessions: true,
    createdAt: now,
    updatedAt: now,
    archivedAt: null,
  };
  const workspace: Workspace = {
    id: createId('ws'),
    organizationId: organization.id,
    name,
    ownerUserId: input.userId,
    zeroMode: true,
    autoScan: true,
    sleepIdleServers: true,
    previewDeployments: false,
    createdAt: now,
    updatedAt: now,
    archivedAt: null,
  };
  const memberId = createId('member');
  const workspaceMemberId = createId('wmem');
  const database = await db();
  await database.batch([
    database.prepare(
      `INSERT INTO organization
         (id, name, slug, ownerUserId, status, adminCanRevokeSessions, createdAt, updatedAt, archivedAt)
       VALUES (?, ?, ?, ?, 'active', 1, ?, ?, NULL)`,
    ).bind(organization.id, organization.name, organization.slug, input.userId, now, now),
    database.prepare(
      `INSERT INTO workspace
         (id, organizationId, name, ownerUserId, zeroMode, autoScan, sleepIdleServers,
          previewDeployments, createdAt, updatedAt, archivedAt)
       VALUES (?, ?, ?, ?, 1, 1, 1, 0, ?, ?, NULL)`,
    ).bind(workspace.id, organization.id, workspace.name, input.userId, now, now),
    database.prepare(
      `INSERT INTO organization_member
         (id, organizationId, userId, role, status, suspendedAt, suspendedReason,
          acceptedAt, lastActiveAt, createdBy, createdAt, updatedAt)
       VALUES (?, ?, ?, 'owner', 'active', NULL, NULL, ?, ?, ?, ?, ?)`,
    ).bind(memberId, organization.id, input.userId, now, now, input.userId, now, now),
    database.prepare(
      `INSERT INTO workspace_member (id, organizationId, workspaceId, userId, createdBy, createdAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(workspaceMemberId, organization.id, workspace.id, input.userId, input.userId, now),
    database.prepare('INSERT INTO organization_limit (organizationId, updatedAt) VALUES (?, ?)')
      .bind(organization.id, now),
    database.prepare(
      'INSERT INTO workspace_limit (workspaceId, organizationId, updatedAt) VALUES (?, ?, ?)',
    ).bind(workspace.id, organization.id, now),
  ]);
  await recordAudit({
    organizationId: organization.id,
    workspaceId: workspace.id,
    actorType: 'user',
    actorId: input.userId,
    action: 'organization.create',
    resourceType: 'organization',
    resourceId: organization.id,
    outcome: 'success',
  });
  return {
    organization,
    workspace,
    membership: {
      id: memberId,
      organizationId: organization.id,
      userId: input.userId,
      role: 'owner',
      status: 'active',
      suspendedAt: null,
    },
    projectIds: null,
    // A brand-new organization is never a repaired preference.
    repairedContext: false,
  };
}

async function accessibleWorkspaces(
  organizationId: string,
  userId: string,
  role: Role,
): Promise<Workspace[]> {
  const privileged = role === 'owner' || role === 'admin';
  const rows = await query<WorkspaceRow>(
    privileged
      ? `SELECT id, organizationId, name, ownerUserId, zeroMode, autoScan,
                sleepIdleServers, previewDeployments, createdAt, updatedAt, archivedAt
           FROM workspace WHERE organizationId = ? AND archivedAt IS NULL ORDER BY createdAt ASC`
      : `SELECT w.id, w.organizationId, w.name, w.ownerUserId, w.zeroMode, w.autoScan,
                w.sleepIdleServers, w.previewDeployments, w.createdAt, w.updatedAt, w.archivedAt
           FROM workspace w JOIN workspace_member m ON m.workspaceId = w.id
          WHERE w.organizationId = ? AND m.userId = ? AND w.archivedAt IS NULL
          ORDER BY w.createdAt ASC`,
    ...(privileged ? [organizationId] : [organizationId, userId]),
  );
  return rows.map(toWorkspace);
}

export async function listOrganizations(userId: string): Promise<OrganizationSummary[]> {
  const memberships = await query<MembershipRow & OrganizationRow>(
    `SELECT m.id, m.organizationId, m.userId, m.role, m.status, m.suspendedAt,
            o.name, o.slug, o.ownerUserId, o.adminCanRevokeSessions,
            o.createdAt, o.updatedAt, o.archivedAt, o.status AS organizationStatus
       FROM organization_member m JOIN organization o ON o.id = m.organizationId
      WHERE m.userId = ? AND m.status = 'active' AND m.suspendedAt IS NULL
        AND o.status = 'active'
      ORDER BY o.updatedAt DESC`,
    userId,
  );
  return Promise.all(memberships.map(async (row) => {
    const role = normalizeRole(row.role);
    return {
      id: row.organizationId,
      name: row.name,
      slug: row.slug,
      ownerUserId: row.ownerUserId,
      status: 'active' as const,
      adminCanRevokeSessions: row.adminCanRevokeSessions === 1,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      archivedAt: row.archivedAt,
      role,
      workspaces: await accessibleWorkspaces(row.organizationId, userId, role),
    };
  }));
}

export async function resolveOrganizationAccess(input: {
  userId: string;
  userName: string;
  email: string;
  organizationId?: string | null;
  workspaceId?: string | null;
}): Promise<OrganizationAccess | null> {
  const memberships = await query<MembershipRow>(
    `SELECT m.id, m.organizationId, m.userId, m.role, m.status, m.suspendedAt
       FROM organization_member m JOIN organization o ON o.id = m.organizationId
      WHERE m.userId = ? AND m.status = 'active' AND m.suspendedAt IS NULL
        AND o.status = 'active' ORDER BY m.updatedAt DESC`,
    input.userId,
  );
  if (memberships.length === 0) {
    const anyMembership = await count(
      `SELECT COUNT(*) AS total FROM organization_member m
         JOIN organization o ON o.id = m.organizationId
        WHERE m.userId = ? AND m.status <> 'removed' AND o.status = 'active'`,
      input.userId,
    );
    // A suspended member cannot create a fresh organization as a bypass.
    // Someone removed from their last organization remains an ordinary user
    // and receives a new personal organization for backward compatibility.
    if (anyMembership > 0) return null;
    return createOrganization(input);
  }
  // A stored preference is exactly that: a preference. If it no longer names
  // an organization this user can reach, fall back to a real membership rather
  // than reporting "no session" — a valid login must never be turned into a
  // sign-out by a year-old cookie. The candidate list is already restricted to
  // this user's active memberships, so the fallback cannot cross a tenant.
  const membershipChoice = selectMembership(memberships, input.organizationId);
  const selectedMembership = membershipChoice.selected;
  if (!selectedMembership) return null;
  const organizationRepaired = membershipChoice.repaired;
  const role = normalizeRole(selectedMembership.role);
  const organization = await getOrganization(selectedMembership.organizationId);
  if (!organization || organization.status !== 'active') return null;
  const workspaces = await accessibleWorkspaces(organization.id, input.userId, role);
  // Same rule for the workspace preference. `accessibleWorkspaces` is already
  // scoped to the resolved organization and this user, so the first entry is a
  // safe landing place and can never belong to another organization.
  const workspaceChoice = selectWorkspace(workspaces, input.workspaceId);
  const workspace = workspaceChoice.selected;
  // Only genuinely empty access reaches here: the organization has no workspace
  // this member may enter. That is a real dead end, not a stale preference.
  if (!workspace) return null;
  const workspaceRepaired = workspaceChoice.repaired;
  const workspaceMembership = role === 'owner' || role === 'admin'
    ? null
    : await queryOne<{ projectScope: string }>(
      `SELECT projectScope FROM workspace_member
        WHERE organizationId = ? AND workspaceId = ? AND userId = ?`,
      organization.id,
      workspace.id,
      input.userId,
    );
  const projects = await query<{ projectId: string }>(
    `SELECT projectId FROM member_project_access
      WHERE organizationId = ? AND workspaceId = ? AND userId = ?`,
    organization.id,
    workspace.id,
    input.userId,
  );
  await execute(
    'UPDATE organization_member SET lastActiveAt = ?, updatedAt = ? WHERE id = ?',
    Date.now(), Date.now(), selectedMembership.id,
  );
  return {
    organization,
    workspace,
    membership: { ...selectedMembership, role },
    projectIds:
      role === 'owner' || role === 'admin' || workspaceMembership?.projectScope !== 'restricted'
        ? null
        : projects.map((row) => row.projectId),
    repairedContext: organizationRepaired || workspaceRepaired,
  };
}

export async function createWorkspace(input: {
  organizationId: string;
  actorId: string;
  name: string;
}): Promise<Workspace> {
  const limit = await queryOne<{ limitValue: number; used: number }>(
    `SELECT l.workspaces AS limitValue,
            (SELECT COUNT(*) FROM workspace w WHERE w.organizationId = ? AND w.archivedAt IS NULL) AS used
       FROM organization_limit l WHERE l.organizationId = ?`,
    input.organizationId,
    input.organizationId,
  );
  if (limit && limit.used >= limit.limitValue) throw new Error('The organization workspace limit has been reached.');
  const organization = await getOrganization(input.organizationId);
  if (!organization || organization.status !== 'active') throw new Error('Organization not found.');
  const now = Date.now();
  const workspace: Workspace = {
    id: createId('ws'), organizationId: input.organizationId,
    name: safeName(input.name, 'Workspace'), ownerUserId: organization.ownerUserId,
    zeroMode: true, autoScan: true, sleepIdleServers: true,
    previewDeployments: false, createdAt: now, updatedAt: now, archivedAt: null,
  };
  const database = await db();
  await database.batch([
    database.prepare(
      `INSERT INTO workspace
         (id, organizationId, name, ownerUserId, zeroMode, autoScan, sleepIdleServers,
          previewDeployments, createdAt, updatedAt, archivedAt)
       VALUES (?, ?, ?, ?, 1, 1, 1, 0, ?, ?, NULL)`,
    ).bind(workspace.id, input.organizationId, workspace.name, organization.ownerUserId, now, now),
    database.prepare(
      `INSERT INTO workspace_member (id, organizationId, workspaceId, userId, createdBy, createdAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(createId('wmem'), input.organizationId, workspace.id, organization.ownerUserId, input.actorId, now),
    database.prepare(
      'INSERT INTO workspace_limit (workspaceId, organizationId, updatedAt) VALUES (?, ?, ?)',
    ).bind(workspace.id, input.organizationId, now),
  ]);
  await recordAudit({
    organizationId: input.organizationId, workspaceId: workspace.id,
    actorType: 'user', actorId: input.actorId, action: 'workspace.create',
    resourceType: 'workspace', resourceId: workspace.id, outcome: 'success',
  });
  return workspace;
}

export async function updateOrganization(input: {
  organizationId: string;
  actorId: string;
  name?: string;
  adminCanRevokeSessions?: boolean;
}): Promise<Organization | null> {
  const current = await getOrganization(input.organizationId);
  if (!current || current.status !== 'active') return null;
  const name = input.name === undefined ? current.name : safeName(input.name, current.name);
  await execute(
    `UPDATE organization SET name = ?, adminCanRevokeSessions = ?, updatedAt = ?
      WHERE id = ? AND status = 'active'`,
    name,
    input.adminCanRevokeSessions === undefined
      ? (current.adminCanRevokeSessions ? 1 : 0)
      : (input.adminCanRevokeSessions ? 1 : 0),
    Date.now(),
    input.organizationId,
  );
  await recordAudit({
    organizationId: input.organizationId, actorType: 'user', actorId: input.actorId,
    action: 'organization.update', resourceType: 'organization',
    resourceId: input.organizationId, outcome: 'success',
  });
  return getOrganization(input.organizationId);
}

export async function archiveOrganization(organizationId: string, actorId: string): Promise<boolean> {
  const alternatives = await count(
    `SELECT COUNT(*) AS total FROM organization_member m
       JOIN organization o ON o.id = m.organizationId
      WHERE m.userId = ? AND m.organizationId <> ? AND m.status = 'active'
        AND m.suspendedAt IS NULL AND o.status = 'active'`,
    actorId,
    organizationId,
  );
  if (alternatives === 0) return false;
  const result = await execute(
    `UPDATE organization SET status = 'archived', archivedAt = ?, updatedAt = ?
      WHERE id = ? AND status = 'active' AND ownerUserId = ?`,
    Date.now(), Date.now(), organizationId, actorId,
  );
  if ((result.meta.changes ?? 0) === 0) return false;
  await recordAudit({
    organizationId, actorType: 'user', actorId, action: 'organization.archive',
    resourceType: 'organization', resourceId: organizationId, outcome: 'success',
  });
  return true;
}

export async function archiveWorkspace(
  organizationId: string,
  workspaceId: string,
  actorId: string,
): Promise<boolean> {
  const active = await count(
    'SELECT COUNT(*) AS total FROM workspace WHERE organizationId = ? AND archivedAt IS NULL',
    organizationId,
  );
  if (active <= 1) return false;
  const result = await execute(
    'UPDATE workspace SET archivedAt = ?, updatedAt = ? WHERE id = ? AND organizationId = ? AND archivedAt IS NULL',
    Date.now(), Date.now(), workspaceId, organizationId,
  );
  if ((result.meta.changes ?? 0) === 0) return false;
  await recordAudit({
    organizationId, workspaceId, actorType: 'user', actorId,
    action: 'workspace.archive', resourceType: 'workspace', resourceId: workspaceId,
    outcome: 'success',
  });
  return true;
}

type MemberRow = Omit<OrganizationMember, 'role' | 'projectIds'> & { role: string };

export async function listMembers(
  organizationId: string,
  workspaceId: string,
): Promise<OrganizationMember[]> {
  const rows = await query<MemberRow>(
    `SELECT m.id, m.userId, u.name, u.email, m.role, m.status, m.suspendedAt,
            m.suspendedReason, m.acceptedAt, m.lastActiveAt,
            (SELECT COUNT(*) FROM "session" s WHERE s.userId = m.userId) AS activeSessions
       FROM organization_member m JOIN "user" u ON u.id = m.userId
      WHERE m.organizationId = ? AND m.status <> 'removed'
      ORDER BY CASE m.role WHEN 'owner' THEN 1 WHEN 'admin' THEN 2 WHEN 'developer' THEN 3 ELSE 4 END,
               m.acceptedAt ASC`,
    organizationId,
  );
  return Promise.all(rows.map(async (row) => ({
    ...row,
    role: normalizeRole(row.role),
    projectIds: (await queryOne<{ projectScope: string }>(
      `SELECT projectScope FROM workspace_member
        WHERE organizationId = ? AND workspaceId = ? AND userId = ?`,
      organizationId, workspaceId, row.userId,
    ))?.projectScope === 'restricted'
      ? (await query<{ projectId: string }>(
        `SELECT projectId FROM member_project_access
          WHERE organizationId = ? AND workspaceId = ? AND userId = ?`,
        organizationId, workspaceId, row.userId,
      )).map((item) => item.projectId)
      : null,
  })));
}

export async function addMember(input: {
  organizationId: string;
  workspaceId: string;
  actorId: string;
  userId: string;
  role: Exclude<Role, 'owner'>;
}): Promise<boolean> {
  const user = await queryOne<{ id: string }>('SELECT id FROM "user" WHERE id = ?', input.userId);
  const workspace = await queryOne<{ id: string }>(
    'SELECT id FROM workspace WHERE id = ? AND organizationId = ? AND archivedAt IS NULL',
    input.workspaceId, input.organizationId,
  );
  if (!user || !workspace) return false;
  const [existingOrganizationMember, existingWorkspaceMember] = await Promise.all([
    queryOne<{ id: string }>(
      `SELECT id FROM organization_member
        WHERE organizationId = ? AND userId = ? AND status <> 'removed'`,
      input.organizationId,
      input.userId,
    ),
    queryOne<{ id: string }>(
      `SELECT id FROM workspace_member
        WHERE organizationId = ? AND workspaceId = ? AND userId = ?`,
      input.organizationId,
      input.workspaceId,
      input.userId,
    ),
  ]);
  const capacity = await assertMemberCapacity(input.organizationId, input.workspaceId, {
    organizationMemberExists: Boolean(existingOrganizationMember),
    workspaceMemberExists: Boolean(existingWorkspaceMember),
  });
  if (!capacity.ok) throw new Error(capacity.error);
  const now = Date.now();
  const database = await db();
  await database.batch([
    database.prepare(
      `INSERT INTO organization_member
         (id, organizationId, userId, role, status, suspendedAt, suspendedReason,
          acceptedAt, lastActiveAt, createdBy, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, 'active', NULL, NULL, ?, NULL, ?, ?, ?)
       ON CONFLICT(organizationId, userId) DO UPDATE SET
         role = excluded.role, status = 'active', suspendedAt = NULL,
         suspendedReason = NULL, updatedAt = excluded.updatedAt`,
    ).bind(createId('member'), input.organizationId, input.userId, input.role, now, input.actorId, now, now),
    database.prepare(
      `INSERT OR IGNORE INTO workspace_member
         (id, organizationId, workspaceId, userId, createdBy, createdAt)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(createId('wmem'), input.organizationId, input.workspaceId, input.userId, input.actorId, now),
  ]);
  await recordAudit({
    organizationId: input.organizationId, workspaceId: input.workspaceId,
    actorType: 'user', actorId: input.actorId, action: 'member.add',
    resourceType: 'member', resourceId: input.userId, outcome: 'success',
    metadata: { role: input.role },
  });
  return true;
}

async function memberForDecision(organizationId: string, userId: string): Promise<{ userId: string; role: Role } | null> {
  const row = await queryOne<{ userId: string; role: string }>(
    `SELECT userId, role FROM organization_member
      WHERE organizationId = ? AND userId = ? AND status <> 'removed'`,
    organizationId, userId,
  );
  return row ? { userId: row.userId, role: normalizeRole(row.role) } : null;
}

export async function changeMemberRole(input: {
  actor: Actor;
  organizationId: string;
  targetUserId: string;
  role: Exclude<Role, 'owner'>;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  const target = await memberForDecision(input.organizationId, input.targetUserId);
  if (!target) return { ok: false, error: 'Member not found.' };
  const ownerCount = await count(
    `SELECT COUNT(*) AS total FROM organization_member
      WHERE organizationId = ? AND role = 'owner' AND status = 'active' AND suspendedAt IS NULL`,
    input.organizationId,
  );
  const decision = canChangeRole(input.actor, target, input.role, ownerCount);
  if (!decision.allowed) return { ok: false, error: decision.message };
  const result = await execute(
    `UPDATE organization_member SET role = ?, updatedAt = ?
      WHERE organizationId = ? AND userId = ?
        AND NOT (role = 'owner' AND
          (SELECT COUNT(*) FROM organization_member
            WHERE organizationId = ? AND role = 'owner' AND status = 'active' AND suspendedAt IS NULL) <= 1)`,
    input.role, Date.now(), input.organizationId, input.targetUserId, input.organizationId,
  );
  if ((result.meta.changes ?? 0) === 0) return { ok: false, error: 'The organization must keep an owner.' };
  await recordAudit({
    organizationId: input.organizationId, actorType: 'user', actorId: input.actor.userId,
    action: 'member.role.change', resourceType: 'member', resourceId: input.targetUserId,
    outcome: 'success', metadata: { from: target.role, to: input.role },
  });
  await emitMemberWorkflowEvents({
    organizationId: input.organizationId,
    type: 'organization.member.role_changed',
    resourceId: input.targetUserId,
    payload: { previousRole: target.role, role: input.role },
    dedupeKey: `member-role:${input.targetUserId}:${input.role}:${Date.now()}`,
  });
  return { ok: true };
}

export async function setMemberStatus(input: {
  actor: Actor;
  organizationId: string;
  targetUserId: string;
  action: 'suspend' | 'reactivate' | 'remove';
  reason?: string;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  const target = await memberForDecision(input.organizationId, input.targetUserId);
  if (!target) return { ok: false, error: 'Member not found.' };
  const decision = canSuspend(input.actor, target);
  if (!decision.allowed) return { ok: false, error: decision.message };
  const now = Date.now();
  const status = input.action === 'remove'
    ? 'removed'
    : input.action === 'suspend'
      ? 'suspended'
      : 'active';
  const suspendedAt = input.action === 'suspend' ? now : null;
  const result = await execute(
    `UPDATE organization_member
        SET status = ?, suspendedAt = ?, suspendedReason = ?, updatedAt = ?
      WHERE organizationId = ? AND userId = ? AND role <> 'owner'`,
    status, suspendedAt, input.action === 'suspend' ? input.reason?.slice(0, 200) ?? null : null,
    now, input.organizationId, input.targetUserId,
  );
  if ((result.meta.changes ?? 0) === 0) return { ok: false, error: 'The organization owner cannot be suspended or removed.' };
  if (input.action !== 'reactivate') {
    await execute('DELETE FROM "session" WHERE userId = ?', input.targetUserId);
  }
  await recordAudit({
    organizationId: input.organizationId, actorType: 'user', actorId: input.actor.userId,
    action: `member.${input.action}`, resourceType: 'member', resourceId: input.targetUserId,
    outcome: 'success',
  });
  if (input.action === 'remove') {
    await emitMemberWorkflowEvents({
      organizationId: input.organizationId,
      type: 'organization.member.removed',
      resourceId: input.targetUserId,
      payload: { previousRole: target.role, status: 'removed' },
      dedupeKey: `member-removed:${input.targetUserId}:${now}`,
    });
  }
  return { ok: true };
}

export async function transferOwnership(input: {
  actor: Actor;
  organizationId: string;
  targetUserId: string;
  confirmation: string;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  const organization = await getOrganization(input.organizationId);
  if (!organization || organization.ownerUserId !== input.actor.userId) {
    return { ok: false, error: 'Only the current organization owner can transfer ownership.' };
  }
  if (input.confirmation !== organization.name) {
    return { ok: false, error: 'Type the exact organization name to confirm ownership transfer.' };
  }
  const target = await memberForDecision(input.organizationId, input.targetUserId);
  const activeTarget = await queryOne<{ ok: number }>(
    `SELECT 1 AS ok FROM organization_member
      WHERE organizationId = ? AND userId = ? AND status = 'active'
        AND suspendedAt IS NULL`,
    input.organizationId,
    input.targetUserId,
  );
  if (!target || !activeTarget || target.userId === input.actor.userId) {
    return { ok: false, error: 'Choose another active member.' };
  }
  const now = Date.now();
  const database = await db();
  await database.batch([
    database.prepare(
      `UPDATE organization_member SET role = 'owner', status = 'active', suspendedAt = NULL,
              suspendedReason = NULL, updatedAt = ?
        WHERE organizationId = ? AND userId = ? AND EXISTS (
          SELECT 1 FROM organization o
           WHERE o.id = ? AND o.ownerUserId = ?
        )`,
    ).bind(now, input.organizationId, input.targetUserId, input.organizationId, input.actor.userId),
    database.prepare(
      'UPDATE organization SET ownerUserId = ?, updatedAt = ? WHERE id = ? AND ownerUserId = ?',
    ).bind(input.targetUserId, now, input.organizationId, input.actor.userId),
    database.prepare(
      `UPDATE organization_member SET role = 'admin', updatedAt = ?
        WHERE organizationId = ? AND userId = ? AND role = 'owner'
          AND EXISTS (SELECT 1 FROM organization o WHERE o.id = ? AND o.ownerUserId = ?)`,
    ).bind(now, input.organizationId, input.actor.userId, input.organizationId, input.targetUserId),
  ]);
  const updated = await getOrganization(input.organizationId);
  if (updated?.ownerUserId !== input.targetUserId) return { ok: false, error: 'Ownership changed concurrently. Reload and try again.' };
  await recordAudit({
    organizationId: input.organizationId, actorType: 'user', actorId: input.actor.userId,
    action: 'member.transfer-ownership', resourceType: 'organization', resourceId: input.organizationId,
    outcome: 'success', metadata: { newOwnerUserId: input.targetUserId },
  });
  return { ok: true };
}

export async function replaceProjectAccess(input: {
  organizationId: string;
  workspaceId: string;
  actorId: string;
  userId: string;
  projectIds: string[] | null;
}): Promise<boolean> {
  const uniqueIds = input.projectIds === null
    ? null
    : [...new Set(input.projectIds)].slice(0, 100);
  if (uniqueIds && uniqueIds.length > 0) {
    const valid = await count(
      `SELECT COUNT(*) AS total FROM project
        WHERE workspaceId = ? AND id IN (${uniqueIds.map(() => '?').join(',')})`,
      input.workspaceId, ...uniqueIds,
    );
    if (valid !== uniqueIds.length) return false;
  }
  const member = await queryOne<{ id: string }>(
    `SELECT wm.id FROM workspace_member wm
      JOIN organization_member om
        ON om.organizationId = wm.organizationId AND om.userId = wm.userId
     WHERE wm.organizationId = ? AND wm.workspaceId = ? AND wm.userId = ?
       AND om.status <> 'removed'`,
    input.organizationId, input.workspaceId, input.userId,
  );
  if (!member) return false;
  const database = await db();
  const statements = [
    database.prepare(
      'DELETE FROM member_project_access WHERE organizationId = ? AND workspaceId = ? AND userId = ?',
    ).bind(input.organizationId, input.workspaceId, input.userId),
    database.prepare(
      `UPDATE workspace_member SET projectScope = ?
        WHERE organizationId = ? AND workspaceId = ? AND userId = ?`,
    ).bind(uniqueIds === null ? 'all' : 'restricted', input.organizationId, input.workspaceId, input.userId),
    ...(uniqueIds ?? []).map((projectId) => database.prepare(
      `INSERT INTO member_project_access
         (id, organizationId, workspaceId, userId, projectId, grantedBy, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(createId('access'), input.organizationId, input.workspaceId, input.userId, projectId, input.actorId, Date.now())),
  ];
  await database.batch(statements);
  await recordAudit({
    organizationId: input.organizationId, workspaceId: input.workspaceId,
    actorType: 'user', actorId: input.actorId, action: 'member.project-scope.update',
    resourceType: 'member', resourceId: input.userId, outcome: 'success',
    metadata: { projectCount: uniqueIds?.length ?? -1 },
  });
  return true;
}

type InvitationRow = Omit<OrganizationInvitation, 'role'> & { role: string };

export async function listInvitations(organizationId: string): Promise<OrganizationInvitation[]> {
  await execute(
    `UPDATE organization_invitation SET status = 'expired', updatedAt = ?
      WHERE organizationId = ? AND status = 'pending' AND expiresAt <= ?`,
    Date.now(), organizationId, Date.now(),
  );
  const rows = await query<InvitationRow>(
    `SELECT i.id, i.email, i.role, i.workspaceId, w.name AS workspaceName,
            i.tokenPrefix, i.status, i.expiresAt, i.createdAt
       FROM organization_invitation i JOIN workspace w ON w.id = i.workspaceId
      WHERE i.organizationId = ? ORDER BY i.createdAt DESC LIMIT 200`,
    organizationId,
  );
  return rows.map((row) => ({ ...row, role: normalizeRole(row.role) as Exclude<Role, 'owner'> }));
}

export async function createInvitation(input: {
  organizationId: string;
  workspaceId: string;
  actorId: string;
  email: string;
  role: Exclude<Role, 'owner'>;
  expiresInHours?: number;
}): Promise<{ invitation: OrganizationInvitation; token: string }> {
  const email = input.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid email address.');
  const existing = await queryOne<{ status: string; workspaceMemberId: string | null }>(
    `SELECT m.status, wm.id AS workspaceMemberId
       FROM organization_member m JOIN "user" u ON u.id = m.userId
       LEFT JOIN workspace_member wm
         ON wm.organizationId = m.organizationId AND wm.workspaceId = ? AND wm.userId = m.userId
      WHERE m.organizationId = ? AND lower(u.email) = ? AND m.status <> 'removed'`,
    input.workspaceId,
    input.organizationId,
    email,
  );
  if (existing?.status === 'suspended') {
    throw new Error('Suspended members must be reactivated explicitly before they can accept an invitation.');
  }
  const capacity = await assertMemberCapacity(input.organizationId, input.workspaceId, {
    reservePendingInvitation: true,
    organizationMemberExists: Boolean(existing),
    workspaceMemberExists: Boolean(existing?.workspaceMemberId),
  });
  if (!capacity.ok) throw new Error(capacity.error);
  await execute(
    `UPDATE organization_invitation SET status = 'expired', updatedAt = ?
      WHERE organizationId = ? AND workspaceId = ? AND email = ?
        AND status = 'pending' AND expiresAt <= ?`,
    Date.now(), input.organizationId, input.workspaceId, email, Date.now(),
  );
  const duplicate = await queryOne<{ id: string }>(
    `SELECT id FROM organization_invitation
      WHERE organizationId = ? AND workspaceId = ? AND email = ? AND status = 'pending'`,
    input.organizationId, input.workspaceId, email,
  );
  if (duplicate) throw new Error('A pending invitation already exists for this email and workspace.');
  const workspace = await getOrganizationWorkspace(input.workspaceId);
  if (!workspace || workspace.organizationId !== input.organizationId || workspace.archivedAt) throw new Error('Workspace not found.');
  const token = createOpaqueToken('ysd_inv');
  const now = Date.now();
  const expiresAt = now + Math.min(30 * 24, Math.max(1, input.expiresInHours ?? 168)) * 60 * 60 * 1000;
  const invitation: OrganizationInvitation = {
    id: createId('invite'), email, role: input.role, workspaceId: workspace.id,
    workspaceName: workspace.name, tokenPrefix: token.slice(0, 18), status: 'pending',
    expiresAt, createdAt: now,
  };
  await execute(
    `INSERT INTO organization_invitation
       (id, organizationId, workspaceId, email, role, tokenHash, tokenPrefix, status,
        expiresAt, usedAt, usedBy, revokedAt, revokedBy, createdBy, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL, NULL, ?, ?, ?)`,
    invitation.id, input.organizationId, workspace.id, email, input.role,
    await sha256Hex(token), invitation.tokenPrefix, expiresAt, input.actorId, now, now,
  );
  await recordAudit({
    organizationId: input.organizationId, workspaceId: workspace.id,
    actorType: 'user', actorId: input.actorId, action: 'invitation.create',
    resourceType: 'invitation', resourceId: invitation.id, outcome: 'success',
    metadata: { email, role: input.role, expiresAt },
  });
  await emitMemberWorkflowEvents({
    organizationId: input.organizationId,
    type: 'organization.member.invited',
    resourceId: invitation.id,
    payload: { role: input.role, status: 'pending' },
    dedupeKey: `member-invited:${invitation.id}`,
  });
  return { invitation, token };
}

export async function revokeInvitation(
  organizationId: string,
  invitationId: string,
  actorId: string,
): Promise<boolean> {
  const result = await execute(
    `UPDATE organization_invitation
        SET status = 'revoked', revokedAt = ?, revokedBy = ?, updatedAt = ?
      WHERE id = ? AND organizationId = ? AND status = 'pending'`,
    Date.now(), actorId, Date.now(), invitationId, organizationId,
  );
  if ((result.meta.changes ?? 0) === 0) return false;
  await recordAudit({
    organizationId, actorType: 'user', actorId, action: 'invitation.revoke',
    resourceType: 'invitation', resourceId: invitationId, outcome: 'success',
  });
  return true;
}

export async function acceptInvitation(input: {
  token: string;
  userId: string;
  email: string;
}): Promise<{ ok: true; organizationId: string; workspaceId: string } | { ok: false; error: string; status: number }> {
  const hash = await sha256Hex(input.token);
  const row = await queryOne<{
    id: string; organizationId: string; workspaceId: string; email: string;
    role: string; status: string; expiresAt: number;
  }>(
    `SELECT id, organizationId, workspaceId, email, role, status, expiresAt
       FROM organization_invitation WHERE tokenHash = ?`,
    hash,
  );
  if (!row) return { ok: false, error: 'Invitation not found.', status: 404 };
  if (row.status !== 'pending') return { ok: false, error: 'This invitation is no longer active.', status: 409 };
  if (row.expiresAt <= Date.now()) {
    await execute(`UPDATE organization_invitation SET status = 'expired', updatedAt = ? WHERE id = ? AND status = 'pending'`, Date.now(), row.id);
    return { ok: false, error: 'This invitation has expired.', status: 410 };
  }
  if (row.email !== input.email.trim().toLowerCase()) {
    await recordAudit({
      organizationId: row.organizationId, workspaceId: row.workspaceId,
      actorType: 'user', actorId: input.userId, action: 'invitation.accept',
      resourceType: 'invitation', resourceId: row.id, outcome: 'denied',
      metadata: { reason: 'email-mismatch' },
    });
    return { ok: false, error: 'Sign in with the email address that was invited.', status: 403 };
  }
  const existingMember = await queryOne<{ id: string; status: string; workspaceMemberId: string | null }>(
    `SELECT m.id, m.status, wm.id AS workspaceMemberId
       FROM organization_member m
       LEFT JOIN workspace_member wm
         ON wm.organizationId = m.organizationId AND wm.workspaceId = ? AND wm.userId = m.userId
      WHERE m.organizationId = ? AND m.userId = ? AND m.status <> 'removed'`,
    row.workspaceId,
    row.organizationId,
    input.userId,
  );
  if (existingMember?.status === 'suspended') {
    return { ok: false, error: 'A suspended membership must be reactivated by an administrator.', status: 403 };
  }
  const capacity = await assertMemberCapacity(row.organizationId, row.workspaceId, {
    organizationMemberExists: Boolean(existingMember),
    workspaceMemberExists: Boolean(existingMember?.workspaceMemberId),
  });
  if (!capacity.ok) return { ok: false, error: capacity.error, status: 409 };
  const now = Date.now();
  const role = normalizeRole(row.role);
  const database = await db();
  const results = await database.batch([
    database.prepare(
      `UPDATE organization_invitation
          SET status = 'accepted', usedAt = ?, usedBy = ?, updatedAt = ?
        WHERE id = ? AND status = 'pending' AND expiresAt > ?`,
    ).bind(now, input.userId, now, row.id, now),
    database.prepare(
      `INSERT INTO organization_member
         (id, organizationId, userId, role, status, suspendedAt, suspendedReason,
          acceptedAt, lastActiveAt, createdBy, createdAt, updatedAt)
       SELECT ?, i.organizationId, ?, ?, 'active', NULL, NULL, ?, NULL, ?, ?, ?
         FROM organization_invitation i
        WHERE i.id = ? AND i.status = 'accepted' AND i.usedBy = ? AND i.usedAt = ?
       ON CONFLICT(organizationId, userId) DO UPDATE SET
         status = 'active', suspendedAt = NULL, suspendedReason = NULL,
         role = excluded.role, updatedAt = excluded.updatedAt`,
    ).bind(createId('member'), input.userId, role, now, input.userId, now, now,
      row.id, input.userId, now),
    database.prepare(
      `INSERT OR IGNORE INTO workspace_member
         (id, organizationId, workspaceId, userId, createdBy, createdAt)
       SELECT ?, i.organizationId, i.workspaceId, ?, ?, ?
         FROM organization_invitation i
        WHERE i.id = ? AND i.status = 'accepted' AND i.usedBy = ? AND i.usedAt = ?`,
    ).bind(createId('wmem'), input.userId, input.userId, now,
      row.id, input.userId, now),
  ]);
  if ((results[0]?.meta.changes ?? 0) !== 1) {
    return { ok: false, error: 'This invitation was already used.', status: 409 };
  }
  await recordAudit({
    organizationId: row.organizationId, workspaceId: row.workspaceId,
    actorType: 'user', actorId: input.userId, action: 'invitation.accept',
    resourceType: 'invitation', resourceId: row.id, outcome: 'success',
    metadata: { role },
  });
  return { ok: true, organizationId: row.organizationId, workspaceId: row.workspaceId };
}

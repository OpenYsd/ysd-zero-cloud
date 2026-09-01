/** Organization-scoped roles and the server-authoritative permission matrix. */

export const ROLES = ['owner', 'admin', 'developer', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

/** `member` was the pre-Phase-7 role and maps to developer during migration. */
export function normalizeRole(value: string | null | undefined): Role {
  if (value === 'member') return 'developer';
  return value && isRole(value) ? value : 'viewer';
}

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

const RANK: Record<Role, number> = { owner: 4, admin: 3, developer: 2, viewer: 1 };

export function rankOf(role: Role): number {
  return RANK[role];
}

export function atLeast(role: Role, minimum: Role): boolean {
  return rankOf(role) >= rankOf(minimum);
}

export const PERMISSIONS = [
  'workspace.use',
  'organization.read',
  'organization.create',
  'organization.update',
  'organization.archive',
  'workspace.read',
  'workspace.create',
  'workspace.update',
  'workspace.archive',
  'project.read',
  'project.create',
  'project.update',
  'project.delete',
  'deployment.read',
  'deployment.deploy',
  'deployment.lifecycle',
  'exposure.read',
  'exposure.preview',
  'exposure.manage',
  'domain.manage',
  'secret.metadata.read',
  'secret.write',
  'node.read',
  'node.manage',
  'game-server.read',
  'game-server.manage',
  'game-server.lifecycle',
  'ai.read',
  'ai.jobs.run',
  'database.read',
  'sql-editor.run',
  'billing.read',
  'billing.cost.configure',
  'member.read',
  'member.manage',
  'member.transfer-ownership',
  'invitation.read',
  'invitation.manage',
  'service-account.read',
  'service-account.manage',
  'session.read-own',
  'session.revoke-own',
  'session.revoke-member',
  'audit.read',
  'audit.export',
  'workflow.read',
  'workflow.create',
  'workflow.manage',
  'workflow.execute',
  'workflow.retry',
  'webhook.read',
  'webhook.manage',
  'notification.read',
  'incident.read',
  'incident.manage',
  'incident.resolve-critical',
  'usage.read',
  'shield.read',
  'shield.scan',
  'storage.read',
  'storage.write',
  // Compatibility names retained for the original admin and page guards.
  'admin.users.read',
  'admin.users.write',
] as const;

export type Permission = (typeof PERMISSIONS)[number];
export type Capability = Permission;

const VIEWER: readonly Permission[] = [
  'workspace.use', 'organization.read', 'workspace.read', 'project.read',
  'deployment.read', 'secret.metadata.read', 'node.read', 'game-server.read',
  'ai.read', 'database.read', 'billing.read', 'member.read',
  'session.read-own', 'session.revoke-own', 'usage.read', 'shield.read',
  'storage.read',
  'exposure.read',
  'workflow.read', 'webhook.read', 'notification.read',
  'incident.read',
];

const DEVELOPER: readonly Permission[] = [
  ...VIEWER,
  'project.create', 'project.update', 'project.delete',
  'deployment.deploy', 'deployment.lifecycle', 'secret.write', 'node.manage',
  'game-server.manage', 'game-server.lifecycle', 'ai.jobs.run', 'shield.scan',
  'storage.write',
  'exposure.preview',
  'workflow.create', 'workflow.execute',
  'incident.manage',
];

const ADMIN: readonly Permission[] = [
  ...DEVELOPER,
  'organization.update', 'workspace.create', 'workspace.update',
  'workspace.archive', 'member.manage', 'invitation.manage',
  'invitation.read',
  'service-account.read', 'service-account.manage', 'session.revoke-member',
  'audit.read', 'audit.export',
  'exposure.manage', 'domain.manage',
  'workflow.manage', 'workflow.retry',
  'webhook.manage',
  'incident.resolve-critical',
];

const OWNER: readonly Permission[] = [
  ...ADMIN,
  'organization.create', 'organization.archive', 'member.transfer-ownership',
  'billing.cost.configure',
];

export const PERMISSION_MATRIX: Readonly<Record<Role, ReadonlySet<Permission>>> = {
  owner: new Set(OWNER),
  admin: new Set(ADMIN),
  developer: new Set(DEVELOPER),
  viewer: new Set(VIEWER),
};

export const SERVICE_TOKEN_SCOPES = [
  'project.read', 'deployment.read', 'deployment.deploy',
  'deployment.lifecycle', 'secret.metadata.read', 'node.read',
  'secret.write',
  'game-server.read', 'game-server.lifecycle', 'ai.read', 'ai.jobs.run',
  'usage.read', 'storage.read', 'storage.write',
] as const satisfies readonly Permission[];

export const PROJECT_SERVICE_TOKEN_SCOPES = [
  'project.read',
  'deployment.read',
  'deployment.deploy',
  'deployment.lifecycle',
  'secret.metadata.read',
  'secret.write',
] as const satisfies readonly Permission[];

export type ServiceTokenScope = (typeof SERVICE_TOKEN_SCOPES)[number];

export function isServiceTokenScope(value: string): value is ServiceTokenScope {
  return (SERVICE_TOKEN_SCOPES as readonly string[]).includes(value);
}

export type Actor = {
  userId: string;
  role: Role;
  suspended: boolean;
  organizationId?: string;
  workspaceId?: string;
  projectIds?: readonly string[] | null;
  serviceAccountId?: string;
  tokenScopes?: readonly Permission[];
};

/**
 * Permissions that still make sense when a workspace membership or service
 * token is restricted to an explicit project allowlist. Workspace-level
 * infrastructure (nodes, AI, game servers, storage and raw database access)
 * deliberately drops out because it cannot be attributed to one project.
 */
const PROJECT_BOUND_PERMISSIONS = new Set<Permission>([
  'workspace.use',
  'organization.read',
  'workspace.read',
  'project.read',
  'project.update',
  'deployment.read',
  'deployment.deploy',
  'deployment.lifecycle',
  'exposure.read',
  'exposure.preview',
  'workflow.read', 'workflow.create', 'workflow.execute',
  'incident.read', 'incident.manage', 'incident.resolve-critical',
  'webhook.read',
  'secret.metadata.read',
  'secret.write',
  'member.read',
  'session.read-own',
  'session.revoke-own',
]);

export type Target = { userId: string; role: Role };

export function can(actor: Actor, permission: Permission): boolean {
  const matrix = PERMISSION_MATRIX[actor.role];
  if (actor.suspended || !matrix?.has(permission)) return false;
  if (actor.projectIds !== null && actor.projectIds !== undefined &&
      !PROJECT_BOUND_PERMISSIONS.has(permission)) {
    return false;
  }
  if (actor.serviceAccountId) {
    // Service tokens are the intersection of the developer matrix and their
    // explicit allowlisted scopes. They never inherit management privileges.
    return Boolean(actor.tokenScopes?.includes(permission));
  }
  return true;
}

export function canAccessProject(actor: Actor, projectId: string | null | undefined): boolean {
  if (!projectId || actor.projectIds === null || actor.projectIds === undefined) return true;
  return actor.projectIds.includes(projectId);
}

export type RoleChangeRefusal =
  | 'not-permitted'
  | 'self'
  | 'outranked'
  | 'cannot-grant-owner'
  | 'last-owner';

export type RoleChangeDecision =
  | { allowed: true }
  | { allowed: false; reason: RoleChangeRefusal; message: string };

export function canChangeRole(
  actor: Actor,
  target: Target,
  nextRole: Role,
  ownerCount: number,
): RoleChangeDecision {
  if (!can(actor, 'member.manage')) {
    return { allowed: false, reason: 'not-permitted', message: 'You cannot manage members.' };
  }
  if (actor.userId === target.userId) {
    return { allowed: false, reason: 'self', message: 'You cannot change your own role.' };
  }
  if (target.role === 'owner' && ownerCount <= 1) {
    return { allowed: false, reason: 'last-owner', message: 'The organization must keep an owner.' };
  }
  if (rankOf(target.role) >= rankOf(actor.role)) {
    return { allowed: false, reason: 'outranked', message: 'You cannot change a member at or above your role.' };
  }
  if (nextRole === 'owner') {
    return {
      allowed: false,
      reason: 'cannot-grant-owner',
      message: 'Use the confirmed ownership transfer flow to grant ownership.',
    };
  }
  return { allowed: true };
}

export function canSuspend(actor: Actor, target: Target): RoleChangeDecision {
  if (!can(actor, 'member.manage')) {
    return { allowed: false, reason: 'not-permitted', message: 'You cannot manage members.' };
  }
  if (actor.userId === target.userId) {
    return { allowed: false, reason: 'self', message: 'You cannot suspend your own account.' };
  }
  if (rankOf(target.role) >= rankOf(actor.role)) {
    return { allowed: false, reason: 'outranked', message: 'You cannot suspend a member at or above your role.' };
  }
  return { allowed: true };
}

/** Central route policy. Unknown API routes fail closed for service tokens. */
export function permissionForRequest(method: string, pathname: string): Permission | null {
  const verb = method.toUpperCase();
  const read = verb === 'GET' || verb === 'HEAD';
  if (pathname.startsWith('/api/projects')) return read ? 'project.read' : verb === 'DELETE' ? 'project.delete' : 'project.create';
  if (pathname === '/api/smart-deploy') return 'deployment.deploy';
  if (pathname.startsWith('/api/deployments')) return read ? 'deployment.read' : 'deployment.lifecycle';
  if (pathname.startsWith('/api/exposures')) return read ? 'exposure.read' : 'exposure.preview';
  if (pathname.startsWith('/api/domains')) return read ? 'exposure.read' : 'domain.manage';
  if (pathname.startsWith('/api/secrets')) return read ? 'secret.metadata.read' : 'secret.write';
  if (pathname.startsWith('/api/nodes/agent/')) return null;
  if (pathname.startsWith('/api/nodes')) return read ? 'node.read' : 'node.manage';
  if (pathname.startsWith('/api/game-servers')) return read ? 'game-server.read' : pathname.includes('/actions') ? 'game-server.lifecycle' : 'game-server.manage';
  if (pathname.startsWith('/api/ai/jobs')) return read ? 'ai.read' : 'ai.jobs.run';
  if (pathname.startsWith('/api/ai/models')) return read ? 'ai.read' : 'ai.jobs.run';
  if (pathname === '/api/ai') return 'ai.read';
  if (pathname.startsWith('/api/database/query')) return 'sql-editor.run';
  if (pathname.startsWith('/api/database')) return 'database.read';
  if (pathname.startsWith('/api/storage')) return read ? 'storage.read' : 'storage.write';
  if (pathname.startsWith('/api/logs')) return 'workspace.read';
  if (pathname.startsWith('/api/usage')) return 'usage.read';
  if (pathname.startsWith('/api/shield/scan')) return 'shield.scan';
  if (pathname.startsWith('/api/shield')) return 'shield.read';
  if (pathname.startsWith('/api/settings')) return read ? 'workspace.read' : 'workspace.update';
  if (pathname.startsWith('/api/webhook-sources')) return read ? 'webhook.read' : 'webhook.manage';
  if (pathname.startsWith('/api/workflows')) return read ? 'workflow.read' : 'workflow.create';
  if (pathname.startsWith('/api/notifications')) return 'notification.read';
  if (pathname.startsWith('/api/incidents')) return read ? 'incident.read' : 'incident.manage';
  if (pathname.startsWith('/api/admin/users')) return read ? 'admin.users.read' : 'admin.users.write';
  return null;
}

import type { DeployTarget, Framework } from './smart-deploy.ts';

/**
 * The shapes that cross the server/client boundary.
 *
 * Client components import from here rather than from `lib/server/*`, which
 * reaches for `cloudflare:workers` and must never be pulled into a browser
 * bundle. Everything in this module is data, JSON-serialisable, and free of
 * runtime dependencies.
 */

export type Project = {
  id: string;
  name: string;
  repository: string | null;
  framework: Framework;
  environment: string;
  region: string;
  status: 'idle' | 'building' | 'live' | 'blocked';
  visibility: 'private' | 'public';
  createdAt: number;
  updatedAt: number;
};

export type Secret = {
  id: string;
  name: string;
  scope: string;
  environment: string;
  fingerprint: string;
  rotationDays: number | null;
  createdAt: number;
  updatedAt: number;
};

export const SECRET_ENVIRONMENTS = [
  'Production',
  'Preview',
  'Development',
  'All',
] as const;
export type SecretEnvironment = (typeof SECRET_ENVIRONMENTS)[number];

export function isSecretEnvironment(value: string): value is SecretEnvironment {
  return (SECRET_ENVIRONMENTS as readonly string[]).includes(value);
}

export type LogLevel = 'INFO' | 'WARN' | 'ERROR';

export type LogSource =
  | 'workspace'
  | 'deployment'
  | 'project'
  | 'database'
  | 'secret'
  | 'shield'
  | 'auth'
  | 'storage'
  | 'networking';

export const LOG_LEVELS = ['INFO', 'WARN', 'ERROR'] as const;

export const LOG_SOURCES = [
  'workspace',
  'deployment',
  'project',
  'database',
  'secret',
  'shield',
  'auth',
  'storage',
  'networking',
] as const;

export type StorageObject = {
  id: string;
  name: string;
  contentType: string;
  size: number;
  etag: string;
  uploadedBy: string;
  createdAt: number;
};

export type StorageUsage = {
  bytesUsed: number;
  bytesReserved: number;
  objectCount: number;
  period: string;
  classAWrites: number;
  classBReads: number;
  updatedAt: number;
};

export type StorageState = {
  available: boolean;
  bucket: string | null;
  access: 'private';
  objects: StorageObject[];
  usage: StorageUsage;
  limits: {
    accountBytes: number;
    workspaceBytes: number;
    objectBytes: number;
    accountObjects: number;
    workspaceObjects: number;
    accountClassA: number;
    workspaceClassA: number;
    accountClassB: number;
    workspaceClassB: number;
  };
};

export function isLogLevel(value: string): value is LogLevel {
  return (LOG_LEVELS as readonly string[]).includes(value);
}

export function isLogSource(value: string): value is LogSource {
  return (LOG_SOURCES as readonly string[]).includes(value);
}

export type LogEvent = {
  id: string;
  level: LogLevel;
  source: LogSource;
  message: string;
  actor: string | null;
  resource: string | null;
  createdAt: number;
};

export type DeploymentState = 'planned' | 'blocked';

export type Deployment = {
  id: string;
  projectId: string | null;
  repository: string;
  target: DeployTarget;
  framework: string;
  commitSha: string;
  state: DeploymentState;
  durationMs: number | null;
  estimatedMonthlyCost: number;
  zeroModeEnabled: boolean;
  createdAt: number;
  finishedAt: number | null;
};

export type Workspace = {
  id: string;
  name: string;
  ownerUserId: string;
  zeroMode: boolean;
  autoScan: boolean;
  sleepIdleServers: boolean;
  previewDeployments: boolean;
  createdAt: number;
  updatedAt: number;
};

export const WORKSPACE_SETTINGS = [
  'zeroMode',
  'autoScan',
  'sleepIdleServers',
  'previewDeployments',
] as const;

export type WorkspaceSetting = (typeof WORKSPACE_SETTINGS)[number];

export function isWorkspaceSetting(value: string): value is WorkspaceSetting {
  return (WORKSPACE_SETTINGS as readonly string[]).includes(value);
}

/** Database Studio shapes, mirrored for the client grid. */
export type ColumnInfo = {
  name: string;
  type: string;
  notNull: boolean;
  primaryKey: boolean;
};

export type TableSummary = {
  name: string;
  kind: 'auth' | 'workspace' | 'system';
  rows: number;
  columns: number;
  hasPrimaryKey: boolean;
  masked: boolean;
};

export type TablePage = {
  table: string;
  columns: ColumnInfo[];
  rows: Record<string, unknown>[];
  total: number;
  maskedColumns: string[];
};

/**
 * The workspace sections.
 *
 * Both the navigation and the section pages read this list, so a surface
 * cannot be advertised as live in one place and rendered as a preview in the
 * other.
 */
export const SECTIONS = [
  'projects',
  'deployments',
  'databases',
  'storage',
  'ai',
  'game-servers',
  'nodes',
  'logs',
  'networking',
  'secrets',
  'usage',
  'shield',
  'admin',
  'settings',
] as const;

export type Section = (typeof SECTIONS)[number];

export function isSection(value: string): value is Section {
  return (SECTIONS as readonly string[]).includes(value);
}

/** Sections backed by live D1 data. Everything else is labelled a preview. */
export const LIVE_SECTIONS: readonly Section[] = [
  'projects',
  'deployments',
  'databases',
  'logs',
  'secrets',
  'usage',
  'shield',
  'admin',
  'settings',
  'storage',
  'networking',
];

export function isLiveSection(section: Section): boolean {
  return LIVE_SECTIONS.includes(section);
}

import type { DeployTarget, Framework } from './smart-deploy.ts';
import type { AiModelState, AiRuntime } from './ai.ts';
import type {
  NodeCapabilities,
  NodeJobState,
  NodeJobType,
  NodeMetrics,
  NodeStatus,
} from './nodes.ts';
import type {
  GameServerStatus,
  MinecraftProperties,
} from './game-servers.ts';

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
  | 'networking'
  | 'node'
  | 'ai'
  | 'game-server';

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
  'node',
  'ai',
  'game-server',
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

export type ComputeNode = {
  id: string;
  name: string;
  status: NodeStatus;
  agentVersion: string;
  protocolVersion: number;
  platform: string;
  architecture: string;
  capabilities: NodeCapabilities;
  pairedAt: number;
  lastHeartbeatAt: number | null;
  revokedAt: number | null;
  metrics: NodeMetrics | null;
};

export type NodeJob = {
  id: string;
  type: NodeJobType;
  state: NodeJobState;
  targetNodeId: string | null;
  assignedNodeId: string | null;
  attempts: number;
  maxAttempts: number;
  leaseExpiresAt: number | null;
  result: Record<string, unknown> | null;
  lastError: string | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
};

export type NodeSecurityEvent = {
  id: string;
  nodeId: string | null;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
  createdAt: number;
};

export type NodesState = {
  nodes: ComputeNode[];
  jobs: NodeJob[];
  securityEvents: NodeSecurityEvent[];
  summary: {
    total: number;
    online: number;
    stale: number;
    offline: number;
    revoked: number;
    queuedJobs: number;
    activeLeases: number;
  };
  protocolVersion: number;
  currentAgentVersion: string;
  minimumAgentVersion: string;
  outboundOnly: true;
  projectedMonthlyCost: 0;
};

export type AiModelCache = {
  nodeId: string;
  nodeName: string;
  state: AiModelState;
  sizeBytes: number;
  checksum: string | null;
  error: string | null;
  lastVerifiedAt: number | null;
  lastUsedAt: number | null;
};

export type AiModel = {
  id: string;
  catalogId: string;
  displayName: string;
  runtime: AiRuntime;
  family: string;
  runtimeModel: string;
  source: 'ollama-library' | 'local-runtime';
  sizeBytes: number;
  expectedMemoryBytes: number;
  requiredVramBytes: number;
  checksum: string | null;
  downloadable: boolean;
  enabled: boolean;
  state: AiModelState;
  caches: AiModelCache[];
  lastVerifiedAt: number | null;
  lastUsedAt: number | null;
};

export type AiRun = {
  jobId: string;
  modelId: string;
  modelName: string;
  runtime: AiRuntime;
  state: NodeJobState;
  requestedNodeId: string | null;
  selectedNodeId: string | null;
  selectedNodeName: string | null;
  promptCharacters: number;
  systemPromptCharacters: number;
  maxTokens: number;
  responseFormat: 'text' | 'json';
  inputTokensEstimate: number | null;
  outputTokensEstimate: number | null;
  latencyMs: number | null;
  attempts: number;
  result: Record<string, unknown> | null;
  lastError: string | null;
  cancelRequestedAt: number | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
};

export type AiState = {
  nodes: ComputeNode[];
  models: AiModel[];
  runs: AiRun[];
  summary: {
    aiCapableNodes: number;
    onlineNodes: number;
    readyModels: number;
    queued: number;
    running: number;
    completed: number;
    failed: number;
    cancelled: number;
    averageLatencyMs: number | null;
  };
  supportedRuntimes: readonly AiRuntime[];
  localOnly: true;
  zeroModeEnforced: true;
  projectedMonthlyCost: 0;
};

export type GameServer = {
  id: string;
  nodeId: string;
  nodeName: string;
  nodeStatus: NodeStatus;
  name: string;
  game: 'minecraft-java';
  serverType: 'vanilla';
  version: string;
  status: GameServerStatus;
  desiredStatus: 'running' | 'stopped';
  ramMb: number;
  cpuCores: number;
  diskQuotaBytes: number;
  port: number;
  exposurePolicy: 'private';
  observedExposure: 'private' | 'unexpected';
  playerCount: number;
  players: string[];
  worlds: string[];
  cpuLoadPercent: number | null;
  memoryUsedBytes: number | null;
  uptimeSeconds: number;
  onlineMode: boolean;
  whitelistEnabled: boolean;
  config: MinecraftProperties;
  binaryHash: string | null;
  binaryVerified: boolean;
  crashCount: number;
  crashLoop: boolean;
  lastError: string | null;
  lastStatusAt: number | null;
  createdAt: number;
  updatedAt: number;
};

export type GameServerAction = {
  id: string;
  serverId: string;
  jobId: string;
  kind: string;
  state: NodeJobState;
  requestedBy: string;
  error: string | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
};

export type GameServerBackup = {
  id: string;
  serverId: string;
  name: string;
  state: 'creating' | 'ready' | 'corrupted' | 'failed' | 'deleted';
  sizeBytes: number;
  checksum: string | null;
  fileCount: number;
  error: string | null;
  createdAt: number;
  verifiedAt: number | null;
  restoredAt: number | null;
};

export type GameServerLog = {
  id: string;
  serverId: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  message: string;
  createdAt: number;
};

export type GameServersState = {
  servers: GameServer[];
  nodes: ComputeNode[];
  actions: GameServerAction[];
  backups: GameServerBackup[];
  logs: GameServerLog[];
  summary: {
    total: number;
    running: number;
    stopped: number;
    attention: number;
    players: number;
    allocatedRamMb: number;
    localBackupBytes: number;
  };
  supportedGames: readonly ['minecraft-java'];
  supportedServerTypes: readonly ['vanilla'];
  localExecutionOnly: true;
  defaultExposure: 'private';
  zeroModeEnforced: true;
  projectedMonthlyCost: 0;
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
  'nodes',
  'ai',
  'game-servers',
];

export function isLiveSection(section: Section): boolean {
  return LIVE_SECTIONS.includes(section);
}

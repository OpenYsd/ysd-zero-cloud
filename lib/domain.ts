import type { Framework } from './smart-deploy.ts';
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
import type { WorkflowDefinition, WorkflowExecutionState } from './workflows.ts';

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
  | 'game-server'
  | 'workflow';

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
  'workflow',
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
  assignmentsDisabledAt: number | null;
  assignmentsDisabledBy: string | null;
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

export type DeploymentState =
  | 'planned'
  | 'blocked'
  | 'queued'
  | 'building'
  | 'starting'
  | 'healthy'
  | 'stopping'
  | 'stopped'
  | 'restarting'
  | 'rolling_back'
  | 'deleting'
  | 'cancelling'
  | 'deleted'
  | 'failed'
  | 'cancelled'
  | 'timed_out'
  | 'crash_loop'
  | 'node_offline'
  | 'node_revoked';

export type Deployment = {
  id: string;
  projectId: string | null;
  repository: string;
  target: string;
  framework: string;
  commitSha: string;
  branch: string;
  environment: 'Production' | 'Preview' | 'Development';
  nodeId: string | null;
  nodeName: string | null;
  jobId: string | null;
  currentArtifactId: string | null;
  localPort: number | null;
  localAddress: string | null;
  exposure: 'private';
  observedBind: '127.0.0.1' | '0.0.0.0' | 'unknown';
  healthPath: string;
  state: DeploymentState;
  durationMs: number | null;
  buildDurationMs: number | null;
  estimatedMonthlyCost: number;
  zeroModeEnabled: boolean;
  restartCount: number;
  crashLoop: boolean;
  lastError: string | null;
  createdAt: number;
  startedAt: number | null;
  updatedAt: number;
  finishedAt: number | null;
  deletedAt: number | null;
};

export type AppDeploymentAction = {
  id: string;
  deploymentId: string;
  projectId: string;
  nodeId: string;
  jobId: string;
  kind: string;
  state: NodeJobState;
  error: string | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
};

export type AppArtifact = {
  id: string;
  deploymentId: string;
  projectId: string;
  nodeId: string;
  commitSha: string;
  version: number;
  state: 'building' | 'verified' | 'failed' | 'corrupted' | 'deleted';
  checksum: string | null;
  sizeBytes: number;
  createdAt: number;
  verifiedAt: number | null;
  activatedAt: number | null;
};

export type AppDeploymentLog = {
  id: string;
  deploymentId: string;
  nodeId: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  phase: string;
  message: string;
  createdAt: number;
};

export type WorkflowVersion = {
  id: string;
  workflowId: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  version: number;
  kind: 'draft' | 'published' | 'rollback';
  triggerType: string;
  definition: WorkflowDefinition;
  definitionHash: string;
  sourceVersionId: string | null;
  createdBy: string;
  createdAt: number;
  publishedAt: number | null;
};

export type WorkflowActionExecution = {
  id: string;
  executionId: string;
  actionIndex: number;
  attempt: number;
  actionType: string;
  state: 'running' | 'succeeded' | 'failed' | 'skipped';
  resourceType: string | null;
  resourceId: string | null;
  error: string | null;
  startedAt: number;
  finishedAt: number | null;
};

export type WorkflowExecution = {
  id: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  workflowId: string;
  versionId: string;
  eventId: string;
  state: WorkflowExecutionState;
  idempotencyKey: string;
  correlationId: string;
  causationId: string | null;
  chainDepth: number;
  actionIndex: number;
  attempts: number;
  maxAttempts: number;
  nextAttemptAt: number | null;
  timeoutAt: number;
  leaseExpiresAt: number | null;
  cancelRequestedAt: number | null;
  cancelRequestedBy: string | null;
  lastError: string | null;
  startedAt: number | null;
  finishedAt: number | null;
  deadLetterAt: number | null;
  manualRetryOf: string | null;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  actions: WorkflowActionExecution[];
  event: {
    type: import('./workflows.ts').WorkflowTriggerType;
    resourceType: string;
    resourceId: string | null;
    correlationId: string;
    sourceId: string | null;
    externalEventType: string | null;
    externalEventId: string | null;
    subject: string | null;
  } | null;
};

export type WorkflowVariable = {
  id: string;
  name: string;
  kind: 'text' | 'number' | 'boolean' | 'secret';
  value: string | null;
  secretId: string | null;
  secretName: string | null;
  secretEnvironment: string | null;
  secretScope: string | null;
  createdAt: number;
  updatedAt: number;
};

export type Workflow = {
  id: string;
  organizationId: string;
  workspaceId: string;
  projectId: string | null;
  name: string;
  description: string;
  status: 'draft' | 'active' | 'paused';
  activeVersionId: string | null;
  latestVersion: number;
  ownerUserId: string;
  failureStreak: number;
  lastTriggeredAt: number | null;
  lastSucceededAt: number | null;
  lastFailedAt: number | null;
  lastScheduledAt: number | null;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  activeVersion: WorkflowVersion | null;
  versions: WorkflowVersion[];
  executions: WorkflowExecution[];
  variables: WorkflowVariable[];
};

export type InternalNotification = {
  id: string;
  projectId: string | null;
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  resourceType: string;
  resourceId: string | null;
  href: string | null;
  readAt: number | null;
  createdAt: number;
};

export type WebhookSource = {
  id: string;
  projectId: string | null;
  name: string;
  description: string;
  status: 'enabled' | 'disabled' | 'archived';
  secretVersion: number;
  receivedCount: number;
  acceptedCount: number;
  rejectedCount: number;
  deduplicatedCount: number;
  workflowExecutionsCreated: number;
  lastReceivedAt: number | null;
  lastAcceptedAt: number | null;
  lastRejectedAt: number | null;
  createdAt: number;
  updatedAt: number;
  rotatedAt: number | null;
  archivedAt: number | null;
  webhookPath: string;
};

export type WebhookDelivery = {
  id: string;
  sourceId: string;
  projectId: string | null;
  externalEventId: string | null;
  eventType: string | null;
  subject: string | null;
  status: 'accepted' | 'rejected' | 'deduplicated';
  reasonCode: string | null;
  workflowEventId: string | null;
  correlationId: string | null;
  workflowExecutionsCreated: number;
  receivedAt: number;
};

export type WorkflowsState = {
  workflows: Workflow[];
  notifications: InternalNotification[];
  webhookGateway: {
    sources: WebhookSource[];
    recentEvents: WebhookDelivery[];
    summary: {
      received: number;
      accepted: number;
      rejected: number;
      deduplicated: number;
      workflowExecutionsCreated: number;
    };
  };
  templates: readonly {
    id: string;
    name: string;
    description: string;
    projectScoped: boolean;
    definition: WorkflowDefinition;
  }[];
  summary: {
    total: number;
    active: number;
    paused: number;
    failedExecutions: number;
    unreadNotifications: number;
  };
  schedule: {
    available: true;
    mode: 'single-free-cron-trigger';
    tickMinutes: 1;
  };
  zeroModeEnforced: true;
  projectedMonthlyCost: 0;
};

export type Workspace = {
  id: string;
  organizationId: string;
  name: string;
  ownerUserId: string;
  zeroMode: boolean;
  autoScan: boolean;
  sleepIdleServers: boolean;
  previewDeployments: boolean;
  createdAt: number;
  updatedAt: number;
  archivedAt: number | null;
};

export type Organization = {
  id: string;
  name: string;
  slug: string;
  ownerUserId: string;
  status: 'active' | 'archived';
  adminCanRevokeSessions: boolean;
  createdAt: number;
  updatedAt: number;
  archivedAt: number | null;
};

export type OrganizationSummary = Organization & {
  role: import('./roles.ts').Role;
  workspaces: Workspace[];
};

export type OrganizationMember = {
  id: string;
  userId: string;
  name: string;
  email: string;
  role: import('./roles.ts').Role;
  status: 'active' | 'suspended' | 'removed';
  suspendedAt: number | null;
  suspendedReason: string | null;
  acceptedAt: number;
  lastActiveAt: number | null;
  activeSessions: number;
  /** `null` means every project in the selected workspace. */
  projectIds: string[] | null;
};

export type OrganizationInvitation = {
  id: string;
  email: string;
  role: Exclude<import('./roles.ts').Role, 'owner'>;
  workspaceId: string;
  workspaceName: string;
  tokenPrefix: string;
  status: 'pending' | 'accepted' | 'revoked' | 'expired';
  expiresAt: number;
  createdAt: number;
};

export type ServiceAccount = {
  id: string;
  name: string;
  workspaceId: string;
  projectId: string | null;
  projectName: string | null;
  status: 'active' | 'revoked';
  scopes: string[];
  tokenPrefix: string | null;
  expiresAt: number | null;
  lastUsedAt: number | null;
  createdAt: number;
};

export type AuditEvent = {
  id: string;
  workspaceId: string | null;
  actorType: 'user' | 'service_account' | 'system';
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  outcome: 'success' | 'denied' | 'failed';
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, string | number | boolean | null>;
  createdAt: number;
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
  'workflows',
  'secrets',
  'usage',
  'shield',
  'members',
  'invitations',
  'service-accounts',
  'audit',
  'sessions',
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
  'members',
  'invitations',
  'service-accounts',
  'audit',
  'sessions',
  'admin',
  'settings',
  'storage',
  'networking',
  'workflows',
  'nodes',
  'ai',
  'game-servers',
];

export function isLiveSection(section: Section): boolean {
  return LIVE_SECTIONS.includes(section);
}

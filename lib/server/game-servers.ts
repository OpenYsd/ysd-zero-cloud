import {
  DEFAULT_MINECRAFT_PROPERTIES,
  GAME_SERVER_LIMITS,
  MINECRAFT_VERSIONS,
  containsGameServerAbuse,
  gameServerResourceEligible,
  validateGameServerJobPayload,
  validateMinecraftProperties,
  type GameServerJobType,
  type GameServerStatus,
  type MinecraftProperties,
} from '@/lib/game-servers';
import { createId } from '@/lib/crypto';
import type {
  ComputeNode,
  GameServer,
  GameServerAction,
  GameServerBackup,
  GameServerLog,
  GameServersState,
  NodeJob,
} from '@/lib/domain';
import { agentVersionSupported, stableJson } from '@/lib/nodes';
import { execute, query, queryOne } from './db';
import { writeLog } from './logs';
import { assertResourceCapacity } from './organization-limits';
import { enqueueJob, readNodesState } from './nodes';
import { getWorkspace } from './workspace';

type ServerRow = {
  id: string;
  workspaceId: string;
  nodeId: string;
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
  playersJson: string;
  worldsJson: string;
  cpuLoadPercent: number | null;
  memoryUsedBytes: number | null;
  uptimeSeconds: number;
  onlineMode: number;
  whitelistEnabled: number;
  config: string;
  binaryHash: string | null;
  binaryVerified: number;
  crashCount: number;
  crashLoop: number;
  lastError: string | null;
  lastStatusAt: number | null;
  createdAt: number;
  updatedAt: number;
};

type ActionRow = {
  id: string;
  serverId: string;
  jobId: string;
  kind: string;
  state: NodeJob['state'];
  jobState: NodeJob['state'] | null;
  requestedBy: string;
  error: string | null;
  jobError: string | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
  jobCompletedAt: number | null;
};

type BackupRow = {
  id: string;
  serverId: string;
  name: string;
  state: GameServerBackup['state'];
  sizeBytes: number;
  checksum: string | null;
  fileCount: number;
  error: string | null;
  createdAt: number;
  verifiedAt: number | null;
  restoredAt: number | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const expected = new Set(keys);
  return (
    Object.keys(value).length === expected.size &&
    Object.keys(value).every((key) => expected.has(key))
  );
}

function safeJsonArray(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed)
      ? parsed.filter((entry): entry is string => typeof entry === 'string')
      : [];
  } catch {
    return [];
  }
}

function safeProperties(value: string): MinecraftProperties {
  try {
    const parsed = validateMinecraftProperties(JSON.parse(value) as unknown);
    if (parsed.ok) return parsed.properties;
  } catch {
    // Historical malformed metadata is rendered with safe defaults.
  }
  return DEFAULT_MINECRAFT_PROPERTIES;
}

function toServer(row: ServerRow, node: ComputeNode | undefined): GameServer {
  const nodeStatus = node?.status ?? 'offline';
  const status =
    nodeStatus === 'revoked'
      ? 'node_revoked'
      : nodeStatus === 'offline' && row.status !== 'stopped'
        ? 'node_offline'
        : row.status;
  return {
    id: row.id,
    nodeId: row.nodeId,
    nodeName: node?.name ?? 'Unavailable node',
    nodeStatus,
    name: row.name,
    game: 'minecraft-java',
    serverType: 'vanilla',
    version: row.version,
    status,
    desiredStatus: row.desiredStatus,
    ramMb: row.ramMb,
    cpuCores: row.cpuCores,
    diskQuotaBytes: row.diskQuotaBytes,
    port: row.port,
    exposurePolicy: 'private',
    observedExposure: row.observedExposure,
    playerCount: row.playerCount,
    players: safeJsonArray(row.playersJson),
    worlds: safeJsonArray(row.worldsJson),
    cpuLoadPercent: row.cpuLoadPercent,
    memoryUsedBytes: row.memoryUsedBytes,
    uptimeSeconds: row.uptimeSeconds,
    onlineMode: Boolean(row.onlineMode),
    whitelistEnabled: Boolean(row.whitelistEnabled),
    config: safeProperties(row.config),
    binaryHash: row.binaryHash,
    binaryVerified: Boolean(row.binaryVerified),
    crashCount: row.crashCount,
    crashLoop: Boolean(row.crashLoop),
    lastError: row.lastError,
    lastStatusAt: row.lastStatusAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function toAction(row: ActionRow): GameServerAction {
  return {
    id: row.id,
    serverId: row.serverId,
    jobId: row.jobId,
    kind: row.kind,
    state: row.jobState ?? row.state,
    requestedBy: row.requestedBy,
    error: row.jobError ?? row.error,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    completedAt: row.jobCompletedAt ?? row.completedAt,
  };
}

function toBackup(row: BackupRow): GameServerBackup {
  return {
    id: row.id,
    serverId: row.serverId,
    name: row.name,
    state: row.state,
    sizeBytes: row.sizeBytes,
    checksum: row.checksum,
    fileCount: row.fileCount,
    error: row.error,
    createdAt: row.createdAt,
    verifiedAt: row.verifiedAt,
    restoredAt: row.restoredAt,
  };
}

export async function readGameServersState(
  workspaceId: string,
  now = Date.now(),
): Promise<GameServersState> {
  const nodesState = await readNodesState(workspaceId, now);
  const [serverRows, actionRows, backupRows, logs] = await Promise.all([
    query<ServerRow>(
      `SELECT * FROM game_server
       WHERE workspaceId = ? AND deletedAt IS NULL
       ORDER BY createdAt DESC`,
      workspaceId,
    ),
    query<ActionRow>(
      `SELECT a.*, j.state AS jobState, j.lastError AS jobError,
              j.completedAt AS jobCompletedAt
       FROM game_server_action a
       JOIN node_job j ON j.id = a.jobId AND j.workspaceId = a.workspaceId
       WHERE a.workspaceId = ? ORDER BY a.createdAt DESC LIMIT 100`,
      workspaceId,
    ),
    query<BackupRow>(
      `SELECT id, serverId, name, state, sizeBytes, checksum, fileCount,
              error, createdAt, verifiedAt, restoredAt
       FROM game_server_backup
       WHERE workspaceId = ? AND deletedAt IS NULL
       ORDER BY createdAt DESC LIMIT 100`,
      workspaceId,
    ),
    query<GameServerLog>(
      `SELECT id, serverId, level, message, createdAt
       FROM game_server_log WHERE workspaceId = ?
       ORDER BY createdAt DESC LIMIT 200`,
      workspaceId,
    ),
  ]);
  const nodeMap = new Map(nodesState.nodes.map((node) => [node.id, node]));
  const servers = serverRows.map((row) => toServer(row, nodeMap.get(row.nodeId)));
  const nodeIds = new Set(servers.map((server) => server.nodeId));
  const nodes = nodesState.nodes.filter(
    (node) =>
      nodeIds.has(node.id) ||
      node.capabilities.contracts.gameServers ||
      node.capabilities.gameServers.minecraftJavaAvailable,
  );
  return {
    servers,
    nodes,
    actions: actionRows.map(toAction),
    backups: backupRows.map(toBackup),
    logs,
    summary: {
      total: servers.length,
      running: servers.filter((server) => server.status === 'running').length,
      stopped: servers.filter((server) => server.status === 'stopped').length,
      attention: servers.filter(
        (server) =>
          server.crashLoop ||
          server.status === 'error' ||
          server.status === 'crashed' ||
          server.status === 'node_offline' ||
          server.status === 'node_revoked' ||
          server.observedExposure === 'unexpected' ||
          !server.binaryVerified,
      ).length,
      players: servers.reduce((total, server) => total + server.playerCount, 0),
      allocatedRamMb: servers.reduce((total, server) => total + server.ramMb, 0),
      localBackupBytes: backupRows.reduce(
        (total, backup) => total + backup.sizeBytes,
        0,
      ),
    },
    supportedGames: ['minecraft-java'],
    supportedServerTypes: ['vanilla'],
    localExecutionOnly: true,
    defaultExposure: 'private',
    zeroModeEnforced: true,
    projectedMonthlyCost: 0,
  };
}

async function recordGameSecurityEvent(input: {
  workspaceId: string;
  nodeId?: string | null;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}): Promise<void> {
  await execute(
    `INSERT INTO node_security_event
     (id, workspaceId, nodeId, type, severity, detail,
      networkFingerprint, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
    createId('nsec'),
    input.workspaceId,
    input.nodeId ?? null,
    input.type,
    input.severity,
    input.detail.slice(0, 500),
    Date.now(),
  );
}

function requestKey(value: string | null): string {
  return value?.trim().slice(0, 80) || createId('idem');
}

async function duplicateAction(
  workspaceId: string,
  idempotencyKey: string,
): Promise<GameServerAction | null> {
  const row = await queryOne<ActionRow>(
    `SELECT a.*, j.state AS jobState, j.lastError AS jobError,
            j.completedAt AS jobCompletedAt
     FROM game_server_action a
     JOIN node_job j ON j.id = a.jobId AND j.workspaceId = a.workspaceId
     WHERE a.workspaceId = ? AND a.idempotencyKey = ?`,
    workspaceId,
    idempotencyKey,
  );
  return row ? toAction(row) : null;
}

function nodeHasCreateCapacity(
  node: ComputeNode,
  ramMb: number,
  diskQuotaBytes: number,
): boolean {
  return (
    node.status === 'online' &&
    agentVersionSupported(node.agentVersion) &&
    node.capabilities.gameServers.minecraftJavaAvailable &&
    gameServerResourceEligible({
      freeMemoryBytes: node.capabilities.memory.freeBytes,
      freeDiskBytes: node.capabilities.disk.freeBytes,
      ramMb,
      diskQuotaBytes,
      activeServers: node.capabilities.gameServers.activeServers,
      maximumServers: node.capabilities.gameServers.maxConcurrentServers,
    }) &&
    (node.metrics?.cpuLoadPercent ?? 0) < 90
  );
}

async function createServer(input: {
  workspaceId: string;
  actor: string;
  body: Record<string, unknown>;
  idempotencyKey: string | null;
}): Promise<QueueGameServerResult> {
  const keys = [
    'action',
    'nodeId',
    'name',
    'version',
    'ramMb',
    'cpuCores',
    'diskQuotaBytes',
    'port',
    'properties',
    'eulaAccepted',
    'provider',
    'zeroMode',
    'exposure',
  ];
  if (!exactKeys(input.body, keys)) {
    return { ok: false, status: 400, error: 'Create contains unknown or missing fields.' };
  }
  const key = `game:create:${requestKey(input.idempotencyKey)}`;
  const duplicate = await duplicateAction(input.workspaceId, key);
  if (duplicate) {
    return {
      ok: true,
      created: false,
      serverId: duplicate.serverId,
      backupId: null,
      action: duplicate,
    };
  }
  const state = await readGameServersState(input.workspaceId);
  if (state.servers.length >= GAME_SERVER_LIMITS.maximumServersPerWorkspace) {
    return { ok: false, status: 409, error: 'The workspace Game Server ceiling is reached.' };
  }
  const capacity = await assertResourceCapacity(input.workspaceId, 'gameServers');
  if (!capacity.ok) return { ok: false, status: 409, error: capacity.error };
  const ramMb = typeof input.body.ramMb === 'number' ? input.body.ramMb : 0;
  const diskQuotaBytes =
    typeof input.body.diskQuotaBytes === 'number' ? input.body.diskQuotaBytes : 0;
  const requestedNodeId =
    typeof input.body.nodeId === 'string' && input.body.nodeId
      ? input.body.nodeId
      : null;
  if (input.body.nodeId !== null && input.body.nodeId !== requestedNodeId) {
    return { ok: false, status: 400, error: 'Target node is invalid.' };
  }
  const candidates = state.nodes
    .filter(
      (node) =>
        (!requestedNodeId || node.id === requestedNodeId) &&
        nodeHasCreateCapacity(node, ramMb, diskQuotaBytes),
    )
    .sort(
      (left, right) =>
        right.capabilities.memory.freeBytes - left.capabilities.memory.freeBytes ||
        (left.metrics?.cpuLoadPercent ?? 0) -
          (right.metrics?.cpuLoadPercent ?? 0),
    );
  const node = candidates[0];
  if (!node) {
    return {
      ok: false,
      status: 409,
      error:
        'No online user-owned node has Java, free RAM, guarded disk, and concurrency capacity for this server.',
    };
  }
  const conflict = await queryOne<{ id: string }>(
    `SELECT id FROM game_server
     WHERE workspaceId = ? AND nodeId = ? AND port = ? AND deletedAt IS NULL`,
    input.workspaceId,
    node.id,
    input.body.port,
  );
  if (conflict) {
    return { ok: false, status: 409, error: 'That private port is already assigned on the node.' };
  }
  const serverId = createId('gsv');
  const contract = validateGameServerJobPayload('game-server.lifecycle', {
    operation: 'create',
    serverId,
    name: input.body.name,
    game: 'minecraft-java',
    serverType: 'vanilla',
    version: input.body.version,
    ramMb: input.body.ramMb,
    cpuCores: input.body.cpuCores,
    diskQuotaBytes: input.body.diskQuotaBytes,
    port: input.body.port,
    properties: input.body.properties,
    eulaAccepted: input.body.eulaAccepted,
    provider: input.body.provider,
    zeroMode: input.body.zeroMode,
    exposure: input.body.exposure,
  });
  if (!contract.ok) {
    await recordGameSecurityEvent({
      workspaceId: input.workspaceId,
      nodeId: node.id,
      type: 'game-payload-abuse',
      severity: 'high',
      detail: contract.error,
    });
    return { ok: false, status: 400, error: contract.error };
  }
  const properties = contract.payload.properties as MinecraftProperties;
  const now = Date.now();
  try {
    await execute(
      `INSERT INTO game_server
       (id, workspaceId, nodeId, name, game, serverType, version, status,
        desiredStatus, ramMb, cpuCores, diskQuotaBytes, port, exposurePolicy,
        observedExposure, playerCount, playersJson, worldsJson, uptimeSeconds,
        onlineMode, whitelistEnabled, config, binaryVerified, crashCount,
        crashLoop, createdBy, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, 'minecraft-java', 'vanilla', ?, 'provisioning',
               'stopped', ?, ?, ?, ?, 'private', 'private', 0, '[]',
               '["world","world_nether","world_the_end"]', 0, ?, ?, ?, 0,
               0, 0, ?, ?, ?)`,
      serverId,
      input.workspaceId,
      node.id,
      contract.payload.name,
      contract.payload.version,
      contract.payload.ramMb,
      contract.payload.cpuCores,
      contract.payload.diskQuotaBytes,
      contract.payload.port,
      properties.onlineMode ? 1 : 0,
      properties.whitelist ? 1 : 0,
      stableJson(properties),
      input.actor,
      now,
      now,
    );
  } catch {
    return { ok: false, status: 409, error: 'The node port or server identity is already in use.' };
  }
  const queued = await enqueueJob({
    workspaceId: input.workspaceId,
    actor: input.actor,
    type: 'game-server.lifecycle',
    payload: contract.payload,
    targetNodeId: node.id,
    idempotencyKey: key,
  });
  if (!queued.ok) {
    await execute(
      'DELETE FROM game_server WHERE workspaceId = ? AND id = ?',
      input.workspaceId,
      serverId,
    );
    return queued;
  }
  if (!queued.created) {
    await execute(
      'DELETE FROM game_server WHERE workspaceId = ? AND id = ?',
      input.workspaceId,
      serverId,
    );
    const existing = await duplicateAction(input.workspaceId, key);
    return existing
      ? {
          ok: true,
          created: false,
          serverId: existing.serverId,
          backupId: null,
          action: existing,
        }
      : {
          ok: false,
          status: 409,
          error: 'The same create request is already being recorded.',
        };
  }
  const actionId = createId('gact');
  await execute(
    `INSERT INTO game_server_action
     (id, workspaceId, serverId, nodeId, jobId, kind, state,
      idempotencyKey, requestedBy, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, 'create', 'queued', ?, ?, ?, ?)`,
    actionId,
    input.workspaceId,
    serverId,
    node.id,
    queued.job.id,
    key,
    input.actor,
    now,
    now,
  );
  await writeLog({
    workspaceId: input.workspaceId,
    source: 'game-server',
    message: `Queued private Vanilla ${String(contract.payload.version)} provisioning on ${node.name}`,
    actor: input.actor,
    resource: serverId,
  });
  return {
    ok: true,
    created: true,
    serverId,
    backupId: null,
    action: {
      id: actionId,
      serverId,
      jobId: queued.job.id,
      kind: 'create',
      state: 'queued',
      requestedBy: input.actor,
      error: null,
      createdAt: now,
      updatedAt: now,
      completedAt: null,
    },
  };
}

const SIMPLE_ACTION_KEYS = ['action', 'provider', 'zeroMode'] as const;

function actionContract(input: {
  body: Record<string, unknown>;
  server: ServerRow;
}):
  | { ok: true; type: GameServerJobType; kind: string; payload: Record<string, unknown>; backupId: string | null }
  | { ok: false; error: string } {
  const action = input.body.action;
  let type: GameServerJobType;
  let payload: Record<string, unknown>;
  let backupId: string | null = null;
  if (['start', 'stop', 'restart', 'status'].includes(String(action))) {
    if (!exactKeys(input.body, SIMPLE_ACTION_KEYS)) return { ok: false, error: 'Lifecycle fields are invalid.' };
    type = 'game-server.lifecycle';
    payload = { operation: action, serverId: input.server.id };
  } else if (action === 'delete') {
    if (!exactKeys(input.body, [...SIMPLE_ACTION_KEYS, 'confirmDelete']) || input.body.confirmDelete !== true) {
      return { ok: false, error: 'Server deletion requires explicit confirmation.' };
    }
    type = 'game-server.lifecycle';
    payload = { operation: 'delete', serverId: input.server.id, confirmDelete: true };
  } else if (action === 'config-update') {
    if (!exactKeys(input.body, [...SIMPLE_ACTION_KEYS, 'port', 'properties'])) {
      return { ok: false, error: 'Configuration fields are invalid.' };
    }
    type = 'game-server.config';
    payload = { operation: 'update', serverId: input.server.id, port: input.body.port, properties: input.body.properties };
  } else if (action === 'player-list') {
    if (!exactKeys(input.body, SIMPLE_ACTION_KEYS)) return { ok: false, error: 'Player list fields are invalid.' };
    type = 'game-server.player';
    payload = { operation: 'list', serverId: input.server.id };
  } else if (['player-kick', 'whitelist-add', 'whitelist-remove', 'op', 'deop'].includes(String(action))) {
    if (!exactKeys(input.body, [...SIMPLE_ACTION_KEYS, 'player'])) return { ok: false, error: 'Player action fields are invalid.' };
    type = 'game-server.player';
    payload = { operation: action === 'player-kick' ? 'kick' : action, serverId: input.server.id, player: input.body.player };
  } else if (action === 'backup-create') {
    if (!exactKeys(input.body, [...SIMPLE_ACTION_KEYS, 'name'])) return { ok: false, error: 'Backup create fields are invalid.' };
    backupId = createId('gbk');
    type = 'game-server.backup';
    payload = { operation: 'create', serverId: input.server.id, backupId, name: input.body.name };
  } else if (action === 'backup-list') {
    if (!exactKeys(input.body, SIMPLE_ACTION_KEYS)) return { ok: false, error: 'Backup list fields are invalid.' };
    type = 'game-server.backup';
    payload = { operation: 'list', serverId: input.server.id };
  } else if (action === 'backup-restore' || action === 'backup-delete') {
    const confirmation = action === 'backup-restore' ? 'confirmRestore' : 'confirmDelete';
    if (!exactKeys(input.body, [...SIMPLE_ACTION_KEYS, 'backupId', confirmation]) || input.body[confirmation] !== true) {
      return { ok: false, error: `Backup ${action === 'backup-restore' ? 'restore' : 'deletion'} requires explicit confirmation.` };
    }
    backupId = typeof input.body.backupId === 'string' ? input.body.backupId : null;
    type = 'game-server.backup';
    payload = { operation: action === 'backup-restore' ? 'restore' : 'delete', serverId: input.server.id, backupId: input.body.backupId, [confirmation]: true };
  } else if (action === 'logs-tail') {
    if (!exactKeys(input.body, [...SIMPLE_ACTION_KEYS, 'lines'])) return { ok: false, error: 'Log tail fields are invalid.' };
    type = 'game-server.logs';
    payload = { operation: 'tail', serverId: input.server.id, lines: input.body.lines };
  } else {
    return { ok: false, error: 'Choose a reviewed Game Server action.' };
  }
  const validated = validateGameServerJobPayload(type, payload);
  return validated.ok
    ? { ok: true, type, kind: String(action), payload: validated.payload, backupId }
    : { ok: false, error: validated.error };
}

export type QueueGameServerResult =
  | {
      ok: true;
      created: boolean;
      serverId: string;
      backupId: string | null;
      action: GameServerAction;
    }
  | { ok: false; status: number; error: string };

export async function queueGameServerRequest(input: {
  workspaceId: string;
  actor: string;
  serverId?: string | null;
  body: unknown;
  idempotencyKey: string | null;
}): Promise<QueueGameServerResult> {
  if (!isRecord(input.body)) {
    return { ok: false, status: 400, error: 'Game Server request must be an object.' };
  }
  if (containsGameServerAbuse(input.body)) {
    await recordGameSecurityEvent({
      workspaceId: input.workspaceId,
      type: 'game-payload-abuse',
      severity: 'critical',
      detail: 'A request attempted to add a command, path, URL, tunnel, executable, JVM argument, or paid provider.',
    });
    return { ok: false, status: 400, error: 'Execution, path, URL, tunnel, and paid-provider fields are forbidden.' };
  }
  if (input.body.provider !== 'local-node' || input.body.zeroMode !== true) {
    await recordGameSecurityEvent({
      workspaceId: input.workspaceId,
      type: 'game-zero-mode-bypass',
      severity: 'critical',
      detail: 'A client attempted to bypass local-node Zero Mode Game Server execution.',
    });
    return { ok: false, status: 400, error: 'Game Servers require local-node Zero Mode execution.' };
  }
  const workspace = await getWorkspace(input.workspaceId);
  if (!workspace?.zeroMode) {
    return { ok: false, status: 409, error: 'Game Servers require Zero Mode to be enabled server-side.' };
  }
  if (input.body.action === 'create') {
    return createServer({ ...input, body: input.body });
  }
  if (!input.serverId) {
    return { ok: false, status: 400, error: 'A Game Server identity is required.' };
  }
  const server = await queryOne<ServerRow>(
    `SELECT * FROM game_server
     WHERE workspaceId = ? AND id = ? AND deletedAt IS NULL`,
    input.workspaceId,
    input.serverId,
  );
  if (!server) return { ok: false, status: 404, error: 'Game Server not found.' };
  const contract = actionContract({ body: input.body, server });
  if (!contract.ok) {
    await recordGameSecurityEvent({
      workspaceId: input.workspaceId,
      nodeId: server.nodeId,
      type: 'game-malformed-action',
      severity: 'high',
      detail: contract.error,
    });
    return { ok: false, status: 400, error: contract.error };
  }
  const nodesState = await readNodesState(input.workspaceId);
  const node = nodesState.nodes.find((candidate) => candidate.id === server.nodeId);
  if (!node || node.status === 'revoked') {
    return { ok: false, status: 409, error: 'The assigned node is revoked and accepts no lifecycle actions.' };
  }
  if (node.status !== 'online' || !agentVersionSupported(node.agentVersion)) {
    return { ok: false, status: 409, error: 'The assigned node must be online with the current agent.' };
  }
  if (['start', 'restart'].includes(String(input.body.action))) {
    const activeAdjustment =
      input.body.action === 'restart' && server.status === 'running' ? 1 : 0;
    if (
      !node.capabilities.gameServers.minecraftJavaAvailable ||
      node.capabilities.gameServers.activeServers - activeAdjustment >=
        node.capabilities.gameServers.maxConcurrentServers ||
      node.capabilities.memory.freeBytes <
        server.ramMb * 1024 ** 2 + GAME_SERVER_LIMITS.memoryReserveBytes ||
      node.capabilities.disk.freeBytes < GAME_SERVER_LIMITS.diskReserveBytes ||
      (node.metrics?.cpuLoadPercent ?? 0) >= 90
    ) {
      await recordGameSecurityEvent({
        workspaceId: input.workspaceId,
        nodeId: node.id,
        type: 'game-resource-exhaustion',
        severity: 'medium',
        detail: 'Start was refused by the RAM, disk, load, Java, or concurrency guard.',
      });
      return { ok: false, status: 409, error: 'The node does not have safe capacity to start this server.' };
    }
  }
  if (contract.type === 'game-server.config') {
    const conflict = await queryOne<{ id: string }>(
      `SELECT id FROM game_server
       WHERE workspaceId = ? AND nodeId = ? AND port = ?
         AND id <> ? AND deletedAt IS NULL`,
      input.workspaceId,
      server.nodeId,
      contract.payload.port,
      server.id,
    );
    if (conflict) return { ok: false, status: 409, error: 'That private port is already assigned on the node.' };
  }
  if (contract.backupId && input.body.action !== 'backup-create') {
    const backup = await queryOne<{ id: string; state: string }>(
      `SELECT id, state FROM game_server_backup
       WHERE workspaceId = ? AND serverId = ? AND id = ? AND deletedAt IS NULL`,
      input.workspaceId,
      server.id,
      contract.backupId,
    );
    if (!backup || backup.state !== 'ready') {
      return { ok: false, status: 404, error: 'A verified local backup was not found.' };
    }
  }
  const key = `game:${server.id}:${contract.kind}:${requestKey(input.idempotencyKey)}`;
  const duplicate = await duplicateAction(input.workspaceId, key);
  if (duplicate) {
    return { ok: true, created: false, serverId: server.id, backupId: contract.backupId, action: duplicate };
  }
  const queued = await enqueueJob({
    workspaceId: input.workspaceId,
    actor: input.actor,
    type: contract.type,
    payload: contract.payload,
    targetNodeId: server.nodeId,
    idempotencyKey: key,
  });
  if (!queued.ok) return queued;
  if (!queued.created) {
    const existing = await duplicateAction(input.workspaceId, key);
    return existing
      ? {
          ok: true,
          created: false,
          serverId: existing.serverId,
          backupId: contract.backupId,
          action: existing,
        }
      : {
          ok: false,
          status: 409,
          error: 'The same Game Server action is already being recorded.',
        };
  }
  const now = Date.now();
  const actionId = createId('gact');
  await execute(
    `INSERT INTO game_server_action
     (id, workspaceId, serverId, nodeId, jobId, kind, state,
      idempotencyKey, requestedBy, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)`,
    actionId,
    input.workspaceId,
    server.id,
    server.nodeId,
    queued.job.id,
    contract.kind,
    key,
    input.actor,
    now,
    now,
  );
  if (contract.kind === 'backup-create' && contract.backupId) {
    await execute(
      `INSERT INTO game_server_backup
       (id, workspaceId, serverId, nodeId, name, state, sizeBytes, fileCount,
        createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, 'creating', 0, 0, ?, ?)`,
      contract.backupId,
      input.workspaceId,
      server.id,
      server.nodeId,
      contract.payload.name,
      now,
      now,
    );
  }
  const transitional: Partial<Record<string, GameServerStatus>> = {
    start: 'starting',
    stop: 'stopping',
    restart: 'restarting',
    delete: 'stopping',
  };
  if (transitional[contract.kind]) {
    await execute(
      `UPDATE game_server SET status = ?, desiredStatus = ?, updatedAt = ?
       WHERE workspaceId = ? AND id = ?`,
      transitional[contract.kind],
      contract.kind === 'stop' || contract.kind === 'delete'
        ? 'stopped'
        : 'running',
      now,
      input.workspaceId,
      server.id,
    );
  }
  await writeLog({
    workspaceId: input.workspaceId,
    source: 'game-server',
    message: `Queued reviewed ${contract.kind} action for ${server.name}`,
    actor: input.actor,
    resource: server.id,
  });
  return {
    ok: true,
    created: queued.created,
    serverId: server.id,
    backupId: contract.backupId,
    action: {
      id: actionId,
      serverId: server.id,
      jobId: queued.job.id,
      kind: contract.kind,
      state: 'queued',
      requestedBy: input.actor,
      error: null,
      createdAt: now,
      updatedAt: now,
      completedAt: null,
    },
  };
}

export type GameServersShieldState = {
  total: number;
  eligibleOnlineNodes: number;
  staleNodes: number;
  revokedNodes: number;
  unexpectedExposure: number;
  onlineModeDisabled: number;
  whitelistDisabled: number;
  outdatedVersions: number;
  unverifiedBinaries: number;
  excessiveRam: number;
  crashLoops: number;
  unsafeConfig: number;
  corruptedBackups: number;
  unsignedJobs: number;
  expiredLeases: number;
  suspiciousVolume: number;
  forgedClaims: number;
  replayedJobs: number;
  revokedActivity: number;
  resourceExhaustion: number;
  zeroModeBypass: number;
  payloadAbuse: number;
};

export async function gameServersForShield(
  workspaceId: string,
  now = Date.now(),
): Promise<GameServersShieldState> {
  const state = await readGameServersState(workspaceId, now);
  const currentVersion = MINECRAFT_VERSIONS.find((version) => version.current)?.id;
  const eventCount = async (types: readonly string[]) => {
    const placeholders = types.map(() => '?').join(',');
    return (
      await queryOne<{ total: number }>(
        `SELECT COUNT(*) AS total FROM node_security_event
         WHERE workspaceId = ? AND createdAt >= ? AND type IN (${placeholders})`,
        workspaceId,
        now - 24 * 60 * 60_000,
        ...types,
      )
    )?.total ?? 0;
  };
  const [unsigned, expired, recent, corrupt] = await Promise.all([
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM node_job
       WHERE workspaceId = ? AND type LIKE 'game-server.%'
         AND state IN ('leased','cancelling','succeeded','failed')
         AND (claimSignature IS NULL OR claimSignature = '')`,
      workspaceId,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM node_job
       WHERE workspaceId = ? AND type LIKE 'game-server.%'
         AND state IN ('leased','cancelling') AND leaseExpiresAt <= ?`,
      workspaceId,
      now,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM node_job
       WHERE workspaceId = ? AND type LIKE 'game-server.%' AND createdAt >= ?`,
      workspaceId,
      now - 60 * 60_000,
    ),
    queryOne<{ total: number }>(
      `SELECT COUNT(*) AS total FROM game_server_backup
       WHERE workspaceId = ? AND state = 'corrupted'`,
      workspaceId,
    ),
  ]);
  return {
    total: state.servers.length,
    eligibleOnlineNodes: state.nodes.filter(
      (node) =>
        node.status === 'online' &&
        agentVersionSupported(node.agentVersion) &&
        node.capabilities.gameServers.minecraftJavaAvailable,
    ).length,
    staleNodes: state.nodes.filter((node) => node.status === 'stale').length,
    revokedNodes: state.nodes.filter((node) => node.status === 'revoked').length,
    unexpectedExposure: state.servers.filter(
      (server) => server.observedExposure === 'unexpected',
    ).length,
    onlineModeDisabled: state.servers.filter((server) => !server.onlineMode).length,
    whitelistDisabled: state.servers.filter(
      (server) => !server.whitelistEnabled,
    ).length,
    outdatedVersions: currentVersion
      ? state.servers.filter((server) => server.version !== currentVersion).length
      : 0,
    unverifiedBinaries: state.servers.filter(
      (server) => !server.binaryVerified && server.status !== 'provisioning',
    ).length,
    excessiveRam: state.servers.filter(
      (server) => server.ramMb > GAME_SERVER_LIMITS.maximumRamMb,
    ).length,
    crashLoops: state.servers.filter((server) => server.crashLoop).length,
    unsafeConfig: state.servers.filter(
      (server) =>
        server.port < 1024 ||
        server.port > 65_535 ||
        server.exposurePolicy !== 'private',
    ).length,
    corruptedBackups: corrupt?.total ?? 0,
    unsignedJobs: unsigned?.total ?? 0,
    expiredLeases:
      (expired?.total ?? 0) + (await eventCount(['game-expired-lease'])),
    suspiciousVolume:
      (recent?.total ?? 0) > GAME_SERVER_LIMITS.suspiciousActionsPerHour
        ? recent?.total ?? 0
        : 0,
    forgedClaims: await eventCount(['unsigned-or-forged-job-completion']),
    replayedJobs: await eventCount(['replay-detected']),
    revokedActivity: await eventCount([
      'revoked-node-game-activity',
      'revoked-token-used',
    ]),
    resourceExhaustion: await eventCount(['game-resource-exhaustion']),
    zeroModeBypass: await eventCount(['game-zero-mode-bypass']),
    payloadAbuse: await eventCount([
      'game-payload-abuse',
      'game-malformed-action',
      'game-unknown-server-snapshot',
      'game-stale-server-snapshot',
    ]),
  };
}
